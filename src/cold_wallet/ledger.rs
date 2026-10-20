//! A stock Ledger running the Bitcoin app as the vault's hardware wallet.
//!
//! The Ledger holds the HWW key; this module only ever sees public keys and signatures. Every
//! vault, savings and connector policy is registered on the device once (the user checks it on
//! screen), and the device returns an HMAC that later signing requests present instead of asking
//! again. Those HMACs are not secret: a forged one fails the device's own check.

use crate::core::{
    keys::VaultKey,
    policy::{ControllerPath, ControllerPolicy, SpendPath, TaprootPolicy},
    signer::VaultSigner,
    storage::{network_name, parse_network_name, read_json, write_json},
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use bitcoin::{
    Address, Network, Psbt, XOnlyPublicKey,
    bip32::{ChildNumber, DerivationPath, Fingerprint},
    hashes::{Hash, sha256},
    taproot::TapLeafHash,
};
use ledger_bitcoin_client::{
    BitcoinClient, PartialSignature, SignPsbtYieldedObject, Transport, WalletPolicy, WalletPubKey,
    apdu::{APDUCommand, StatusWord},
    wallet::Version,
};
use miniscript::{Descriptor, DescriptorPublicKey, ForEachKey};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Mutex,
};
use zeroize::Zeroizing;

/// Public description of a Ledger-backed HWW, written by `hww init --ledger`.
pub const LEDGER_DEVICE_FILE: &str = "hww/ledger.json";
/// Wallet policies the Ledger has registered, by policy id.
const LEDGER_REGISTRATIONS_FILE: &str = "hww/ledger-registrations.json";
/// Selects the device: unset or `usb` for a Ledger plugged in over USB, or `tcp:HOST:PORT` for
/// Ledger's Speculos emulator.
pub const LEDGER_TRANSPORT_ENV: &str = "ANZEN_LEDGER";
/// Message the Ledger signs to unlock its copy of the cloud backup key. The device shows it in
/// full before signing, and its deterministic (RFC 6979) signature is the same every time.
const BACKUP_UNLOCK_MESSAGE: &str = "Anzen: unlock the vault recovery backup (v1)";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerDeviceFile {
    pub version: u8,
    pub kind: String,
    pub network: String,
    pub vault_key: VaultKey,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Registrations {
    /// Hex policy id (sha256 of the serialized wallet policy) to hex HMAC.
    policies: BTreeMap<String, String>,
}

pub fn is_ledger_hww(data_dir: &Path) -> bool {
    data_dir.join(LEDGER_DEVICE_FILE).exists()
}

/// Read the vault account key from the Ledger and record it as this vault's HWW.
pub fn initialize(data_dir: &Path, network: Network, vault_key_index: u32) -> Result<VaultKey> {
    let path = data_dir.join(LEDGER_DEVICE_FILE);
    ensure!(
        !path.exists(),
        "a Ledger HWW is already set up at {}",
        path.display()
    );
    let device = LedgerDevice::connect()?;
    device.check_app(network)?;
    let vault_key = device.vault_key(network, vault_key_index)?;
    write_json(
        &path,
        &LedgerDeviceFile {
            version: 1,
            kind: "ledger-hww".to_owned(),
            network: network_name(network).to_owned(),
            vault_key,
        },
    )?;
    Ok(vault_key)
}

/// The Ledger that was set up for this vault, checked to hold the same key.
pub struct LedgerHww {
    device: LedgerDevice,
    network: Network,
    vault_key: VaultKey,
    registrations: PathBuf,
}

impl LedgerHww {
    pub fn open(data_dir: &Path) -> Result<Self> {
        let file: LedgerDeviceFile = read_json(&data_dir.join(LEDGER_DEVICE_FILE))?;
        ensure!(
            file.version == 1 && file.kind == "ledger-hww",
            "unsupported Ledger HWW file"
        );
        let network = parse_network_name(&file.network)?;
        let device = LedgerDevice::connect()?;
        device.check_app(network)?;
        ensure!(
            device.fingerprint()? == file.vault_key.fingerprint,
            "this Ledger holds a different seed than the one set up for this vault"
        );
        Ok(Self {
            device,
            network,
            vault_key: file.vault_key,
            registrations: data_dir.join(LEDGER_REGISTRATIONS_FILE),
        })
    }

    /// Register `descriptor` on the device if it is not registered yet, and return the policy
    /// with its HMAC. The device shows every key and spending path before it agrees.
    fn registered(
        &self,
        name: String,
        descriptor: &Descriptor<DescriptorPublicKey>,
        address: &Address,
    ) -> Result<(WalletPolicy, [u8; 32])> {
        let policy = wallet_policy(name, descriptor)?;
        let id = sha256::Hash::hash(&policy.serialize()).to_string();
        let mut registrations: Registrations = if self.registrations.exists() {
            read_json(&self.registrations)?
        } else {
            Registrations::default()
        };
        let hmac = match registrations.policies.get(&id) {
            Some(hex) => decode_hmac(hex)?,
            None => {
                eprintln!(
                    "Check the \"{}\" policy on your Ledger and approve it if every key and spending path matches.",
                    policy.name
                );
                let (_, hmac) = self
                    .device
                    .client
                    .register_wallet(&policy)
                    .map_err(|error| {
                        anyhow!("the Ledger did not register the policy: {error:?}")
                    })?;
                registrations
                    .policies
                    .insert(id, bitcoin::hex::DisplayHex::to_lower_hex_string(&hmac[..]));
                write_json(&self.registrations, &registrations)?;
                hmac
            }
        };
        // The device derives the address itself; it must match the one Anzen funds.
        let device_address = self
            .device
            .client
            .get_wallet_address(&policy, Some(&hmac), false, 0, false)
            .map_err(|error| {
                anyhow!("the Ledger could not derive the policy address: {error:?}")
            })?;
        ensure!(
            device_address.assume_checked_ref().script_pubkey() == address.script_pubkey(),
            "the Ledger derives a different address for {} than Anzen does",
            policy.name
        );
        Ok((policy, hmac))
    }

    /// Ask the device to sign, then keep only signatures by `key` for `leaf_hash` on the
    /// requested inputs. A signature for any other leaf is dropped rather than trusted.
    fn sign(
        &self,
        psbt: &mut Psbt,
        policy: &WalletPolicy,
        hmac: &[u8; 32],
        key: XOnlyPublicKey,
        leaf_hash: TapLeafHash,
        input_indexes: &[usize],
    ) -> Result<()> {
        for &index in input_indexes {
            ensure!(
                index < psbt.inputs.len(),
                "signing input index {index} is out of range"
            );
        }
        eprintln!("Review the transaction on your Ledger and sign it if it matches.");
        let signatures = self
            .device
            .client
            .sign_psbt(psbt, policy, Some(hmac))
            .map_err(|error| anyhow!("the Ledger did not sign: {error:?}"))?;
        let mut signed = vec![false; psbt.inputs.len()];
        for (index, object) in signatures {
            let SignPsbtYieldedObject::Partial(PartialSignature::TapScriptSig(
                signer,
                Some(leaf),
                signature,
            )) = object
            else {
                continue;
            };
            if signer != key || leaf != leaf_hash || !input_indexes.contains(&index) {
                continue;
            }
            psbt.inputs[index]
                .tap_script_sigs
                .insert((signer, leaf), signature);
            signed[index] = true;
        }
        for &index in input_indexes {
            ensure!(
                signed[index],
                "the Ledger returned no signature for input {index}"
            );
        }
        Ok(())
    }
}

impl VaultSigner for LedgerHww {
    fn vault_key(&self) -> VaultKey {
        self.vault_key
    }

    fn sign_vault_inputs(
        &self,
        psbt: &mut Psbt,
        policy: &dyn TaprootPolicy,
        path: SpendPath,
        input_indexes: &[usize],
    ) -> Result<()> {
        ensure!(
            !matches!(
                path,
                SpendPath::PhoneRecovery | SpendPath::Heir | SpendPath::PhoneYubikey
            ),
            "the HWW cannot sign a path that belongs to the phone, the YubiKey or the heir"
        );
        let (wallet, hmac) =
            self.registered(policy.wallet_name(), policy.descriptor(), policy.address())?;
        let leaf = policy.leaf(path)?;
        self.sign(
            psbt,
            &wallet,
            &hmac,
            self.vault_key.for_path(path),
            leaf.leaf_hash,
            input_indexes,
        )
    }

    fn sign_controller_inputs(
        &self,
        psbt: &mut Psbt,
        policy: &ControllerPolicy,
        path: ControllerPath,
        input_indexes: &[usize],
    ) -> Result<()> {
        ensure!(
            path == ControllerPath::Hww,
            "the HWW signs only its own connector path"
        );
        let (wallet, hmac) =
            self.registered(policy.wallet_name(), &policy.descriptor, &policy.address)?;
        let leaf = policy.leaf(path)?;
        self.sign(
            psbt,
            &wallet,
            &hmac,
            self.vault_key.cooperative(),
            leaf.leaf_hash,
            input_indexes,
        )
    }

    fn backup_secret(&self) -> Result<Zeroizing<Vec<u8>>> {
        eprintln!("Approve the \"{BACKUP_UNLOCK_MESSAGE}\" message on your Ledger.");
        let path = backup_unlock_path(self.network)?;
        let (header, signature) = self
            .device
            .client
            .sign_message(BACKUP_UNLOCK_MESSAGE.as_bytes(), &path)
            .map_err(|error| anyhow!("the Ledger did not sign the unlock message: {error:?}"))?;
        let mut secret = Zeroizing::new(vec![header]);
        secret.extend_from_slice(&signature.serialize_compact());
        Ok(secret)
    }
}

/// `m/86'/coin'/100'/1/0`: next to the vault account keys, used for nothing else.
fn backup_unlock_path(network: Network) -> Result<DerivationPath> {
    let coin = if network == Network::Bitcoin { 0 } else { 1 };
    Ok(DerivationPath::from_str(&format!(
        "m/86'/{coin}'/100'/1/0"
    ))?)
}

/// Write a multipath descriptor as a BIP388 wallet policy: each distinct key becomes `@i`, and
/// `/<0;1>/*` becomes `/**`.
pub fn wallet_policy(
    name: String,
    descriptor: &Descriptor<DescriptorPublicKey>,
) -> Result<WalletPolicy> {
    let text = descriptor.to_string();
    let mut template = text.split('#').next().unwrap_or_default().to_owned();
    let mut keys: Vec<String> = Vec::new();
    descriptor.for_each_key(|key| {
        let text = key.to_string();
        let base = text
            .split_once("/<")
            .map(|(base, _)| base.to_owned())
            .unwrap_or(text);
        if !keys.contains(&base) {
            keys.push(base);
        }
        true
    });
    // Replace longer keys first so a key that is a prefix of another cannot clash.
    let mut order: Vec<usize> = (0..keys.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(keys[i].len()));
    for i in order {
        template = template.replace(&keys[i], &format!("@{i}"));
    }
    template = template.replace("/<0;1>/*", "/**");
    ensure!(
        !template.contains("pub"),
        "could not turn the descriptor into a wallet policy template"
    );
    let keys = keys
        .iter()
        .map(|key| {
            WalletPubKey::from_str(key)
                .map_err(|error| anyhow!("invalid wallet policy key {key}: {error:?}"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(WalletPolicy::new(name, Version::V2, template, keys))
}

fn decode_hmac(hex: &str) -> Result<[u8; 32]> {
    let bytes = bitcoin::hex::FromHex::from_hex(hex).context("invalid stored Ledger HMAC")?;
    Ok(bytes)
}

/// A connection to the Ledger Bitcoin app.
struct LedgerDevice {
    client: BitcoinClient<LedgerTransport>,
}

impl LedgerDevice {
    fn connect() -> Result<Self> {
        let transport = match std::env::var(LEDGER_TRANSPORT_ENV) {
            Ok(value) if value.starts_with("tcp:") => {
                LedgerTransport::tcp(value.trim_start_matches("tcp:"))?
            }
            Ok(value) if value != "usb" && !value.is_empty() => {
                bail!("{LEDGER_TRANSPORT_ENV} must be `usb` or `tcp:HOST:PORT`, not {value}")
            }
            _ => LedgerTransport::usb()?,
        };
        Ok(Self {
            client: BitcoinClient::new(transport),
        })
    }

    /// Mainnet needs the "Bitcoin" app; every test network needs "Bitcoin Test".
    fn check_app(&self, network: Network) -> Result<()> {
        let (name, version, _) = self.client.get_version().map_err(|error| {
            anyhow!("open the Bitcoin app on the Ledger and try again ({error:?})")
        })?;
        let expected = if network == Network::Bitcoin {
            "Bitcoin"
        } else {
            "Bitcoin Test"
        };
        ensure!(
            name == expected,
            "open the \"{expected}\" app on the Ledger (it is running \"{name}\")"
        );
        let major_minor: Vec<u32> = version
            .split('.')
            .take(2)
            .filter_map(|part| part.parse().ok())
            .collect();
        ensure!(
            major_minor.as_slice() >= [2, 1].as_slice(),
            "the Ledger Bitcoin app {version} is too old; update it to 2.1 or newer in Ledger Live"
        );
        Ok(())
    }

    fn fingerprint(&self) -> Result<Fingerprint> {
        self.client
            .get_master_fingerprint()
            .map_err(|error| anyhow!("could not read the Ledger fingerprint: {error:?}"))
    }

    fn vault_key(&self, network: Network, index: u32) -> Result<VaultKey> {
        let fingerprint = self.fingerprint()?;
        let coin = if network == Network::Bitcoin { 0 } else { 1 };
        let path = DerivationPath::from_str(&format!("m/86'/{coin}'/100'/0"))?
            .child(ChildNumber::from_normal_idx(index)?);
        let xpub = self
            .client
            .get_extended_pubkey(&path, false)
            .map_err(|error| anyhow!("could not read the vault key from the Ledger: {error:?}"))?;
        // Same derivation path as the software HWW, so a vault key never depends on the device.
        VaultKey::new(fingerprint, &path, xpub)
    }
}

/// Byte transport to the Ledger: USB HID for a real device, TCP for the Speculos emulator.
enum LedgerTransport {
    Tcp(Mutex<TcpStream>),
    #[cfg(feature = "ledger-usb")]
    Usb(ledger_transport_hid::TransportNativeHID),
}

impl LedgerTransport {
    fn tcp(address: &str) -> Result<Self> {
        let stream = TcpStream::connect(address)
            .with_context(|| format!("could not reach the Ledger emulator at {address}"))?;
        Ok(Self::Tcp(Mutex::new(stream)))
    }

    #[cfg(feature = "ledger-usb")]
    fn usb() -> Result<Self> {
        let api = ledger_transport_hid::hidapi::HidApi::new()
            .context("could not open USB HID to look for a Ledger")?;
        let device = ledger_transport_hid::TransportNativeHID::new(&api).map_err(|error| {
            anyhow!(
                "no Ledger found over USB; plug it in, unlock it and open the Bitcoin app ({error})"
            )
        })?;
        Ok(Self::Usb(device))
    }

    #[cfg(not(feature = "ledger-usb"))]
    fn usb() -> Result<Self> {
        bail!(
            "this build has no USB Ledger support; rebuild with `--features ledger-usb`, or set {LEDGER_TRANSPORT_ENV}=tcp:HOST:PORT for the emulator"
        )
    }
}

impl Transport for LedgerTransport {
    type Error = anyhow::Error;

    fn exchange(&self, command: &APDUCommand) -> Result<(StatusWord, Vec<u8>), Self::Error> {
        let apdu = command.encode();
        let mut answer = match self {
            Self::Tcp(stream) => {
                // Speculos framing: 4-byte big-endian length, then the bytes. The reply length
                // excludes the 2-byte status word that follows the data.
                let mut stream = stream
                    .lock()
                    .map_err(|_| anyhow!("emulator connection poisoned"))?;
                stream.write_all(&(apdu.len() as u32).to_be_bytes())?;
                stream.write_all(&apdu)?;
                let mut length = [0_u8; 4];
                stream.read_exact(&mut length)?;
                let mut answer = vec![0_u8; u32::from_be_bytes(length) as usize + 2];
                stream.read_exact(&mut answer)?;
                answer
            }
            #[cfg(feature = "ledger-usb")]
            Self::Usb(device) => {
                let command = ledger_apdu::APDUCommand {
                    cla: command.cla,
                    ins: command.ins,
                    p1: command.p1,
                    p2: command.p2,
                    data: command.data.clone(),
                };
                let answer = device
                    .exchange(&command)
                    .map_err(|error| anyhow!("USB exchange with the Ledger failed: {error}"))?;
                let mut bytes = answer.data().to_vec();
                bytes.extend_from_slice(&answer.retcode().to_be_bytes());
                bytes
            }
        };
        ensure!(answer.len() >= 2, "the Ledger sent a truncated reply");
        let status = answer.split_off(answer.len() - 2);
        let code = u16::from_be_bytes([status[0], status[1]]);
        let status = StatusWord::try_from(code)
            .map_err(|_| anyhow!("the Ledger replied with unknown status {code:#06x}"))?;
        Ok((status, answer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        keys::DeviceKeys,
        policy::{PolicyKeys, VaultPolicy},
    };

    #[test]
    fn a_yubikey_vault_gives_each_pair_its_own_branch() {
        let secp = bitcoin::key::Secp256k1::new();
        let [phone, hww, yubikey] = [0; 3].map(|_| DeviceKeys::generate(&secp).unwrap());
        let keys = PolicyKeys {
            yubikey: Some(yubikey.vault_pubkey),
            ..PolicyKeys::new(phone.vault_pubkey, hww.vault_pubkey)
        };
        let vault = VaultPolicy::build(&keys, Network::Regtest).unwrap();
        let policy = wallet_policy("Anzen vault".to_owned(), &vault.descriptor).unwrap();
        assert_eq!(policy.keys.len(), 4);
        assert_eq!(
            policy.descriptor_template,
            "tr(@3/**,{multi_a(2,@0/**,@1/**),{{multi_a(2,@0/<4;5>/*,@2/<4;5>/*),multi_a(2,@1/<6;7>/*,@2/<6;7>/*)},{and_v(v:older(61200),pk(@0/<2;3>/*)),and_v(v:older(65535),pk(@1/<2;3>/*))}}})"
        );
    }

    #[test]
    fn an_heir_vault_is_a_four_key_wallet_policy() {
        let secp = bitcoin::key::Secp256k1::new();
        let [phone, hww, heir] = [0; 3].map(|_| DeviceKeys::generate(&secp).unwrap());
        let vault = VaultPolicy::with_heir(
            phone.vault_pubkey,
            hww.vault_pubkey,
            Some(heir.vault_pubkey),
            Network::Regtest,
        )
        .unwrap();
        let policy = wallet_policy("Anzen vault".to_owned(), &vault.descriptor).unwrap();
        assert_eq!(policy.keys.len(), 4);
        assert_eq!(
            policy.descriptor_template,
            "tr(@3/**,{multi_a(2,@0/**,@1/**),{{and_v(v:older(61200),pk(@0/<2;3>/*)),and_v(v:older(65535),pk(@1/<2;3>/*))},and_v(v:older(65535),pk(@2/<2;3>/*))}})"
        );
    }
}
