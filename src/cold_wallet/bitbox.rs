//! A BitBox02 (firmware 9.21 or newer) as the vault's hardware wallet.
//!
//! Like the Ledger, the BitBox02 holds the HWW key and this module only sees public keys and
//! signatures. Each policy is registered on the device once, after the user checks every key
//! and path on its screen; the device keeps the registration itself. Two limits shape the code:
//!
//! - The BitBox02 signs a transaction only when every input belongs to one registered policy.
//!   Anzen's HWW transactions already are (the vault, a savings lock, one allowance month, or the
//!   connector), so a transaction with inputs the device does not own is refused here with a
//!   plain explanation instead of a device error.
//! - It picks the leaf to sign from the key derivation in the PSBT, so the copy it receives keeps
//!   only the derivation of the leaf Anzen asked for.

use crate::core::{
    keys::{RECOVERY_BRANCH, VaultKey},
    policy::{ControllerPath, ControllerPolicy, SpendPath, TaprootPolicy},
    signer::VaultSigner,
    storage::{network_name, parse_network_name, read_json, write_json},
    transactions::{verify_controller_psbt_signatures, verify_vault_psbt_signatures},
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use bitbox_api::{
    Keypath, PairedBitBox, PersistedNoiseConfig,
    btc::KeyOriginInfo,
    pb::{self, BtcCoin},
    runtime::TokioRuntime,
};
use bitcoin::{
    Address, Network, Psbt, ScriptBuf, XOnlyPublicKey,
    bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub},
    hashes::{Hash, HashEngine, sha256},
    taproot::TapLeafHash,
};
use miniscript::{Descriptor, DescriptorPublicKey};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};
use zeroize::Zeroizing;

/// Public description of a BitBox02-backed HWW, written by `hww init --bitbox`.
pub const BITBOX_DEVICE_FILE: &str = "hww/bitbox02.json";
/// Where the pairing with this computer is kept, so the code is confirmed only once.
const BITBOX_PAIRING_DIR: &str = "hww/bitbox02-pairing";
/// Selects the device: unset or `usb` for a BitBox02 plugged in over USB, or `tcp:HOST:PORT` for
/// the BitBox02 simulator.
pub const BITBOX_TRANSPORT_ENV: &str = "ANZEN_BITBOX";
/// Taproot Miniscript policies arrived in this firmware.
const MINIMUM_FIRMWARE: &str = ">=9.21.0";
/// Account `m/86'/coin'/99'` is a standard Taproot account, so the device exports it without an
/// "unusual keypath" warning. Its xpub never leaves this computer and nothing receives coins
/// there; it only unlocks the HWW's copy of the cloud backup key.
const BACKUP_UNLOCK_ACCOUNT: u32 = 99;
const BACKUP_UNLOCK_TAG: &[u8] = b"Anzen: unlock the vault recovery backup (BitBox02, v1)";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitBoxDeviceFile {
    pub version: u8,
    pub kind: String,
    pub network: String,
    pub vault_key: VaultKey,
}

pub fn is_bitbox_hww(data_dir: &Path) -> bool {
    data_dir.join(BITBOX_DEVICE_FILE).exists()
}

/// Read the vault account key from the BitBox02 and record it as this vault's HWW.
pub fn initialize(data_dir: &Path, network: Network, vault_key_index: u32) -> Result<VaultKey> {
    let path = data_dir.join(BITBOX_DEVICE_FILE);
    ensure!(
        !path.exists(),
        "a BitBox02 HWW is already set up at {}",
        path.display()
    );
    let device = BitBoxDevice::connect(data_dir)?;
    let vault_key = device.vault_key(network, vault_key_index)?;
    write_json(
        &path,
        &BitBoxDeviceFile {
            version: 1,
            kind: "bitbox02-hww".to_owned(),
            network: network_name(network).to_owned(),
            vault_key,
        },
    )?;
    Ok(vault_key)
}

/// The BitBox02 that was set up for this vault, checked to hold the same seed.
pub struct BitBoxHww {
    device: BitBoxDevice,
    network: Network,
    vault_key: VaultKey,
}

impl BitBoxHww {
    pub fn open(data_dir: &Path) -> Result<Self> {
        let file: BitBoxDeviceFile = read_json(&data_dir.join(BITBOX_DEVICE_FILE))?;
        ensure!(
            file.version == 1 && file.kind == "bitbox02-hww",
            "unsupported BitBox02 HWW file"
        );
        let network = parse_network_name(&file.network)?;
        let device = BitBoxDevice::connect(data_dir)?;
        ensure!(
            device.fingerprint()? == file.vault_key.fingerprint,
            "this BitBox02 holds a different seed than the one set up for this vault"
        );
        Ok(Self {
            device,
            network,
            vault_key: file.vault_key,
        })
    }

    fn coin(&self) -> BtcCoin {
        coin(self.network)
    }

    /// Register `descriptor` on the device if it is not registered yet, then check that the
    /// device derives the same address Anzen funds. Returns the policy as the device knows it.
    fn registered(
        &self,
        name: &str,
        descriptor: &Descriptor<DescriptorPublicKey>,
        address: &Address,
    ) -> Result<pb::BtcScriptConfig> {
        let (template, keys) = super::wallet_policy::template(descriptor)?;
        let keys = keys
            .iter()
            .map(|key| key_origin_info(key))
            .collect::<Result<Vec<_>>>()?;
        let config = bitbox_api::btc::make_script_config_policy(&template, &keys);
        let policy = &config;
        let registered = self.device.run(|bitbox| async move {
            bitbox
                .btc_is_script_config_registered(self.coin(), policy, None)
                .await
        });
        let registered = registered
            .map_err(|error| anyhow!("could not ask the BitBox02 about a policy: {error}"))?;
        if !registered {
            eprintln!(
                "Check the \"{name}\" policy on your BitBox02 and approve it if every key and spending path matches."
            );
            self.device
                .run(|bitbox| async move {
                    bitbox
                        .btc_register_script_config(
                            self.coin(),
                            policy,
                            None,
                            pb::btc_register_script_config_request::XPubType::AutoXpubTpub,
                            Some(name),
                        )
                        .await
                })
                .map_err(|error| anyhow!("the BitBox02 did not register the policy: {error}"))?;
        }
        // The device derives the address itself; it must match the one Anzen funds.
        let keypath = address_keypath(descriptor, self.vault_key)?;
        let device_address = self
            .device
            .run(|bitbox| async move {
                bitbox
                    .btc_address(self.coin(), &keypath, policy, false)
                    .await
            })
            .map_err(|error| {
                anyhow!("the BitBox02 could not derive the policy address: {error}")
            })?;
        let device_script = Address::from_str(&device_address)
            .context("the BitBox02 returned an invalid address")?
            .assume_checked()
            .script_pubkey();
        ensure!(
            device_script == address.script_pubkey(),
            "the BitBox02 derives a different address for {name} than Anzen does"
        );
        Ok(config)
    }

    /// Ask the device to sign every input of `psbt` with `key` for `leaf_hash`, then copy back
    /// only those signatures.
    fn sign(
        &self,
        psbt: &mut Psbt,
        config: pb::BtcScriptConfig,
        policy_script: &ScriptBuf,
        key: XOnlyPublicKey,
        leaf_hash: TapLeafHash,
        input_indexes: &[usize],
    ) -> Result<()> {
        let mut wanted = input_indexes.to_vec();
        wanted.sort_unstable();
        wanted.dedup();
        ensure!(
            wanted == (0..psbt.inputs.len()).collect::<Vec<_>>(),
            "a BitBox02 can only sign a transaction whose every input it owns, and this one has \
             inputs from elsewhere (such as emergency-access connectors); this action is not \
             available with a BitBox02 yet"
        );
        let fingerprint = self.vault_key.fingerprint;
        let mut copy = psbt.clone();
        for (index, input) in copy.inputs.iter_mut().enumerate() {
            ensure!(
                input
                    .witness_utxo
                    .as_ref()
                    .is_some_and(|utxo| &utxo.script_pubkey == policy_script),
                "input {index} is not from the policy being signed"
            );
            let origin = input
                .tap_key_origins
                .get(&key)
                .filter(|(leaves, _)| leaves.contains(&leaf_hash))
                .map(|(_, source)| source.clone())
                .with_context(|| format!("PSBT input {index} does not name the HWW leaf key"))?;
            // Only the leaf being signed: the device signs for the first of its keys it finds.
            input
                .tap_key_origins
                .retain(|_, (_, (origin_fingerprint, _))| *origin_fingerprint != fingerprint);
            input.tap_key_origins.insert(key, (vec![leaf_hash], origin));
        }
        for output in &mut copy.outputs {
            output
                .tap_key_origins
                .retain(|_, (_, (origin_fingerprint, _))| *origin_fingerprint != fingerprint);
        }
        // Change back to the same policy is shown as the vault's own: give the device the
        // derivation it needs to check that.
        for (output, txout) in copy.outputs.iter_mut().zip(&copy.unsigned_tx.output) {
            if &txout.script_pubkey == policy_script {
                let origin = copy.inputs[0].tap_key_origins[&key].1.clone();
                output
                    .tap_key_origins
                    .insert(key, (vec![leaf_hash], origin));
            }
        }
        eprintln!("Review the transaction on your BitBox02 and sign it if it matches.");
        let script_config = pb::BtcScriptConfigWithKeypath {
            script_config: Some(config),
            keypath: self
                .vault_key
                .origin()
                .into_iter()
                .map(|c| u32::from(*c))
                .collect(),
        };
        let coin = self.coin();
        self.device
            .run(|bitbox| async move {
                bitbox
                    .btc_sign_psbt(
                        coin,
                        &mut copy,
                        Some(script_config),
                        pb::btc_sign_init_request::FormatUnit::Default,
                    )
                    .await
                    .map(|()| copy)
            })
            .map_err(|error| anyhow!("the BitBox02 did not sign: {error}"))
            .and_then(|signed| {
                for &index in input_indexes {
                    let signature = signed.inputs[index]
                        .tap_script_sigs
                        .get(&(key, leaf_hash))
                        .with_context(|| {
                            format!("the BitBox02 returned no signature for input {index}")
                        })?;
                    psbt.inputs[index]
                        .tap_script_sigs
                        .insert((key, leaf_hash), *signature);
                }
                Ok(())
            })
    }
}

impl VaultSigner for BitBoxHww {
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
        let config =
            self.registered(&policy.wallet_name(), policy.descriptor(), policy.address())?;
        let leaf = policy.leaf(path)?;
        self.sign(
            psbt,
            config,
            &policy.address().script_pubkey(),
            self.vault_key.for_path(path),
            leaf.leaf_hash,
            input_indexes,
        )?;
        // A signature that does not verify is refused here rather than at broadcast.
        verify_vault_psbt_signatures(psbt, policy, path, self.vault_key, input_indexes)
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
        let config = self.registered(&policy.wallet_name(), &policy.descriptor, &policy.address)?;
        let leaf = policy.leaf(path)?;
        self.sign(
            psbt,
            config,
            &policy.address.script_pubkey(),
            self.vault_key.cooperative(),
            leaf.leaf_hash,
            input_indexes,
        )?;
        verify_controller_psbt_signatures(
            psbt,
            policy,
            path,
            self.vault_key.cooperative(),
            input_indexes,
        )
    }

    fn one_policy_per_transaction(&self) -> bool {
        true
    }

    fn backup_secret(&self) -> Result<Zeroizing<Vec<u8>>> {
        let coin_type = if self.network == Network::Bitcoin {
            0
        } else {
            1
        };
        let keypath = Keypath::from(&DerivationPath::from_str(&format!(
            "m/86'/{coin_type}'/{BACKUP_UNLOCK_ACCOUNT}'"
        ))?);
        let xpub = self
            .device
            .run(|bitbox| async move {
                bitbox
                    .btc_xpub(
                        self.coin(),
                        &keypath,
                        pb::btc_pub_request::XPubType::Xpub,
                        false,
                    )
                    .await
            })
            .map_err(|error| anyhow!("the BitBox02 did not unlock the backup: {error}"))?;
        let xpub = Xpub::from_str(&xpub).context("the BitBox02 returned an invalid xpub")?;
        let mut engine = sha256::Hash::engine();
        engine.input(BACKUP_UNLOCK_TAG);
        engine.input(&xpub.encode());
        Ok(Zeroizing::new(
            sha256::Hash::from_engine(engine).to_byte_array().to_vec(),
        ))
    }
}

/// The firmware takes wallet policies only for Bitcoin and testnet. Regtest shares testnet's coin
/// type, and Anzen compares scripts rather than address strings, so it uses testnet too.
fn coin(network: Network) -> BtcCoin {
    if network == Network::Bitcoin {
        BtcCoin::Btc
    } else {
        BtcCoin::Tbtc
    }
}

/// A wallet policy key, `[fingerprint/path]xpub` or a bare xpub, as the BitBox02 takes it.
fn key_origin_info(key: &str) -> Result<KeyOriginInfo> {
    if key.starts_with('[') {
        let key = VaultKey::from_str(key)?;
        Ok(KeyOriginInfo {
            root_fingerprint: Some(key.fingerprint),
            keypath: Some(Keypath::from(&key.origin())),
            xpub: key.xpub,
        })
    } else {
        Ok(KeyOriginInfo {
            root_fingerprint: None,
            keypath: None,
            xpub: Xpub::from_str(key).with_context(|| format!("invalid policy key {key}"))?,
        })
    }
}

/// The full derivation of the HWW key at Anzen's address index in the first branch where the
/// policy uses it. The device derives the policy's address from it.
fn address_keypath(descriptor: &Descriptor<DescriptorPublicKey>, hww: VaultKey) -> Result<Keypath> {
    let prefix = format!("{hww}/<");
    let text = descriptor.to_string();
    let branch = text
        .split(&prefix)
        .nth(1)
        .and_then(|rest| rest.split_once(';'))
        .and_then(|(branch, _)| branch.parse::<u32>().ok())
        .unwrap_or(RECOVERY_BRANCH);
    let path = hww.origin().extend([
        ChildNumber::from_normal_idx(branch)?,
        ChildNumber::from_normal_idx(crate::core::keys::ADDRESS_INDEX)?,
    ]);
    Ok(Keypath::from(&path))
}

/// A paired connection to the BitBox02, driven from this synchronous program by its own small
/// async runtime.
struct BitBoxDevice {
    runtime: tokio::runtime::Runtime,
    bitbox: PairedBitBox<TokioRuntime>,
}

impl BitBoxDevice {
    fn connect(data_dir: &Path) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("could not start the BitBox02 connection")?;
        let pairing_dir = data_dir.join(BITBOX_PAIRING_DIR);
        std::fs::create_dir_all(&pairing_dir)
            .with_context(|| format!("could not create {}", pairing_dir.display()))?;
        let bitbox = runtime.block_on(pair(pairing_dir))?;
        bitbox.validate_firmware()?;
        Ok(Self { runtime, bitbox })
    }

    fn run<'a, T, F>(
        &'a self,
        call: impl FnOnce(&'a PairedBitBox<TokioRuntime>) -> F,
    ) -> Result<T, bitbox_api::error::Error>
    where
        F: std::future::Future<Output = Result<T, bitbox_api::error::Error>>,
    {
        self.runtime.block_on(call(&self.bitbox))
    }

    fn fingerprint(&self) -> Result<Fingerprint> {
        let text = self
            .run(|bitbox| bitbox.root_fingerprint())
            .map_err(|error| anyhow!("could not read the BitBox02 fingerprint: {error}"))?;
        Fingerprint::from_str(&text).context("the BitBox02 returned an invalid fingerprint")
    }

    /// The vault key at `m/86'/coin'/100'/0/index`, the same path as on every other HWW, so the
    /// key does not depend on the device holding the seed. The BitBox02 asks the user to approve
    /// exporting it, because the path is not one of its standard accounts.
    fn vault_key(&self, network: Network, index: u32) -> Result<VaultKey> {
        let fingerprint = self.fingerprint()?;
        let coin_type = if network == Network::Bitcoin { 0 } else { 1 };
        let path = DerivationPath::from_str(&format!("m/86'/{coin_type}'/100'/0"))?
            .child(ChildNumber::from_normal_idx(index)?);
        let xpub_type = if network == Network::Bitcoin {
            pb::btc_pub_request::XPubType::Xpub
        } else {
            pb::btc_pub_request::XPubType::Tpub
        };
        eprintln!(
            "Your BitBox02 will warn that {path} is an unusual keypath. It is Anzen's vault key \
             path; approve it to continue."
        );
        let keypath = Keypath::from(&path);
        let xpub = self
            .run(|bitbox| async move {
                bitbox
                    .btc_xpub(coin(network), &keypath, xpub_type, false)
                    .await
            })
            .map_err(|error| anyhow!("could not read the vault key from the BitBox02: {error}"))?;
        let xpub = Xpub::from_str(&xpub).context("the BitBox02 returned an invalid xpub")?;
        VaultKey::new(fingerprint, &path, xpub)
    }
}

trait FirmwareCheck {
    fn validate_firmware(&self) -> Result<()>;
}

impl FirmwareCheck for PairedBitBox<TokioRuntime> {
    fn validate_firmware(&self) -> Result<()> {
        let required = semver::VersionReq::parse(MINIMUM_FIRMWARE).expect("valid requirement");
        ensure!(
            required.matches(self.version()),
            "the BitBox02 firmware {} is too old for Taproot policies; update it to 9.21 or newer \
             in the BitBoxApp",
            self.version()
        );
        Ok(())
    }
}

async fn pair(pairing_dir: PathBuf) -> Result<PairedBitBox<TokioRuntime>> {
    let pairing_dir = pairing_dir
        .to_str()
        .context("the vault folder path is not valid UTF-8")?
        .to_owned();
    let noise_config = Box::new(PersistedNoiseConfig::new(&pairing_dir));
    let bitbox = match std::env::var(BITBOX_TRANSPORT_ENV) {
        Ok(value) if value.starts_with("tcp:") => {
            let address = value.trim_start_matches("tcp:");
            bitbox_api::BitBox::<TokioRuntime>::from_simulator(Some(address), noise_config)
                .await
                .map_err(|error| {
                    anyhow!("could not reach the BitBox02 simulator at {address}: {error}")
                })?
        }
        Ok(value) if value != "usb" && !value.is_empty() => {
            bail!("{BITBOX_TRANSPORT_ENV} must be `usb` or `tcp:HOST:PORT`, not {value}")
        }
        _ => usb(noise_config).await?,
    };
    let pairing = bitbox
        .unlock_and_pair()
        .await
        .map_err(|error| anyhow!("could not unlock the BitBox02: {error}"))?;
    if let Some(code) = pairing.get_pairing_code() {
        eprintln!(
            "Pairing this computer with your BitBox02. Check that it shows this code, then confirm \
             on the device:\n{code}"
        );
    }
    pairing
        .wait_confirm()
        .await
        .map_err(|error| anyhow!("the BitBox02 did not confirm the pairing: {error}"))
}

#[cfg(feature = "bitbox-usb")]
async fn usb(noise_config: Box<PersistedNoiseConfig>) -> Result<bitbox_api::BitBox<TokioRuntime>> {
    let device = bitbox_api::usb::get_any_bitbox02().map_err(|error| {
        anyhow!("no BitBox02 found over USB; plug it in and unlock it ({error})")
    })?;
    bitbox_api::BitBox::<TokioRuntime>::from_hid_device(device, noise_config)
        .await
        .map_err(|error| anyhow!("could not open the BitBox02: {error}"))
}

#[cfg(not(feature = "bitbox-usb"))]
async fn usb(_noise_config: Box<PersistedNoiseConfig>) -> Result<bitbox_api::BitBox<TokioRuntime>> {
    bail!(
        "this build has no USB BitBox02 support; rebuild with `--features bitbox-usb`, or set \
         {BITBOX_TRANSPORT_ENV}=tcp:HOST:PORT for the simulator"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        keys::DeviceKeys,
        policy::{InternalKey, PolicyKeys, RungPolicy, VaultPolicy},
    };

    #[test]
    fn the_address_keypath_follows_the_hww_branch_in_each_policy() {
        let secp = bitcoin::key::Secp256k1::new();
        let [phone, hww] = [0; 2].map(|_| DeviceKeys::generate(&secp).unwrap());
        let vault = VaultPolicy::build(
            &PolicyKeys {
                internal_key: InternalKey::Provable,
                ..PolicyKeys::new(phone.vault_pubkey, hww.vault_pubkey)
            },
            Network::Regtest,
        )
        .unwrap();
        let origin: Vec<u32> = hww
            .vault_pubkey
            .origin()
            .into_iter()
            .map(|c| u32::from(*c))
            .collect();
        assert_eq!(
            address_keypath(&vault.descriptor, hww.vault_pubkey)
                .unwrap()
                .to_vec(),
            [origin.clone(), vec![0, 0]].concat()
        );
        let rung = RungPolicy::new_for_network(
            phone.vault_pubkey,
            hww.vault_pubkey,
            1_924_992_000,
            InternalKey::Provable,
            Network::Regtest,
        )
        .unwrap();
        assert_eq!(
            address_keypath(&rung.descriptor, hww.vault_pubkey)
                .unwrap()
                .to_vec(),
            [origin, vec![RECOVERY_BRANCH, 0]].concat()
        );
    }

    #[test]
    fn policy_keys_carry_their_origin_and_the_nums_key_has_none() {
        let secp = bitcoin::key::Secp256k1::new();
        let [phone, hww] = [0; 2].map(|_| DeviceKeys::generate(&secp).unwrap());
        let vault = VaultPolicy::build(
            &PolicyKeys {
                internal_key: InternalKey::Provable,
                ..PolicyKeys::new(phone.vault_pubkey, hww.vault_pubkey)
            },
            Network::Regtest,
        )
        .unwrap();
        let (template, keys) = super::super::wallet_policy::template(&vault.descriptor).unwrap();
        assert!(template.starts_with("tr(@2/**,"));
        let infos = keys
            .iter()
            .map(|key| key_origin_info(key).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            infos[1].root_fingerprint,
            Some(hww.vault_pubkey.fingerprint)
        );
        assert_eq!(infos[1].xpub, hww.vault_pubkey.xpub);
        assert_eq!(infos[2].root_fingerprint, None);
    }
}
