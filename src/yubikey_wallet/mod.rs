//! The YubiKey's side of the vault.
//!
//! The YubiKey is the owner's optional third key. With it in the vault, any two of the three
//! keys can move the coins at any time:
//!
//! * phone + hardware wallet: everyday use, as before;
//! * hardware wallet + YubiKey: when the phone is lost;
//! * phone + YubiKey: when the hardware wallet is lost.
//!
//! The YubiKey is used only on a computer, never on the phone, so one stolen phone never holds
//! two keys. Its key is backed up as 24 words on paper, like the hardware wallet's.
//!
//! This prototype keeps the YubiKey's key in a software key store on the computer, standing in
//! for the key a real YubiKey will unlock. Like the cold wallet, this module signs only. The
//! CLI reads the chain and broadcasts.

use crate::core::{
    keys::{DeviceKeys, VaultKey},
    recovery::{self, PairSweepPackage, SweepResult},
    storage::{
        CONFIG_FILE, DeviceFile, HWW_DEVICE_FILE, PHONE_DEVICE_FILE, VaultConfig,
        YUBIKEY_DEVICE_FILE, YUBIKEY_PUBLIC_FILE, YUBIKEY_PUBLIC_KIND, YubikeyPublicFile,
        config_exists, load_device_keys, load_yubikey, network_name, restore_public_config,
        validate_supported_network, write_json,
    },
};
use anyhow::{Context, Result, bail};
use bitcoin::{Network, Transaction, key::Secp256k1};
use std::{path::Path, str::FromStr};

pub struct InitializedYubikey {
    /// The 24 backup words, shown once. `None` when only the public key was imported.
    pub mnemonic: Option<String>,
    pub vault_pubkey: VaultKey,
}

fn write_public(data_dir: &Path, network: Network, key: VaultKey) -> Result<()> {
    write_json(
        &data_dir.join(YUBIKEY_PUBLIC_FILE),
        &YubikeyPublicFile {
            version: 1,
            kind: YUBIKEY_PUBLIC_KIND.to_owned(),
            network: network_name(network).to_owned(),
            vault_pubkey: key.to_string(),
        },
    )
}

/// Set up the YubiKey's key on the computer that will use it. Refused where the phone's or
/// the hardware wallet's key lives, so two keys never end up on one device.
pub fn initialize(data_dir: &Path, network: Network) -> Result<InitializedYubikey> {
    validate_supported_network(network)?;
    if data_dir.join(PHONE_DEVICE_FILE).exists() || data_dir.join(HWW_DEVICE_FILE).exists() {
        bail!(
            "the YubiKey must live on its own computer, not next to the phone's or the hardware wallet's key"
        );
    }
    if data_dir.join(YUBIKEY_DEVICE_FILE).exists() || data_dir.join(YUBIKEY_PUBLIC_FILE).exists() {
        bail!("a YubiKey is already set up in {}", data_dir.display());
    }
    let yubikey = DeviceKeys::generate_for_network(&Secp256k1::new(), network)?;
    write_json(
        &data_dir.join(YUBIKEY_DEVICE_FILE),
        &DeviceFile {
            kind: "yubikey".to_owned(),
            network: network_name(network).to_owned(),
            mnemonic: yubikey.mnemonic.to_string(),
            vault_key_index: yubikey.vault_key_index,
        },
    )?;
    write_public(data_dir, network, yubikey.vault_pubkey)?;
    Ok(InitializedYubikey {
        mnemonic: Some(yubikey.mnemonic.to_string()),
        vault_pubkey: yubikey.vault_pubkey,
    })
}

/// Add the YubiKey to a new vault by its public key, as `[fingerprint/path]xpub`. It must be
/// done before `anzen init`, because the key is part of the vault address.
pub fn import(data_dir: &Path, network: Network, key: &str) -> Result<InitializedYubikey> {
    validate_supported_network(network)?;
    if config_exists(data_dir) {
        bail!(
            "the vault already exists; a YubiKey must be added before `anzen init`, because its key is part of the vault address (to add one later, move the coins to a new vault)"
        );
    }
    if data_dir.join(YUBIKEY_PUBLIC_FILE).exists() {
        bail!("a YubiKey is already added in {}", data_dir.display());
    }
    let key = VaultKey::from_str(key.trim())?;
    if bitcoin::NetworkKind::from(network) != key.xpub.network {
        bail!("the YubiKey's key is for a different network");
    }
    write_public(data_dir, network, key)?;
    Ok(InitializedYubikey {
        mnemonic: None,
        vault_pubkey: key,
    })
}

/// On the YubiKey's computer: learn the vault from the descriptors printed in the recovery kit,
/// so the computer can check what it is asked to sign. The vault must name this YubiKey.
pub fn restore(
    data_dir: &Path,
    network: Network,
    vault_descriptor: &str,
    savings_descriptors: &[String],
) -> Result<VaultConfig> {
    validate_supported_network(network)?;
    if config_exists(data_dir) {
        bail!("a vault is already set up in {}", data_dir.display());
    }
    let own =
        load_yubikey(data_dir, network)?.context("set up the YubiKey first: anzen yubikey init")?;
    let config = restore_public_config(network, vault_descriptor, savings_descriptors, None)?;
    if config.yubikey_key()? != Some(own) {
        bail!("this vault does not name this YubiKey");
    }
    write_json(&data_dir.join(CONFIG_FILE), &config)?;
    Ok(config)
}

/// The YubiKey's key store, checked against the YubiKey the vault names.
fn yubikey_keys(data_dir: &Path, config: &VaultConfig) -> Result<DeviceKeys> {
    let expected = config.yubikey_key()?.context("this vault has no YubiKey")?;
    let yubikey = load_device_keys(data_dir, YUBIKEY_DEVICE_FILE)
        .context("the YubiKey's key is not on this computer")?;
    if yubikey.vault_pubkey != expected {
        bail!("this YubiKey is not the one the vault names");
    }
    Ok(yubikey)
}

/// Check a sweep the phone or the hardware wallet proposed, add the YubiKey's signature and
/// finish the transaction.
pub fn confirm_sweep(
    data_dir: &Path,
    config: &VaultConfig,
    package: &PairSweepPackage,
) -> Result<(Transaction, SweepResult)> {
    let yubikey = yubikey_keys(data_dir, config)?;
    recovery::finalize_pair_sweep(config, package, &yubikey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_yubikey_lives_on_its_own_computer() {
        let phone_dir = tempfile::tempdir().unwrap();
        crate::hot_wallet::initialize(phone_dir.path(), Network::Regtest).unwrap();
        assert!(initialize(phone_dir.path(), Network::Regtest).is_err());

        let computer = tempfile::tempdir().unwrap();
        let yubikey = initialize(computer.path(), Network::Regtest).unwrap();
        assert_eq!(yubikey.mnemonic.as_ref().unwrap().split(' ').count(), 24);
        assert!(initialize(computer.path(), Network::Regtest).is_err());

        // The vault records it by public key before `anzen init`.
        let key = yubikey.vault_pubkey.to_string();
        assert!(import(phone_dir.path(), Network::Bitcoin, &key).is_err());
        let imported = import(phone_dir.path(), Network::Regtest, &key).unwrap();
        assert_eq!(imported.vault_pubkey, yubikey.vault_pubkey);
        assert!(imported.mnemonic.is_none());
        assert!(import(phone_dir.path(), Network::Regtest, &key).is_err());
    }
}
