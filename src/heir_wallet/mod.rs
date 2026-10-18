//! The heir's side of the vault.
//!
//! An heir holds one key of their own. It is written into every vault and savings policy when
//! the vault is created, behind the longest timelock in each:
//!
//! * vault coins: 65,535 blocks (about 15 months) after the coins last moved, the same delay as
//!   the HWW alone and a month after the phone alone;
//! * savings coins: 485 days after the savings unlock date, a month after the HWW alone.
//!
//! The owner's normal use keeps moving vault coins (the yearly rollover and the presigned
//! renewal), and every move restarts the heir's wait. When the owner stops, the coins stop
//! moving and the heir's key opens. Nothing here can sign for any other path, and the heir can
//! never act earlier than consensus allows.
//!
//! Like the cold wallet, this module signs only. The CLI reads the chain and broadcasts.

use crate::core::{
    HWW_RECOVERY_BLOCKS, PHONE_RECOVERY_BLOCKS,
    keys::{DeviceKeys, VaultKey},
    policy::{SavingsPolicy, SpendPath, VaultPolicy},
    recovery::{self, SweepPath, SweepResult},
    savings::SavingsLock,
    savings_spend,
    storage::{
        CONFIG_FILE, DeviceFile, HEIR_DEVICE_FILE, HEIR_PUBLIC_FILE, HEIR_PUBLIC_KIND,
        HeirPublicFile, VaultConfig, config_exists, load_device_keys, network_name,
        validate_supported_network, write_json,
    },
    types::VaultUtxo,
};
use anyhow::{Context, Result, bail};
use bitcoin::{Address, Network, Transaction, key::Secp256k1};
use std::{path::Path, str::FromStr};

pub struct InitializedHeir {
    pub name: String,
    pub mnemonic: Option<String>,
    pub vault_pubkey: VaultKey,
}

fn ensure_vault_not_created(data_dir: &Path) -> Result<()> {
    if config_exists(data_dir) {
        bail!(
            "the vault already exists; an heir must be named before `anzen init`, because their key is part of the vault address"
        );
    }
    if data_dir.join(HEIR_PUBLIC_FILE).exists() {
        bail!("an heir is already named in {}", data_dir.display());
    }
    Ok(())
}

fn write_public(data_dir: &Path, network: Network, name: &str, key: VaultKey) -> Result<()> {
    let name = name.trim();
    if name.is_empty() {
        bail!("give the heir a name, so the recovery kit can say who they are");
    }
    write_json(
        &data_dir.join(HEIR_PUBLIC_FILE),
        &HeirPublicFile {
            version: 1,
            kind: HEIR_PUBLIC_KIND.to_owned(),
            network: network_name(network).to_owned(),
            name: name.to_owned(),
            vault_pubkey: key.to_string(),
        },
    )
}

/// Create a key for the heir with the software key store, standing in for the heir's own
/// wallet. The secret words belong to the heir alone.
pub fn initialize(data_dir: &Path, network: Network, name: &str) -> Result<InitializedHeir> {
    validate_supported_network(network)?;
    ensure_vault_not_created(data_dir)?;
    let heir = DeviceKeys::generate_for_network(&Secp256k1::new(), network)?;
    write_public(data_dir, network, name, heir.vault_pubkey)?;
    write_json(
        &data_dir.join(HEIR_DEVICE_FILE),
        &DeviceFile {
            kind: "heir".to_owned(),
            network: network_name(network).to_owned(),
            mnemonic: heir.mnemonic.to_string(),
            vault_key_index: heir.vault_key_index,
        },
    )?;
    Ok(InitializedHeir {
        name: name.trim().to_owned(),
        mnemonic: Some(heir.mnemonic.to_string()),
        vault_pubkey: heir.vault_pubkey,
    })
}

/// Name an heir by the public key their own wallet exported, as `[fingerprint/path]xpub`.
pub fn import(data_dir: &Path, network: Network, name: &str, key: &str) -> Result<InitializedHeir> {
    validate_supported_network(network)?;
    ensure_vault_not_created(data_dir)?;
    let key = VaultKey::from_str(key.trim())?;
    if bitcoin::NetworkKind::from(network) != key.xpub.network {
        bail!("the heir's key is for a different network");
    }
    write_public(data_dir, network, name, key)?;
    Ok(InitializedHeir {
        name: name.trim().to_owned(),
        mnemonic: None,
        vault_pubkey: key,
    })
}

/// On the heir's own device: rebuild the vault from the descriptors printed in the recovery kit,
/// so the heir can watch and claim without anything from the owner's devices. Every descriptor
/// must be an Anzen policy that names this heir's key.
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
    let heir = crate::core::storage::load_heir(data_dir, network)?
        .context("set up the heir's key first: anzen heir init (or heir import)")?;
    let vault = VaultPolicy::from_descriptor_for_network(vault_descriptor, network)?;
    let (phone, hww, vault_heir) = vault.keys(network)?;
    if vault_heir.map(|key| key.to_string()) != Some(heir.vault_pubkey.clone()) {
        bail!("this vault does not name this heir's key");
    }
    let mut savings_locks = Vec::with_capacity(savings_descriptors.len());
    for text in savings_descriptors {
        let policy = SavingsPolicy::from_descriptor_for_network(text, network)?;
        let (lock_phone, lock_hww, lock_heir) = policy.keys();
        if lock_heir.map(|key| key.to_string()) != Some(heir.vault_pubkey.clone()) {
            bail!("a savings lock does not name this heir's key");
        }
        savings_locks.push(SavingsLock {
            unlock: policy.unlock,
            phone_vault_pubkey: lock_phone.to_string(),
            hww_vault_pubkey: lock_hww.to_string(),
            heir_vault_pubkey: Some(heir.vault_pubkey.clone()),
            address: policy.address.to_string(),
            default_deposit: false,
        });
    }
    savings_locks.sort_by_key(|lock| lock.unlock);
    let config = VaultConfig {
        version: 1,
        network: network_name(network).to_owned(),
        phone_vault_pubkey: phone.to_string(),
        hww_vault_pubkey: hww.to_string(),
        // The heir has no phone wallet; only the heir commands use this config.
        phone_hot_external_descriptor: String::new(),
        phone_hot_internal_descriptor: String::new(),
        vault_descriptor: vault.descriptor_string(),
        vault_address: vault.address.to_string(),
        phone_recovery_blocks: PHONE_RECOVERY_BLOCKS,
        hww_recovery_blocks: HWW_RECOVERY_BLOCKS,
        monthly_limit_sats: 0,
        emergency_access_limit_sats: 0,
        savings_locks,
        heir: Some(heir),
    };
    write_json(&data_dir.join(CONFIG_FILE), &config)?;
    Ok(config)
}

/// The heir's key store, checked against the heir the vault names.
fn heir_keys(data_dir: &Path, config: &VaultConfig) -> Result<DeviceKeys> {
    let expected = config
        .heir
        .as_ref()
        .context("this vault has no heir")?
        .vault_pubkey
        .clone();
    let heir = load_device_keys(data_dir, HEIR_DEVICE_FILE)
        .context("the heir's key is not on this device")?;
    if heir.vault_pubkey.to_string() != expected {
        bail!("this heir key is not the one the vault names");
    }
    Ok(heir)
}

/// Sweep every vault coin that has not moved for 65,535 blocks to `destination`.
pub fn claim_vault(
    data_dir: &Path,
    config: &VaultConfig,
    utxos: &[VaultUtxo],
    tip_height: u64,
    destination: &Address,
) -> Result<(Transaction, SweepResult)> {
    let heir = heir_keys(data_dir, config)?;
    let plan = recovery::prepare_sweep(config, utxos, tip_height, SweepPath::Heir, destination)?;
    recovery::sign_recovery_sweep(plan, SweepPath::Heir, &heir)
}

/// Sweep a savings lock's coins, 485 days after its unlock date.
pub fn claim_savings(
    data_dir: &Path,
    config: &VaultConfig,
    lock: &SavingsLock,
    utxos: &[VaultUtxo],
    median_time: u64,
    destination: &Address,
    fee_rate_sat_vb: u64,
) -> Result<(Transaction, SweepResult)> {
    let heir = heir_keys(data_dir, config)?;
    savings_spend::sign_savings_recovery(
        config,
        lock,
        utxos,
        median_time,
        SpendPath::Heir,
        destination,
        fee_rate_sat_vb,
        &heir,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_heir_must_be_named_before_the_vault_exists() {
        let dir = tempfile::tempdir().unwrap();
        let heir = initialize(dir.path(), Network::Regtest, " Ana ").unwrap();
        assert_eq!(heir.name, "Ana");
        assert!(heir.mnemonic.is_some());
        assert!(initialize(dir.path(), Network::Regtest, "Ben").is_err());

        let other = tempfile::tempdir().unwrap();
        assert!(
            import(
                other.path(),
                Network::Regtest,
                "",
                &heir.vault_pubkey.to_string()
            )
            .is_err()
        );
        assert!(
            import(
                other.path(),
                Network::Bitcoin,
                "Ana",
                &heir.vault_pubkey.to_string()
            )
            .is_err()
        );
        let imported = import(
            other.path(),
            Network::Regtest,
            "Ana",
            &heir.vault_pubkey.to_string(),
        )
        .unwrap();
        assert_eq!(imported.vault_pubkey, heir.vault_pubkey);
        assert!(imported.mnemonic.is_none());
    }
}
