//! Minimal hardware-wallet-facing policy validation and signing implementation.
//!
//! Keep this module deliberately small and readable. It may depend on `crate::core`, but never on
//! `crate::hot_wallet`.

pub mod ledger;

use crate::core::{
    ceremony::{self, BatchManifest},
    crypto::{self, EncryptedBlob},
    keys::DeviceKeys,
    policy::{ControllerPath, ControllerPolicy, SpendPath},
    recovery::{
        self, CooperativeSweepPackage, PhoneRecoveryPackage, PhoneRotationPackage, SweepPath,
        SweepResult,
    },
    savings::SavingsLock,
    savings_spend::{self, SavingsSpendPackage},
    signer::VaultSigner,
    social::{self, CloudRecoveryBackup, RecoveryPayload},
    storage::{
        DeviceFile, HWW_DEVICE_FILE, HWW_PUBLIC_FILE, InitializedDevice, PHONE_BACKUP_FILE,
        PHONE_DEVICE_FILE, PublicDeviceFile, VaultConfig, load_config, load_device,
        load_device_keys, network_name, read_json, validate_supported_network, write_json,
    },
    transactions::{
        build_controller_revocation_psbt, finalize_vault_psbt, verify_controller_psbt_signatures,
        verify_vault_psbt_signature, verify_vault_psbt_signatures,
    },
    types::VaultUtxo,
};
use anyhow::{Context, Result};
use bitcoin::{Address, Network, Transaction, key::Secp256k1};
use std::path::Path;
use std::str::FromStr;

/// Initialize the simulated HWW. The descriptor-bound cloud backup is created after `anzen init`.
pub fn initialize(data_dir: &Path, network: Network) -> Result<InitializedDevice> {
    validate_supported_network(network)?;
    let hww_path = data_dir.join(HWW_DEVICE_FILE);
    if hww_path.exists() {
        anyhow::bail!("HWW already initialized at {}", hww_path.display());
    }
    let secp = Secp256k1::new();
    if data_dir.join(PHONE_DEVICE_FILE).exists() {
        let phone_file = load_device(data_dir, PHONE_DEVICE_FILE)?;
        if phone_file.bitcoin_network()? != network {
            anyhow::bail!(
                "phone is configured for {}; initialize the HWW for the same network",
                phone_file.network
            );
        }
        DeviceKeys::parse_for_network_at_index(
            &secp,
            &phone_file.mnemonic,
            network,
            phone_file.vault_key_index,
        )?;
    }
    let hww = DeviceKeys::generate_for_network(&secp, network)?;
    let mnemonic = hww.mnemonic.to_string();
    write_json(
        &data_dir.join(HWW_PUBLIC_FILE),
        &PublicDeviceFile {
            version: 1,
            kind: "hww-public-key".to_owned(),
            network: network_name(network).to_owned(),
            vault_pubkey: hww.vault_pubkey.to_string(),
        },
    )?;
    write_json(
        &hww_path,
        &DeviceFile {
            kind: "hww".to_owned(),
            network: network_name(network).to_owned(),
            mnemonic: mnemonic.clone(),
            vault_key_index: hww.vault_key_index,
        },
    )?;
    Ok(InitializedDevice {
        mnemonic,
        vault_pubkey: hww.vault_pubkey.to_string(),
        vault_key_index: hww.vault_key_index,
    })
}

/// Use a Ledger as the HWW. Only its public vault key is stored.
pub fn initialize_ledger(data_dir: &Path, network: Network) -> Result<crate::core::keys::VaultKey> {
    validate_supported_network(network)?;
    for existing in [HWW_DEVICE_FILE, HWW_PUBLIC_FILE] {
        if data_dir.join(existing).exists() {
            anyhow::bail!(
                "HWW already initialized at {}",
                data_dir.join(existing).display()
            );
        }
    }
    if data_dir.join(PHONE_DEVICE_FILE).exists()
        && load_device(data_dir, PHONE_DEVICE_FILE)?.bitcoin_network()? != network
    {
        anyhow::bail!("initialize the HWW for the same network as the phone");
    }
    let vault_key = ledger::initialize(data_dir, network, 0)?;
    write_json(
        &data_dir.join(HWW_PUBLIC_FILE),
        &PublicDeviceFile {
            version: 1,
            kind: "hww-public-key".to_owned(),
            network: network_name(network).to_owned(),
            vault_pubkey: vault_key.to_string(),
        },
    )?;
    Ok(vault_key)
}

pub fn decrypt_phone_backup(data_dir: &Path) -> Result<String> {
    let config = load_config(data_dir)?;
    let hww = load_hww(data_dir)?;
    let backup =
        load_or_migrate_cloud_backup(data_dir, &data_dir.join(PHONE_BACKUP_FILE), &config, &*hww)?;
    let payload = social::decrypt_with_hww(&backup, &hww.backup_secret()?)?;
    payload.validate_against(&config)?;
    Ok(payload.phone_mnemonic)
}

/// Create a descriptor-bound cloud backup after the vault configuration exists.
pub fn create_cloud_recovery_backup(
    data_dir: &Path,
    config: &VaultConfig,
) -> Result<CloudRecoveryBackup> {
    let phone = load_device_keys(data_dir, PHONE_DEVICE_FILE)?;
    let hww = load_hww(data_dir)?;
    let backup = social::create_backup(
        &RecoveryPayload::new(config, &phone)?,
        &hww.backup_secret()?,
        &[],
    )?;
    write_json(&data_dir.join(PHONE_BACKUP_FILE), &backup)?;
    Ok(backup)
}

/// Answer a health-check challenge with the HWW cooperative and recovery keys. A real device shows the vault it
/// belongs to and asks for confirmation before signing; the signature cannot move coins.
pub fn sign_health_challenge(
    data_dir: &Path,
    challenge: &crate::core::health::Challenge,
) -> Result<crate::core::health::HealthProof> {
    let hww = load_device_keys(data_dir, HWW_DEVICE_FILE)?;
    crate::core::health::sign_challenge(challenge, &hww.vault_keypair)
}

/// Add a 1-of-N OpenPGP recovery friend by wrapping the existing symmetric backup key.
pub fn add_recovery_friend(data_dir: &Path, public_key: &[u8]) -> Result<String> {
    let config = load_config(data_dir)?;
    let hww = load_hww(data_dir)?;
    let mut backup =
        load_or_migrate_cloud_backup(data_dir, &data_dir.join(PHONE_BACKUP_FILE), &config, &*hww)?;
    let secret = hww.backup_secret()?;
    social::decrypt_with_hww(&backup, &secret)?.validate_against(&config)?;
    let fingerprint = social::add_friend(&mut backup, &secret, public_key)?;
    write_json(&data_dir.join(PHONE_BACKUP_FILE), &backup)?;
    Ok(fingerprint)
}

/// Validate every transaction against the displayed policy, verify the phone signatures, and add
/// the HWW signatures.
pub fn approve_policy(data_dir: &Path, batch_dir: &Path) -> Result<BatchManifest> {
    let config = load_config(data_dir)?;
    approve_policy_for_config(data_dir, &config, batch_dir)
}

fn approve_policy_for_config(
    data_dir: &Path,
    config: &VaultConfig,
    batch_dir: &Path,
) -> Result<BatchManifest> {
    let mut manifest = ceremony::load_manifest(batch_dir)?;
    let policy = ceremony::validate_batch(config, &manifest, batch_dir)?;
    let phone_pubkey = crate::core::keys::VaultKey::from_str(&config.phone_vault_pubkey)?;
    let controller = ControllerPolicy::new_for_network(
        phone_pubkey,
        crate::core::keys::VaultKey::from_str(&config.hww_vault_pubkey)?,
        config.bitcoin_network()?,
    )?;
    let hww = load_hww(data_dir)?;
    if hww.vault_key().to_string() != config.hww_vault_pubkey {
        anyhow::bail!("HWW key does not match the configured vault policy");
    }

    for transaction in ceremony::manifest_transactions(&manifest) {
        let path = batch_dir.join(&transaction.psbt_file);
        let mut psbt = ceremony::read_psbt(&path)?;
        let vault_indexes = transaction
            .vault_input_indexes
            .iter()
            .map(|index| usize::try_from(*index).context("vault input index exceeds usize"))
            .collect::<Result<Vec<_>>>()?;
        let controller_indexes = transaction
            .controller_input_indexes
            .iter()
            .map(|index| usize::try_from(*index).context("controller input index exceeds usize"))
            .collect::<Result<Vec<_>>>()?;
        verify_vault_psbt_signatures(
            &psbt,
            &policy,
            SpendPath::Cooperative,
            phone_pubkey,
            &vault_indexes,
        )?;
        if !controller_indexes.is_empty() && transaction.psbt_file == manifest.rollover.psbt_file {
            verify_controller_psbt_signatures(
                &psbt,
                &controller,
                ControllerPath::Phone,
                phone_pubkey.cooperative(),
                &controller_indexes,
            )?;
        }
        hww.sign_vault_inputs(&mut psbt, &policy, SpendPath::Cooperative, &vault_indexes)?;
        ceremony::write_psbt(&path, &psbt)?;
    }
    manifest.hww_approved = true;
    write_json(&batch_dir.join("manifest.json"), &manifest)?;
    // The parent validation above already checked that the renewal spends this epoch's remainder.
    if manifest.has_presigned_renewal {
        approve_policy_for_config(data_dir, config, &batch_dir.join(ceremony::NEXT_BATCH_DIR))?;
    }
    Ok(manifest)
}

pub fn decrypt_phone_backup_package(
    data_dir: &Path,
    backup_path: &Path,
) -> Result<PhoneRecoveryPackage> {
    let config = load_config(data_dir)?;
    let hww = load_hww(data_dir)?;
    let backup = load_or_migrate_cloud_backup(data_dir, backup_path, &config, &*hww)?;
    let payload = social::decrypt_with_hww(&backup, &hww.backup_secret()?)?;
    payload.validate_against(&config)?;
    let words = payload.phone_mnemonic;
    let phone = DeviceKeys::parse_for_network_at_index(
        &Secp256k1::new(),
        &words,
        config.bitcoin_network()?,
        payload.phone_vault_key_index,
    )?;
    if phone.vault_pubkey.to_string() != config.phone_vault_pubkey {
        anyhow::bail!("decrypted phone backup does not match the configured vault policy");
    }
    Ok(PhoneRecoveryPackage {
        version: 2,
        kind: "phone-recovery".to_owned(),
        phone_mnemonic: words,
        phone_vault_key_index: phone.vault_key_index,
        phone_vault_pubkey: phone.vault_pubkey.to_string(),
        vault_descriptor: payload.vault_descriptor,
        vault_address: payload.vault_address,
    })
}

pub fn recover(
    data_dir: &Path,
    config: &VaultConfig,
    utxos: &[VaultUtxo],
    tip_height: u64,
    destination: &Address,
) -> Result<(Transaction, SweepResult)> {
    let plan = recovery::prepare_sweep(
        config,
        utxos,
        tip_height,
        SweepPath::HwwRecovery,
        destination,
    )?;
    let hww = load_hww(data_dir)?;
    recovery::sign_recovery_sweep(plan, SweepPath::HwwRecovery, &*hww)
}

/// Validate a phone-built savings spend and add the HWW signature.
pub fn approve_savings_spend(
    data_dir: &Path,
    package: &SavingsSpendPackage,
) -> Result<SavingsSpendPackage> {
    let config = load_config(data_dir)?;
    let hww = load_hww(data_dir)?;
    savings_spend::approve_savings_spend(&config, package, &*hww)
}

/// Move a savings lock's coins with the HWW alone, 455 days after its unlock date.
pub fn recover_savings(
    data_dir: &Path,
    config: &VaultConfig,
    lock: &SavingsLock,
    utxos: &[VaultUtxo],
    median_time: u64,
    destination: &Address,
    fee_rate_sat_vb: u64,
) -> Result<(Transaction, SweepResult)> {
    let hww = load_hww(data_dir)?;
    savings_spend::sign_savings_recovery(
        config,
        lock,
        utxos,
        median_time,
        SpendPath::HwwRecovery,
        destination,
        fee_rate_sat_vb,
        &*hww,
    )
}

/// Revoke every currently live policy state with the HWW controller path.
///
/// The destination is explicit because the cold signer does not own a general-purpose wallet.
/// It should normally be a replacement vault or another independently verified safe address.
pub fn revoke_policy(
    data_dir: &Path,
    config: &VaultConfig,
    controller_utxos: &[VaultUtxo],
    destination: &Address,
) -> Result<Transaction> {
    let phone_pubkey = crate::core::keys::VaultKey::from_str(&config.phone_vault_pubkey)?;
    let hww = load_hww(data_dir)?;
    if hww.vault_key().to_string() != config.hww_vault_pubkey {
        anyhow::bail!("HWW key does not match the configured vault policy");
    }
    let controller = ControllerPolicy::new_for_network(
        phone_pubkey,
        hww.vault_key(),
        config.bitcoin_network()?,
    )?;
    // TODO(production): obtain a current feerate and support explicit fee inputs/RBF/CPFP. The
    // MVP's connector reserve pays a deterministic 1 sat/vB revocation fee.
    let (mut psbt, _) = build_controller_revocation_psbt(
        controller_utxos,
        destination.script_pubkey(),
        crate::core::DEFAULT_FEE_RATE_SAT_VB,
        &controller,
    )?;
    let indexes = (0..psbt.inputs.len()).collect::<Vec<_>>();
    hww.sign_controller_inputs(&mut psbt, &controller, ControllerPath::Hww, &indexes)?;
    finalize_vault_psbt(psbt)
}

pub fn approve_cooperative_sweep(
    data_dir: &Path,
    package: &CooperativeSweepPackage,
) -> Result<CooperativeSweepPackage> {
    let config = load_config(data_dir)?;
    approve_cooperative_sweep_for_config(data_dir, &config, package)
}

fn approve_cooperative_sweep_for_config(
    data_dir: &Path,
    config: &VaultConfig,
    package: &CooperativeSweepPackage,
) -> Result<CooperativeSweepPackage> {
    let (policy, mut psbt) = recovery::validate_cooperative_sweep(config, package)?;
    let phone_pubkey = crate::core::keys::VaultKey::from_str(&config.phone_vault_pubkey)?;
    verify_vault_psbt_signature(&psbt, &policy, SpendPath::Cooperative, phone_pubkey)?;
    let hww = load_hww(data_dir)?;
    if hww.vault_key().to_string() != config.hww_vault_pubkey {
        anyhow::bail!("HWW key does not match the configured vault policy");
    }
    hww.sign_all_vault_inputs(&mut psbt, &policy, SpendPath::Cooperative)?;
    let mut approved = package.clone();
    approved.psbt = psbt.to_string();
    approved.hww_approved = true;
    Ok(approved)
}

pub fn approve_phone_rotation(
    data_dir: &Path,
    package: &PhoneRotationPackage,
) -> Result<PhoneRotationPackage> {
    let (old_config, new_config, new_phone) = recovery::validate_phone_rotation(data_dir, package)?;
    let mut approved = package.clone();
    approved.sweep = approve_cooperative_sweep_for_config(data_dir, &old_config, &package.sweep)?;

    if let Some(policy) = &package.renewed_policy {
        let workspace = data_dir.join("hww/rotation-policy-review");
        reset_workspace(&workspace)?;
        ceremony::materialize_policy_package(policy, &workspace)?;
        recovery::validate_rotation_policy_binding(
            &old_config,
            &new_config,
            &approved.sweep,
            policy,
        )?;
        approve_policy_for_config(data_dir, &new_config, &workspace)?;
        approved.renewed_policy = Some(ceremony::package_from_batch(&workspace)?);
        reset_workspace(&workspace)?;
    }

    let hww = load_hww(data_dir)?;
    let current_backup = load_or_migrate_cloud_backup(
        data_dir,
        &data_dir.join(PHONE_BACKUP_FILE),
        &old_config,
        &*hww,
    )?;
    let secret = hww.backup_secret()?;
    social::decrypt_with_hww(&current_backup, &secret)?.validate_against(&old_config)?;
    let friend_public_keys = social::friend_public_keys(&current_backup);
    let payload = RecoveryPayload::new(&new_config, &new_phone)?;
    approved.cloud_recovery_backup = Some(social::create_backup(
        &payload,
        &secret,
        &friend_public_keys,
    )?);
    Ok(approved)
}

fn load_or_migrate_cloud_backup(
    data_dir: &Path,
    backup_path: &Path,
    config: &VaultConfig,
    hww: &dyn VaultSigner,
) -> Result<CloudRecoveryBackup> {
    if let Ok(backup) = read_json::<CloudRecoveryBackup>(backup_path) {
        return Ok(backup);
    }
    let legacy: EncryptedBlob = read_json(backup_path)
        .context("backup is neither a cloud recovery envelope nor a legacy phone backup")?;
    let secret = hww.backup_secret()?;
    let words = crypto::decrypt(&secret, "phone-seed-backup", &legacy)?;
    let words = String::from_utf8(words.to_vec()).context("legacy phone backup was not UTF-8")?;
    let phone =
        DeviceKeys::parse_for_network(&Secp256k1::new(), &words, config.bitcoin_network()?)?;
    let payload = RecoveryPayload::new(config, &phone)?;
    let migrated = social::create_backup(&payload, &secret, &[])?;
    if backup_path == data_dir.join(PHONE_BACKUP_FILE) {
        write_json(backup_path, &migrated)?;
    }
    Ok(migrated)
}

/// The vault's HWW: a Ledger when one was set up with `hww init --ledger`, otherwise the
/// software stand-in.
pub fn load_hww(data_dir: &Path) -> Result<Box<dyn VaultSigner>> {
    if ledger::is_ledger_hww(data_dir) {
        return Ok(Box::new(ledger::LedgerHww::open(data_dir)?));
    }
    Ok(Box::new(load_device_keys(data_dir, HWW_DEVICE_FILE)?))
}

fn reset_workspace(path: &Path) -> Result<()> {
    if path.exists() {
        std::fs::remove_dir_all(path)
            .with_context(|| format!("failed to reset workspace {}", path.display()))?;
    }
    Ok(())
}
