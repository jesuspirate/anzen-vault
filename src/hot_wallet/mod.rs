//! Phone/mobile-wallet implementation.
//!
//! Mobile applications can build on this module without importing hardware-wallet behavior.

mod rotation;
mod wallet;

pub use rotation::{
    VanityPhoneRotation, activate_phone_rotation, create_phone_rotation,
    create_vanity_phone_rotation,
};
pub use wallet::{HotWallet, MIN_LEFTOVER_RETURN_SATS};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmergencyBroadcastResult {
    pub transaction_txid: Txid,
}

/// The HWW hand-off is a plain protocol package; the phone's durable retry copy is encrypted.
#[derive(serde::Deserialize)]
#[serde(untagged)]
pub enum ApprovedPolicyInput {
    Package(Box<crate::core::ceremony::PolicyPackage>),
    Encrypted(crate::core::crypto::EncryptedBlob),
}

pub fn open_approved_policy(data_dir: &Path, input: ApprovedPolicyInput) -> Result<PolicyPackage> {
    match input {
        ApprovedPolicyInput::Package(package) => Ok(*package),
        ApprovedPolicyInput::Encrypted(blob) => {
            if !blob.purpose.starts_with("policy-activation-v1:") {
                bail!("encrypted artifact is not an approved policy backup");
            }
            let phone = load_device_keys(data_dir, PHONE_DEVICE_FILE)?;
            let plaintext = crate::core::crypto::decrypt(&phone.seed, &blob.purpose, &blob)?;
            let package: PolicyPackage = serde_json::from_slice(&plaintext)?;
            if blob.purpose
                != format!(
                    "policy-activation-v1:{}",
                    package.manifest.rollover.unsigned_txid
                )
            {
                bail!("encrypted policy backup does not match its rollover");
            }
            Ok(package)
        }
    }
}

use crate::core::{
    ceremony::{
        self, BatchManifest, EmergencyAccessSchedule, EmergencyTransactionKind,
        EncryptedEmergencyTransaction, HotAddressProvider, PolicyLimits, PolicyPackage,
        SCHEDULE_FILE, Schedule,
    },
    chain::{BitcoinCoreBackend, Blockchain, ElectrumBackend},
    policy::{ControllerPath, ControllerPolicy, SpendPath, VaultAddressTemplate},
    recovery::{self, CooperativeSweepPackage, PhoneRecoveryPackage, SweepPath, SweepResult},
    savings::SavingsLock,
    savings_spend::{self, SavingsSpendPackage},
};
use anyhow::{Context, Result, bail};
use bitcoin::{Address, Amount, Network, Psbt, Transaction, TxOut, Txid, key::Secp256k1};
use chrono::{DateTime, Utc};
use std::{
    fs,
    path::Path,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread,
};

use crate::core::{
    DEFAULT_FEE_RATE_SAT_VB,
    keys::DeviceKeys,
    ladder,
    storage::{
        DeviceFile, HWW_PUBLIC_FILE, InitializedDevice, PHONE_DEVICE_FILE, VaultConfig,
        load_config, load_device_keys, load_public_device, network_name, read_json,
        validate_supported_network, write_json,
    },
    transactions::{
        build_controller_revocation_psbt, finalize_vault_psbt, sign_controller_psbt_inputs,
    },
    types::VaultUtxo,
};

/// How much the owner keeps on the phone after each cycle, for bills and emergencies.
pub const PHONE_BUFFER_FILE: &str = "phone/buffer.json";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PhoneBuffer {
    pub version: u8,
    pub keep_sats: u64,
}

pub fn set_buffer(data_dir: &Path, keep_sats: u64) -> Result<()> {
    load_config(data_dir)?;
    write_json(
        &data_dir.join(PHONE_BUFFER_FILE),
        &PhoneBuffer {
            version: 1,
            keep_sats,
        },
    )
}

/// The buffer the owner chose, if any.
pub fn buffer(data_dir: &Path) -> Result<Option<u64>> {
    let path = data_dir.join(PHONE_BUFFER_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let buffer: PhoneBuffer = read_json(&path)?;
    if buffer.version != 1 {
        bail!("unsupported phone buffer file");
    }
    Ok(Some(buffer.keep_sats))
}

/// What the phone holds above its buffer: the part that should go back to the vault before a
/// ceremony, so it joins the new months. `None` when no buffer is set.
pub fn leftovers(data_dir: &Path, backend: &dyn HotWalletBackend) -> Result<Option<(u64, u64)>> {
    let Some(keep_sats) = buffer(data_dir)? else {
        return Ok(None);
    };
    let config = load_config(data_dir)?;
    ensure_backend_network(backend, &config)?;
    let mut wallet = HotWallet::open_or_create(data_dir)?;
    backend.sync_hot_wallet(&mut wallet)?;
    let spendable = wallet.spendable_sats();
    Ok(Some((spendable.saturating_sub(keep_sats), keep_sats)))
}

#[derive(Debug, Clone)]
pub struct LeftoverReturn {
    pub txid: Txid,
    pub returned_sats: u64,
    pub fee_sats: u64,
    pub kept_sats: u64,
}

/// Send everything above the buffer back to the vault, where it needs two keys again. Run it just
/// before a ceremony: the ceremony's rollover then folds it into the new months. Returned coins
/// are not in the current presigned months, and each starts its own recovery clock.
pub fn return_leftovers(
    data_dir: &Path,
    backend: &dyn HotWalletBackend,
    keep_override: Option<u64>,
) -> Result<Option<LeftoverReturn>> {
    let keep_sats = match keep_override {
        Some(keep) => keep,
        None => buffer(data_dir)?
            .context("choose how much to keep on the phone first: anzen phone buffer --set SATS")?,
    };
    let config = load_config(data_dir)?;
    ensure_backend_network(backend, &config)?;
    let vault_script = config
        .vault_address
        .parse::<Address<_>>()?
        .require_network(config.bitcoin_network()?)?
        .script_pubkey();
    let mut wallet = HotWallet::open_or_create(data_dir)?;
    backend.sync_hot_wallet(&mut wallet)?;
    let Some((transaction, returned_sats, fee_sats)) =
        wallet.build_leftover_return(keep_sats, vault_script)?
    else {
        return Ok(None);
    };
    let txid = backend
        .broadcast(&transaction)
        .context("failed to broadcast the leftover return")?;
    Ok(Some(LeftoverReturn {
        txid,
        returned_sats,
        fee_sats,
        // The fee comes out of the buffer.
        kept_sats: keep_sats.saturating_sub(fee_sats),
    }))
}

/// Initialize the phone key material and its BDK wallet state.
pub fn initialize(data_dir: &Path, network: Network) -> Result<InitializedDevice> {
    validate_supported_network(network)?;
    let phone = DeviceKeys::generate_for_network(&Secp256k1::new(), network)?;
    persist_phone(data_dir, network, &phone)
}

pub const VANITY_SUFFIX: &str = "vault";

#[derive(Debug)]
pub struct VanityInitialization {
    pub device: InitializedDevice,
    pub vault_address: String,
    pub attempts: u64,
    pub worker_count: usize,
}

#[derive(Debug)]
struct VanityPhoneKey {
    phone: DeviceKeys,
    vault_address: String,
    attempts: u64,
    worker_count: usize,
}

/// Grind the phone vault-key derivation index across all available CPU threads.
pub fn initialize_vanity<F>(
    data_dir: &Path,
    network: Network,
    report_progress: F,
) -> Result<VanityInitialization>
where
    F: Fn(u64) + Sync,
{
    let worker_count = available_worker_count();
    initialize_vanity_with_suffix(
        data_dir,
        network,
        VANITY_SUFFIX,
        worker_count,
        report_progress,
    )
}

/// Answer a health-check challenge with the phone cooperative and recovery keys.
pub fn sign_health_challenge(
    data_dir: &Path,
    challenge: &crate::core::health::Challenge,
) -> Result<crate::core::health::HealthProof> {
    let phone = load_device_keys(data_dir, PHONE_DEVICE_FILE)?;
    crate::core::health::sign_challenge(challenge, &phone.vault_keypair)
}

pub fn vanity_address_prefix(network: Network) -> Result<&'static str> {
    match network {
        Network::Bitcoin => Ok("bc1pvault"),
        Network::Regtest => Ok("bcrt1pvault"),
        other => bail!("vanity initialization is unsupported on {other}"),
    }
}

fn initialize_vanity_with_suffix<F>(
    data_dir: &Path,
    network: Network,
    suffix: &str,
    worker_count: usize,
    report_progress: F,
) -> Result<VanityInitialization>
where
    F: Fn(u64) + Sync,
{
    validate_supported_network(network)?;
    ensure_phone_is_uninitialized(data_dir)?;
    if worker_count == 0 {
        bail!("vanity search requires at least one worker thread");
    }
    if !data_dir.join(HWW_PUBLIC_FILE).exists() {
        bail!("initialize the HWW before using phone init --vanity");
    }
    let public_hww = load_public_device(data_dir, HWW_PUBLIC_FILE)
        .context("initialize the HWW before using phone init --vanity")?;
    if public_hww.version != 1 || public_hww.kind != "hww-public-key" {
        bail!("unsupported HWW public metadata");
    }
    if public_hww.bitcoin_network()? != network {
        bail!("phone and HWW must use the same network");
    }
    let hww_pubkey = public_hww.parsed_vault_pubkey()?;
    // The heir is part of the vault address, so it must be named before the search starts.
    let heir = crate::core::storage::load_heir(data_dir, network)?
        .as_ref()
        .map(crate::core::storage::HeirConfig::parsed_vault_pubkey)
        .transpose()?;
    // So is the YubiKey.
    let yubikey = crate::core::storage::load_yubikey(data_dir, network)?;
    let vanity = grind_vanity_phone_key(
        network,
        hww_pubkey,
        yubikey,
        heir,
        suffix,
        worker_count,
        report_progress,
    )?;
    let device = persist_phone(data_dir, network, &vanity.phone)?;
    Ok(VanityInitialization {
        device,
        vault_address: vanity.vault_address,
        attempts: vanity.attempts,
        worker_count: vanity.worker_count,
    })
}

fn available_worker_count() -> usize {
    thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
}

fn grind_vanity_phone_key<F>(
    network: Network,
    hww_pubkey: crate::core::keys::VaultKey,
    yubikey: Option<crate::core::keys::VaultKey>,
    heir: Option<crate::core::keys::VaultKey>,
    suffix: &str,
    worker_count: usize,
    report_progress: F,
) -> Result<VanityPhoneKey>
where
    F: Fn(u64) + Sync,
{
    validate_supported_network(network)?;
    if worker_count == 0 {
        bail!("vanity search requires at least one worker thread");
    }
    let target = VanityTarget::new(suffix)?;
    let base_phone = DeviceKeys::generate_for_network(&Secp256k1::new(), network)?;
    // Public derivation is enough to test candidates; the winner is re-derived privately below.
    let parent = base_phone.vault_parent(&Secp256k1::new())?;
    let template = Arc::new(VaultAddressTemplate::with_keys(
        hww_pubkey, yubikey, heir, network,
    )?);
    let stopped = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU64::new(0));
    let last_report = Arc::new(AtomicU64::new(0));
    let (sender, receiver) = mpsc::channel::<Result<u32>>();

    let winning_index = thread::scope(|scope| -> Result<u32> {
        for worker in 0..worker_count {
            let sender = sender.clone();
            let template = Arc::clone(&template);
            let stopped = Arc::clone(&stopped);
            let attempts = Arc::clone(&attempts);
            let last_report = Arc::clone(&last_report);
            let report_progress = &report_progress;
            let parent = &parent;
            scope.spawn(move || {
                let result = (|| -> Result<()> {
                    let secp = Secp256k1::new();
                    let mut index = worker as u64;
                    let stride = worker_count as u64;
                    let mut pending_attempts = 0_u64;
                    while index < (1_u64 << 31) && !stopped.load(Ordering::Relaxed) {
                        let phone_pubkey = parent.vault_key(&secp, index as u32)?;
                        pending_attempts += 1;
                        let output_key = template.output_key(&secp, phone_pubkey);
                        if target.matches(&output_key.to_x_only_public_key().serialize()) {
                            attempts.fetch_add(pending_attempts, Ordering::Relaxed);
                            if !stopped.swap(true, Ordering::Relaxed) {
                                let _ = sender.send(Ok(index as u32));
                            }
                            return Ok(());
                        }
                        if pending_attempts == 4_096 {
                            let total = attempts.fetch_add(pending_attempts, Ordering::Relaxed)
                                + pending_attempts;
                            pending_attempts = 0;
                            maybe_report_progress(total, &last_report, report_progress);
                        }
                        index += stride;
                    }
                    if pending_attempts != 0 {
                        attempts.fetch_add(pending_attempts, Ordering::Relaxed);
                    }
                    Ok(())
                })();
                if let Err(error) = result {
                    if !stopped.swap(true, Ordering::Relaxed) {
                        let _ = sender.send(Err(error));
                    }
                }
            });
        }
        drop(sender);
        receiver
            .recv()
            .context("vanity search ended without finding a matching key")?
    })?;

    let phone = base_phone.with_vault_key_index(&Secp256k1::new(), winning_index)?;
    let vault_address =
        template.address(&Secp256k1::verification_only(), phone.vault_pubkey, network);
    let expected_prefix = match network {
        Network::Bitcoin => format!("bc1p{suffix}"),
        Network::Regtest => format!("bcrt1p{suffix}"),
        Network::Signet => format!("tb1p{suffix}"),
        other => bail!("vanity initialization is unsupported on {other}"),
    };
    if !vault_address.to_string().starts_with(&expected_prefix) {
        bail!("vanity search result did not reproduce the requested address prefix");
    }
    Ok(VanityPhoneKey {
        phone,
        vault_address: vault_address.to_string(),
        attempts: attempts.load(Ordering::Relaxed),
        worker_count,
    })
}

fn persist_phone(
    data_dir: &Path,
    network: Network,
    phone: &DeviceKeys,
) -> Result<InitializedDevice> {
    ensure_phone_is_uninitialized(data_dir)?;
    let phone_path = data_dir.join(PHONE_DEVICE_FILE);
    let mnemonic = phone.mnemonic.to_string();
    write_json(
        &phone_path,
        &DeviceFile {
            kind: "phone".to_owned(),
            network: network_name(network).to_owned(),
            mnemonic: mnemonic.clone(),
            vault_key_index: phone.vault_key_index,
        },
    )?;
    HotWallet::open_or_create(data_dir)?;
    Ok(InitializedDevice {
        mnemonic,
        vault_pubkey: phone.vault_pubkey.to_string(),
        vault_key_index: phone.vault_key_index,
    })
}

fn ensure_phone_is_uninitialized(data_dir: &Path) -> Result<()> {
    let phone_path = data_dir.join(PHONE_DEVICE_FILE);
    if phone_path.exists() {
        bail!("phone already initialized at {}", phone_path.display());
    }
    Ok(())
}

fn maybe_report_progress<F>(total: u64, last_report: &AtomicU64, report_progress: &F)
where
    F: Fn(u64),
{
    let previous = last_report.load(Ordering::Relaxed);
    if total.saturating_sub(previous) >= 1_000_000
        && last_report
            .compare_exchange(previous, total, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        report_progress(total);
    }
}

#[derive(Debug, Clone, Copy)]
struct VanityTarget {
    value: u32,
    bit_count: u32,
}

impl VanityTarget {
    fn new(suffix: &str) -> Result<Self> {
        const CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        if suffix.is_empty() || suffix.len() > 6 {
            bail!("vanity suffix must contain between one and six Bech32 characters");
        }
        let mut value = 0_u32;
        for character in suffix.chars() {
            let digit = CHARSET
                .find(character)
                .with_context(|| format!("{character:?} is not a lowercase Bech32 character"))?;
            value = (value << 5) | digit as u32;
        }
        Ok(Self {
            value,
            bit_count: (suffix.len() * 5) as u32,
        })
    }

    fn matches(self, output_key: &[u8; 32]) -> bool {
        let first_bits =
            u32::from_be_bytes([output_key[0], output_key[1], output_key[2], output_key[3]]);
        first_bits >> (32 - self.bit_count) == self.value
    }
}

pub fn propose_policy(
    data_dir: &Path,
    backend: &dyn HotWalletBackend,
    now: DateTime<Utc>,
    monthly_limit_sats: u64,
    emergency_access_limit_sats: u64,
    presigned_years: u8,
    batch_dir: &Path,
) -> Result<BatchManifest> {
    let config = load_config(data_dir)?;
    ensure_backend_network(backend, &config)?;
    let utxos = backend.scan_vault(&config)?;
    let connectors = backend.scan_connectors(&config)?;
    let phone = load_device_keys(data_dir, PHONE_DEVICE_FILE)?;
    let mut wallet = HotWallet::open_or_create(data_dir)?;
    // Months from an earlier ceremony that are still waiting keep their dates; the new months
    // start after the last of them, so the monthly limit never doubles.
    let mut ladder_start = now.timestamp();
    if data_dir.join(SCHEDULE_FILE).is_file() {
        let schedule = load_schedule(data_dir)?;
        for rung in live_rungs_for(&config, backend, &schedule)? {
            ladder_start = ladder_start.max(i64::from(rung.entry.unlock));
        }
    }
    ceremony::build_policy_proposal_with_renewal(
        &config,
        &utxos,
        &connectors,
        now,
        ladder_start,
        PolicyLimits {
            monthly_limit_sats,
            emergency_access_limit_sats,
        },
        presigned_years,
        batch_dir,
        &phone,
        &mut wallet,
    )
}

/// Broadcast the active epoch's presigned renewal and switch to its schedule. Its rollover is
/// valid only once the current rollover's cold remainder is 360 days old.
pub fn activate_presigned_renewal(
    data_dir: &Path,
    backend: &dyn HotWalletBackend,
) -> Result<Schedule> {
    let schedule = load_schedule(data_dir)?;
    let blob: crate::core::crypto::EncryptedBlob = crate::core::storage::read_json(
        &data_dir
            .join("phone/transactions")
            .join(&schedule.rollover_txid)
            .join("approved-policy.json"),
    )
    .context("the active policy's approval record is missing")?;
    let package = open_approved_policy(data_dir, ApprovedPolicyInput::Encrypted(blob))?;
    if package.manifest.rollover.unsigned_txid != schedule.rollover_txid {
        bail!("the stored approval does not belong to the active policy");
    }
    let next = package
        .next
        .context("the active policy has no presigned renewal; run a new HWW ceremony")?;
    let renewal_dir = data_dir
        .join("phone/renewals")
        .join(&next.manifest.rollover.unsigned_txid);
    if !renewal_dir.join("manifest.json").is_file() {
        ceremony::materialize_policy_package(&next, &renewal_dir)?;
    }
    activate_policy(data_dir, backend, &renewal_dir).context(
        "presigned renewal was not accepted; it unlocks 360 days after the current rollover confirmed",
    )
}

pub fn activate_policy(
    data_dir: &Path,
    backend: &dyn HotWalletBackend,
    batch_dir: &Path,
) -> Result<Schedule> {
    let config = load_config(data_dir)?;
    ensure_backend_network(backend, &config)?;
    let manifest = ceremony::load_manifest(batch_dir)?;
    ceremony::validate_approved_batch(&config, &manifest, batch_dir)?;
    let phone = load_device_keys(data_dir, PHONE_DEVICE_FILE)?;

    let rollover = finalize_vault_psbt(read_psbt(&batch_dir.join(&manifest.rollover.psbt_file))?)?;
    // Stage each epoch independently. A rejected or interrupted rollover must leave the current
    // schedule and its encrypted transactions intact. Retain enough material to retry activation.
    let epoch_dir = data_dir
        .join("phone/transactions")
        .join(rollover.compute_txid().to_string());
    let previous_epoch = if data_dir.join(SCHEDULE_FILE).is_file() {
        Some(load_schedule(data_dir)?.rollover_txid.parse::<Txid>()?)
    } else {
        None
    };
    if epoch_dir.join("activated.json").exists()
        && previous_epoch.is_some_and(|txid| txid != rollover.compute_txid())
    {
        bail!("this policy epoch has already been superseded; refusing to reactivate it");
    }
    write_json(
        &epoch_dir.join("approved-policy.json"),
        &crate::core::crypto::encrypt(
            &phone.seed,
            &format!("policy-activation-v1:{}", rollover.compute_txid()),
            &serde_json::to_vec(&ceremony::package_from_batch(batch_dir)?)?,
        )?,
    )?;
    write_json(&epoch_dir.join("rollover.json"), &rollover)?;
    if manifest.rollover.unsigned_txid != rollover.compute_txid().to_string() {
        bail!("approved rollover does not match its manifest");
    }
    let entries = ladder::entries_from_manifest(&manifest)?;
    let rollover_txid = rollover.compute_txid();
    let emergency_access = manifest
        .emergency_access
        .as_ref()
        .map(|emergency| {
            let trigger = read_psbt(&batch_dir.join(&emergency.trigger.psbt_file))?;
            let withdrawal = read_psbt(&batch_dir.join(&emergency.withdrawal.psbt_file))?;
            let trigger_path = emergency_transaction_path(
                &epoch_dir,
                EmergencyTransactionKind::Trigger,
                trigger.unsigned_tx.compute_txid(),
            );
            let withdrawal_path = emergency_transaction_path(
                &epoch_dir,
                EmergencyTransactionKind::Withdrawal,
                withdrawal.unsigned_tx.compute_txid(),
            );
            write_encrypted_emergency_transaction(
                &trigger_path,
                &phone.seed,
                EmergencyTransactionKind::Trigger,
                &trigger,
            )?;
            write_encrypted_emergency_transaction(
                &withdrawal_path,
                &phone.seed,
                EmergencyTransactionKind::Withdrawal,
                &withdrawal,
            )?;
            Ok::<EmergencyAccessSchedule, anyhow::Error>(EmergencyAccessSchedule {
                amount_sats: emergency.amount_sats,
                delay_seconds: emergency.delay_seconds,
                hot_address: emergency.hot_address.clone(),
                trigger_file: relative_to(data_dir, &trigger_path)?,
                trigger_txid: trigger.unsigned_tx.compute_txid().to_string(),
                withdrawal_file: relative_to(data_dir, &withdrawal_path)?,
                withdrawal_txid: withdrawal.unsigned_tx.compute_txid().to_string(),
                trigger_connector: emergency.trigger_connector.clone(),
                withdrawal_connector: emergency.withdrawal_connector.clone(),
            })
        })
        .transpose()?;
    // A new rollover does not touch earlier months, so keep the ones still waiting.
    let previous_entries = match (&manifest.renews, previous_epoch) {
        (Some(link), Some(previous)) if link.parent_rollover_txid != previous.to_string() => {
            bail!("presigned renewal does not renew the active policy")
        }
        (Some(_), None) => bail!("presigned renewal does not renew the active policy"),
        (_, Some(previous)) if previous != rollover_txid => {
            live_rungs_for(&config, backend, &load_schedule(data_dir)?)?
                .into_iter()
                .map(|rung| rung.entry)
                .collect()
        }
        (_, Some(_)) => load_schedule(data_dir)?.previous_entries,
        (None, None) => Vec::new(),
    };
    let schedule = Schedule {
        previous_entries,
        version: 6,
        rollover_txid: rollover.compute_txid().to_string(),
        controller_descriptor: manifest.controller_descriptor.clone(),
        controller_address: manifest.controller_address.clone(),
        connector_value_sats: manifest.connector_value_sats,
        monthly_limit_sats: manifest.monthly_limit_sats,
        emergency_access_limit_sats: manifest.emergency_access_limit_sats,
        entries,
        emergency_access,
    };
    write_json(&epoch_dir.join("schedule.json"), &schedule)?;
    // Tell the watcher about this epoch's presigned transactions before any of them can appear.
    let mut plan = crate::core::watch::known_from_manifest(&manifest, manifest.renews.is_some());
    if let Some(next) = ceremony::load_presigned_renewal(&manifest, batch_dir)? {
        plan.extend(crate::core::watch::known_from_manifest(&next, true));
    }
    crate::core::watch::record_plan(data_dir, plan)?;
    let broadcast_txid = match manifest.rollover_anchor_vout {
        // A presigned renewal's fee was fixed a year ago; bump it to today's rate.
        Some(anchor_vout) => broadcast_with_anchor_bump(
            data_dir,
            backend,
            &rollover,
            manifest.rollover.fee_sats,
            anchor_vout,
        ),
        None => backend.broadcast(&rollover),
    }
    .context("failed to broadcast rollover transaction")?;
    if broadcast_txid != rollover.compute_txid() {
        bail!("chain backend returned an unexpected rollover transaction ID");
    }
    // Pre-staging versions have no activation marker. Remember their active epoch too before
    // replacing the pointer, so an already-confirmed legacy approval cannot reactivate it later.
    if let Some(previous) = previous_epoch.filter(|txid| *txid != broadcast_txid) {
        write_json(
            &data_dir.join("phone/transactions").join(previous.to_string()).join("activated.json"),
            &true,
        ).context("rollover accepted but archiving the prior epoch failed; retry the same approved policy")?;
    }
    write_json(&data_dir.join(SCHEDULE_FILE), &schedule).context(
        "rollover accepted but schedule activation failed; retry the same approved policy",
    )?;
    crate::core::storage::set_policy_limits(
        data_dir,
        manifest.monthly_limit_sats,
        manifest.emergency_access_limit_sats,
    )
    .context("rollover accepted but saving policy limits failed; retry the same approved policy")?;
    write_json(&epoch_dir.join("activated.json"), &true)?;
    Ok(schedule)
}

pub fn initiate_emergency_access(
    data_dir: &Path,
    backend: &dyn HotWalletBackend,
) -> Result<EmergencyBroadcastResult> {
    let schedule = load_schedule(data_dir)?;
    schedule
        .emergency_access
        .as_ref()
        .context("emergency access is disabled for the active vault epoch")?;
    let config = load_config(data_dir)?;
    ensure_backend_network(backend, &config)?;
    let phone = load_device_keys(data_dir, PHONE_DEVICE_FILE)?;
    let transaction_txid = broadcast_emergency_transaction(
        data_dir,
        backend,
        &schedule,
        &config,
        &phone,
        EmergencyTransactionKind::Trigger,
    )?;
    Ok(EmergencyBroadcastResult { transaction_txid })
}

pub fn withdraw_emergency_access(data_dir: &Path, backend: &dyn HotWalletBackend) -> Result<Txid> {
    let schedule = load_schedule(data_dir)?;
    let config = load_config(data_dir)?;
    ensure_backend_network(backend, &config)?;
    let phone = load_device_keys(data_dir, PHONE_DEVICE_FILE)?;
    broadcast_emergency_transaction(
        data_dir,
        backend,
        &schedule,
        &config,
        &phone,
        EmergencyTransactionKind::Withdrawal,
    )
}

pub fn cancel_emergency_access(data_dir: &Path, backend: &dyn HotWalletBackend) -> Result<Txid> {
    let schedule = load_schedule(data_dir)?;
    let config = load_config(data_dir)?;
    ensure_backend_network(backend, &config)?;
    let phone = load_device_keys(data_dir, PHONE_DEVICE_FILE)?;
    let connector = schedule
        .emergency_access
        .as_ref()
        .context("emergency access is disabled for the active vault epoch")?
        .withdrawal_connector
        .clone();
    revoke_connector_to_phone(data_dir, backend, &config, &phone, &connector)
}

fn broadcast_emergency_transaction(
    data_dir: &Path,
    backend: &dyn HotWalletBackend,
    schedule: &Schedule,
    config: &VaultConfig,
    phone: &DeviceKeys,
    kind: EmergencyTransactionKind,
) -> Result<Txid> {
    let emergency = schedule
        .emergency_access
        .as_ref()
        .context("emergency access is disabled for the active vault epoch")?;
    let (file, expected_txid, connector) = match kind {
        EmergencyTransactionKind::Trigger => (
            &emergency.trigger_file,
            &emergency.trigger_txid,
            &emergency.trigger_connector,
        ),
        EmergencyTransactionKind::Withdrawal => (
            &emergency.withdrawal_file,
            &emergency.withdrawal_txid,
            &emergency.withdrawal_connector,
        ),
        EmergencyTransactionKind::Cancellation => bail!(
            "emergency cancellation is constructed dynamically from the live controller output"
        ),
    };
    let artifact: EncryptedEmergencyTransaction = read_json(&data_dir.join(file))?;
    if artifact.version != 2 || artifact.kind != kind || artifact.txid != *expected_txid {
        bail!("encrypted emergency transaction metadata does not match the requested action");
    }
    let purpose = emergency_transaction_purpose(kind, &artifact.txid);
    let plaintext = crate::core::crypto::decrypt(&phone.seed, &purpose, &artifact.encrypted_psbt)?;
    let mut psbt = Psbt::from_str(
        std::str::from_utf8(&plaintext).context("decrypted emergency PSBT was not UTF-8")?,
    )
    .context("decrypted emergency PSBT was invalid")?;
    let txid = psbt.unsigned_tx.compute_txid();
    if txid.to_string() != artifact.txid {
        bail!("decrypted emergency PSBT ID does not match its metadata");
    }
    ensure_connector_input(&psbt, connector)?;
    let controller = controller_policy(config)?;
    validate_schedule_controller(schedule, &controller)?;
    sign_controller_psbt_inputs(
        &mut psbt,
        &controller,
        ControllerPath::Phone,
        &phone.vault_keypair.cooperative,
        &[1],
    )?;
    let parent_fee = psbt_fee(&psbt)?;
    let transaction = finalize_vault_psbt(psbt)?;
    if kind == EmergencyTransactionKind::Withdrawal {
        // The withdrawal's only output pays the hot wallet, so the phone can bump it.
        broadcast_with_fee_bump(data_dir, backend, &transaction, parent_fee, 0)
            .with_context(|| format!("failed to broadcast emergency access {kind:?}"))?;
        return Ok(txid);
    }
    // The trigger pays no hot-wallet output, so the phone bumps it through its anchor.
    broadcast_with_anchor_bump(
        data_dir,
        backend,
        &transaction,
        parent_fee,
        ceremony::TRIGGER_ANCHOR_VOUT as u32,
    )
    .with_context(|| format!("failed to broadcast emergency access {kind:?}"))?;
    Ok(txid)
}

/// Every month of the active policy that is still unspent at its rung address, with the
/// previous epoch's months first. A month whose rollover has not confirmed yet is not listed.
pub fn live_rungs(
    data_dir: &Path,
    backend: &dyn HotWalletBackend,
) -> Result<Vec<ladder::LiveRung>> {
    let schedule = load_schedule(data_dir)?;
    let config = load_config(data_dir)?;
    ensure_backend_network(backend, &config)?;
    live_rungs_for(&config, backend, &schedule)
}

pub fn live_rungs_for<B: Blockchain + ?Sized>(
    config: &VaultConfig,
    backend: &B,
    schedule: &Schedule,
) -> Result<Vec<ladder::LiveRung>> {
    let mut live = Vec::new();
    for entry in schedule.previous_entries.iter().chain(&schedule.entries) {
        let rung = ladder::LiveRung::new(config, entry)?;
        let coins = backend.scan_savings(&rung.policy.address)?;
        if coins.iter().any(|coin| {
            coin.outpoint == entry.outpoint && coin.txout.value.to_sat() == entry.value_sats
        }) {
            live.push(rung);
        }
    }
    Ok(live)
}

fn vault_script(config: &VaultConfig) -> Result<bitcoin::ScriptBuf> {
    Ok(config
        .vault_address
        .parse::<Address<_>>()?
        .require_network(config.bitcoin_network()?)?
        .script_pubkey())
}

fn current_fee_rate<B: Blockchain + ?Sized>(backend: &B) -> Result<u64> {
    Ok(backend
        .estimate_fee_rate(crate::core::fees::DEFAULT_CONFIRMATION_TARGET)?
        .unwrap_or(DEFAULT_FEE_RATE_SAT_VB))
}

fn broadcast_rung_spend<B: Blockchain + ?Sized>(
    backend: &B,
    transaction: &Transaction,
) -> Result<Txid> {
    let txid = backend
        .broadcast(transaction)
        .context("failed to broadcast the allowance transaction")?;
    if txid != transaction.compute_txid() {
        bail!("chain backend returned an unexpected allowance transaction ID");
    }
    Ok(txid)
}

/// Move one unlocked month to the phone's hot wallet. With `soft_limit_sats`, only that much
/// comes to the phone and the rest of the month goes back to the vault. The fee comes out of the
/// phone's share.
pub fn claim_month(
    data_dir: &Path,
    backend: &dyn HotWalletBackend,
    step: u8,
    previous: bool,
    soft_limit_sats: Option<u64>,
) -> Result<ladder::RungSpendResult> {
    let schedule = load_schedule(data_dir)?;
    let config = load_config(data_dir)?;
    ensure_backend_network(backend, &config)?;
    let entries = if previous {
        &schedule.previous_entries
    } else {
        &schedule.entries
    };
    // Earlier months can come from more than one ceremony; take the oldest of that number.
    let entry = entries
        .iter()
        .filter(|entry| entry.step == step)
        .min_by_key(|entry| entry.unlock)
        .with_context(|| format!("no allowance exists for month {step}"))?;
    let median_time = backend.chain_tip()?.median_time;
    if !ladder::is_unlocked(entry, median_time) {
        bail!(
            "month {step} unlocks after {}",
            ladder::unlock_date(entry.unlock)
        );
    }
    let rung = live_rungs_for(&config, backend, &schedule)?
        .into_iter()
        .find(|rung| rung.outpoint() == entry.outpoint)
        .with_context(|| {
            format!("month {step} is not available: it was already claimed, returned or rescued")
        })?;
    let phone = load_device_keys(data_dir, PHONE_DEVICE_FILE)?;
    let mut wallet = HotWallet::open_or_create(data_dir)?;
    let hot_script = wallet.next_receive_address()?.script_pubkey();
    let mut outputs = Vec::new();
    let mut returned_sats = 0;
    if let Some(limit) = soft_limit_sats.filter(|limit| *limit < entry.value_sats) {
        returned_sats = entry.value_sats - limit;
        outputs.push(TxOut {
            value: Amount::from_sat(returned_sats),
            script_pubkey: vault_script(&config)?,
        });
    }
    outputs.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: hot_script,
    });
    let rungs = [rung];
    let spend = ladder::build_rung_spend(
        &rungs,
        SpendPath::PhoneRecovery,
        outputs,
        current_fee_rate(backend)?,
    )?;
    let fee_sats = spend.fee_sats;
    let transaction = ladder::sign_as_phone(spend, &rungs, &phone)?;
    let sent_sats = transaction
        .output
        .last()
        .map(|output| output.value.to_sat())
        .unwrap_or_default();
    let txid = broadcast_rung_spend(backend, &transaction)?;
    Ok(ladder::RungSpendResult {
        txid,
        month_count: 1,
        sent_sats,
        returned_sats,
        fee_sats,
    })
}

/// Send unclaimed months back to the vault, so they cannot pile up on a phone that might be
/// stolen. By default a month goes back once the month after it has unlocked; `all` also returns
/// the current month. Returns `None` when there is nothing to return.
pub fn return_unclaimed_months(
    data_dir: &Path,
    backend: &dyn HotWalletBackend,
    all: bool,
) -> Result<Option<ladder::RungSpendResult>> {
    let schedule = load_schedule(data_dir)?;
    let config = load_config(data_dir)?;
    ensure_backend_network(backend, &config)?;
    let median_time = backend.chain_tip()?.median_time;
    let grace = if all {
        0
    } else {
        u64::from(crate::core::MONTHLY_ALLOWANCE_DELAY_SECONDS)
    };
    let rungs: Vec<_> = live_rungs_for(&config, backend, &schedule)?
        .into_iter()
        .filter(|rung| median_time > u64::from(rung.entry.unlock) + grace)
        .collect();
    if rungs.is_empty() {
        return Ok(None);
    }
    let phone = load_device_keys(data_dir, PHONE_DEVICE_FILE)?;
    let spend = ladder::build_rung_spend(
        &rungs,
        SpendPath::PhoneRecovery,
        vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: vault_script(&config)?,
        }],
        current_fee_rate(backend)?,
    )?;
    let fee_sats = spend.fee_sats;
    let transaction = ladder::sign_as_phone(spend, &rungs, &phone)?;
    let returned_sats = transaction.output[0].value.to_sat();
    let txid = broadcast_rung_spend(backend, &transaction)?;
    Ok(Some(ladder::RungSpendResult {
        txid,
        month_count: rungs.len(),
        sent_sats: 0,
        returned_sats,
        fee_sats,
    }))
}

/// Fee paid by a fully described PSBT: inputs (from `witness_utxo`) minus outputs.
fn psbt_fee(psbt: &Psbt) -> Result<u64> {
    let mut inputs = 0u64;
    for input in &psbt.inputs {
        inputs += input
            .witness_utxo
            .as_ref()
            .context("policy PSBT input is missing its witness UTXO")?
            .value
            .to_sat();
    }
    let outputs: u64 = psbt
        .unsigned_tx
        .output
        .iter()
        .map(|o| o.value.to_sat())
        .sum();
    inputs
        .checked_sub(outputs)
        .context("policy PSBT outputs exceed its inputs")
}

/// Broadcast a presigned `parent`, bumping it with a child that spends its output `hot_vout`
/// (which pays this phone's hot wallet) when the parent's frozen fee is below today's rate.
fn broadcast_with_fee_bump(
    data_dir: &Path,
    backend: &dyn HotWalletBackend,
    parent: &Transaction,
    parent_fee: u64,
    hot_vout: u32,
) -> Result<Txid> {
    use crate::core::fees;
    // A typical one-input, one-output P2TR key-path child.
    const CHILD_VSIZE_ESTIMATE: u64 = 111;

    let txid = parent.compute_txid();
    let target = backend
        .estimate_fee_rate(fees::DEFAULT_CONFIRMATION_TARGET)?
        .unwrap_or(DEFAULT_FEE_RATE_SAT_VB);
    let parent_vsize = parent.vsize() as u64;
    let child_fee = fees::cpfp_child_fee(parent_vsize, parent_fee, CHILD_VSIZE_ESTIMATE, target)?;
    if child_fee == 0 {
        let broadcast = backend.broadcast(parent)?;
        if broadcast != txid {
            bail!("chain backend returned an unexpected transaction ID");
        }
        return Ok(txid);
    }
    let hot_value = parent
        .output
        .get(hot_vout as usize)
        .context("presigned transaction has no hot-wallet output to bump from")?
        .value
        .to_sat();
    fees::child_output_after_fee(hot_value, child_fee)?;
    let mut wallet = HotWallet::open_or_create(data_dir)?;
    let mut child = wallet.build_cpfp_child(parent, hot_vout, Amount::from_sat(child_fee))?;
    // Rebuild once if the real child is larger than estimated, so the package still hits target.
    let actual_vsize = child.vsize() as u64;
    if actual_vsize > CHILD_VSIZE_ESTIMATE {
        let fee = fees::cpfp_child_fee(parent_vsize, parent_fee, actual_vsize, target)?;
        fees::child_output_after_fee(hot_value, fee)?;
        child = wallet.build_cpfp_child(parent, hot_vout, Amount::from_sat(fee))?;
    }
    backend.broadcast_package(parent, &child)?;
    Ok(txid)
}

/// Broadcast a presigned `parent` that carries a pay-to-anchor output, bumping it with a child
/// funded by hot-wallet coins when the parent's frozen fee is below today's rate.
fn broadcast_with_anchor_bump(
    data_dir: &Path,
    backend: &dyn HotWalletBackend,
    parent: &Transaction,
    parent_fee: u64,
    anchor_vout: u32,
) -> Result<Txid> {
    use crate::core::fees;
    // Anchor input (41 vB) plus one P2TR key-path input and one P2TR change output.
    const CHILD_VSIZE_ESTIMATE: u64 = 152;

    let txid = parent.compute_txid();
    let target = backend
        .estimate_fee_rate(fees::DEFAULT_CONFIRMATION_TARGET)?
        .unwrap_or(DEFAULT_FEE_RATE_SAT_VB);
    let parent_vsize = parent.vsize() as u64;
    let child_fee = fees::cpfp_child_fee(parent_vsize, parent_fee, CHILD_VSIZE_ESTIMATE, target)?;
    if child_fee == 0 {
        let broadcast = backend.broadcast(parent)?;
        if broadcast != txid {
            bail!("chain backend returned an unexpected transaction ID");
        }
        return Ok(txid);
    }
    let mut wallet = HotWallet::open_or_create(data_dir)?;
    let mut child =
        match wallet.build_anchor_child(parent, anchor_vout, Amount::from_sat(child_fee)) {
            Ok(child) => child,
            // An empty phone wallet must never block emergency access: send the trigger at its
            // presigned fee and let the user bump it later once the phone holds coins.
            Err(error) => {
                eprintln!("warning: broadcasting without a fee bump: {error:#}");
                let broadcast = backend.broadcast(parent)?;
                if broadcast != txid {
                    bail!("chain backend returned an unexpected transaction ID");
                }
                return Ok(txid);
            }
        };
    let actual_vsize = child.vsize() as u64;
    if actual_vsize > CHILD_VSIZE_ESTIMATE {
        let fee = fees::cpfp_child_fee(parent_vsize, parent_fee, actual_vsize, target)?;
        child = wallet.build_anchor_child(parent, anchor_vout, Amount::from_sat(fee))?;
    }
    backend.broadcast_package(parent, &child)?;
    Ok(txid)
}

fn revoke_connector_to_phone(
    data_dir: &Path,
    backend: &dyn HotWalletBackend,
    config: &VaultConfig,
    phone: &DeviceKeys,
    connector: &ceremony::ConnectorState,
) -> Result<Txid> {
    let controller = controller_policy(config)?;
    let mut wallet = HotWallet::open_or_create(data_dir)?;
    let destination = wallet.next_change_address()?.script_pubkey();
    let connector_utxo = VaultUtxo {
        outpoint: connector.outpoint,
        txout: TxOut {
            value: Amount::from_sat(connector.value_sats),
            script_pubkey: controller.address.script_pubkey(),
        },
        // The dynamic transaction can validly spend an unconfirmed connector output. Chain
        // acceptance, rather than this local placeholder, determines whether that state is live.
        confirmation_height: 0,
    };
    // TODO(production): select current-feerate phone inputs and expose RBF/CPFP controls. The MVP
    // intentionally uses its fixed 1 sat/vB fee and pays it from the controller output.
    let (mut psbt, _fee_sats) = build_controller_revocation_psbt(
        &[connector_utxo],
        destination,
        DEFAULT_FEE_RATE_SAT_VB,
        &controller,
    )?;
    sign_controller_psbt_inputs(
        &mut psbt,
        &controller,
        ControllerPath::Phone,
        &phone.vault_keypair.cooperative,
        &[0],
    )?;
    let transaction = finalize_vault_psbt(psbt)?;
    let txid = transaction.compute_txid();
    let broadcast_txid = backend
        .broadcast(&transaction)
        .context("failed to broadcast dynamic policy revocation")?;
    if broadcast_txid != txid {
        bail!("chain backend returned an unexpected revocation transaction ID");
    }
    Ok(txid)
}

fn ensure_connector_input(psbt: &Psbt, connector: &ceremony::ConnectorState) -> Result<()> {
    if psbt
        .unsigned_tx
        .input
        .get(1)
        .map(|input| input.previous_output)
        != Some(connector.outpoint)
        || psbt
            .inputs
            .get(1)
            .and_then(|input| input.witness_utxo.as_ref())
            .map(|output| output.value.to_sat())
            != Some(connector.value_sats)
    {
        bail!("encrypted policy PSBT does not consume the scheduled controller state");
    }
    Ok(())
}

fn controller_policy(config: &VaultConfig) -> Result<ControllerPolicy> {
    let phone = crate::core::keys::VaultKey::from_str(&config.phone_vault_pubkey)
        .context("invalid configured phone vault key")?;
    let hww = crate::core::keys::VaultKey::from_str(&config.hww_vault_pubkey)
        .context("invalid configured HWW vault key")?;
    ControllerPolicy::new_for_network(phone, hww, config.bitcoin_network()?)
}

fn validate_schedule_controller(schedule: &Schedule, controller: &ControllerPolicy) -> Result<()> {
    if schedule.controller_descriptor != controller.descriptor_string()
        || schedule.controller_address != controller.address.to_string()
        || schedule.connector_value_sats != crate::core::CONNECTOR_VALUE_SATS
    {
        bail!("active schedule controller does not match the configured vault keys");
    }
    Ok(())
}

pub fn load_schedule(data_dir: &Path) -> Result<Schedule> {
    let schedule: Schedule = read_json(&data_dir.join(SCHEDULE_FILE))?;
    if schedule.version != 6 {
        bail!("unsupported active policy version; approve a new vault policy");
    }
    Ok(schedule)
}

pub fn restore_phone(data_dir: &Path, package: &PhoneRecoveryPackage) -> Result<String> {
    if package.version != 2 || package.kind != "phone-recovery" {
        bail!("unsupported phone recovery package");
    }
    let phone_path = data_dir.join(PHONE_DEVICE_FILE);
    if phone_path.exists() {
        bail!(
            "phone key still exists at {}; refusing to overwrite it",
            phone_path.display()
        );
    }
    let config = load_config(data_dir)?;
    let phone = DeviceKeys::parse_for_network_at_index(
        &Secp256k1::new(),
        &package.phone_mnemonic,
        config.bitcoin_network()?,
        package.phone_vault_key_index,
    )?;
    if phone.vault_pubkey.to_string() != package.phone_vault_pubkey
        || package.phone_vault_pubkey != config.phone_vault_pubkey
        || package.vault_descriptor != config.vault_descriptor
        || package.vault_address != config.vault_address
    {
        bail!("phone recovery package does not match the configured vault policy");
    }
    write_json(
        &phone_path,
        &DeviceFile {
            kind: "phone".to_owned(),
            network: config.network,
            mnemonic: package.phone_mnemonic.clone(),
            vault_key_index: package.phone_vault_key_index,
        },
    )?;
    HotWallet::open_or_create(data_dir)?.request_full_scan()?;
    Ok(package.phone_mnemonic.clone())
}

pub fn recover(
    data_dir: &Path,
    config: &VaultConfig,
    utxos: &[crate::core::types::VaultUtxo],
    tip_height: u64,
    destination: &Address,
) -> Result<(Transaction, SweepResult)> {
    let plan = recovery::prepare_sweep(
        config,
        utxos,
        tip_height,
        SweepPath::PhoneRecovery,
        destination,
    )?;
    let phone = load_device_keys(data_dir, PHONE_DEVICE_FILE)?;
    recovery::sign_recovery_sweep(plan, SweepPath::PhoneRecovery, &phone)
}

/// Propose a sweep of every vault coin with the phone and the YubiKey, for when the hardware
/// wallet is lost. The phone signs here; the YubiKey's computer finishes it.
pub fn create_yubikey_sweep(
    data_dir: &Path,
    config: &VaultConfig,
    utxos: &[crate::core::types::VaultUtxo],
    destination: &Address,
) -> Result<recovery::PairSweepPackage> {
    let phone = load_device_keys(data_dir, PHONE_DEVICE_FILE)?;
    recovery::create_pair_sweep(config, utxos, SweepPath::PhoneYubikey, destination, &phone)
}

pub fn create_cooperative_sweep(
    data_dir: &Path,
    backend: &dyn HotWalletBackend,
    destination: &Address,
) -> Result<CooperativeSweepPackage> {
    let config = load_config(data_dir)?;
    ensure_backend_network(backend, &config)?;
    let utxos = backend.scan_vault(&config)?;
    let phone = load_device_keys(data_dir, PHONE_DEVICE_FILE)?;
    recovery::create_cooperative_sweep(&config, &utxos, destination, &phone)
}

pub fn broadcast_cooperative_sweep(
    data_dir: &Path,
    backend: &dyn HotWalletBackend,
    package: &CooperativeSweepPackage,
) -> Result<SweepResult> {
    let config = load_config(data_dir)?;
    ensure_backend_network(backend, &config)?;
    broadcast_cooperative_sweep_for_config(backend, &config, package)
}

fn broadcast_cooperative_sweep_for_config(
    backend: &dyn HotWalletBackend,
    config: &VaultConfig,
    package: &CooperativeSweepPackage,
) -> Result<SweepResult> {
    let (transaction, result) = recovery::finalize_cooperative_sweep(config, package)?;
    let txid = backend
        .broadcast(&transaction)
        .context("failed to broadcast cooperative vault sweep")?;
    if txid != result.txid {
        bail!("chain backend returned an unexpected cooperative sweep transaction ID");
    }
    Ok(result)
}

/// The phone key that created `lock`. A savings lock keeps the keys it was created with, so after
/// a phone-key rotation the earlier key is read back from the rotation archive.
pub fn phone_keys_for_lock(data_dir: &Path, lock: &SavingsLock) -> Result<DeviceKeys> {
    let current = load_device_keys(data_dir, PHONE_DEVICE_FILE)?;
    if current.vault_pubkey.to_string() == lock.phone_vault_pubkey {
        return Ok(current);
    }
    let history = data_dir.join("history");
    if history.is_dir() {
        for entry in std::fs::read_dir(&history)? {
            let archive = entry?.path();
            if !archive.join(PHONE_DEVICE_FILE).is_file() {
                continue;
            }
            let keys = load_device_keys(&archive, PHONE_DEVICE_FILE)?;
            if keys.vault_pubkey.to_string() == lock.phone_vault_pubkey {
                return Ok(keys);
            }
        }
    }
    bail!(
        "this phone does not hold the key that created the savings lock; restore it from the HWW backup"
    )
}

fn savings_lock_coins(
    data_dir: &Path,
    backend: &dyn HotWalletBackend,
    unlock: Option<u32>,
) -> Result<(VaultConfig, SavingsLock, Vec<crate::core::types::VaultUtxo>)> {
    let config = load_config(data_dir)?;
    ensure_backend_network(backend, &config)?;
    let lock = savings_spend::find_lock(&config, unlock)?.clone();
    let utxos = backend.scan_savings(&lock.address(config.bitcoin_network()?)?)?;
    Ok((config, lock, utxos))
}

/// Build the cooperative spend of one savings lock at today's fee rate and add the phone's
/// signature. The HWW signs it next with `cold_wallet::approve_savings_spend`.
pub fn create_savings_spend(
    data_dir: &Path,
    backend: &dyn HotWalletBackend,
    unlock: Option<u32>,
    destination: &Address,
) -> Result<SavingsSpendPackage> {
    let (config, lock, utxos) = savings_lock_coins(data_dir, backend, unlock)?;
    let phone = phone_keys_for_lock(data_dir, &lock)?;
    let tip = backend.chain_tip()?;
    let fee_rate = savings_spend::current_fee_rate(backend)?;
    savings_spend::create_savings_spend(
        &config,
        &lock,
        &utxos,
        tip.median_time,
        destination,
        fee_rate,
        &phone,
    )
}

pub fn broadcast_savings_spend(
    data_dir: &Path,
    backend: &dyn HotWalletBackend,
    package: &SavingsSpendPackage,
) -> Result<SweepResult> {
    let config = load_config(data_dir)?;
    ensure_backend_network(backend, &config)?;
    let (transaction, result) = savings_spend::finalize_savings_spend(&config, package)?;
    let txid = backend
        .broadcast(&transaction)
        .context("failed to broadcast savings spend")?;
    if txid != result.txid {
        bail!("chain backend returned an unexpected savings spend transaction ID");
    }
    Ok(result)
}

/// Move a savings lock's coins with the phone alone, 425 days after its unlock date.
pub fn recover_savings(
    data_dir: &Path,
    backend: &dyn HotWalletBackend,
    unlock: Option<u32>,
    destination: &Address,
) -> Result<SweepResult> {
    let (config, lock, utxos) = savings_lock_coins(data_dir, backend, unlock)?;
    let phone = phone_keys_for_lock(data_dir, &lock)?;
    let tip = backend.chain_tip()?;
    let fee_rate = savings_spend::current_fee_rate(backend)?;
    let (transaction, result) = savings_spend::sign_savings_recovery(
        &config,
        &lock,
        &utxos,
        tip.median_time,
        SpendPath::PhoneRecovery,
        destination,
        fee_rate,
        &phone,
    )?;
    let txid = backend
        .broadcast(&transaction)
        .context("failed to broadcast savings recovery")?;
    if txid != result.txid {
        bail!("chain backend returned an unexpected savings recovery transaction ID");
    }
    Ok(result)
}

pub fn validate_policy_package(package: &PolicyPackage) -> Result<()> {
    if !ceremony::is_supported_policy_package(package) {
        bail!("unsupported policy package");
    }
    Ok(())
}

/// Chain functionality needed by a mobile wallet in addition to the shared vault operations.
pub trait HotWalletBackend: Blockchain {
    fn sync_hot_wallet(&self, wallet: &mut HotWallet) -> Result<()>;
}

impl HotWalletBackend for BitcoinCoreBackend {
    fn sync_hot_wallet(&self, wallet: &mut HotWallet) -> Result<()> {
        wallet.sync_core(&self.client)
    }
}

impl HotWalletBackend for ElectrumBackend {
    fn sync_hot_wallet(&self, wallet: &mut HotWallet) -> Result<()> {
        wallet.sync_electrum(&self.client)
    }
}

impl HotAddressProvider for HotWallet {
    fn next_receive_address(&mut self) -> Result<bitcoin::Address> {
        HotWallet::next_receive_address(self)
    }
}

fn ensure_backend_network<B>(backend: &B, config: &VaultConfig) -> Result<()>
where
    B: Blockchain + ?Sized,
{
    let expected = config.bitcoin_network()?;
    if backend.network() != expected {
        bail!(
            "chain backend network {} does not match vault network {}",
            backend.network(),
            config.network
        );
    }
    Ok(())
}

fn read_psbt(path: &Path) -> Result<Psbt> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read PSBT {}", path.display()))?;
    Psbt::from_str(text.trim()).with_context(|| format!("invalid PSBT in {}", path.display()))
}

fn emergency_transaction_path(
    epoch_dir: &Path,
    kind: EmergencyTransactionKind,
    txid: Txid,
) -> std::path::PathBuf {
    epoch_dir.join(format!(
        "emergency-{}-{txid}.json",
        emergency_transaction_kind_name(kind)
    ))
}

fn write_encrypted_emergency_transaction(
    path: &Path,
    phone_seed: &[u8],
    kind: EmergencyTransactionKind,
    psbt: &Psbt,
) -> Result<()> {
    let txid = psbt.unsigned_tx.compute_txid().to_string();
    let purpose = emergency_transaction_purpose(kind, &txid);
    let encrypted_psbt =
        crate::core::crypto::encrypt(phone_seed, &purpose, psbt.to_string().as_bytes())?;
    write_json(
        path,
        &EncryptedEmergencyTransaction {
            version: 2,
            kind,
            txid,
            encrypted_psbt,
        },
    )
}

fn emergency_transaction_purpose(kind: EmergencyTransactionKind, txid: &str) -> String {
    format!("emergency/{}/{txid}", emergency_transaction_kind_name(kind))
}

fn emergency_transaction_kind_name(kind: EmergencyTransactionKind) -> &'static str {
    match kind {
        EmergencyTransactionKind::Trigger => "trigger",
        EmergencyTransactionKind::Withdrawal => "withdrawal",
        EmergencyTransactionKind::Cancellation => "cancellation",
    }
}

fn relative_to(base: &Path, path: &Path) -> Result<String> {
    Ok(path
        .strip_prefix(base)
        .with_context(|| format!("{} is outside {}", path.display(), base.display()))?
        .to_string_lossy()
        .into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        keys::DeviceKeys,
        recovery::PhoneRecoveryPackage,
        storage::{
            DeviceFile, HWW_DEVICE_FILE, HWW_PUBLIC_FILE, PublicDeviceFile, initialize_vault,
            load_config, load_device_keys,
        },
    };

    #[test]
    fn multithreaded_vanity_search_persists_a_recoverable_indexed_phone_key() {
        let dir = tempfile::tempdir().unwrap();
        let network = Network::Regtest;
        let secp = Secp256k1::new();
        let hww = DeviceKeys::generate_for_network(&secp, network).unwrap();
        write_json(
            &dir.path().join(HWW_DEVICE_FILE),
            &DeviceFile {
                kind: "hww".to_owned(),
                network: network_name(network).to_owned(),
                mnemonic: hww.mnemonic.to_string(),
                vault_key_index: hww.vault_key_index,
            },
        )
        .unwrap();
        write_json(
            &dir.path().join(HWW_PUBLIC_FILE),
            &PublicDeviceFile {
                version: 1,
                kind: "hww-public-key".to_owned(),
                network: network_name(network).to_owned(),
                vault_pubkey: hww.vault_pubkey.to_string(),
            },
        )
        .unwrap();

        let result = initialize_vanity_with_suffix(dir.path(), network, "v", 4, |_| {}).unwrap();
        assert!(result.vault_address.starts_with("bcrt1pv"));
        assert_eq!(result.worker_count, 4);
        assert!(result.attempts > 0);

        let persisted = load_device_keys(dir.path(), PHONE_DEVICE_FILE).unwrap();
        assert_eq!(
            persisted.vault_pubkey.to_string(),
            result.device.vault_pubkey
        );
        assert_eq!(persisted.vault_key_index, result.device.vault_key_index);
        let config = initialize_vault(dir.path()).unwrap();
        assert_eq!(config.vault_address, result.vault_address);

        fs::remove_file(dir.path().join(PHONE_DEVICE_FILE)).unwrap();
        restore_phone(
            dir.path(),
            &PhoneRecoveryPackage {
                version: 2,
                kind: "phone-recovery".to_owned(),
                phone_mnemonic: result.device.mnemonic,
                phone_vault_key_index: result.device.vault_key_index,
                phone_vault_pubkey: result.device.vault_pubkey,
                vault_descriptor: config.vault_descriptor,
                vault_address: config.vault_address,
            },
        )
        .unwrap();
        let restored = load_device_keys(dir.path(), PHONE_DEVICE_FILE).unwrap();
        assert_eq!(restored.vault_pubkey, persisted.vault_pubkey);
        assert_eq!(load_config(dir.path()).unwrap().network, "regtest");
    }

    #[test]
    fn vanity_search_encodes_the_mainnet_prefix() {
        let network = Network::Bitcoin;
        let hww = DeviceKeys::generate_for_network(&Secp256k1::new(), network).unwrap();
        let result =
            grind_vanity_phone_key(network, hww.vault_pubkey, None, None, "v", 4, |_| {}).unwrap();
        assert!(result.vault_address.starts_with("bc1pv"));
        assert_eq!(result.worker_count, 4);
        assert!(result.attempts > 0);
    }
}
