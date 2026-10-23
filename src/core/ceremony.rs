use super::{
    CONNECTOR_VALUE_SATS, DEFAULT_FEE_RATE_SAT_VB, EMERGENCY_ACCESS_DELAY_SECONDS,
    MONTHLY_ALLOWANCE_DELAY_SECONDS, MONTHS_PER_ROLLOVER, PRESIGNED_RENEWAL_DELAY_SECONDS,
    crypto::EncryptedBlob,
    keys::{DeviceKeys, VaultKey},
    policy::{ControllerPath, ControllerPolicy, RungPolicy, SpendPath, VaultPolicy},
    storage::{VaultConfig, read_json, write_json, write_private},
    transactions::{
        create_policy_psbt, estimate_policy_vsize, sign_controller_psbt_inputs,
        sign_vault_psbt_inputs, validate_default_sighashes, verify_vault_psbt_signatures,
    },
    types::VaultUtxo,
};
use anyhow::{Context, Result, bail};
use bitcoin::{
    Address, Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    absolute, transaction::Version,
};
use chrono::{DateTime, Utc};
use miniscript::psbt::PsbtExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
    str::FromStr,
};

pub const DEFAULT_BATCH_DIR: &str = "ceremony/active";
pub const SCHEDULE_FILE: &str = "phone/schedule.json";
pub const POLICY_PACKAGE_KIND: &str = "vault-policy";
/// Version 6 replaced the presigned allowance chain with the allowance ladder.
pub const MANIFEST_VERSION: u8 = 6;
/// Subdirectory of a ceremony that holds its presigned next-epoch renewal.
pub const NEXT_BATCH_DIR: &str = "next";

/// The emergency trigger pays only vault and connector outputs, so it carries a small
/// pay-to-anchor output (spendable by anyone, no signature) that the phone spends in a child
/// transaction to raise the fee at broadcast time. 240 sats is the P2A dust threshold.
pub const ANCHOR_VALUE_SATS: u64 = 240;
pub const TRIGGER_ANCHOR_VALUE_SATS: u64 = ANCHOR_VALUE_SATS;
pub const TRIGGER_ANCHOR_VOUT: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyLimits {
    pub monthly_limit_sats: u64,
    pub emergency_access_limit_sats: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchTransaction {
    pub psbt_file: String,
    pub unsigned_txid: String,
    pub fee_sats: u64,
    pub vault_input_indexes: Vec<u32>,
    pub controller_input_indexes: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorState {
    pub outpoint: OutPoint,
    pub value_sats: u64,
}

/// One month of the allowance ladder: a rollover output the phone alone may spend after
/// `unlock`, and the HWW alone at any time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LadderRung {
    pub step: u8,
    pub unlock: u32,
    pub vout: u32,
    pub value_sats: u64,
    pub descriptor: String,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyAccessPolicy {
    pub amount_sats: u64,
    pub delay_seconds: u32,
    pub delay_sequence: u32,
    pub hot_address: String,
    pub staging_vout: u32,
    pub staging_value_sats: u64,
    pub vault_change_vout: u32,
    pub vault_change_value_sats: u64,
    pub trigger_connector: ConnectorState,
    pub withdrawal_connector: ConnectorState,
    pub trigger: BatchTransaction,
    pub withdrawal: BatchTransaction,
}

/// Ties a presigned renewal to the epoch it renews: its rollover spends that epoch's cold
/// remainder, and only after a relative delay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewalLink {
    pub parent_rollover_txid: String,
    pub outpoint: OutPoint,
    pub value_sats: u64,
    pub delay_seconds: u32,
    pub delay_sequence: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchManifest {
    pub version: u8,
    pub created_at: i64,
    pub network: String,
    pub vault_descriptor: String,
    pub vault_address: String,
    pub controller_descriptor: String,
    pub controller_address: String,
    pub connector_value_sats: u64,
    #[serde(alias = "hard_limit_sats")]
    pub monthly_limit_sats: u64,
    #[serde(default)]
    pub emergency_access_limit_sats: u64,
    pub fee_rate_sat_vb: u64,
    pub total_input_sats: u64,
    pub vault_input_sats: u64,
    pub controller_input_sats: u64,
    pub allowance_count: usize,
    /// Month `n` of the ladder unlocks `n` allowance delays after this Unix time.
    pub ladder_start: i64,
    pub rollover: BatchTransaction,
    /// Total value of the ladder's months.
    pub allowance_value_sats: u64,
    pub remainder_vout: u32,
    pub remainder_value_sats: u64,
    pub emergency_connector_vout: Option<u32>,
    pub rungs: Vec<LadderRung>,
    #[serde(default)]
    pub emergency_access: Option<EmergencyAccessPolicy>,
    pub phone_approved: bool,
    pub hww_approved: bool,
    /// Set when this epoch is a presigned renewal of an earlier one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renews: Option<RenewalLink>,
    /// A presigned renewal's rollover carries a pay-to-anchor output so the phone can bump it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollover_anchor_vout: Option<u32>,
    /// Whether this ceremony also holds the next epoch's renewal in `NEXT_BATCH_DIR`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub has_presigned_renewal: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EmergencyTransactionKind {
    Trigger,
    Withdrawal,
    Cancellation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEmergencyTransaction {
    pub version: u8,
    pub kind: EmergencyTransactionKind,
    pub txid: String,
    pub encrypted_psbt: EncryptedBlob,
}

/// A month of the active ladder, as the phone tracks it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleEntry {
    pub step: u8,
    pub unlock: u32,
    pub outpoint: OutPoint,
    pub value_sats: u64,
    pub descriptor: String,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyAccessSchedule {
    pub amount_sats: u64,
    pub delay_seconds: u32,
    pub hot_address: String,
    pub trigger_file: String,
    pub trigger_txid: String,
    pub withdrawal_file: String,
    pub withdrawal_txid: String,
    pub trigger_connector: ConnectorState,
    pub withdrawal_connector: ConnectorState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schedule {
    pub version: u8,
    pub rollover_txid: String,
    pub controller_descriptor: String,
    pub controller_address: String,
    pub connector_value_sats: u64,
    pub monthly_limit_sats: u64,
    #[serde(default)]
    pub emergency_access_limit_sats: u64,
    pub entries: Vec<ScheduleEntry>,
    #[serde(default)]
    pub emergency_access: Option<EmergencyAccessSchedule>,
    /// After a presigned renewal, the previous epoch's months. The renewal does not touch them,
    /// so any unclaimed months stay claimable alongside the new epoch's.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub previous_entries: Vec<ScheduleEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPackage {
    pub version: u8,
    pub kind: String,
    pub manifest: BatchManifest,
    pub psbts: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<Box<PolicyPackage>>,
}

/// Supplies fresh phone receive addresses without coupling the protocol rules to a wallet SDK.
pub trait HotAddressProvider {
    fn next_receive_address(&mut self) -> Result<Address>;
}

pub fn default_batch_path(data_dir: &Path) -> PathBuf {
    data_dir.join(DEFAULT_BATCH_DIR)
}

pub fn package_from_batch(batch_dir: &Path) -> Result<PolicyPackage> {
    let manifest = load_manifest(batch_dir)?;
    let mut psbts = BTreeMap::new();
    for transaction in manifest_transactions(&manifest) {
        let text = fs::read_to_string(batch_dir.join(&transaction.psbt_file))
            .with_context(|| format!("failed to read packaged PSBT {}", transaction.psbt_file))?;
        psbts.insert(transaction.psbt_file.clone(), text.trim().to_owned());
    }
    let next = if manifest.has_presigned_renewal {
        Some(Box::new(package_from_batch(
            &batch_dir.join(NEXT_BATCH_DIR),
        )?))
    } else {
        None
    };
    Ok(PolicyPackage {
        version: MANIFEST_VERSION,
        kind: POLICY_PACKAGE_KIND.to_owned(),
        manifest,
        psbts,
        next,
    })
}

pub fn is_supported_policy_package(package: &PolicyPackage) -> bool {
    package.version == MANIFEST_VERSION && package.kind == POLICY_PACKAGE_KIND
}

pub fn materialize_policy_package(package: &PolicyPackage, batch_dir: &Path) -> Result<()> {
    if !is_supported_policy_package(package) {
        bail!("unsupported policy package");
    }
    if batch_dir.exists() && batch_dir.read_dir()?.next().is_some() {
        bail!("policy workspace {} is not empty", batch_dir.display());
    }
    let expected = manifest_transactions(&package.manifest)
        .into_iter()
        .map(|transaction| transaction.psbt_file.clone())
        .collect::<BTreeSet<_>>();
    let actual = package.psbts.keys().cloned().collect::<BTreeSet<_>>();
    if actual != expected {
        bail!("policy package PSBT set does not match its manifest");
    }
    fs::create_dir_all(batch_dir)?;
    write_json(&batch_dir.join("manifest.json"), &package.manifest)?;
    for (relative, psbt) in &package.psbts {
        let relative_path = Path::new(relative);
        if relative_path.is_absolute()
            || relative_path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            bail!("policy package contains an unsafe PSBT path");
        }
        write_private(
            &batch_dir.join(relative_path),
            format!("{psbt}\n").as_bytes(),
        )?;
    }
    match (&package.next, package.manifest.has_presigned_renewal) {
        (Some(next), true) => materialize_policy_package(next, &batch_dir.join(NEXT_BATCH_DIR)),
        (None, false) => Ok(()),
        _ => bail!("policy package renewal does not match its manifest"),
    }
}

pub fn build_policy_proposal(
    config: &VaultConfig,
    utxos: &[VaultUtxo],
    now: DateTime<Utc>,
    limits: PolicyLimits,
    batch_dir: &Path,
    phone: &DeviceKeys,
    hot: &mut impl HotAddressProvider,
) -> Result<BatchManifest> {
    build_policy_proposal_with_connectors(config, utxos, &[], now, limits, batch_dir, phone, hot)
}

#[allow(clippy::too_many_arguments)]
pub fn build_policy_proposal_with_connectors(
    config: &VaultConfig,
    vault_utxos: &[VaultUtxo],
    controller_utxos: &[VaultUtxo],
    now: DateTime<Utc>,
    limits: PolicyLimits,
    batch_dir: &Path,
    phone: &DeviceKeys,
    hot: &mut impl HotAddressProvider,
) -> Result<BatchManifest> {
    build_epoch(
        config,
        vault_utxos,
        controller_utxos,
        None,
        now,
        now.timestamp(),
        limits,
        batch_dir,
        phone,
        hot,
    )
}

/// Build this epoch's ceremony and, when `presigned_years` is 2, the next epoch's renewal in
/// `NEXT_BATCH_DIR`. The renewal's rollover spends this epoch's cold remainder after
/// `PRESIGNED_RENEWAL_DELAY_SECONDS`, so one HWW ceremony covers two years.
///
/// Month 1 unlocks one month after `ladder_start`, which is `now` unless months from an earlier
/// ceremony are still waiting; then the new months follow them instead of doubling up.
#[allow(clippy::too_many_arguments)]
pub fn build_policy_proposal_with_renewal(
    config: &VaultConfig,
    vault_utxos: &[VaultUtxo],
    controller_utxos: &[VaultUtxo],
    now: DateTime<Utc>,
    ladder_start: i64,
    limits: PolicyLimits,
    presigned_years: u8,
    batch_dir: &Path,
    phone: &DeviceKeys,
    hot: &mut impl HotAddressProvider,
) -> Result<BatchManifest> {
    if !(1..=2).contains(&presigned_years) {
        bail!("a ceremony can presign one or two years");
    }
    if ladder_start < now.timestamp() {
        bail!("allowance months cannot start before the ceremony");
    }
    let mut manifest = build_epoch(
        config,
        vault_utxos,
        controller_utxos,
        None,
        now,
        ladder_start,
        limits,
        batch_dir,
        phone,
        hot,
    )?;
    if presigned_years == 1 {
        return Ok(manifest);
    }
    let link = renewal_link(&manifest)?;
    let remainder = VaultUtxo {
        outpoint: link.outpoint,
        txout: TxOut {
            value: Amount::from_sat(link.value_sats),
            script_pubkey: Address::from_str(&config.vault_address)?
                .require_network(config.bitcoin_network()?)?
                .script_pubkey(),
        },
        confirmation_height: 0,
    };
    build_epoch(
        config,
        &[remainder],
        &[],
        Some(&link),
        now,
        renewal_ladder_start(&manifest),
        limits,
        &batch_dir.join(NEXT_BATCH_DIR),
        phone,
        hot,
    )
    .context("the vault balance cannot fund a presigned second year; presign one year instead")?;
    manifest.has_presigned_renewal = true;
    write_json(&batch_dir.join("manifest.json"), &manifest)?;
    Ok(manifest)
}

/// The renewal that the epoch described by `parent` must be followed by.
fn renewal_link(parent: &BatchManifest) -> Result<RenewalLink> {
    Ok(RenewalLink {
        parent_rollover_txid: parent.rollover.unsigned_txid.clone(),
        outpoint: OutPoint::new(
            parent.rollover.unsigned_txid.parse()?,
            parent.remainder_vout,
        ),
        value_sats: parent.remainder_value_sats,
        delay_seconds: PRESIGNED_RENEWAL_DELAY_SECONDS,
        delay_sequence: renewal_delay_sequence()?.to_consensus_u32(),
    })
}

#[allow(clippy::too_many_arguments)]
fn build_epoch(
    config: &VaultConfig,
    vault_utxos: &[VaultUtxo],
    controller_utxos: &[VaultUtxo],
    renewal: Option<&RenewalLink>,
    now: DateTime<Utc>,
    ladder_start: i64,
    limits: PolicyLimits,
    batch_dir: &Path,
    phone: &DeviceKeys,
    hot: &mut impl HotAddressProvider,
) -> Result<BatchManifest> {
    let PolicyLimits {
        monthly_limit_sats,
        emergency_access_limit_sats,
    } = limits;
    if vault_utxos.is_empty() {
        bail!("vault has no confirmed UTXOs to roll over");
    }
    if batch_dir.exists() && batch_dir.read_dir()?.next().is_some() {
        bail!("ceremony directory {} is not empty", batch_dir.display());
    }
    fs::create_dir_all(batch_dir)?;

    if phone.vault_pubkey.to_string() != config.phone_vault_pubkey {
        bail!("phone key does not match the configured vault policy");
    }
    let policy = VaultPolicy::from_descriptor_for_network(
        &config.vault_descriptor,
        config.bitcoin_network()?,
    )?;
    let controller = controller_policy(config)?;
    let vault_script = policy.address.script_pubkey();
    let controller_script = controller.address.script_pubkey();
    if vault_utxos
        .iter()
        .any(|utxo| utxo.txout.script_pubkey != vault_script)
    {
        bail!("policy proposal contains an input outside the configured vault script");
    }
    if controller_utxos
        .iter()
        .any(|utxo| utxo.txout.script_pubkey != controller_script)
    {
        bail!("policy proposal contains an input outside the fixed controller script");
    }
    let vault_input_sats = checked_input_sum(vault_utxos)?;
    let controller_input_sats = checked_input_sum(controller_utxos)?;
    let total_input_sats = vault_input_sats
        .checked_add(controller_input_sats)
        .context("policy input total overflowed")?;
    let has_anchor = renewal.is_some();
    let anchor_sats = if has_anchor { ANCHOR_VALUE_SATS } else { 0 };
    let vault_sequence = renewal.map_or(Sequence::MAX, |link| {
        Sequence::from_consensus(link.delay_sequence)
    });
    let mut input_template = vault_utxos
        .iter()
        .map(|utxo| vault_input(utxo.outpoint, vault_sequence))
        .collect::<Vec<_>>();
    input_template.extend(
        controller_utxos
            .iter()
            .map(|utxo| vault_input(utxo.outpoint, Sequence::ENABLE_RBF_NO_LOCKTIME)),
    );
    let vault_input_indexes = (0..vault_utxos.len()).collect::<Vec<_>>();
    let controller_input_indexes =
        (vault_utxos.len()..vault_utxos.len() + controller_utxos.len()).collect::<Vec<_>>();

    let emergency_hot_address = (emergency_access_limit_sats > 0)
        .then(|| hot.next_receive_address())
        .transpose()?;
    let emergency_delay_sequence = emergency_delay_sequence()?;
    let emergency_staging_value_sats = match &emergency_hot_address {
        Some(address) => {
            if emergency_access_limit_sats < address.script_pubkey().minimal_non_dust().to_sat() {
                bail!("emergency access amount would create a dust hot-wallet output");
            }
            let withdrawal_fee = emergency_withdrawal_fee(
                &policy,
                &controller,
                OutPoint::null(),
                emergency_access_limit_sats,
                emergency_delay_sequence,
                address.script_pubkey(),
            )?;
            emergency_access_limit_sats
                .checked_add(withdrawal_fee)
                .and_then(|value| value.checked_sub(CONNECTOR_VALUE_SATS))
                .context("emergency access amount plus withdrawal fee overflowed")?
        }
        None => 0,
    };
    let minimum_remainder_value = if emergency_access_limit_sats == 0 {
        vault_script.minimal_non_dust().to_sat()
    } else {
        let minimum_vault_change = vault_script.minimal_non_dust().to_sat();
        let trigger_fee = emergency_trigger_fee(
            &policy,
            &controller,
            OutPoint::null(),
            emergency_staging_value_sats,
            minimum_vault_change,
            vault_script.clone(),
        )?;
        emergency_staging_value_sats
            .checked_add(trigger_fee)
            .and_then(|value| value.checked_add(TRIGGER_ANCHOR_VALUE_SATS))
            .and_then(|value| value.checked_add(minimum_vault_change))
            .context("emergency access reserve overflowed")?
    };

    if monthly_limit_sats > 0 && monthly_limit_sats < vault_script.minimal_non_dust().to_sat() {
        bail!("monthly limit would create a dust allowance month");
    }
    let rung_policies = (1..=MONTHS_PER_ROLLOVER)
        .map(|step| rung_policy(config, rung_unlock(ladder_start, step)?))
        .collect::<Result<Vec<_>>>()?;

    // The rollover creates one output per funded month (the ladder), then the cold remainder.
    // Fund as many months as the balance allows, latest months dropped first.
    let connector_outputs = usize::from(emergency_access_limit_sats > 0);
    let mut selected = None;
    let max_count = if monthly_limit_sats > 0 {
        MONTHS_PER_ROLLOVER
    } else {
        0
    };
    for count in (0..=max_count).rev() {
        let template = rollover_template(
            input_template.clone(),
            &rung_policies[..count],
            monthly_limit_sats,
            1,
            vault_script.clone(),
            controller_script.clone(),
            emergency_access_limit_sats > 0,
            has_anchor,
        );
        let fee = estimate_policy_vsize(
            &template,
            &policy,
            SpendPath::Cooperative,
            &vault_input_indexes,
            &controller,
            ControllerPath::Phone,
            &controller_input_indexes,
        )? * DEFAULT_FEE_RATE_SAT_VB;
        let ladder_value = monthly_limit_sats
            .checked_mul(count as u64)
            .context("allowance ladder value overflowed")?;
        let spent = fee
            .checked_add(ladder_value)
            .and_then(|value| value.checked_add(CONNECTOR_VALUE_SATS * connector_outputs as u64))
            .and_then(|value| value.checked_add(anchor_sats))
            .context("allowance rollover requirement overflowed")?;
        if let Some(remainder) = total_input_sats
            .checked_sub(spent)
            .filter(|remainder| *remainder >= minimum_remainder_value)
        {
            selected = Some((count, ladder_value, fee, remainder));
            break;
        }
    }
    let (allowance_count, allowance_value_sats, rollover_fee, remainder_value_sats) = match selected
    {
        Some(selected) => selected,
        None if emergency_access_limit_sats > 0 => {
            bail!("vault balance cannot fund the configured emergency access amount and fees")
        }
        None => bail!("vault balance cannot create a non-dust rollover remainder"),
    };

    let rollover_tx = rollover_template(
        input_template,
        &rung_policies[..allowance_count],
        monthly_limit_sats,
        remainder_value_sats,
        vault_script.clone(),
        controller_script.clone(),
        emergency_access_limit_sats > 0,
        has_anchor,
    );
    let rollover_txid = rollover_tx.compute_txid();
    let mut prevouts = vault_utxos
        .iter()
        .map(|utxo| utxo.txout.clone())
        .collect::<Vec<_>>();
    prevouts.extend(controller_utxos.iter().map(|utxo| utxo.txout.clone()));
    let mut rollover_psbt = create_policy_psbt(
        rollover_tx.clone(),
        &prevouts,
        &vault_input_indexes,
        &controller_input_indexes,
        &policy,
        &controller,
    )?;
    sign_vault_psbt_inputs(
        &mut rollover_psbt,
        &policy,
        SpendPath::Cooperative,
        &phone.vault_keypair,
        &vault_input_indexes,
    )?;
    sign_controller_psbt_inputs(
        &mut rollover_psbt,
        &controller,
        ControllerPath::Phone,
        &phone.vault_keypair.cooperative,
        &controller_input_indexes,
    )?;
    let rollover_file = "rollover.psbt".to_owned();
    write_psbt(&batch_dir.join(&rollover_file), &rollover_psbt)?;

    let remainder_vout = u32::try_from(allowance_count)?;
    let emergency_connector_vout = (emergency_access_limit_sats > 0).then_some(remainder_vout + 1);
    let rungs = rung_policies[..allowance_count]
        .iter()
        .enumerate()
        .map(|(index, rung)| {
            Ok(LadderRung {
                step: u8::try_from(index + 1)?,
                unlock: rung.unlock,
                vout: u32::try_from(index)?,
                value_sats: monthly_limit_sats,
                descriptor: rung.descriptor_string(),
                address: rung.address.to_string(),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let emergency_access = match emergency_hot_address {
        Some(hot_address) => {
            let source_outpoint = OutPoint::new(rollover_txid, remainder_vout);
            let source_txout = rollover_tx.output[remainder_vout as usize].clone();
            Some(build_emergency_access(
                &policy,
                &controller,
                source_outpoint,
                &source_txout,
                ConnectorState {
                    outpoint: OutPoint::new(
                        rollover_txid,
                        emergency_connector_vout.context("emergency connector vout is missing")?,
                    ),
                    value_sats: CONNECTOR_VALUE_SATS,
                },
                emergency_access_limit_sats,
                emergency_delay_sequence,
                &hot_address,
                vault_script.clone(),
                batch_dir,
                phone,
            )?)
        }
        None => None,
    };

    let manifest = BatchManifest {
        version: MANIFEST_VERSION,
        created_at: now.timestamp(),
        network: config.network.clone(),
        vault_descriptor: config.vault_descriptor.clone(),
        vault_address: config.vault_address.clone(),
        controller_descriptor: controller.descriptor_string(),
        controller_address: controller.address.to_string(),
        connector_value_sats: CONNECTOR_VALUE_SATS,
        monthly_limit_sats,
        emergency_access_limit_sats,
        fee_rate_sat_vb: DEFAULT_FEE_RATE_SAT_VB,
        total_input_sats,
        vault_input_sats,
        controller_input_sats,
        allowance_count,
        ladder_start,
        rollover: BatchTransaction {
            psbt_file: rollover_file,
            unsigned_txid: rollover_txid.to_string(),
            fee_sats: rollover_fee,
            vault_input_indexes: vault_input_indexes
                .iter()
                .map(|index| *index as u32)
                .collect(),
            controller_input_indexes: controller_input_indexes
                .iter()
                .map(|index| *index as u32)
                .collect(),
        },
        allowance_value_sats,
        remainder_vout,
        remainder_value_sats,
        emergency_connector_vout,
        rungs,
        emergency_access,
        phone_approved: true,
        hww_approved: false,
        renews: renewal.cloned(),
        rollover_anchor_vout: has_anchor
            .then(|| u32::try_from(rollover_tx.output.len() - 1))
            .transpose()?,
        has_presigned_renewal: false,
    };
    write_json(&batch_dir.join("manifest.json"), &manifest)?;
    Ok(manifest)
}

pub fn load_manifest(batch_dir: &Path) -> Result<BatchManifest> {
    read_json(&batch_dir.join("manifest.json"))
}

/// Verify the complete returned ceremony before the phone funds it. Finalize individual vault
/// inputs on a temporary copy: this checks signatures and satisfaction metadata without creating
/// any of the controller signatures that must remain deferred until a user executes an action.
pub fn validate_approved_batch(
    config: &VaultConfig,
    manifest: &BatchManifest,
    batch_dir: &Path,
) -> Result<VaultPolicy> {
    if !manifest.phone_approved || !manifest.hww_approved {
        bail!("both phone and HWW approval are required before finalization");
    }
    let policy = validate_batch(config, manifest, batch_dir)?;
    let phone_pubkey = config.phone_vault_pubkey.parse()?;
    let hww_pubkey = config.hww_vault_pubkey.parse()?;
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    for transaction in manifest_transactions(manifest) {
        let mut psbt = read_psbt(&batch_dir.join(&transaction.psbt_file))?;
        let indexes = transaction_indexes(&transaction.vault_input_indexes)?;
        for pubkey in [phone_pubkey, hww_pubkey] {
            verify_vault_psbt_signatures(&psbt, &policy, SpendPath::Cooperative, pubkey, &indexes)
                .with_context(|| {
                    format!("invalid vault signatures in {}", transaction.psbt_file)
                })?;
        }
        for index in indexes {
            psbt.finalize_inp_mut(&secp, index).with_context(|| {
                format!(
                    "vault input {index} cannot finalize in {}",
                    transaction.psbt_file
                )
            })?;
        }
        if transaction.psbt_file == manifest.rollover.psbt_file {
            for index in transaction_indexes(&transaction.controller_input_indexes)? {
                psbt.finalize_inp_mut(&secp, index)
                    .context("rollover controller input cannot finalize")?;
            }
        }
    }
    if let Some(next) = load_presigned_renewal(manifest, batch_dir)? {
        validate_approved_batch(config, &next, &batch_dir.join(NEXT_BATCH_DIR))?;
    }
    Ok(policy)
}

pub fn validate_batch(
    config: &VaultConfig,
    manifest: &BatchManifest,
    batch_dir: &Path,
) -> Result<VaultPolicy> {
    if manifest.version != MANIFEST_VERSION || manifest.network != config.network {
        bail!("unsupported ceremony manifest or network mismatch");
    }
    for transaction in manifest_transactions(manifest) {
        validate_default_sighashes(&read_psbt(&batch_dir.join(&transaction.psbt_file))?)?;
    }
    if manifest.vault_descriptor != config.vault_descriptor
        || manifest.vault_address != config.vault_address
    {
        bail!("ceremony policy does not match configured vault policy");
    }
    if manifest.fee_rate_sat_vb != DEFAULT_FEE_RATE_SAT_VB {
        bail!("MVP ceremony must use the fixed 1 sat/vB fee rate");
    }
    if (manifest.monthly_limit_sats == 0 && manifest.allowance_count != 0)
        || manifest.allowance_count > MONTHS_PER_ROLLOVER
        || manifest.rungs.len() != manifest.allowance_count
    {
        bail!("invalid ceremony allowance count");
    }

    let policy = VaultPolicy::from_descriptor_for_network(
        &config.vault_descriptor,
        config.bitcoin_network()?,
    )?;
    let controller = controller_policy(config)?;
    if manifest.controller_descriptor != controller.descriptor_string()
        || manifest.controller_address != controller.address.to_string()
        || manifest.connector_value_sats != CONNECTOR_VALUE_SATS
    {
        bail!("ceremony controller does not match the fixed vault-key controller policy");
    }
    let vault_script = policy.address.script_pubkey();
    let controller_script = controller.address.script_pubkey();

    let rollover = read_psbt(&batch_dir.join(&manifest.rollover.psbt_file))?;
    let rollover_tx = &rollover.unsigned_tx;
    let vault_indexes = transaction_indexes(&manifest.rollover.vault_input_indexes)?;
    let controller_indexes = transaction_indexes(&manifest.rollover.controller_input_indexes)?;
    validate_input_partition(rollover_tx.input.len(), &vault_indexes, &controller_indexes)?;
    let expected_vault_sequence = match &manifest.renews {
        Some(link) => {
            let expected_delay = renewal_delay_sequence()?;
            if link.delay_seconds != PRESIGNED_RENEWAL_DELAY_SECONDS
                || link.delay_sequence != expected_delay.to_consensus_u32()
                || vault_indexes.len() != 1
                || !controller_indexes.is_empty()
                || rollover_tx.input[vault_indexes[0]].previous_output != link.outpoint
                || manifest.vault_input_sats != link.value_sats
            {
                bail!("presigned renewal does not spend the renewed epoch's remainder");
            }
            expected_delay
        }
        None => Sequence::MAX,
    };
    let has_anchor = manifest.renews.is_some();
    let expected_output_count = manifest.allowance_count
        + 1
        + usize::from(manifest.emergency_access_limit_sats > 0)
        + usize::from(has_anchor);
    let expected_anchor_vout = has_anchor
        .then(|| u32::try_from(expected_output_count - 1))
        .transpose()?;
    if manifest.rollover_anchor_vout != expected_anchor_vout {
        bail!("rollover anchor does not match the approved policy");
    }
    if let Some(vout) = expected_anchor_vout {
        let anchor = rollover_tx
            .output
            .get(vout as usize)
            .context("rollover anchor vout is out of range")?;
        if anchor.script_pubkey != ScriptBuf::new_p2a()
            || anchor.value.to_sat() != ANCHOR_VALUE_SATS
        {
            bail!("rollover anchor output does not match the approved policy");
        }
    }
    if rollover_tx.compute_txid().to_string() != manifest.rollover.unsigned_txid
        || rollover_tx.version != Version::TWO
        || rollover_tx.lock_time != absolute::LockTime::ZERO
        || rollover_tx.input.is_empty()
        || rollover_tx.input.len() != rollover.inputs.len()
        || rollover_tx.output.len() != expected_output_count
        || vault_indexes
            .iter()
            .any(|index| rollover_tx.input[*index].sequence != expected_vault_sequence)
        || controller_indexes
            .iter()
            .any(|index| rollover_tx.input[*index].sequence != Sequence::ENABLE_RBF_NO_LOCKTIME)
    {
        bail!("rollover PSBT does not match its manifest");
    }
    let calculated_vault_inputs =
        psbt_role_input_sum(&rollover, &vault_indexes, &vault_script, "rollover vault")?;
    let calculated_controller_inputs = psbt_role_input_sum(
        &rollover,
        &controller_indexes,
        &controller_script,
        "rollover controller",
    )?;
    let calculated_total = calculated_vault_inputs
        .checked_add(calculated_controller_inputs)
        .context("rollover input total overflowed")?;
    let fee = calculated_total
        .checked_sub(output_sum(rollover_tx)?)
        .context("rollover outputs exceed inputs")?;
    if calculated_vault_inputs != manifest.vault_input_sats
        || calculated_controller_inputs != manifest.controller_input_sats
        || calculated_total != manifest.total_input_sats
        || fee != manifest.rollover.fee_sats
    {
        bail!("rollover amount or fee does not match its manifest");
    }
    let expected_rollover_fee = estimate_policy_vsize(
        rollover_tx,
        &policy,
        SpendPath::Cooperative,
        &vault_indexes,
        &controller,
        ControllerPath::Phone,
        &controller_indexes,
    )? * DEFAULT_FEE_RATE_SAT_VB;
    if manifest.rollover.fee_sats != expected_rollover_fee {
        bail!("rollover does not pay the approved fixed fee rate");
    }

    let expected_remainder_vout = u32::try_from(manifest.allowance_count)?;
    let expected_emergency_connector_vout =
        (manifest.emergency_access_limit_sats > 0).then_some(expected_remainder_vout + 1);
    if manifest.remainder_vout != expected_remainder_vout
        || manifest.emergency_connector_vout != expected_emergency_connector_vout
        || manifest.allowance_value_sats
            != manifest
                .monthly_limit_sats
                .checked_mul(manifest.allowance_count as u64)
                .context("allowance ladder value overflowed")?
    {
        bail!("rollover output indexes do not match the approved policy");
    }
    let remainder = &rollover_tx.output[manifest.remainder_vout as usize];
    if remainder.script_pubkey != vault_script
        || remainder.value.to_sat() != manifest.remainder_value_sats
        || remainder.value.to_sat() < vault_script.minimal_non_dust().to_sat()
    {
        bail!("rollover remainder does not match its manifest");
    }
    if let Some(vout) = manifest.emergency_connector_vout {
        validate_connector_output(
            rollover_tx
                .output
                .get(vout as usize)
                .context("rollover connector vout is out of range")?,
            &controller_script,
        )?;
    }
    validate_ladder(config, manifest, rollover_tx)?;
    validate_connector_emergency(config, manifest, batch_dir, &policy, &controller, &rollover)?;
    if let Some(next) = load_presigned_renewal(manifest, batch_dir)? {
        validate_batch(config, &next, &batch_dir.join(NEXT_BATCH_DIR))?;
    }
    Ok(policy)
}

/// Load the presigned renewal a ceremony carries and check that it renews exactly this epoch
/// with the same limits. Renewals are one level deep: a renewal never carries its own.
pub fn load_presigned_renewal(
    manifest: &BatchManifest,
    batch_dir: &Path,
) -> Result<Option<BatchManifest>> {
    if !manifest.has_presigned_renewal {
        return Ok(None);
    }
    if manifest.renews.is_some() {
        bail!("a presigned renewal cannot carry another renewal");
    }
    let next = load_manifest(&batch_dir.join(NEXT_BATCH_DIR))?;
    if next.renews.as_ref() != Some(&renewal_link(manifest)?)
        || next.has_presigned_renewal
        || next.network != manifest.network
        || next.monthly_limit_sats != manifest.monthly_limit_sats
        || next.ladder_start != renewal_ladder_start(manifest)
        || next.emergency_access_limit_sats != manifest.emergency_access_limit_sats
        || next.phone_approved != manifest.phone_approved
        || next.hww_approved != manifest.hww_approved
    {
        bail!("presigned renewal does not match the epoch it renews");
    }
    Ok(Some(next))
}

/// Every month of the ladder must pay exactly the monthly limit to the rung policy of the
/// configured keys, unlocking on schedule. The HWW checks this before signing the rollover.
fn validate_ladder(
    config: &VaultConfig,
    manifest: &BatchManifest,
    rollover_tx: &Transaction,
) -> Result<()> {
    for (index, rung) in manifest.rungs.iter().enumerate() {
        let step = u8::try_from(index + 1).context("allowance month exceeds u8")?;
        let policy = rung_policy(config, rung_unlock(manifest.ladder_start, step.into())?)?;
        let output = rollover_tx
            .output
            .get(index)
            .with_context(|| format!("rollover has no output for month {step}"))?;
        if rung.step != step
            || rung.unlock != policy.unlock
            || rung.vout != u32::try_from(index)?
            || rung.value_sats != manifest.monthly_limit_sats
            || rung.descriptor != policy.descriptor_string()
            || rung.address != policy.address.to_string()
            || output.script_pubkey != policy.address.script_pubkey()
            || output.value.to_sat() != manifest.monthly_limit_sats
        {
            bail!("allowance month {step} violates the approved policy");
        }
    }
    Ok(())
}

/// The policy of the allowance month that unlocks at `unlock`, for this vault's keys.
pub fn rung_policy(config: &VaultConfig, unlock: u32) -> Result<RungPolicy> {
    RungPolicy::new_for_network(
        VaultKey::from_str(&config.phone_vault_pubkey).context("invalid phone vault key")?,
        VaultKey::from_str(&config.hww_vault_pubkey).context("invalid HWW vault key")?,
        unlock,
        config.internal_key,
        config.bitcoin_network()?,
    )
}

/// When month `step` of a ladder that starts at `ladder_start` unlocks.
pub fn rung_unlock(ladder_start: i64, step: usize) -> Result<u32> {
    let offset = i64::from(MONTHLY_ALLOWANCE_DELAY_SECONDS)
        .checked_mul(i64::try_from(step)?)
        .context("allowance month offset overflowed")?;
    u32::try_from(ladder_start + offset).context("allowance month unlocks outside Unix time")
}

/// A presigned renewal's ladder continues where the renewed epoch's ends.
fn renewal_ladder_start(parent: &BatchManifest) -> i64 {
    parent.ladder_start + i64::from(PRESIGNED_RENEWAL_DELAY_SECONDS)
}

fn validate_connector_emergency(
    config: &VaultConfig,
    manifest: &BatchManifest,
    batch_dir: &Path,
    policy: &VaultPolicy,
    controller: &ControllerPolicy,
    rollover: &Psbt,
) -> Result<()> {
    let emergency = match (
        manifest.emergency_access_limit_sats,
        &manifest.emergency_access,
    ) {
        (0, None) => return Ok(()),
        (0, Some(_)) => bail!("disabled emergency access contains presigned transactions"),
        (_, None) => bail!("configured emergency access is missing its presigned transactions"),
        (_, Some(emergency)) => emergency,
    };
    let expected_delay = emergency_delay_sequence()?;
    if emergency.amount_sats != manifest.emergency_access_limit_sats
        || emergency.delay_seconds != EMERGENCY_ACCESS_DELAY_SECONDS
        || emergency.delay_sequence != expected_delay.to_consensus_u32()
        || emergency.staging_vout != 0
        || emergency.vault_change_vout != 1
    {
        bail!("emergency access metadata violates the approved policy");
    }
    let hot_script = Address::from_str(&emergency.hot_address)?
        .require_network(config.bitcoin_network()?)?
        .script_pubkey();
    let vault_script = policy.address.script_pubkey();
    let controller_script = controller.address.script_pubkey();
    let source_outpoint =
        OutPoint::new(rollover.unsigned_tx.compute_txid(), manifest.remainder_vout);
    let source_prevout = &rollover.unsigned_tx.output[manifest.remainder_vout as usize];
    let trigger_connector = ConnectorState {
        outpoint: OutPoint::new(
            rollover.unsigned_tx.compute_txid(),
            manifest
                .emergency_connector_vout
                .context("emergency connector output is missing")?,
        ),
        value_sats: CONNECTOR_VALUE_SATS,
    };
    if emergency.trigger_connector != trigger_connector {
        bail!("emergency trigger connector metadata violates the approved policy");
    }
    let trigger = read_psbt(&batch_dir.join(&emergency.trigger.psbt_file))?;
    validate_connector_child(
        &trigger,
        source_prevout,
        source_outpoint,
        trigger_connector.outpoint,
        &controller_script,
        &emergency.trigger,
    )?;
    let trigger_tx = &trigger.unsigned_tx;
    if trigger_tx.version != Version::TWO
        || trigger_tx.lock_time != absolute::LockTime::ZERO
        || trigger_tx.input[0].sequence != Sequence::MAX
        || trigger_tx.input[1].sequence != Sequence::ENABLE_RBF_NO_LOCKTIME
        || trigger_tx.output.len() != 4
        || trigger_tx.output[0].script_pubkey != vault_script
        || trigger_tx.output[0].value.to_sat() != emergency.staging_value_sats
        || trigger_tx.output[1].script_pubkey != vault_script
        || trigger_tx.output[1].value.to_sat() != emergency.vault_change_value_sats
        || emergency.vault_change_value_sats < vault_script.minimal_non_dust().to_sat()
    {
        bail!("emergency access trigger violates the approved policy");
    }
    validate_connector_output(&trigger_tx.output[2], &controller_script)?;
    if trigger_tx.output[TRIGGER_ANCHOR_VOUT]
        != (TxOut {
            value: Amount::from_sat(TRIGGER_ANCHOR_VALUE_SATS),
            script_pubkey: ScriptBuf::new_p2a(),
        })
    {
        bail!("emergency access trigger lacks its fee-bump anchor");
    }
    let withdrawal_connector = ConnectorState {
        outpoint: OutPoint::new(trigger_tx.compute_txid(), 2),
        value_sats: CONNECTOR_VALUE_SATS,
    };
    if emergency.withdrawal_connector != withdrawal_connector {
        bail!("emergency withdrawal connector metadata violates the approved policy");
    }
    let trigger_fee = estimate_policy_vsize(
        trigger_tx,
        policy,
        SpendPath::Cooperative,
        &[0],
        controller,
        ControllerPath::Phone,
        &[1],
    )? * DEFAULT_FEE_RATE_SAT_VB;
    if emergency.trigger.fee_sats != trigger_fee {
        bail!("emergency trigger does not pay the approved fixed fee rate");
    }

    let staging_outpoint = OutPoint::new(trigger_tx.compute_txid(), emergency.staging_vout);
    let staging_prevout = &trigger_tx.output[emergency.staging_vout as usize];
    let withdrawal = read_psbt(&batch_dir.join(&emergency.withdrawal.psbt_file))?;
    validate_connector_child(
        &withdrawal,
        staging_prevout,
        staging_outpoint,
        withdrawal_connector.outpoint,
        &controller_script,
        &emergency.withdrawal,
    )?;
    let withdrawal_tx = &withdrawal.unsigned_tx;
    if withdrawal_tx.version != Version::TWO
        || withdrawal_tx.lock_time != absolute::LockTime::ZERO
        || withdrawal_tx.input[0].sequence != expected_delay
        || withdrawal_tx.input[1].sequence != Sequence::ENABLE_RBF_NO_LOCKTIME
        || withdrawal_tx.output.len() != 1
        || withdrawal_tx.output[0].script_pubkey != hot_script
        || withdrawal_tx.output[0].value.to_sat() != manifest.emergency_access_limit_sats
        || emergency
            .staging_value_sats
            .checked_add(CONNECTOR_VALUE_SATS)
            != manifest
                .emergency_access_limit_sats
                .checked_add(emergency.withdrawal.fee_sats)
    {
        bail!("emergency access withdrawal violates the approved policy");
    }
    let withdrawal_fee = estimate_policy_vsize(
        withdrawal_tx,
        policy,
        SpendPath::Cooperative,
        &[0],
        controller,
        ControllerPath::Phone,
        &[1],
    )? * DEFAULT_FEE_RATE_SAT_VB;
    if emergency.withdrawal.fee_sats != withdrawal_fee {
        bail!("emergency withdrawal does not pay the approved fixed fee rate");
    }
    Ok(())
}

fn validate_connector_child(
    psbt: &Psbt,
    vault_prevout: &TxOut,
    vault_outpoint: OutPoint,
    connector_outpoint: OutPoint,
    controller_script: &ScriptBuf,
    manifest_tx: &BatchTransaction,
) -> Result<()> {
    if manifest_tx.vault_input_indexes != [0]
        || manifest_tx.controller_input_indexes != [1]
        || psbt.unsigned_tx.compute_txid().to_string() != manifest_tx.unsigned_txid
        || psbt.unsigned_tx.input.len() != 2
        || psbt.inputs.len() != 2
        || psbt.unsigned_tx.input[0].previous_output != vault_outpoint
        || psbt.inputs[0].witness_utxo.as_ref() != Some(vault_prevout)
        || psbt.unsigned_tx.input[1].previous_output != connector_outpoint
        || !psbt.inputs[1].tap_script_sigs.is_empty()
    {
        bail!("policy PSBT does not spend its assigned vault and unsigned connector outputs");
    }
    let connector_prevout = psbt.inputs[1]
        .witness_utxo
        .as_ref()
        .context("policy connector input lacks witness UTXO")?;
    if connector_prevout.script_pubkey != *controller_script
        || connector_prevout.value.to_sat() != CONNECTOR_VALUE_SATS
    {
        bail!("policy PSBT connector input violates the fixed controller policy");
    }
    let input = vault_prevout
        .value
        .to_sat()
        .checked_add(CONNECTOR_VALUE_SATS)
        .context("policy transaction input sum overflowed")?;
    let fee = input
        .checked_sub(output_sum(&psbt.unsigned_tx)?)
        .context("policy transaction outputs exceed inputs")?;
    if fee != manifest_tx.fee_sats {
        bail!("policy transaction fee does not match its manifest");
    }
    Ok(())
}

fn validate_connector_output(output: &TxOut, controller_script: &ScriptBuf) -> Result<()> {
    if output.script_pubkey != *controller_script || output.value.to_sat() != CONNECTOR_VALUE_SATS {
        bail!("connector output violates the fixed controller script or value");
    }
    Ok(())
}

fn transaction_indexes(indexes: &[u32]) -> Result<Vec<usize>> {
    indexes
        .iter()
        .map(|index| usize::try_from(*index).context("policy input index exceeds usize"))
        .collect()
}

fn validate_input_partition(
    input_count: usize,
    vault_indexes: &[usize],
    controller_indexes: &[usize],
) -> Result<()> {
    let vault = vault_indexes.iter().copied().collect::<BTreeSet<_>>();
    let controller = controller_indexes.iter().copied().collect::<BTreeSet<_>>();
    if vault.len() != vault_indexes.len()
        || controller.len() != controller_indexes.len()
        || !vault.is_disjoint(&controller)
        || vault.len() + controller.len() != input_count
        || vault
            .iter()
            .chain(&controller)
            .any(|index| *index >= input_count)
    {
        bail!("policy input roles do not form an exact input partition");
    }
    Ok(())
}

fn psbt_role_input_sum(
    psbt: &Psbt,
    indexes: &[usize],
    expected_script: &ScriptBuf,
    label: &str,
) -> Result<u64> {
    indexes.iter().try_fold(0_u64, |sum, index| {
        let prevout = psbt.inputs[*index]
            .witness_utxo
            .as_ref()
            .with_context(|| format!("{label} input lacks witness UTXO"))?;
        if prevout.script_pubkey != *expected_script {
            bail!("{label} input uses an unexpected script");
        }
        sum.checked_add(prevout.value.to_sat())
            .with_context(|| format!("{label} input sum overflowed"))
    })
}

fn controller_policy(config: &VaultConfig) -> Result<ControllerPolicy> {
    let phone = crate::core::keys::VaultKey::from_str(&config.phone_vault_pubkey)
        .context("invalid configured phone vault key")?;
    let hww = crate::core::keys::VaultKey::from_str(&config.hww_vault_pubkey)
        .context("invalid configured HWW vault key")?;
    ControllerPolicy::new_for_network(phone, hww, config.internal_key, config.bitcoin_network()?)
}

#[allow(clippy::too_many_arguments)]
fn build_emergency_access(
    policy: &VaultPolicy,
    controller: &ControllerPolicy,
    source_outpoint: OutPoint,
    source_txout: &TxOut,
    trigger_connector: ConnectorState,
    amount_sats: u64,
    delay_sequence: Sequence,
    hot_address: &Address,
    vault_script: ScriptBuf,
    batch_dir: &Path,
    phone: &DeviceKeys,
) -> Result<EmergencyAccessPolicy> {
    let controller_script = controller.address.script_pubkey();
    let withdrawal_fee = emergency_withdrawal_fee(
        policy,
        controller,
        OutPoint::null(),
        amount_sats,
        delay_sequence,
        hot_address.script_pubkey(),
    )?;
    let staging_value_sats = amount_sats
        .checked_add(withdrawal_fee)
        .and_then(|value| value.checked_sub(CONNECTOR_VALUE_SATS))
        .context("emergency access amount and fee cannot be funded with the connector")?;
    if staging_value_sats < vault_script.minimal_non_dust().to_sat() {
        bail!("emergency staging output would be dust");
    }
    let trigger_fee = emergency_trigger_fee(
        policy,
        controller,
        source_outpoint,
        staging_value_sats,
        vault_script.minimal_non_dust().to_sat(),
        vault_script.clone(),
    )?;
    let vault_change_value_sats = source_txout
        .value
        .to_sat()
        .checked_sub(staging_value_sats)
        .and_then(|value| value.checked_sub(trigger_fee))
        .and_then(|value| value.checked_sub(TRIGGER_ANCHOR_VALUE_SATS))
        .context("vault remainder cannot fund the configured emergency access amount and fees")?;
    if vault_change_value_sats < vault_script.minimal_non_dust().to_sat() {
        bail!("emergency access trigger would create dust vault change");
    }
    let trigger_tx = emergency_trigger_template(
        source_outpoint,
        trigger_connector.outpoint,
        staging_value_sats,
        vault_change_value_sats,
        vault_script.clone(),
        controller_script.clone(),
    );
    let connector_prevout = TxOut {
        value: Amount::from_sat(CONNECTOR_VALUE_SATS),
        script_pubkey: controller_script.clone(),
    };
    let mut trigger_psbt = create_policy_psbt(
        trigger_tx.clone(),
        &[source_txout.clone(), connector_prevout.clone()],
        &[0],
        &[1],
        policy,
        controller,
    )?;
    sign_vault_psbt_inputs(
        &mut trigger_psbt,
        policy,
        SpendPath::Cooperative,
        &phone.vault_keypair,
        &[0],
    )?;

    let staging_outpoint = OutPoint::new(trigger_tx.compute_txid(), 0);
    let staging_txout = &trigger_tx.output[0];
    let withdrawal_connector = ConnectorState {
        outpoint: OutPoint::new(trigger_tx.compute_txid(), 2),
        value_sats: CONNECTOR_VALUE_SATS,
    };
    let withdrawal_tx = emergency_withdrawal_template(
        staging_outpoint,
        withdrawal_connector.outpoint,
        amount_sats,
        delay_sequence,
        hot_address.script_pubkey(),
    );
    let mut withdrawal_psbt = create_policy_psbt(
        withdrawal_tx.clone(),
        &[staging_txout.clone(), connector_prevout],
        &[0],
        &[1],
        policy,
        controller,
    )?;
    sign_vault_psbt_inputs(
        &mut withdrawal_psbt,
        policy,
        SpendPath::Cooperative,
        &phone.vault_keypair,
        &[0],
    )?;

    let trigger_file = "emergency/trigger.psbt".to_owned();
    let withdrawal_file = "emergency/withdrawal.psbt".to_owned();
    write_psbt(&batch_dir.join(&trigger_file), &trigger_psbt)?;
    write_psbt(&batch_dir.join(&withdrawal_file), &withdrawal_psbt)?;

    Ok(EmergencyAccessPolicy {
        amount_sats,
        delay_seconds: EMERGENCY_ACCESS_DELAY_SECONDS,
        delay_sequence: delay_sequence.to_consensus_u32(),
        hot_address: hot_address.to_string(),
        staging_vout: 0,
        staging_value_sats,
        vault_change_vout: 1,
        vault_change_value_sats,
        trigger_connector,
        withdrawal_connector,
        trigger: BatchTransaction {
            psbt_file: trigger_file,
            unsigned_txid: trigger_tx.compute_txid().to_string(),
            fee_sats: trigger_fee,
            vault_input_indexes: vec![0],
            controller_input_indexes: vec![1],
        },
        withdrawal: BatchTransaction {
            psbt_file: withdrawal_file,
            unsigned_txid: withdrawal_tx.compute_txid().to_string(),
            fee_sats: withdrawal_fee,
            vault_input_indexes: vec![0],
            controller_input_indexes: vec![1],
        },
    })
}

fn emergency_trigger_fee(
    policy: &VaultPolicy,
    controller: &ControllerPolicy,
    outpoint: OutPoint,
    staging_value_sats: u64,
    vault_change_value_sats: u64,
    vault_script: ScriptBuf,
) -> Result<u64> {
    let template = emergency_trigger_template(
        outpoint,
        OutPoint::null(),
        staging_value_sats,
        vault_change_value_sats,
        vault_script,
        controller.address.script_pubkey(),
    );
    Ok(estimate_policy_vsize(
        &template,
        policy,
        SpendPath::Cooperative,
        &[0],
        controller,
        ControllerPath::Phone,
        &[1],
    )? * DEFAULT_FEE_RATE_SAT_VB)
}

fn emergency_trigger_template(
    vault_outpoint: OutPoint,
    connector_outpoint: OutPoint,
    staging_value_sats: u64,
    vault_change_value_sats: u64,
    vault_script: ScriptBuf,
    controller_script: ScriptBuf,
) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![
            vault_input(vault_outpoint, Sequence::MAX),
            vault_input(connector_outpoint, Sequence::ENABLE_RBF_NO_LOCKTIME),
        ],
        output: vec![
            TxOut {
                value: Amount::from_sat(staging_value_sats),
                script_pubkey: vault_script.clone(),
            },
            TxOut {
                value: Amount::from_sat(vault_change_value_sats),
                script_pubkey: vault_script,
            },
            TxOut {
                value: Amount::from_sat(CONNECTOR_VALUE_SATS),
                script_pubkey: controller_script,
            },
            TxOut {
                value: Amount::from_sat(TRIGGER_ANCHOR_VALUE_SATS),
                script_pubkey: ScriptBuf::new_p2a(),
            },
        ],
    }
}

fn emergency_withdrawal_fee(
    policy: &VaultPolicy,
    controller: &ControllerPolicy,
    outpoint: OutPoint,
    amount_sats: u64,
    delay_sequence: Sequence,
    hot_script: ScriptBuf,
) -> Result<u64> {
    let template = emergency_withdrawal_template(
        outpoint,
        OutPoint::null(),
        amount_sats,
        delay_sequence,
        hot_script,
    );
    Ok(estimate_policy_vsize(
        &template,
        policy,
        SpendPath::Cooperative,
        &[0],
        controller,
        ControllerPath::Phone,
        &[1],
    )? * DEFAULT_FEE_RATE_SAT_VB)
}

fn emergency_withdrawal_template(
    vault_outpoint: OutPoint,
    connector_outpoint: OutPoint,
    amount_sats: u64,
    delay_sequence: Sequence,
    hot_script: ScriptBuf,
) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![
            vault_input(vault_outpoint, delay_sequence),
            vault_input(connector_outpoint, Sequence::ENABLE_RBF_NO_LOCKTIME),
        ],
        output: vec![TxOut {
            value: Amount::from_sat(amount_sats),
            script_pubkey: hot_script,
        }],
    }
}

#[allow(clippy::too_many_arguments)]
fn rollover_template(
    inputs: Vec<TxIn>,
    rungs: &[RungPolicy],
    monthly_limit_sats: u64,
    remainder_value: u64,
    vault_script: ScriptBuf,
    controller_script: ScriptBuf,
    emergency_connector: bool,
    anchor: bool,
) -> Transaction {
    let mut outputs = rungs
        .iter()
        .map(|rung| TxOut {
            value: Amount::from_sat(monthly_limit_sats),
            script_pubkey: rung.address.script_pubkey(),
        })
        .collect::<Vec<_>>();
    outputs.push(TxOut {
        value: Amount::from_sat(remainder_value),
        script_pubkey: vault_script,
    });
    if emergency_connector {
        outputs.push(TxOut {
            value: Amount::from_sat(CONNECTOR_VALUE_SATS),
            script_pubkey: controller_script,
        });
    }
    if anchor {
        outputs.push(TxOut {
            value: Amount::from_sat(ANCHOR_VALUE_SATS),
            script_pubkey: ScriptBuf::new_p2a(),
        });
    }
    Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: inputs,
        output: outputs,
    }
}

fn renewal_delay_sequence() -> Result<Sequence> {
    Sequence::from_seconds_ceil(PRESIGNED_RENEWAL_DELAY_SECONDS)
        .context("presigned renewal delay cannot be represented by BIP68")
}

fn emergency_delay_sequence() -> Result<Sequence> {
    Sequence::from_seconds_ceil(EMERGENCY_ACCESS_DELAY_SECONDS)
        .context("emergency access delay cannot be represented by BIP68")
}

fn vault_input(outpoint: OutPoint, sequence: Sequence) -> TxIn {
    TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(),
        sequence,
        witness: Witness::new(),
    }
}

fn checked_input_sum(utxos: &[VaultUtxo]) -> Result<u64> {
    utxos.iter().try_fold(0_u64, |sum, utxo| {
        sum.checked_add(utxo.txout.value.to_sat())
            .context("vault input total overflowed")
    })
}

fn output_sum(transaction: &Transaction) -> Result<u64> {
    transaction.output.iter().try_fold(0_u64, |sum, output| {
        sum.checked_add(output.value.to_sat())
            .context("transaction output sum overflowed")
    })
}

pub fn write_psbt(path: &Path, psbt: &Psbt) -> Result<()> {
    write_private(path, format!("{psbt}\n").as_bytes())
}

pub fn read_psbt(path: &Path) -> Result<Psbt> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read PSBT {}", path.display()))?;
    Psbt::from_str(text.trim()).with_context(|| format!("invalid PSBT in {}", path.display()))
}

pub fn manifest_transactions(manifest: &BatchManifest) -> Vec<&BatchTransaction> {
    let mut transactions = Vec::with_capacity(3);
    transactions.push(&manifest.rollover);
    if let Some(emergency) = &manifest.emergency_access {
        transactions.push(&emergency.trigger);
        transactions.push(&emergency.withdrawal);
    }
    transactions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cold_wallet,
        core::{
            storage::{PHONE_DEVICE_FILE, load_device_keys},
            transactions::finalize_vault_psbt,
        },
        hot_wallet::HotWallet,
        test_support::{initialize, initialize_for_network},
    };
    use bitcoin::{Network, Txid, hashes::Hash};
    use chrono::TimeZone;

    fn prepare_from_utxos(
        data_dir: &Path,
        config: &VaultConfig,
        utxos: &[VaultUtxo],
        now: DateTime<Utc>,
        monthly_limit_sats: u64,
        batch_dir: &Path,
    ) -> Result<BatchManifest> {
        prepare_policy_from_utxos(
            data_dir,
            config,
            utxos,
            now,
            monthly_limit_sats,
            0,
            batch_dir,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_policy_from_utxos(
        data_dir: &Path,
        config: &VaultConfig,
        utxos: &[VaultUtxo],
        now: DateTime<Utc>,
        monthly_limit_sats: u64,
        emergency_access_limit_sats: u64,
        batch_dir: &Path,
    ) -> Result<BatchManifest> {
        let phone = load_device_keys(data_dir, PHONE_DEVICE_FILE)?;
        let mut hot = HotWallet::open_or_create(data_dir)?;
        build_policy_proposal(
            config,
            utxos,
            now,
            PolicyLimits {
                monthly_limit_sats,
                emergency_access_limit_sats,
            },
            batch_dir,
            &phone,
            &mut hot,
        )
    }

    fn fake_utxo(config: &VaultConfig, sats: u64) -> VaultUtxo {
        VaultUtxo {
            outpoint: OutPoint::new(Txid::all_zeros(), 0),
            txout: TxOut {
                value: Amount::from_sat(sats),
                script_pubkey: Address::from_str(&config.vault_address)
                    .unwrap()
                    .require_network(config.bitcoin_network().unwrap())
                    .unwrap()
                    .script_pubkey(),
            },
            confirmation_height: 1,
        }
    }

    fn fake_connector_utxo(config: &VaultConfig, txid_byte: u8) -> VaultUtxo {
        let controller = controller_policy(config).unwrap();
        VaultUtxo {
            outpoint: OutPoint::new(Txid::from_byte_array([txid_byte; 32]), 0),
            txout: TxOut {
                value: Amount::from_sat(CONNECTOR_VALUE_SATS),
                script_pubkey: controller.address.script_pubkey(),
            },
            confirmation_height: 1,
        }
    }

    fn prepare_two_years(data_dir: &Path, config: &VaultConfig, batch_dir: &Path) -> BatchManifest {
        let phone = load_device_keys(data_dir, PHONE_DEVICE_FILE).unwrap();
        let mut hot = HotWallet::open_or_create(data_dir).unwrap();
        build_policy_proposal_with_renewal(
            config,
            &[fake_utxo(config, 400_000_000)],
            &[],
            Utc.with_ymd_and_hms(2026, 8, 3, 12, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 8, 3, 12, 0, 0)
                .unwrap()
                .timestamp(),
            PolicyLimits {
                monthly_limit_sats: 10_000_000,
                emergency_access_limit_sats: 50_000_000,
            },
            2,
            batch_dir,
            &phone,
            &mut hot,
        )
        .unwrap()
    }

    #[test]
    fn two_year_ceremony_presigns_a_delayed_renewal_of_the_remainder() {
        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize(dir.path()).unwrap();
        let batch = dir.path().join("batch");
        let first = prepare_two_years(dir.path(), &initialized.config, &batch);
        assert!(first.has_presigned_renewal);
        assert_eq!(first.allowance_count, MONTHS_PER_ROLLOVER);

        let next_dir = batch.join(NEXT_BATCH_DIR);
        let next = load_manifest(&next_dir).unwrap();
        let link = next.renews.clone().unwrap();
        assert_eq!(link.parent_rollover_txid, first.rollover.unsigned_txid);
        assert_eq!(link.value_sats, first.remainder_value_sats);
        assert_eq!(next.allowance_count, MONTHS_PER_ROLLOVER);
        assert!(next.emergency_access.is_some());
        assert!(!next.has_presigned_renewal);

        let rollover = read_psbt(&next_dir.join(&next.rollover.psbt_file)).unwrap();
        let tx = &rollover.unsigned_tx;
        assert_eq!(tx.input.len(), 1);
        assert_eq!(
            tx.input[0].previous_output,
            OutPoint::new(
                first.rollover.unsigned_txid.parse().unwrap(),
                first.remainder_vout
            )
        );
        assert_eq!(
            tx.input[0].sequence,
            Sequence::from_seconds_ceil(PRESIGNED_RENEWAL_DELAY_SECONDS).unwrap()
        );
        let anchor_vout = next.rollover_anchor_vout.unwrap() as usize;
        assert_eq!(anchor_vout, tx.output.len() - 1);
        assert_eq!(tx.output[anchor_vout].script_pubkey, ScriptBuf::new_p2a());

        let approved = cold_wallet::approve_policy(dir.path(), &batch).unwrap();
        assert!(approved.hww_approved);
        assert!(load_manifest(&next_dir).unwrap().hww_approved);
        validate_approved_batch(&initialized.config, &approved, &batch).unwrap();
        let renewal =
            finalize_vault_psbt(read_psbt(&next_dir.join(&next.rollover.psbt_file)).unwrap());
        assert!(renewal.is_ok(), "the renewal rollover is fully presigned");

        let package = package_from_batch(&batch).unwrap();
        let restored = dir.path().join("restored");
        materialize_policy_package(&package, &restored).unwrap();
        validate_approved_batch(
            &initialized.config,
            &load_manifest(&restored).unwrap(),
            &restored,
        )
        .unwrap();
    }

    #[test]
    fn hww_rejects_a_renewal_without_its_relative_delay() {
        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize(dir.path()).unwrap();
        let batch = dir.path().join("batch");
        prepare_two_years(dir.path(), &initialized.config, &batch);
        let next_dir = batch.join(NEXT_BATCH_DIR);
        let mut next = load_manifest(&next_dir).unwrap();
        let path = next_dir.join(&next.rollover.psbt_file);
        let mut psbt = read_psbt(&path).unwrap();
        psbt.unsigned_tx.input[0].sequence = Sequence::MAX;
        next.rollover.unsigned_txid = psbt.unsigned_tx.compute_txid().to_string();
        write_psbt(&path, &psbt).unwrap();
        write_json(&next_dir.join("manifest.json"), &next).unwrap();
        assert!(cold_wallet::approve_policy(dir.path(), &batch).is_err());
    }

    #[test]
    fn hww_rejects_a_renewal_of_a_different_output() {
        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize(dir.path()).unwrap();
        let batch = dir.path().join("batch");
        prepare_two_years(dir.path(), &initialized.config, &batch);
        let next_dir = batch.join(NEXT_BATCH_DIR);
        let mut next = load_manifest(&next_dir).unwrap();
        let link = next.renews.as_mut().unwrap();
        link.outpoint.vout += 1;
        write_json(&next_dir.join("manifest.json"), &next).unwrap();
        assert!(cold_wallet::approve_policy(dir.path(), &batch).is_err());
    }

    #[test]
    fn package_without_its_declared_renewal_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize(dir.path()).unwrap();
        let batch = dir.path().join("batch");
        prepare_two_years(dir.path(), &initialized.config, &batch);
        let mut package = package_from_batch(&batch).unwrap();
        package.next = None;
        assert!(materialize_policy_package(&package, &dir.path().join("restored")).is_err());
    }

    #[test]
    fn two_btc_creates_twelve_monthly_rungs_and_one_remainder() {
        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize(dir.path()).unwrap();
        let batch = dir.path().join("batch");
        let now = Utc.with_ymd_and_hms(2026, 8, 3, 12, 0, 0).unwrap();
        let manifest = prepare_from_utxos(
            dir.path(),
            &initialized.config,
            &[fake_utxo(&initialized.config, 200_000_000)],
            now,
            10_000_000,
            &batch,
        )
        .unwrap();
        assert_eq!(manifest.allowance_count, 12);
        assert_eq!(manifest.rungs.len(), 12);
        assert_eq!(manifest.ladder_start, now.timestamp());
        assert_eq!(manifest.allowance_value_sats, 12 * 10_000_000);
        let rollover = read_psbt(&batch.join(&manifest.rollover.psbt_file)).unwrap();
        // Twelve months and the remainder; nothing else is presigned.
        assert_eq!(rollover.unsigned_tx.output.len(), 13);
        assert_eq!(manifest.remainder_vout, 12);
        assert_eq!(manifest_transactions(&manifest).len(), 1);
        let mut addresses = std::collections::HashSet::new();
        for (index, rung) in manifest.rungs.iter().enumerate() {
            assert_eq!(rung.step as usize, index + 1);
            assert_eq!(rung.vout as usize, index);
            assert_eq!(
                rung.unlock,
                rung_unlock(manifest.ladder_start, index + 1).unwrap()
            );
            assert_eq!(
                i64::from(rung.unlock) - now.timestamp(),
                (index as i64 + 1) * i64::from(MONTHLY_ALLOWANCE_DELAY_SECONDS)
            );
            let output = &rollover.unsigned_tx.output[index];
            assert_eq!(output.value.to_sat(), 10_000_000);
            let policy = rung_policy(&initialized.config, rung.unlock).unwrap();
            assert_eq!(output.script_pubkey, policy.address.script_pubkey());
            assert_eq!(rung.address, policy.address.to_string());
            assert!(addresses.insert(rung.address.clone()));
        }
        assert_eq!(
            rollover.unsigned_tx.output[manifest.remainder_vout as usize]
                .value
                .to_sat(),
            manifest.remainder_value_sats
        );
        validate_batch(&initialized.config, &manifest, &batch).unwrap();
    }

    #[test]
    fn a_tampered_rung_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize(dir.path()).unwrap();
        let batch = dir.path().join("batch");
        let mut manifest = prepare_from_utxos(
            dir.path(),
            &initialized.config,
            &[fake_utxo(&initialized.config, 200_000_000)],
            Utc.with_ymd_and_hms(2026, 8, 3, 12, 0, 0).unwrap(),
            10_000_000,
            &batch,
        )
        .unwrap();
        manifest.rungs[3].unlock -= 86_400;
        assert!(validate_batch(&initialized.config, &manifest, &batch).is_err());
    }

    #[test]
    fn insufficient_balance_reduces_the_number_of_funded_allowance_steps() {
        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize(dir.path()).unwrap();
        let manifest = prepare_from_utxos(
            dir.path(),
            &initialized.config,
            &[fake_utxo(&initialized.config, 35_000_000)],
            Utc.with_ymd_and_hms(2026, 8, 3, 12, 0, 0).unwrap(),
            10_000_000,
            &dir.path().join("batch"),
        )
        .unwrap();
        assert_eq!(manifest.allowance_count, 3);
        assert_eq!(manifest.rungs.len(), 3);
    }

    #[test]
    fn emergency_access_uses_two_presigned_transactions_and_unsigned_connectors() {
        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize(dir.path()).unwrap();
        let batch = dir.path().join("batch");
        let manifest = prepare_policy_from_utxos(
            dir.path(),
            &initialized.config,
            &[fake_utxo(&initialized.config, 200_000_000)],
            Utc.with_ymd_and_hms(2026, 8, 3, 12, 0, 0).unwrap(),
            10_000_000,
            50_000_000,
            &batch,
        )
        .unwrap();
        assert_eq!(manifest.allowance_count, 12);
        // The rollover plus the emergency pair; the months need no presigned transactions.
        assert_eq!(manifest_transactions(&manifest).len(), 3);
        let emergency = manifest.emergency_access.as_ref().unwrap();
        assert_eq!(emergency.amount_sats, 50_000_000);
        assert_eq!(emergency.delay_seconds, EMERGENCY_ACCESS_DELAY_SECONDS);

        let rollover = read_psbt(&batch.join(&manifest.rollover.psbt_file)).unwrap();
        let trigger = read_psbt(&batch.join(&emergency.trigger.psbt_file)).unwrap();
        assert_eq!(
            trigger.unsigned_tx.input[0].previous_output,
            OutPoint::new(rollover.unsigned_tx.compute_txid(), manifest.remainder_vout)
        );
        assert_eq!(trigger.unsigned_tx.input.len(), 2);
        assert_eq!(
            trigger.unsigned_tx.input[1].previous_output,
            emergency.trigger_connector.outpoint
        );
        assert!(trigger.inputs[1].tap_script_sigs.is_empty());
        assert_eq!(trigger.unsigned_tx.output.len(), 4);
        assert!(
            trigger.unsigned_tx.output[TRIGGER_ANCHOR_VOUT].script_pubkey == ScriptBuf::new_p2a()
        );
        assert_eq!(
            trigger.unsigned_tx.output[TRIGGER_ANCHOR_VOUT]
                .value
                .to_sat(),
            TRIGGER_ANCHOR_VALUE_SATS
        );
        assert!(trigger.unsigned_tx.output[..2].iter().all(|output| {
            output.script_pubkey
                == Address::from_str(&manifest.vault_address)
                    .unwrap()
                    .require_network(Network::Regtest)
                    .unwrap()
                    .script_pubkey()
        }));

        let staged = OutPoint::new(trigger.unsigned_tx.compute_txid(), 0);
        let withdrawal = read_psbt(&batch.join(&emergency.withdrawal.psbt_file)).unwrap();
        assert_eq!(withdrawal.unsigned_tx.input[0].previous_output, staged);
        assert_eq!(
            withdrawal.unsigned_tx.input[1].previous_output,
            emergency.withdrawal_connector.outpoint
        );
        assert_eq!(
            withdrawal.unsigned_tx.input[0].sequence,
            emergency_delay_sequence().unwrap()
        );
        assert_eq!(withdrawal.unsigned_tx.output[0].value.to_sat(), 50_000_000);
        validate_batch(&initialized.config, &manifest, &batch).unwrap();

        let approved = cold_wallet::approve_policy(dir.path(), &batch).unwrap();
        let phone = load_device_keys(dir.path(), PHONE_DEVICE_FILE).unwrap();
        let controller = controller_policy(&initialized.config).unwrap();
        for transaction in manifest_transactions(&approved) {
            let mut psbt = read_psbt(&batch.join(&transaction.psbt_file)).unwrap();
            if !transaction.controller_input_indexes.is_empty() {
                assert!(finalize_vault_psbt(psbt.clone()).is_err());
                let indexes = transaction
                    .controller_input_indexes
                    .iter()
                    .map(|index| *index as usize)
                    .collect::<Vec<_>>();
                sign_controller_psbt_inputs(
                    &mut psbt,
                    &controller,
                    ControllerPath::Phone,
                    &phone.vault_keypair.cooperative,
                    &indexes,
                )
                .unwrap();
            }
            assert!(finalize_vault_psbt(psbt).is_ok());
        }
    }

    #[test]
    fn emergency_access_can_be_enabled_without_monthly_spending() {
        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize(dir.path()).unwrap();
        let batch = dir.path().join("batch");
        let manifest = prepare_policy_from_utxos(
            dir.path(),
            &initialized.config,
            &[fake_utxo(&initialized.config, 200_000_000)],
            Utc.with_ymd_and_hms(2026, 8, 3, 12, 0, 0).unwrap(),
            0,
            50_000_000,
            &batch,
        )
        .unwrap();
        assert_eq!(manifest.allowance_count, 0);
        assert_eq!(manifest_transactions(&manifest).len(), 3);
        let emergency = manifest.emergency_access.as_ref().unwrap();
        let trigger = read_psbt(&batch.join(&emergency.trigger.psbt_file)).unwrap();
        assert_eq!(
            trigger.unsigned_tx.input[0].previous_output,
            OutPoint::new(Txid::from_str(&manifest.rollover.unsigned_txid).unwrap(), 0)
        );
        validate_batch(&initialized.config, &manifest, &batch).unwrap();
    }

    #[test]
    fn annual_refresh_consumes_old_connectors_and_creates_only_new_policy_state() {
        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize(dir.path()).unwrap();
        let batch = dir.path().join("batch");
        let phone = load_device_keys(dir.path(), PHONE_DEVICE_FILE).unwrap();
        let mut hot = HotWallet::open_or_create(dir.path()).unwrap();
        let old_connectors = vec![
            fake_connector_utxo(&initialized.config, 1),
            fake_connector_utxo(&initialized.config, 2),
        ];
        let manifest = build_policy_proposal_with_connectors(
            &initialized.config,
            &[fake_utxo(&initialized.config, 200_000_000)],
            &old_connectors,
            Utc.with_ymd_and_hms(2026, 8, 3, 12, 0, 0).unwrap(),
            PolicyLimits {
                monthly_limit_sats: 10_000_000,
                emergency_access_limit_sats: 50_000_000,
            },
            &batch,
            &phone,
            &mut hot,
        )
        .unwrap();

        assert_eq!(manifest.vault_input_sats, 200_000_000);
        assert_eq!(manifest.controller_input_sats, 2 * CONNECTOR_VALUE_SATS);
        assert_eq!(manifest.rollover.vault_input_indexes, [0]);
        assert_eq!(manifest.rollover.controller_input_indexes, [1, 2]);
        let rollover = read_psbt(&batch.join(&manifest.rollover.psbt_file)).unwrap();
        assert_eq!(rollover.unsigned_tx.input.len(), 3);
        assert_eq!(
            rollover.unsigned_tx.input[1].previous_output,
            old_connectors[0].outpoint
        );
        assert_eq!(
            rollover.unsigned_tx.input[2].previous_output,
            old_connectors[1].outpoint
        );
        assert!(
            rollover.inputs[1..]
                .iter()
                .all(|input| input.tap_script_sigs.len() == 1)
        );
        let controller_script = controller_policy(&initialized.config)
            .unwrap()
            .address
            .script_pubkey();
        assert_eq!(
            rollover
                .unsigned_tx
                .output
                .iter()
                .filter(|output| output.script_pubkey == controller_script)
                .count(),
            // Only the emergency connector: the months carry no controller state.
            1
        );

        let approved = cold_wallet::approve_policy(dir.path(), &batch).unwrap();
        assert!(approved.hww_approved);
        assert!(finalize_vault_psbt(read_psbt(&batch.join("rollover.psbt")).unwrap()).is_ok());
    }

    #[test]
    fn emergency_reserve_reduces_allowance_steps_before_reducing_its_amount() {
        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize(dir.path()).unwrap();
        let manifest = prepare_policy_from_utxos(
            dir.path(),
            &initialized.config,
            &[fake_utxo(&initialized.config, 130_000_000)],
            Utc.with_ymd_and_hms(2026, 8, 3, 12, 0, 0).unwrap(),
            10_000_000,
            20_000_000,
            &dir.path().join("batch"),
        )
        .unwrap();
        assert!(manifest.allowance_count < MONTHS_PER_ROLLOVER);
        assert_eq!(
            manifest.emergency_access.as_ref().unwrap().amount_sats,
            20_000_000
        );
    }

    #[test]
    fn policy_rollover_continues_when_no_allowance_step_can_be_funded() {
        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize(dir.path()).unwrap();
        let batch = dir.path().join("batch");
        let manifest = prepare_policy_from_utxos(
            dir.path(),
            &initialized.config,
            &[fake_utxo(&initialized.config, 25_000_000)],
            Utc.with_ymd_and_hms(2026, 8, 3, 12, 0, 0).unwrap(),
            10_000_000,
            20_000_000,
            &batch,
        )
        .unwrap();
        assert_eq!(manifest.monthly_limit_sats, 10_000_000);
        assert_eq!(manifest.allowance_count, 0);
        assert!(manifest.rungs.is_empty());
        assert_eq!(
            manifest.emergency_access.as_ref().unwrap().amount_sats,
            20_000_000
        );
        validate_batch(&initialized.config, &manifest, &batch).unwrap();
    }

    #[test]
    fn hww_rejects_a_tampered_emergency_delay() {
        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize(dir.path()).unwrap();
        let batch = dir.path().join("batch");
        let manifest = prepare_policy_from_utxos(
            dir.path(),
            &initialized.config,
            &[fake_utxo(&initialized.config, 200_000_000)],
            Utc.with_ymd_and_hms(2026, 8, 3, 12, 0, 0).unwrap(),
            10_000_000,
            20_000_000,
            &batch,
        )
        .unwrap();
        let path = batch.join(
            &manifest
                .emergency_access
                .as_ref()
                .unwrap()
                .withdrawal
                .psbt_file,
        );
        let mut psbt = read_psbt(&path).unwrap();
        psbt.unsigned_tx.input[0].sequence = Sequence::from_height(1);
        write_psbt(&path, &psbt).unwrap();
        assert!(cold_wallet::approve_policy(dir.path(), &batch).is_err());
    }

    #[test]
    fn hww_validates_and_signs_the_complete_batch_once() {
        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize(dir.path()).unwrap();
        let batch = dir.path().join("batch");
        prepare_from_utxos(
            dir.path(),
            &initialized.config,
            &[fake_utxo(&initialized.config, 200_000_000)],
            Utc.with_ymd_and_hms(2026, 8, 3, 12, 0, 0).unwrap(),
            10_000_000,
            &batch,
        )
        .unwrap();
        let approved = cold_wallet::approve_policy(dir.path(), &batch).unwrap();
        assert!(approved.phone_approved);
        assert!(approved.hww_approved);
        for transaction in manifest_transactions(&approved) {
            let psbt = read_psbt(&batch.join(&transaction.psbt_file)).unwrap();
            if transaction.psbt_file == approved.rollover.psbt_file {
                assert!(finalize_vault_psbt(psbt).is_ok());
            } else {
                assert!(
                    finalize_vault_psbt(psbt).is_err(),
                    "presigned policy actions must remain incomplete until a device signs their controller input"
                );
            }
        }
    }

    #[test]
    fn hww_rejects_unsupported_sighash_before_signing_any_batch_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize(dir.path()).unwrap();
        let batch = dir.path().join("batch");
        let manifest = prepare_from_utxos(
            dir.path(),
            &initialized.config,
            &[fake_utxo(&initialized.config, 200_000_000)],
            Utc.with_ymd_and_hms(2026, 8, 3, 12, 0, 0).unwrap(),
            10_000_000,
            &batch,
        )
        .unwrap();
        let path = batch.join(&manifest.rollover.psbt_file);
        let mut psbt = read_psbt(&path).unwrap();
        psbt.inputs[0].sighash_type = Some(bitcoin::sighash::TapSighashType::All.into());
        write_psbt(&path, &psbt).unwrap();
        let before = manifest_transactions(&manifest)
            .iter()
            .map(|transaction| {
                let path = batch.join(&transaction.psbt_file);
                (path.clone(), fs::read(path).unwrap())
            })
            .collect::<Vec<_>>();
        let error = cold_wallet::approve_policy(dir.path(), &batch).unwrap_err();
        assert!(error.to_string().contains("SIGHASH_DEFAULT"));
        assert!(!load_manifest(&batch).unwrap().hww_approved);
        for (path, contents) in before {
            assert_eq!(fs::read(path).unwrap(), contents);
        }
    }

    #[test]
    fn hww_rejects_a_month_redirected_away_from_its_rung() {
        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize(dir.path()).unwrap();
        let batch = dir.path().join("batch");
        let manifest = prepare_from_utxos(
            dir.path(),
            &initialized.config,
            &[fake_utxo(&initialized.config, 200_000_000)],
            Utc.with_ymd_and_hms(2026, 8, 3, 12, 0, 0).unwrap(),
            10_000_000,
            &batch,
        )
        .unwrap();
        // A compromised computer swaps month 1's address for month 12's (unlocks a year early
        // for the wrong month) and keeps the manifest unchanged.
        let path = batch.join(&manifest.rollover.psbt_file);
        let mut psbt = read_psbt(&path).unwrap();
        psbt.unsigned_tx.output[0].script_pubkey =
            psbt.unsigned_tx.output[11].script_pubkey.clone();
        write_psbt(&path, &psbt).unwrap();
        assert!(cold_wallet::approve_policy(dir.path(), &batch).is_err());
    }

    #[test]
    fn hww_rejects_a_tampered_allowance_chain_output() {
        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize(dir.path()).unwrap();
        let batch = dir.path().join("batch");
        let manifest = prepare_from_utxos(
            dir.path(),
            &initialized.config,
            &[fake_utxo(&initialized.config, 200_000_000)],
            Utc.with_ymd_and_hms(2026, 8, 3, 12, 0, 0).unwrap(),
            10_000_000,
            &batch,
        )
        .unwrap();
        let path = batch.join(&manifest.rollover.psbt_file);
        let mut psbt = read_psbt(&path).unwrap();
        psbt.unsigned_tx.output[0].value += Amount::from_sat(1);
        write_psbt(&path, &psbt).unwrap();
        assert!(cold_wallet::approve_policy(dir.path(), &batch).is_err());
    }

    #[test]
    fn zero_monthly_limit_creates_only_a_cold_rollover() {
        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize(dir.path()).unwrap();
        let batch = dir.path().join("batch");
        let manifest = prepare_from_utxos(
            dir.path(),
            &initialized.config,
            &[fake_utxo(&initialized.config, 200_000_000)],
            Utc.with_ymd_and_hms(2026, 8, 3, 12, 0, 0).unwrap(),
            0,
            &batch,
        )
        .unwrap();
        assert_eq!(manifest.monthly_limit_sats, 0);
        assert_eq!(manifest.allowance_count, 0);
        assert!(manifest.rungs.is_empty());
        validate_batch(&initialized.config, &manifest, &batch).unwrap();
    }

    #[test]
    fn mainnet_policy_batch_uses_mainnet_manifest_and_hot_addresses() {
        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize_for_network(dir.path(), Network::Bitcoin).unwrap();
        let batch = dir.path().join("mainnet-batch");
        let utxo = fake_utxo(&initialized.config, 200_000_000);
        let manifest = prepare_from_utxos(
            dir.path(),
            &initialized.config,
            &[utxo],
            Utc::now(),
            10_000_000,
            &batch,
        )
        .unwrap();
        assert_eq!(manifest.network, "mainnet");
        assert!(
            manifest
                .rungs
                .iter()
                .all(|rung| rung.address.starts_with("bc1p"))
        );
        let approved = cold_wallet::approve_policy(dir.path(), &batch).unwrap();
        assert!(approved.hww_approved);
    }

    #[test]
    fn hww_rejects_months_dated_in_the_past_on_a_real_network() {
        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize_for_network(dir.path(), Network::Bitcoin).unwrap();
        let batch = dir.path().join("stale-batch");
        prepare_from_utxos(
            dir.path(),
            &initialized.config,
            &[fake_utxo(&initialized.config, 200_000_000)],
            Utc::now() - chrono::Duration::days(3),
            10_000_000,
            &batch,
        )
        .unwrap();
        let error = cold_wallet::approve_policy(dir.path(), &batch).unwrap_err();
        assert!(error.to_string().contains("start in the past"));
    }

    #[test]
    fn policy_package_round_trips_all_psbts() {
        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize(dir.path()).unwrap();
        let batch = dir.path().join("batch");
        prepare_from_utxos(
            dir.path(),
            &initialized.config,
            &[fake_utxo(&initialized.config, 200_000_000)],
            Utc.with_ymd_and_hms(2026, 8, 3, 12, 0, 0).unwrap(),
            10_000_000,
            &batch,
        )
        .unwrap();
        let package = package_from_batch(&batch).unwrap();
        assert_eq!(package.kind, POLICY_PACKAGE_KIND);
        let imported = dir.path().join("imported");
        materialize_policy_package(&package, &imported).unwrap();
        validate_batch(&initialized.config, &package.manifest, &imported).unwrap();
        assert_eq!(package.version, MANIFEST_VERSION);
        assert_eq!(package.psbts.len(), 1);

        let mut legacy = package.clone();
        legacy.version = 3;
        let legacy_imported = dir.path().join("legacy-imported");
        assert!(materialize_policy_package(&legacy, &legacy_imported).is_err());
    }
}
