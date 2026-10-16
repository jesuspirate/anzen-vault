//! Spending hard-locked savings once their date has passed.
//!
//! Savings spends are built when the user wants to move the coins, not presigned, so they pay a
//! fee rate fetched at that moment. Every path is an absolute-time lock (CLTV): the transaction's
//! nLockTime is set to the path's date and consensus only accepts it once the chain's median time
//! past has moved beyond that date.
//!
//! * Cooperative: phone and HWW together, from the unlock date.
//! * Phone recovery: the phone alone, 425 days after the unlock date.
//! * HWW recovery: the HWW alone, 455 days after the unlock date.

use super::{
    fees::{MAX_FEE_RATE_SAT_VB, MIN_FEE_RATE_SAT_VB},
    keys::DeviceKeys,
    policy::{SavingsPolicy, SpendPath},
    recovery::SweepResult,
    savings::SavingsLock,
    storage::VaultConfig,
    transactions::{
        create_vault_psbt, estimate_vault_vsize, finalize_vault_psbt, sign_vault_psbt,
        verify_vault_psbt_signature,
    },
    types::VaultUtxo,
};
use anyhow::{Context, Result, bail};
use bitcoin::{
    Address, Amount, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute,
    secp256k1::XOnlyPublicKey, transaction::Version,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub const SAVINGS_SPEND_KIND: &str = "savings-spend";

/// Every savings input signals RBF, which also makes nLockTime enforceable (CLTV requires a
/// non-final sequence) without enabling a relative lock.
const SAVINGS_INPUT_SEQUENCE: Sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;

/// A phone-built cooperative spend of one savings lock, passed to the HWW for its signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavingsSpendPackage {
    pub version: u8,
    pub kind: String,
    pub unlock: u32,
    pub savings_descriptor: String,
    pub destination: String,
    pub psbt: String,
    pub input_count: usize,
    pub sent_sats: u64,
    pub fee_sats: u64,
    pub fee_rate_sat_vb: u64,
    pub phone_approved: bool,
    pub hww_approved: bool,
}

/// Pick the savings lock to spend: the one unlocking at `unlock`, or the only lock when there is
/// exactly one and no date was given.
pub fn find_lock(config: &VaultConfig, unlock: Option<u32>) -> Result<&SavingsLock> {
    match unlock {
        Some(unlock) => config
            .savings_locks
            .iter()
            .find(|lock| lock.unlock == unlock)
            .context("no savings lock unlocks on that date"),
        None => match config.savings_locks.as_slice() {
            [lock] => Ok(lock),
            [] => bail!("there are no savings locks"),
            _ => bail!("there are several savings locks; choose one with --unlock YYYY-MM-DD"),
        },
    }
}

/// The nLockTime for `path`, or an error explaining how long until it opens. Consensus requires
/// nLockTime to be strictly below the median time past of the block before the one including
/// the transaction, which for the next block is the current tip's.
pub fn ready_lock_time(policy: &SavingsPolicy, path: SpendPath, median_time: u64) -> Result<u32> {
    let lock_time = policy.earliest_lock_time(path);
    if median_time <= u64::from(lock_time) {
        let days = (u64::from(lock_time) - median_time).div_ceil(86_400);
        let what = match path {
            SpendPath::Cooperative => "this savings lock opens",
            SpendPath::PhoneRecovery => "phone-only recovery of this savings lock opens",
            SpendPath::HwwRecovery => "HWW-only recovery of this savings lock opens",
        };
        let when = chrono::DateTime::from_timestamp(i64::from(lock_time), 0).map_or_else(
            || lock_time.to_string(),
            |time| time.format("%Y-%m-%d %H:%M UTC").to_string(),
        );
        bail!("{what} on {when}, in about {days} day(s); nothing can move it before then");
    }
    Ok(lock_time)
}

fn check_fee_rate(fee_rate_sat_vb: u64) -> Result<()> {
    if !(MIN_FEE_RATE_SAT_VB..=MAX_FEE_RATE_SAT_VB).contains(&fee_rate_sat_vb) {
        bail!(
            "fee rate {fee_rate_sat_vb} sat/vB is outside {MIN_FEE_RATE_SAT_VB}..={MAX_FEE_RATE_SAT_VB} sat/vB"
        );
    }
    Ok(())
}

fn check_utxos(policy: &SavingsPolicy, utxos: &[VaultUtxo]) -> Result<()> {
    if utxos.is_empty() {
        bail!("this savings lock holds no confirmed coins");
    }
    let script = policy.address.script_pubkey();
    if utxos.iter().any(|utxo| utxo.txout.script_pubkey != script) {
        bail!("a coin to spend is not at this savings lock's address");
    }
    Ok(())
}

struct SpendPlan {
    psbt: Psbt,
    input_count: usize,
    sent_sats: u64,
    fee_sats: u64,
}

fn build_spend(
    policy: &SavingsPolicy,
    utxos: &[VaultUtxo],
    path: SpendPath,
    lock_time: u32,
    destination: &Address,
    fee_rate_sat_vb: u64,
) -> Result<SpendPlan> {
    let input_sats = utxos.iter().try_fold(0_u64, |sum, utxo| {
        sum.checked_add(utxo.txout.value.to_sat())
            .context("savings input total overflowed")
    })?;
    let mut transaction = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::from_time(lock_time)
            .context("savings lock time is not a Unix time")?,
        input: utxos
            .iter()
            .map(|utxo| TxIn {
                previous_output: utxo.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: SAVINGS_INPUT_SEQUENCE,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(input_sats),
            script_pubkey: destination.script_pubkey(),
        }],
    };
    let fee_sats = estimate_vault_vsize(&transaction, policy, path)?
        .checked_mul(fee_rate_sat_vb)
        .context("savings spend fee overflowed")?;
    let sent_sats = input_sats
        .checked_sub(fee_sats)
        .context("savings coins cannot pay the spend fee")?;
    if sent_sats < destination.script_pubkey().minimal_non_dust().to_sat() {
        bail!("savings spend would leave only dust after the fee");
    }
    transaction.output[0].value = Amount::from_sat(sent_sats);
    let prevouts = utxos
        .iter()
        .map(|utxo| utxo.txout.clone())
        .collect::<Vec<_>>();
    Ok(SpendPlan {
        psbt: create_vault_psbt(transaction, &prevouts, policy)?,
        input_count: utxos.len(),
        sent_sats,
        fee_sats,
    })
}

/// Build the cooperative spend of every coin at `lock` and add the phone's signature.
#[allow(clippy::too_many_arguments)]
pub fn create_savings_spend(
    config: &VaultConfig,
    lock: &SavingsLock,
    utxos: &[VaultUtxo],
    median_time: u64,
    destination: &Address,
    fee_rate_sat_vb: u64,
    phone: &DeviceKeys,
) -> Result<SavingsSpendPackage> {
    check_fee_rate(fee_rate_sat_vb)?;
    let policy = lock.policy(config.bitcoin_network()?)?;
    if phone.vault_pubkey.to_string() != lock.phone_vault_pubkey {
        bail!("this phone key did not create the savings lock");
    }
    check_utxos(&policy, utxos)?;
    let lock_time = ready_lock_time(&policy, SpendPath::Cooperative, median_time)?;
    let mut plan = build_spend(
        &policy,
        utxos,
        SpendPath::Cooperative,
        lock_time,
        destination,
        fee_rate_sat_vb,
    )?;
    sign_vault_psbt(
        &mut plan.psbt,
        &policy,
        SpendPath::Cooperative,
        &phone.vault_keypair,
    )?;
    Ok(SavingsSpendPackage {
        version: 1,
        kind: SAVINGS_SPEND_KIND.to_owned(),
        unlock: lock.unlock,
        savings_descriptor: policy.descriptor_string(),
        destination: destination.to_string(),
        psbt: plan.psbt.to_string(),
        input_count: plan.input_count,
        sent_sats: plan.sent_sats,
        fee_sats: plan.fee_sats,
        fee_rate_sat_vb,
        phone_approved: true,
        hww_approved: false,
    })
}

/// Check that a cooperative savings spend does exactly what its package says: it spends only
/// coins of one configured savings lock, pays everything but the stated fee to the stated
/// destination, and uses the lock's own date as its nLockTime.
pub fn validate_savings_spend(
    config: &VaultConfig,
    package: &SavingsSpendPackage,
) -> Result<(SavingsLock, SavingsPolicy, Psbt)> {
    if package.version != 1 || package.kind != SAVINGS_SPEND_KIND || !package.phone_approved {
        bail!("unsupported or unsigned savings spend package");
    }
    check_fee_rate(package.fee_rate_sat_vb)?;
    let network = config.bitcoin_network()?;
    let lock = find_lock(config, Some(package.unlock))?.clone();
    let policy = lock.policy(network)?;
    if policy.descriptor_string() != package.savings_descriptor {
        bail!("savings spend package does not match the configured savings lock");
    }
    let destination = Address::from_str(&package.destination)?.require_network(network)?;
    let psbt = Psbt::from_str(&package.psbt).context("invalid savings spend PSBT")?;
    let transaction = &psbt.unsigned_tx;
    if transaction.version != Version::TWO
        || transaction.lock_time != absolute::LockTime::from_time(lock.unlock)?
        || transaction.input.is_empty()
        || transaction.input.len() != package.input_count
        || psbt.inputs.len() != package.input_count
        || transaction
            .input
            .iter()
            .any(|input| input.sequence != SAVINGS_INPUT_SEQUENCE)
        || transaction.output.len() != 1
        || transaction.output[0].script_pubkey != destination.script_pubkey()
        || transaction.output[0].value.to_sat() != package.sent_sats
    {
        bail!("savings spend transaction does not match its package");
    }
    let savings_script = policy.address.script_pubkey();
    let input_sats = psbt.inputs.iter().try_fold(0_u64, |total, input| {
        let prevout = input
            .witness_utxo
            .as_ref()
            .context("savings spend input lacks its witness UTXO")?;
        if prevout.script_pubkey != savings_script {
            bail!("savings spend input is outside the savings lock");
        }
        total
            .checked_add(prevout.value.to_sat())
            .context("savings spend input sum overflowed")
    })?;
    let fee_sats = input_sats
        .checked_sub(package.sent_sats)
        .context("savings spend outputs exceed its inputs")?;
    let expected_fee = estimate_vault_vsize(transaction, &policy, SpendPath::Cooperative)?
        .checked_mul(package.fee_rate_sat_vb)
        .context("savings spend fee overflowed")?;
    if fee_sats != package.fee_sats || fee_sats != expected_fee {
        bail!("savings spend fee does not match its package");
    }
    Ok((lock, policy, psbt))
}

/// The HWW's half of a cooperative savings spend.
pub fn approve_savings_spend(
    config: &VaultConfig,
    package: &SavingsSpendPackage,
    hww: &DeviceKeys,
) -> Result<SavingsSpendPackage> {
    let (lock, policy, mut psbt) = validate_savings_spend(config, package)?;
    verify_vault_psbt_signature(
        &psbt,
        &policy,
        SpendPath::Cooperative,
        XOnlyPublicKey::from_str(&lock.phone_vault_pubkey)?,
    )?;
    if hww.vault_pubkey.to_string() != lock.hww_vault_pubkey {
        bail!("HWW key does not match the savings lock");
    }
    sign_vault_psbt(
        &mut psbt,
        &policy,
        SpendPath::Cooperative,
        &hww.vault_keypair,
    )?;
    let mut approved = package.clone();
    approved.psbt = psbt.to_string();
    approved.hww_approved = true;
    Ok(approved)
}

pub fn finalize_savings_spend(
    config: &VaultConfig,
    package: &SavingsSpendPackage,
) -> Result<(Transaction, SweepResult)> {
    if !package.phone_approved || !package.hww_approved {
        bail!("both phone and HWW approval are required for a savings spend");
    }
    let (lock, policy, psbt) = validate_savings_spend(config, package)?;
    for key in [&lock.phone_vault_pubkey, &lock.hww_vault_pubkey] {
        verify_vault_psbt_signature(
            &psbt,
            &policy,
            SpendPath::Cooperative,
            XOnlyPublicKey::from_str(key)?,
        )?;
    }
    let transaction = finalize_vault_psbt(psbt)?;
    let result = SweepResult {
        txid: transaction.compute_txid(),
        input_count: package.input_count,
        sent_sats: package.sent_sats,
        fee_sats: package.fee_sats,
    };
    Ok((transaction, result))
}

/// Move every coin at `lock` with one device alone, once that device's recovery date has passed.
#[allow(clippy::too_many_arguments)]
pub fn sign_savings_recovery(
    config: &VaultConfig,
    lock: &SavingsLock,
    utxos: &[VaultUtxo],
    median_time: u64,
    path: SpendPath,
    destination: &Address,
    fee_rate_sat_vb: u64,
    signer: &DeviceKeys,
) -> Result<(Transaction, SweepResult)> {
    let expected_key = match path {
        SpendPath::Cooperative => bail!("a cooperative savings spend needs both devices"),
        SpendPath::PhoneRecovery => &lock.phone_vault_pubkey,
        SpendPath::HwwRecovery => &lock.hww_vault_pubkey,
    };
    if signer.vault_pubkey.to_string() != *expected_key {
        bail!("this device key did not create the savings lock");
    }
    check_fee_rate(fee_rate_sat_vb)?;
    let policy = lock.policy(config.bitcoin_network()?)?;
    check_utxos(&policy, utxos)?;
    let lock_time = ready_lock_time(&policy, path, median_time)?;
    let mut plan = build_spend(
        &policy,
        utxos,
        path,
        lock_time,
        destination,
        fee_rate_sat_vb,
    )?;
    sign_vault_psbt(&mut plan.psbt, &policy, path, &signer.vault_keypair)?;
    let transaction = finalize_vault_psbt(plan.psbt)?;
    let result = SweepResult {
        txid: transaction.compute_txid(),
        input_count: plan.input_count,
        sent_sats: plan.sent_sats,
        fee_sats: plan.fee_sats,
    };
    Ok((transaction, result))
}

/// Today's fee rate for a savings spend, from the chain backend (1 sat/vB when it has no data).
pub fn current_fee_rate<B>(backend: &B) -> Result<u64>
where
    B: super::chain::Blockchain + ?Sized,
{
    Ok(backend
        .estimate_fee_rate(super::fees::DEFAULT_CONFIRMATION_TARGET)?
        .unwrap_or(super::DEFAULT_FEE_RATE_SAT_VB))
}
