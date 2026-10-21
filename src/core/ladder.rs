//! Spending the allowance ladder.
//!
//! Each month of allowance is its own rollover output (a rung). Nothing about a rung is
//! presigned: the phone spends a rung alone once its date has passed, and the HWW alone may move
//! any rung at any time. All three spends below are built when they are needed, at today's fee
//! rate.
//!
//! * Claim: the phone moves one unlocked month to its hot wallet, optionally returning part of
//!   it to the vault (a soft limit).
//! * Return: the phone moves every unlocked, unclaimed month back to the vault, so an unused
//!   month cannot pile up for a thief.
//! * Rescue: the HWW moves months, unlocked or not, to a safe address, normally the vault.

use super::{
    ceremony::{BatchManifest, ScheduleEntry, rung_policy},
    keys::DeviceKeys,
    policy::{RungPolicy, SpendPath, TaprootPolicy},
    signer::VaultSigner,
    storage::VaultConfig,
    transactions::{estimate_vault_vsize, finalize_vault_psbt, sign_vault_psbt_inputs},
};
use anyhow::{Context, Result, bail};
use bitcoin::{
    Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute,
    psbt::PsbtSighashType, sighash::TapSighashType, transaction::Version,
};
use miniscript::psbt::PsbtExt;

/// The HWW's own record of the months it approved, so it can rescue them without the phone.
pub const HWW_LADDER_FILE: &str = "hww/ladder.json";

/// Every rung input signals RBF, which also makes nLockTime enforceable for the phone's
/// absolute-time leaf without enabling a relative lock.
const RUNG_INPUT_SEQUENCE: Sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;

/// The months a ceremony's rollover creates. A segwit transaction's ID is fixed before it is
/// signed, so the outpoints are known at approval time.
pub fn entries_from_manifest(manifest: &BatchManifest) -> Result<Vec<ScheduleEntry>> {
    let rollover_txid: bitcoin::Txid = manifest
        .rollover
        .unsigned_txid
        .parse()
        .context("invalid rollover transaction ID")?;
    Ok(manifest
        .rungs
        .iter()
        .map(|rung| ScheduleEntry {
            step: rung.step,
            unlock: rung.unlock,
            outpoint: OutPoint::new(rollover_txid, rung.vout),
            value_sats: rung.value_sats,
            descriptor: rung.descriptor.clone(),
            address: rung.address.clone(),
        })
        .collect())
}

/// A month still sitting at its rung address.
#[derive(Debug, Clone)]
pub struct LiveRung {
    pub entry: ScheduleEntry,
    pub policy: RungPolicy,
    pub txout: TxOut,
}

impl LiveRung {
    pub fn new(config: &VaultConfig, entry: &ScheduleEntry) -> Result<Self> {
        let policy = rung_policy(config, entry.unlock)?;
        if policy.descriptor_string() != entry.descriptor
            || policy.address.to_string() != entry.address
        {
            bail!(
                "allowance month {} does not match this vault's keys",
                entry.step
            );
        }
        let txout = TxOut {
            value: Amount::from_sat(entry.value_sats),
            script_pubkey: policy.address.script_pubkey(),
        };
        Ok(Self {
            entry: entry.clone(),
            policy,
            txout,
        })
    }

    pub fn outpoint(&self) -> OutPoint {
        self.entry.outpoint
    }
}

/// A rung spend, ready to sign.
pub struct RungSpend {
    pub psbt: Psbt,
    pub fee_sats: u64,
}

/// What a claim, return or rescue moved.
#[derive(Debug, Clone, Copy)]
pub struct RungSpendResult {
    pub txid: bitcoin::Txid,
    pub month_count: usize,
    /// Sent to the hot wallet (claim) or to the destination (return, rescue).
    pub sent_sats: u64,
    /// Returned to the vault by a soft-limited claim.
    pub returned_sats: u64,
    pub fee_sats: u64,
}

/// Build a spend of `rungs` through `path`. `outputs` are paid as given except the last, which
/// receives whatever is left after the fee.
pub fn build_rung_spend(
    rungs: &[LiveRung],
    path: SpendPath,
    outputs: Vec<TxOut>,
    fee_rate_sat_vb: u64,
) -> Result<RungSpend> {
    let first = rungs.first().context("no allowance months to spend")?;
    let lock_time = rungs
        .iter()
        .map(|rung| rung.policy.earliest_lock_time(path))
        .max()
        .unwrap_or(0);
    let input_sats = rungs.iter().try_fold(0_u64, |sum, rung| {
        sum.checked_add(rung.entry.value_sats)
            .context("allowance input total overflowed")
    })?;
    let fixed_sats = outputs[..outputs.len().saturating_sub(1)]
        .iter()
        .try_fold(0_u64, |sum, output| sum.checked_add(output.value.to_sat()))
        .context("allowance output total overflowed")?;
    let mut transaction = Transaction {
        version: Version::TWO,
        lock_time: if lock_time == 0 {
            absolute::LockTime::ZERO
        } else {
            absolute::LockTime::from_time(lock_time)
                .context("allowance month unlock is not a Unix time")?
        },
        input: rungs
            .iter()
            .map(|rung| TxIn {
                previous_output: rung.outpoint(),
                script_sig: ScriptBuf::new(),
                sequence: RUNG_INPUT_SEQUENCE,
                witness: Witness::new(),
            })
            .collect(),
        output: outputs,
    };
    // Every rung has the same two leaves at the same depth, so one policy sizes them all.
    let fee_sats = estimate_vault_vsize(&transaction, &first.policy, path)?
        .checked_mul(fee_rate_sat_vb)
        .context("allowance spend fee overflowed")?;
    let last = transaction
        .output
        .last_mut()
        .context("allowance spend has no outputs")?;
    let rest = input_sats
        .checked_sub(fixed_sats)
        .and_then(|value| value.checked_sub(fee_sats))
        .context("allowance months cannot pay this spend and its fee")?;
    if rest < last.script_pubkey.minimal_non_dust().to_sat() {
        bail!("allowance spend would leave only dust after the fee");
    }
    last.value = Amount::from_sat(rest);

    let mut psbt = Psbt::from_unsigned_tx(transaction)?;
    for (index, rung) in rungs.iter().enumerate() {
        psbt.inputs[index].witness_utxo = Some(rung.txout.clone());
        psbt.inputs[index].sighash_type = Some(PsbtSighashType::from(TapSighashType::Default));
        psbt.update_input_with_descriptor(index, &rung.policy.definite_descriptor()?)
            .with_context(|| format!("failed to describe allowance month {}", rung.entry.step))?;
    }
    Ok(RungSpend { psbt, fee_sats })
}

/// Sign every input with the phone's rung key and finalize.
pub fn sign_as_phone(
    mut spend: RungSpend,
    rungs: &[LiveRung],
    phone: &DeviceKeys,
) -> Result<Transaction> {
    for (index, rung) in rungs.iter().enumerate() {
        sign_vault_psbt_inputs(
            &mut spend.psbt,
            &rung.policy,
            SpendPath::PhoneRecovery,
            &phone.vault_keypair,
            &[index],
        )?;
    }
    finalize_vault_psbt(spend.psbt)
}

/// Sign every input with the HWW's rung key and finalize. A hardware wallet reviews one
/// signature request per month, since each month is its own wallet policy.
pub fn sign_as_hww(
    mut spend: RungSpend,
    rungs: &[LiveRung],
    hww: &dyn VaultSigner,
) -> Result<Transaction> {
    for (index, rung) in rungs.iter().enumerate() {
        hww.sign_vault_inputs(
            &mut spend.psbt,
            &rung.policy,
            SpendPath::HwwRecovery,
            &[index],
        )?;
    }
    finalize_vault_psbt(spend.psbt)
}

/// Whether a month's date has passed, judged by the chain's median time past.
pub fn is_unlocked(entry: &ScheduleEntry, median_time: u64) -> bool {
    median_time > u64::from(entry.unlock)
}

pub fn unlock_date(unlock: u32) -> String {
    chrono::DateTime::from_timestamp(i64::from(unlock), 0).map_or_else(
        || unlock.to_string(),
        |time| time.format("%Y-%m-%d %H:%M UTC").to_string(),
    )
}
