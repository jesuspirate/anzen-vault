//! Simple mode: a phone-only wallet that pays savings out on a schedule.
//!
//! There is no hardware wallet. The owner's 12 words (which may be the same words another app,
//! such as Fedi, shows) sign everything. Deposits land in an inbox; `lock` splits them into
//! dated payouts that Bitcoin itself refuses to move before their date, so savings open one
//! payout at a time. An optional rescue paper, 12 more words never kept on the phone, can move
//! every payout at any time together with the owner key: a thief who copied only the owner's
//! words has to wait, while the owner moves everything away.

use crate::core::{
    DEFAULT_FEE_RATE_SAT_VB,
    chain::Blockchain,
    fees::DEFAULT_CONFIRMATION_TARGET,
    keys::{VaultKey, VaultKeypairs, generate_words, simple_account_keys},
    policy::{PayoutPolicy, SpendPath, TaprootPolicy},
    storage::{network_name, parse_network_name, read_json, write_json},
    transactions::{estimate_vault_vsize, finalize_vault_psbt, sign_vault_psbt_inputs},
    types::VaultUtxo,
};
use anyhow::{Context, Result, bail, ensure};
use bitcoin::{
    Address, Amount, Network, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness, absolute, psbt::PsbtSighashType, secp256k1::Secp256k1, sighash::TapSighashType,
    transaction::Version,
};
use clap::ValueEnum;
use miniscript::psbt::PsbtExt;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path, str::FromStr};

pub const SIMPLE_CONFIG_FILE: &str = "simple/config.json";
/// The owner's words. A real phone keeps them in its secure storage.
pub const SIMPLE_OWNER_FILE: &str = "simple/owner.json";
pub const SIMPLE_PAYOUTS_FILE: &str = "simple/payouts.json";

/// Above this share of the savings per year in fees, Simple mode advises staying in ecash.
pub const FEE_FLOOR_PERCENT_PER_YEAR: f64 = 2.0;
const SECONDS_PER_YEAR: f64 = 365.0 * 86_400.0;
/// A spend of one payout through the owner's leaf, one P2TR output: used to warn about fees.
const CLAIM_VSIZE_ESTIMATE: u64 = 111;
const PAYOUT_SEQUENCE: Sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Frequency {
    Weekly,
    Biweekly,
    Monthly,
    Quarterly,
}

impl Frequency {
    pub fn seconds(self) -> u32 {
        const DAY: u32 = 86_400;
        match self {
            Self::Weekly => 7 * DAY,
            Self::Biweekly => 14 * DAY,
            Self::Monthly => 30 * DAY,
            Self::Quarterly => 91 * DAY,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Weekly => "every week",
            Self::Biweekly => "every two weeks",
            Self::Monthly => "every month",
            Self::Quarterly => "every three months",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleConfig {
    pub version: u32,
    pub network: String,
    pub owner: VaultKey,
    #[serde(default)]
    pub rescue: Option<VaultKey>,
    pub frequency: Frequency,
}

impl SimpleConfig {
    pub fn bitcoin_network(&self) -> Result<Network> {
        parse_network_name(&self.network)
    }

    pub fn inbox(&self) -> Result<PayoutPolicy> {
        PayoutPolicy::inbox(self.owner, self.bitcoin_network()?)
    }

    pub fn payout_policy(&self, unlock: u32) -> Result<PayoutPolicy> {
        PayoutPolicy::new_for_network(self.owner, self.rescue, unlock, self.bitcoin_network()?)
    }
}

#[derive(Serialize, Deserialize)]
struct OwnerFile {
    words: String,
}

/// One dated payout this phone created.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Payout {
    pub unlock: u32,
    pub outpoint: OutPoint,
    pub value_sats: u64,
    pub address: String,
}

pub struct SimpleInit {
    pub config: SimpleConfig,
    pub inbox: Address,
    /// The rescue paper's words, shown once and never stored.
    pub rescue_words: Option<String>,
}

pub fn is_initialized(data_dir: &Path) -> bool {
    data_dir.join(SIMPLE_CONFIG_FILE).is_file()
}

pub fn load_config(data_dir: &Path) -> Result<SimpleConfig> {
    let config: SimpleConfig = read_json(&data_dir.join(SIMPLE_CONFIG_FILE))
        .context("Simple mode is not set up here; run `anzen simple init` first")?;
    ensure!(config.version == 1, "unsupported Simple mode version");
    Ok(config)
}

pub fn payouts(data_dir: &Path) -> Result<Vec<Payout>> {
    let path = data_dir.join(SIMPLE_PAYOUTS_FILE);
    if !path.is_file() {
        return Ok(Vec::new());
    }
    read_json(&path)
}

/// Set up Simple mode from the owner's words, for example the 12 words Fedi shows.
pub fn initialize(
    data_dir: &Path,
    network: Network,
    owner_words: &str,
    with_rescue: bool,
    frequency: Frequency,
) -> Result<SimpleInit> {
    if is_initialized(data_dir) {
        bail!("Simple mode is already set up in {}", data_dir.display());
    }
    let secp = Secp256k1::new();
    let (_, owner) = simple_account_keys(&secp, owner_words, network)?;
    let rescue_words = with_rescue.then(generate_words).transpose()?;
    let rescue = rescue_words
        .as_deref()
        .map(|words| simple_account_keys(&secp, words, network).map(|(_, key)| key))
        .transpose()?;
    let config = SimpleConfig {
        version: 1,
        network: network_name(network).to_owned(),
        owner,
        rescue,
        frequency,
    };
    fs::create_dir_all(data_dir.join("simple"))?;
    write_json(
        &data_dir.join(SIMPLE_OWNER_FILE),
        &OwnerFile {
            words: owner_words.split_whitespace().collect::<Vec<_>>().join(" "),
        },
    )?;
    write_json(&data_dir.join(SIMPLE_CONFIG_FILE), &config)?;
    let inbox = config.inbox()?.address;
    Ok(SimpleInit {
        config,
        inbox,
        rescue_words,
    })
}

fn owner_keys(data_dir: &Path, config: &SimpleConfig) -> Result<VaultKeypairs> {
    let owner: OwnerFile = read_json(&data_dir.join(SIMPLE_OWNER_FILE))?;
    let (keys, key) =
        simple_account_keys(&Secp256k1::new(), &owner.words, config.bitcoin_network()?)?;
    ensure!(
        key == config.owner,
        "the stored words do not match this Simple mode wallet"
    );
    Ok(keys)
}

fn fee_rate<B: Blockchain + ?Sized>(backend: &B) -> Result<u64> {
    Ok(backend
        .estimate_fee_rate(DEFAULT_CONFIRMATION_TARGET)?
        .unwrap_or(DEFAULT_FEE_RATE_SAT_VB))
}

/// A coin and the policy it is locked under, ready to spend.
struct Coin {
    outpoint: OutPoint,
    txout: TxOut,
    policy: PayoutPolicy,
}

/// Build a spend of `coins` through `path`. `outputs` are paid as given except the last, which
/// receives whatever is left after the fee.
fn build_spend(
    coins: &[Coin],
    path: SpendPath,
    mut outputs: Vec<TxOut>,
    fee_rate_sat_vb: u64,
) -> Result<(Psbt, u64)> {
    let first = coins.first().context("nothing to spend")?;
    let lock_time = coins
        .iter()
        .map(|coin| coin.policy.earliest_lock_time(path))
        .max()
        .unwrap_or(0);
    let input_sats = coins
        .iter()
        .map(|coin| coin.txout.value.to_sat())
        .sum::<u64>();
    let fixed_sats = outputs[..outputs.len().saturating_sub(1)]
        .iter()
        .map(|output| output.value.to_sat())
        .sum::<u64>();
    outputs.last_mut().context("a spend needs an output")?.value = Amount::ZERO;
    let mut transaction = Transaction {
        version: Version::TWO,
        lock_time: if lock_time == 0 {
            absolute::LockTime::ZERO
        } else {
            absolute::LockTime::from_time(lock_time).context("payout date is not a Unix time")?
        },
        input: coins
            .iter()
            .map(|coin| TxIn {
                previous_output: coin.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: PAYOUT_SEQUENCE,
                witness: Witness::new(),
            })
            .collect(),
        output: outputs,
    };
    // Every coin spent at once uses a leaf of the same shape, so one policy sizes them all.
    let fee_sats = estimate_vault_vsize(&transaction, &first.policy, path)?
        .checked_mul(fee_rate_sat_vb)
        .context("fee overflowed")?;
    let last = transaction.output.last_mut().expect("checked above");
    let rest = input_sats
        .checked_sub(fixed_sats)
        .and_then(|value| value.checked_sub(fee_sats))
        .context("these coins cannot pay this spend and its fee")?;
    if rest < last.script_pubkey.minimal_non_dust().to_sat() {
        bail!("this spend would leave only dust after the fee");
    }
    last.value = Amount::from_sat(rest);

    let mut psbt = Psbt::from_unsigned_tx(transaction)?;
    for (index, coin) in coins.iter().enumerate() {
        psbt.inputs[index].witness_utxo = Some(coin.txout.clone());
        psbt.inputs[index].sighash_type = Some(PsbtSighashType::from(TapSighashType::Default));
        psbt.update_input_with_descriptor(index, &coin.policy.definite_descriptor()?)
            .context("failed to describe a payout input")?;
    }
    Ok((psbt, fee_sats))
}

fn sign(psbt: &mut Psbt, coins: &[Coin], path: SpendPath, keys: &VaultKeypairs) -> Result<()> {
    for (index, coin) in coins.iter().enumerate() {
        sign_vault_psbt_inputs(psbt, &coin.policy, path, keys, &[index])?;
    }
    Ok(())
}

fn broadcast<B: Blockchain + ?Sized>(backend: &B, transaction: &Transaction) -> Result<Txid> {
    let txid = backend.broadcast(transaction)?;
    ensure!(
        txid == transaction.compute_txid(),
        "chain backend returned an unexpected transaction ID"
    );
    Ok(txid)
}

fn scan<B: Blockchain + ?Sized>(backend: &B, address: &Address) -> Result<Vec<VaultUtxo>> {
    backend.scan_savings(address)
}

/// Coins waiting in the inbox to be locked.
pub fn inbox_coins<B: Blockchain + ?Sized>(data_dir: &Path, backend: &B) -> Result<Vec<VaultUtxo>> {
    let config = load_config(data_dir)?;
    scan(backend, &config.inbox()?.address)
}

/// A payout and whether it is still on the chain, unspent.
#[derive(Debug, Clone)]
pub struct PayoutStatus {
    pub payout: Payout,
    pub live: bool,
    pub open: bool,
}

pub fn payout_statuses<B: Blockchain + ?Sized>(
    data_dir: &Path,
    backend: &B,
) -> Result<Vec<PayoutStatus>> {
    let config = load_config(data_dir)?;
    let median_time = backend.chain_tip()?.median_time;
    payouts(data_dir)?
        .into_iter()
        .map(|payout| {
            let address = config.payout_policy(payout.unlock)?.address;
            let live = scan(backend, &address)?
                .iter()
                .any(|utxo| utxo.outpoint == payout.outpoint);
            Ok(PayoutStatus {
                open: median_time > u64::from(payout.unlock),
                live,
                payout,
            })
        })
        .collect()
}

#[derive(Debug)]
pub struct LockPlan {
    pub txid: Txid,
    pub payouts: Vec<Payout>,
    pub fee_sats: u64,
    /// Estimated fees for setting up and later claiming these payouts, per year, as a share of
    /// what they hold.
    pub yearly_fee_percent: f64,
}

/// Split every inbox coin into payouts of `amount_sats`, one per period after the last payout
/// already scheduled. The last payout takes what is left over. Refuses when the estimated fees
/// pass the fee floor unless `accept_high_fees`.
pub fn lock<B: Blockchain + ?Sized>(
    data_dir: &Path,
    backend: &B,
    amount_sats: u64,
    now: u32,
    accept_high_fees: bool,
) -> Result<LockPlan> {
    let config = load_config(data_dir)?;
    let keys = owner_keys(data_dir, &config)?;
    let inbox = config.inbox()?;
    let coins: Vec<Coin> = scan(backend, &inbox.address)?
        .into_iter()
        .map(|utxo| Coin {
            outpoint: utxo.outpoint,
            txout: utxo.txout,
            policy: inbox.clone(),
        })
        .collect();
    ensure!(
        !coins.is_empty(),
        "the inbox is empty; deposit to {} first",
        inbox.address
    );
    let total = coins
        .iter()
        .map(|coin| coin.txout.value.to_sat())
        .sum::<u64>();
    let rate = fee_rate(backend)?;
    ensure!(amount_sats >= 1_000, "a payout must be at least 1,000 sats");

    // Count first with a generous fee guess, then build for real.
    let mut count = total / amount_sats;
    ensure!(
        count > 0,
        "the inbox holds {total} sats, less than one payout"
    );
    let existing = payouts(data_dir)?;
    let step = config.frequency.seconds();
    let start = existing
        .iter()
        .map(|payout| payout.unlock)
        .max()
        .unwrap_or(0)
        .max(now);
    let (psbt, fee_sats, policies) = loop {
        let policies = (1..=count)
            .map(|index| {
                let unlock = u32::try_from(index)
                    .ok()
                    .and_then(|index| index.checked_mul(step))
                    .and_then(|offset| start.checked_add(offset))
                    .context("payout date overflowed")?;
                config.payout_policy(unlock)
            })
            .collect::<Result<Vec<_>>>()?;
        let outputs = policies
            .iter()
            .map(|policy| TxOut {
                value: Amount::from_sat(amount_sats),
                script_pubkey: policy.address.script_pubkey(),
            })
            .collect();
        match build_spend(&coins, SpendPath::PhoneRecovery, outputs, rate) {
            Ok((psbt, fee)) => break (psbt, fee, policies),
            Err(_) if count > 1 => count -= 1,
            Err(error) => return Err(error),
        }
    };
    let locked_sats = total - fee_sats;
    let span_years = f64::from(step) * count as f64 / SECONDS_PER_YEAR;
    let claim_fees = count * CLAIM_VSIZE_ESTIMATE * rate;
    let yearly_fee_percent =
        (fee_sats + claim_fees) as f64 / locked_sats as f64 * 100.0 / span_years.max(1.0);
    if yearly_fee_percent > FEE_FLOOR_PERCENT_PER_YEAR && !accept_high_fees {
        bail!(
            "fees would take about {yearly_fee_percent:.1}% of these savings a year, more than \
             {FEE_FLOOR_PERCENT_PER_YEAR}%. Keeping them as ecash in your federation is cheaper. \
             Pass --accept-high-fees to lock them anyway."
        );
    }

    let mut psbt = psbt;
    sign(&mut psbt, &coins, SpendPath::PhoneRecovery, &keys)?;
    let transaction = finalize_vault_psbt(psbt)?;
    let txid = transaction.compute_txid();
    let new: Vec<Payout> = policies
        .iter()
        .zip(&transaction.output)
        .enumerate()
        .map(|(vout, (policy, output))| Payout {
            unlock: policy.unlock,
            outpoint: OutPoint::new(txid, vout as u32),
            value_sats: output.value.to_sat(),
            address: policy.address.to_string(),
        })
        .collect();
    // Record the payouts before broadcasting, so a crash cannot lose track of them.
    let mut all = existing;
    all.extend(new.iter().cloned());
    write_json(&data_dir.join(SIMPLE_PAYOUTS_FILE), &all)?;
    broadcast(backend, &transaction)?;
    Ok(LockPlan {
        txid,
        payouts: new,
        fee_sats,
        yearly_fee_percent,
    })
}

#[derive(Debug)]
pub struct SpendResult {
    pub txid: Txid,
    pub payout_count: usize,
    pub sent_sats: u64,
    pub fee_sats: u64,
}

fn live_coins<B: Blockchain + ?Sized>(
    data_dir: &Path,
    backend: &B,
    config: &SimpleConfig,
    open_only: bool,
) -> Result<Vec<Coin>> {
    payout_statuses(data_dir, backend)?
        .into_iter()
        .filter(|status| status.live && (status.open || !open_only))
        .map(|status| {
            let policy = config.payout_policy(status.payout.unlock)?;
            Ok(Coin {
                outpoint: status.payout.outpoint,
                txout: TxOut {
                    value: Amount::from_sat(status.payout.value_sats),
                    script_pubkey: policy.address.script_pubkey(),
                },
                policy,
            })
        })
        .collect()
}

/// Send every open payout to `destination`, for example a Fedi deposit address.
pub fn claim<B: Blockchain + ?Sized>(
    data_dir: &Path,
    backend: &B,
    destination: &Address,
) -> Result<SpendResult> {
    let config = load_config(data_dir)?;
    let keys = owner_keys(data_dir, &config)?;
    let coins = live_coins(data_dir, backend, &config, true)?;
    ensure!(!coins.is_empty(), "no payout is open yet");
    let outputs = vec![TxOut {
        value: Amount::ZERO,
        script_pubkey: destination.script_pubkey(),
    }];
    let (mut psbt, fee_sats) = build_spend(
        &coins,
        SpendPath::PhoneRecovery,
        outputs,
        fee_rate(backend)?,
    )?;
    sign(&mut psbt, &coins, SpendPath::PhoneRecovery, &keys)?;
    let transaction = finalize_vault_psbt(psbt)?;
    let sent_sats = transaction.output[0].value.to_sat();
    Ok(SpendResult {
        txid: broadcast(backend, &transaction)?,
        payout_count: coins.len(),
        sent_sats,
        fee_sats,
    })
}

/// With the rescue paper, move every payout still on the chain, open or not, to `destination`:
/// a fresh wallet after a theft, or the full vault when graduating.
pub fn rescue<B: Blockchain + ?Sized>(
    data_dir: &Path,
    backend: &B,
    rescue_words: &str,
    destination: &Address,
) -> Result<SpendResult> {
    let config = load_config(data_dir)?;
    let expected = config
        .rescue
        .context("this wallet was set up without a rescue paper")?;
    let (rescue_keys, rescue_key) =
        simple_account_keys(&Secp256k1::new(), rescue_words, config.bitcoin_network()?)?;
    ensure!(
        rescue_key == expected,
        "these are not this wallet's rescue words"
    );
    let owner = owner_keys(data_dir, &config)?;
    let coins = live_coins(data_dir, backend, &config, false)?;
    ensure!(!coins.is_empty(), "no payout is left to move");
    let outputs = vec![TxOut {
        value: Amount::ZERO,
        script_pubkey: destination.script_pubkey(),
    }];
    let (mut psbt, fee_sats) =
        build_spend(&coins, SpendPath::Cooperative, outputs, fee_rate(backend)?)?;
    sign(&mut psbt, &coins, SpendPath::Cooperative, &owner)?;
    sign(&mut psbt, &coins, SpendPath::Cooperative, &rescue_keys)?;
    let transaction = finalize_vault_psbt(psbt)?;
    let sent_sats = transaction.output[0].value.to_sat();
    Ok(SpendResult {
        txid: broadcast(backend, &transaction)?,
        payout_count: coins.len(),
        sent_sats,
        fee_sats,
    })
}

pub fn parse_address(config: &SimpleConfig, text: &str) -> Result<Address> {
    Ok(Address::from_str(text)?.require_network(config.bitcoin_network()?)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn owner_and_rescue_keys_do_not_touch_the_vault_account() {
        let secp = Secp256k1::new();
        let (_, owner) = simple_account_keys(&secp, OWNER, Network::Regtest).unwrap();
        assert_eq!(owner.origin().to_string(), "86'/1'/7000'/0/0");
        let phone = crate::core::keys::DeviceKeys::parse(&secp, OWNER).unwrap();
        assert_ne!(owner.recovery(), phone.vault_pubkey.recovery());
    }

    #[test]
    fn a_payout_has_a_rescue_leaf_only_with_a_rescue_paper() {
        let secp = Secp256k1::new();
        let (_, owner) = simple_account_keys(&secp, OWNER, Network::Regtest).unwrap();
        let (_, rescue) =
            simple_account_keys(&secp, &generate_words().unwrap(), Network::Regtest).unwrap();
        let unlock = 1_900_000_000;
        let with =
            PayoutPolicy::new_for_network(owner, Some(rescue), unlock, Network::Regtest).unwrap();
        let without = PayoutPolicy::new_for_network(owner, None, unlock, Network::Regtest).unwrap();
        assert_ne!(with.address, without.address);
        assert!(with.leaf(SpendPath::Cooperative).is_ok());
        assert!(without.leaf(SpendPath::Cooperative).is_err());
        assert_eq!(with.earliest_lock_time(SpendPath::PhoneRecovery), unlock);
        assert_eq!(with.earliest_lock_time(SpendPath::Cooperative), 0);
        assert!(with.descriptor_string().contains("after(1900000000)"));
        assert!(
            PayoutPolicy::new_for_network(owner, Some(owner), unlock, Network::Regtest).is_err()
        );
    }

    #[test]
    fn setup_stores_the_rescue_key_but_never_its_words() {
        let dir = tempfile::tempdir().unwrap();
        let init = initialize(
            dir.path(),
            Network::Regtest,
            OWNER,
            true,
            Frequency::Monthly,
        )
        .unwrap();
        let words = init.rescue_words.unwrap();
        for entry in walk(dir.path()) {
            let text = fs::read_to_string(&entry).unwrap();
            assert!(
                !text.contains(&words),
                "{} holds the rescue words",
                entry.display()
            );
        }
        assert!(load_config(dir.path()).unwrap().rescue.is_some());
        assert!(
            initialize(
                dir.path(),
                Network::Regtest,
                OWNER,
                false,
                Frequency::Monthly
            )
            .is_err()
        );
    }

    fn walk(path: &Path) -> Vec<std::path::PathBuf> {
        let mut files = Vec::new();
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                files.extend(walk(&path));
            } else {
                files.push(path);
            }
        }
        files
    }
}
