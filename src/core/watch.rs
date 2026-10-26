//! The self-hosted watcher.
//!
//! The vault's delays only protect the owner if the owner hears about a move while there is still
//! time to act: the one-week emergency window, the month between allowance releases, the
//! months before a forgotten rollover opens the phone-alone path. The watcher reads the chain
//! from the owner's own node (or Electrum server), recognises every transaction the vault's
//! plan expects, and raises an alert for anything else.
//!
//! It holds no keys. A *watch plan* ([`WatchPackage`]) has only public data: the vault, savings
//! and allowance-controller descriptors, and the txids of the presigned transactions this epoch
//! may broadcast. The phone can export it so the watcher runs on any always-on computer.
//!
//! Alert text is written to be safe on a third-party notification service: it never carries
//! amounts, addresses or txids. The caller may show those locally.

use super::{
    PHONE_RECOVERY_BLOCKS,
    ceremony::{BatchManifest, SCHEDULE_FILE, Schedule},
    chain::{Blockchain, WatchActivity, WatchBaseline, WatchCursor},
    policy::{ControllerPolicy, RungPolicy, SavingsPolicy, SpendPath, VaultPolicy},
    savings::CEREMONY_WARNING_BLOCKS,
    storage::{VaultConfig, parse_network_name, read_json, validate_supported_network, write_json},
    types::VaultUtxo,
};
use anyhow::{Context, Result, bail};
use bitcoin::{
    Address, Network, OutPoint, ScriptBuf, Transaction, Txid,
    hashes::{Hash, sha256},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    path::Path,
    str::FromStr,
};

/// On a watcher-only computer: the imported watch plan.
pub const WATCH_PACKAGE_FILE: &str = "watch/package.json";
/// What the watcher has already seen and reported.
pub const WATCH_STATE_FILE: &str = "watch/state.json";
/// Written by the phone at every policy activation: the presigned transactions it may broadcast.
pub const WATCH_PLAN_FILE: &str = "phone/watch-plan.json";
pub const WATCH_PACKAGE_KIND: &str = "anzen-watch-plan";
/// Repeat a reminder at most once a week.
pub const REMINDER_INTERVAL_SECS: i64 = 7 * 86_400;
/// Forget handled transactions beyond this many, oldest first.
const MAX_SEEN: usize = 2_000;
const BLOCKS_PER_DAY: u64 = 144;

/// A transaction the vault's own plan may broadcast.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum KnownKind {
    /// The rollover a ceremony broadcasts.
    Rollover,
    /// The presigned second-year rollover.
    Renewal,
    /// A monthly allowance release from the presigned chain that the ladder replaced. Kept so
    /// older watch plans still load.
    Allowance { step: u8 },
    /// Starts the one-week emergency withdrawal.
    EmergencyTrigger,
    /// Completes it after the week.
    EmergencyWithdrawal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownTransaction {
    pub txid: String,
    #[serde(flatten)]
    pub kind: KnownKind,
}

/// Public, key-free description of what to watch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchPackage {
    pub version: u8,
    pub kind: String,
    pub network: String,
    pub vault_descriptor: String,
    pub controller_address: String,
    #[serde(default)]
    pub savings_descriptors: Vec<String>,
    #[serde(default)]
    pub known: Vec<KnownTransaction>,
    /// Unlock dates of the allowance months still in play. Their addresses follow from the vault
    /// keys, so the dates are all the watcher needs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowance_unlocks: Vec<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct WatchPlanFile {
    version: u8,
    known: Vec<KnownTransaction>,
}

/// The presigned transactions of one ceremony epoch. `renewal` marks a presigned renewal.
pub fn known_from_manifest(manifest: &BatchManifest, renewal: bool) -> Vec<KnownTransaction> {
    let mut known = vec![KnownTransaction {
        txid: manifest.rollover.unsigned_txid.clone(),
        kind: if renewal {
            KnownKind::Renewal
        } else {
            KnownKind::Rollover
        },
    }];
    if let Some(emergency) = &manifest.emergency_access {
        known.push(KnownTransaction {
            txid: emergency.trigger.unsigned_txid.clone(),
            kind: KnownKind::EmergencyTrigger,
        });
        known.push(KnownTransaction {
            txid: emergency.withdrawal.unsigned_txid.clone(),
            kind: KnownKind::EmergencyWithdrawal,
        });
    }
    known
}

/// Add an epoch's presigned transactions to the phone's watch plan. Earlier epochs stay listed:
/// a renewal leaves the previous allowance chain claimable, and an old txid can never confirm
/// twice, so keeping it costs nothing.
pub fn record_plan(data_dir: &Path, known: Vec<KnownTransaction>) -> Result<()> {
    let path = data_dir.join(WATCH_PLAN_FILE);
    let mut plan: WatchPlanFile = if path.is_file() {
        read_json(&path)?
    } else {
        WatchPlanFile::default()
    };
    plan.version = 1;
    for entry in known {
        if !plan.known.iter().any(|old| old.txid == entry.txid) {
            plan.known.push(entry);
        }
    }
    write_json(&path, &plan)
}

fn known_from_schedule(schedule: &Schedule) -> Vec<KnownTransaction> {
    let mut known = vec![KnownTransaction {
        txid: schedule.rollover_txid.clone(),
        kind: KnownKind::Rollover,
    }];
    if let Some(emergency) = &schedule.emergency_access {
        known.push(KnownTransaction {
            txid: emergency.trigger_txid.clone(),
            kind: KnownKind::EmergencyTrigger,
        });
        known.push(KnownTransaction {
            txid: emergency.withdrawal_txid.clone(),
            kind: KnownKind::EmergencyWithdrawal,
        });
    }
    known
}

impl WatchPackage {
    /// Build the watch plan from the owner's own vault folder.
    pub fn from_vault(data_dir: &Path, config: &VaultConfig) -> Result<Self> {
        let network = config.bitcoin_network()?;
        let controller = ControllerPolicy::new_for_network(
            FromStr::from_str(&config.phone_vault_pubkey)?,
            FromStr::from_str(&config.hww_vault_pubkey)?,
            config.internal_key,
            network,
        )?;
        let savings_descriptors = config
            .savings_locks
            .iter()
            .map(|lock| Ok(lock.policy(network)?.descriptor_string()))
            .collect::<Result<Vec<_>>>()?;
        let mut known = Vec::new();
        let plan_path = data_dir.join(WATCH_PLAN_FILE);
        if plan_path.is_file() {
            known.extend(read_json::<WatchPlanFile>(&plan_path)?.known);
        }
        // Vaults activated before the plan file existed still have their schedule.
        let schedule_path = data_dir.join(SCHEDULE_FILE);
        let mut allowance_unlocks = Vec::new();
        if schedule_path.is_file() {
            let schedule = read_json::<Schedule>(&schedule_path)?;
            known.extend(known_from_schedule(&schedule));
            allowance_unlocks.extend(
                schedule
                    .previous_entries
                    .iter()
                    .chain(&schedule.entries)
                    .map(|entry| entry.unlock),
            );
        }
        let mut txids = HashSet::new();
        known.retain(|entry| txids.insert(entry.txid.clone()));
        let package = Self {
            version: 1,
            kind: WATCH_PACKAGE_KIND.to_owned(),
            network: config.network.clone(),
            vault_descriptor: config.vault_descriptor.clone(),
            controller_address: controller.address.to_string(),
            savings_descriptors,
            known,
            allowance_unlocks,
        };
        WatchTargets::new(&package)?;
        Ok(package)
    }

    pub fn bitcoin_network(&self) -> Result<Network> {
        parse_network_name(&self.network)
    }
}

/// Which part of the vault a watched output belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pot {
    Vault,
    /// The small allowance and emergency connector outputs.
    Controller,
    Savings {
        unlock: u32,
    },
    /// One month of the allowance ladder.
    Allowance {
        unlock: u32,
    },
}

/// A watch plan, parsed and checked.
pub struct WatchTargets {
    pub network: Network,
    vault: VaultPolicy,
    controller_script: ScriptBuf,
    savings: Vec<SavingsPolicy>,
    allowance: Vec<RungPolicy>,
    known: HashMap<Txid, KnownKind>,
}

impl WatchTargets {
    pub fn new(package: &WatchPackage) -> Result<Self> {
        if package.version != 1 || package.kind != WATCH_PACKAGE_KIND {
            bail!("this is not an Anzen watch plan");
        }
        let network = package.bitcoin_network()?;
        validate_supported_network(network)?;
        let vault = VaultPolicy::from_descriptor_for_network(&package.vault_descriptor, network)
            .context("the watch plan's vault descriptor is not an Anzen vault")?;
        let keys = vault
            .keys(network)
            .context("the watch plan's vault descriptor is not an Anzen vault")?;
        let allowance = package
            .allowance_unlocks
            .iter()
            .map(|unlock| {
                RungPolicy::new_for_network(
                    keys.phone,
                    keys.hww,
                    *unlock,
                    keys.internal_key,
                    network,
                )
            })
            .collect::<Result<Vec<_>>>()
            .context("an allowance month in the watch plan is invalid")?;
        let controller_script = Address::from_str(&package.controller_address)
            .context("invalid controller address in the watch plan")?
            .require_network(network)?
            .script_pubkey();
        let savings = package
            .savings_descriptors
            .iter()
            .map(|text| SavingsPolicy::from_descriptor_for_network(text, network))
            .collect::<Result<Vec<_>>>()
            .context("a savings descriptor in the watch plan is not an Anzen savings lock")?;
        let known = package
            .known
            .iter()
            .map(|entry| Ok((Txid::from_str(&entry.txid)?, entry.kind)))
            .collect::<Result<HashMap<_, _>>>()
            .context("invalid txid in the watch plan")?;
        Ok(Self {
            network,
            vault,
            controller_script,
            savings,
            allowance,
            known,
        })
    }

    pub fn scripts(&self) -> Vec<ScriptBuf> {
        let mut scripts = vec![
            self.vault.address.script_pubkey(),
            self.controller_script.clone(),
        ];
        scripts.extend(self.savings.iter().map(|lock| lock.address.script_pubkey()));
        scripts.extend(
            self.allowance
                .iter()
                .map(|rung| rung.address.script_pubkey()),
        );
        scripts
    }

    /// Changes whenever the set of watched scripts does (a new savings lock, a key rotation).
    fn scripts_id(&self) -> String {
        let mut engine = Vec::new();
        for script in self.scripts() {
            engine.extend_from_slice(script.as_bytes());
            engine.push(0);
        }
        sha256::Hash::hash(&engine).to_string()
    }

    pub fn pot(&self, script: &bitcoin::Script) -> Option<Pot> {
        if script == self.vault.address.script_pubkey().as_script() {
            Some(Pot::Vault)
        } else if script == self.controller_script.as_script() {
            Some(Pot::Controller)
        } else if let Some(lock) = self
            .savings
            .iter()
            .find(|lock| script == lock.address.script_pubkey().as_script())
        {
            Some(Pot::Savings {
                unlock: lock.unlock,
            })
        } else {
            self.allowance
                .iter()
                .find(|rung| script == rung.address.script_pubkey().as_script())
                .map(|rung| Pot::Allowance {
                    unlock: rung.unlock,
                })
        }
    }

    /// The leaf an input spending a vault or savings output used, read from its witness.
    fn spend_path(&self, pot: Pot, input: &bitcoin::TxIn) -> Option<SpendPath> {
        let leaf = input.witness.taproot_leaf_script()?;
        if leaf.version != bitcoin::taproot::LeafVersion::TapScript {
            return None;
        }
        let script = leaf.script;
        let paths = [
            SpendPath::Cooperative,
            SpendPath::PhoneRecovery,
            SpendPath::HwwRecovery,
            SpendPath::Heir,
        ];
        paths.into_iter().find(|path| {
            let leaf = match pot {
                Pot::Vault => self.vault.leaf(*path),
                Pot::Savings { unlock } => match self.savings.iter().find(|s| s.unlock == unlock) {
                    Some(lock) => lock.leaf(*path),
                    None => return false,
                },
                Pot::Allowance { unlock } => {
                    match self.allowance.iter().find(|r| r.unlock == unlock) {
                        Some(rung) => rung.leaf(*path),
                        None => return false,
                    }
                }
                Pot::Controller => return false,
            };
            leaf.is_ok_and(|leaf| leaf.script.as_script() == script)
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Good to know; nothing to do.
    Info,
    /// Check that this was you.
    Notice,
    /// Act now.
    Alert,
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Info => "info",
            Self::Notice => "notice",
            Self::Alert => "alert",
        })
    }
}

/// Something the owner should hear about. `title` and `message` never contain amounts,
/// addresses or txids; the remaining fields are for local display only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchEvent {
    pub level: Level,
    pub title: String,
    pub message: String,
    pub txid: Option<Txid>,
    pub confirmed: bool,
    /// Vault and savings value this transaction moved or added.
    pub amount_sats: Option<u64>,
}

impl WatchEvent {
    fn new(level: Level, title: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            level,
            title: title.into(),
            message: message.into(),
            txid: None,
            confirmed: false,
            amount_sats: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct SeenTransaction {
    confirmed: bool,
    order: u64,
}

/// What the watcher has read so far. Saved after each poll.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WatchState {
    pub version: u8,
    scripts_id: String,
    pub cursor: Option<WatchCursor>,
    /// Confirmed outputs paying a watched script.
    pub coins: Vec<VaultUtxo>,
    seen: BTreeMap<Txid, SeenTransaction>,
    next_order: u64,
    /// When each reminder was last sent (Unix seconds).
    reminders: BTreeMap<String, i64>,
}

impl WatchState {
    pub fn load(path: &Path) -> Result<Self> {
        if path.is_file() {
            read_json(path)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        write_json(path, self)
    }

    fn mark_seen(&mut self, txid: Txid, confirmed: bool) {
        let order = self.next_order;
        self.next_order += 1;
        self.seen.insert(txid, SeenTransaction { confirmed, order });
        if self.seen.len() > MAX_SEEN {
            if let Some(oldest) = self
                .seen
                .iter()
                .min_by_key(|(_, seen)| seen.order)
                .map(|(txid, _)| *txid)
            {
                self.seen.remove(&oldest);
            }
        }
    }

    fn handled(&self) -> HashSet<Txid> {
        self.seen
            .iter()
            .filter(|(_, seen)| seen.confirmed)
            .map(|(txid, _)| *txid)
            .collect()
    }

    fn vault_coin_count(&self) -> usize {
        self.coins.len()
    }
}

/// The outcome of one poll. The caller saves `state` once the events are delivered, so an
/// event that failed to send is found again next time.
pub struct WatchReport {
    pub state: WatchState,
    pub events: Vec<WatchEvent>,
    pub height: u64,
    pub coins_watched: usize,
}

/// Read the chain once and report everything new since the last poll.
pub fn poll(
    chain: &dyn Blockchain,
    package: &WatchPackage,
    mut state: WatchState,
    now: i64,
) -> Result<WatchReport> {
    let targets = WatchTargets::new(package)?;
    if chain.network() != targets.network {
        bail!("the chain backend is not on the watch plan's network");
    }
    let scripts = targets.scripts();
    let scripts_id = targets.scripts_id();
    let mut events = Vec::new();
    match state.cursor.clone() {
        Some(cursor) if state.scripts_id == scripts_id => {
            let coins = state
                .coins
                .iter()
                .map(|coin| coin.outpoint)
                .collect::<Vec<_>>();
            let activity = chain.watch_activity(&scripts, &coins, &cursor, &state.handled())?;
            if activity.caught_up {
                events.extend(apply_activity(&targets, &mut state, activity));
            } else {
                let baseline = chain.watch_baseline(&scripts)?;
                events.extend(apply_baseline(
                    &targets,
                    &mut state,
                    baseline,
                    Rebaseline::LostTrack,
                ));
            }
        }
        previous => {
            let baseline = chain.watch_baseline(&scripts)?;
            let reason = if previous.is_none() {
                Rebaseline::FirstRun
            } else {
                Rebaseline::PlanChanged
            };
            events.extend(apply_baseline(&targets, &mut state, baseline, reason));
            state.scripts_id = scripts_id;
        }
    }
    state.version = 1;
    let height = state.cursor.as_ref().map_or(0, |cursor| cursor.height);
    events.extend(reminders(&targets, &mut state, height, now));
    let coins_watched = state.vault_coin_count();
    Ok(WatchReport {
        state,
        events,
        height,
        coins_watched,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rebaseline {
    FirstRun,
    PlanChanged,
    LostTrack,
}

fn apply_baseline(
    targets: &WatchTargets,
    state: &mut WatchState,
    baseline: WatchBaseline,
    reason: Rebaseline,
) -> Vec<WatchEvent> {
    let mut events = Vec::new();
    let watched = |coin: &VaultUtxo| {
        matches!(
            targets.pot(&coin.txout.script_pubkey),
            Some(Pot::Vault | Pot::Savings { .. } | Pot::Allowance { .. })
        )
    };
    match reason {
        Rebaseline::FirstRun => events.push(WatchEvent::new(
            Level::Info,
            "Watcher is on",
            "Anzen is now watching your vault. You will get a message like this one whenever \
             vault or savings coins move.",
        )),
        Rebaseline::PlanChanged => {}
        Rebaseline::LostTrack => {
            let old = state
                .coins
                .iter()
                .filter(|coin| watched(coin))
                .map(|coin| coin.outpoint)
                .collect::<HashSet<_>>();
            let new = baseline
                .coins
                .iter()
                .filter(|coin| watched(coin))
                .map(|coin| coin.outpoint)
                .collect::<HashSet<_>>();
            let moved = old.difference(&new).count();
            let arrived = new.difference(&old).count();
            if moved > 0 || arrived > 0 {
                events.push(WatchEvent::new(
                    Level::Notice,
                    "Coins moved while the watcher was away",
                    format!(
                        "The watcher could not follow the chain block by block (it was off for \
                         more than a week, or the chain reorganised). Since it last looked, \
                         {moved} vault or savings coin(s) moved and {arrived} arrived. Run \
                         `anzen coins` to check that this was you."
                    ),
                ));
            }
        }
    }
    state.cursor = Some(baseline.cursor);
    state.coins = baseline.coins;
    for txid in baseline.history {
        state.mark_seen(txid, true);
    }
    events
}

fn apply_activity(
    targets: &WatchTargets,
    state: &mut WatchState,
    activity: WatchActivity,
) -> Vec<WatchEvent> {
    let mut events = Vec::new();
    for watched in activity.transactions {
        let transaction = watched.transaction;
        let txid = transaction.compute_txid();
        let confirmed = watched.height.is_some();
        let spent = transaction
            .input
            .iter()
            .filter_map(|input| {
                state
                    .coins
                    .iter()
                    .find(|coin| coin.outpoint == input.previous_output)
                    .map(|coin| (input, coin.clone()))
            })
            .collect::<Vec<_>>();
        let previously = state.seen.get(&txid).copied();
        if confirmed {
            let spent_outpoints = spent
                .iter()
                .map(|(_, coin)| coin.outpoint)
                .collect::<Vec<_>>();
            state
                .coins
                .retain(|coin| !spent_outpoints.contains(&coin.outpoint));
            for (vout, output) in transaction.output.iter().enumerate() {
                let outpoint = OutPoint::new(txid, vout as u32);
                if targets.pot(&output.script_pubkey).is_some()
                    && !state.coins.iter().any(|coin| coin.outpoint == outpoint)
                {
                    state.coins.push(VaultUtxo {
                        outpoint,
                        txout: output.clone(),
                        confirmation_height: watched.height.unwrap_or_default(),
                    });
                }
            }
        }
        // Report each transaction once, when first seen; confirmation only updates the coins.
        if previously.is_none() {
            if let Some(mut event) = describe(targets, &transaction, &spent) {
                event.txid = Some(txid);
                event.confirmed = confirmed;
                events.push(event);
            }
        }
        if previously.is_none_or(|seen| !seen.confirmed) {
            state.mark_seen(txid, confirmed);
        }
    }
    state.cursor = Some(activity.cursor);
    events
}

fn date(unix: u32) -> String {
    chrono::DateTime::from_timestamp(i64::from(unix), 0).map_or_else(
        || unix.to_string(),
        |time| time.format("%Y-%m-%d").to_string(),
    )
}

fn pot_name(pot: Pot) -> String {
    match pot {
        Pot::Vault => "Vault".to_owned(),
        Pot::Controller => "Emergency access".to_owned(),
        Pot::Savings { unlock } => format!("Savings until {}", date(unlock)),
        Pot::Allowance { unlock } => format!("Allowance month of {}", date(unlock)),
    }
}

/// What a transaction touching the vault means, in plain words.
fn describe(
    targets: &WatchTargets,
    transaction: &Transaction,
    spent: &[(&bitcoin::TxIn, VaultUtxo)],
) -> Option<WatchEvent> {
    let txid = transaction.compute_txid();
    let moved_sats = spent
        .iter()
        .filter(|(_, coin)| targets.pot(&coin.txout.script_pubkey) != Some(Pot::Controller))
        .map(|(_, coin)| coin.txout.value.to_sat())
        .sum::<u64>();
    let mut event = if let Some(kind) = targets.known.get(&txid) {
        describe_known(*kind)
    } else if let Some(event) = describe_allowance_spend(targets, transaction, spent) {
        event
    } else if let Some(event) = describe_spend(targets, spent) {
        event
    } else if !spent.is_empty() {
        WatchEvent::new(
            Level::Notice,
            "An allowance or emergency withdrawal was cancelled",
            "A cancel was sent from your phone or hardware wallet: the remaining allowance months, \
             or a pending emergency withdrawal, can no longer happen. Your vault coins did not \
             move. If you did not do this, someone else has one of your devices.",
        )
    } else {
        return describe_deposit(targets, transaction);
    };
    if moved_sats > 0 {
        event.amount_sats = Some(moved_sats);
    }
    Some(event)
}

fn describe_known(kind: KnownKind) -> WatchEvent {
    match kind {
        KnownKind::Rollover => WatchEvent::new(
            Level::Info,
            "Yearly rollover sent",
            "Your vault renewed its plan for another year. Nothing to do.",
        ),
        KnownKind::Renewal => WatchEvent::new(
            Level::Info,
            "Second-year renewal sent",
            "The renewal you presigned last year was sent, so the vault's plan runs for another \
             year. Plan a ceremony with your hardware wallet within the next year.",
        ),
        KnownKind::Allowance { step } => WatchEvent::new(
            Level::Notice,
            format!("Month {step} allowance released"),
            "This month's allowance moved from the vault to your phone wallet. If you did not do \
             this, stop the remaining months with your hardware wallet: `anzen hww revoke-policy`.",
        ),
        KnownKind::EmergencyTrigger => WatchEvent::new(
            Level::Alert,
            "Emergency withdrawal started",
            "Someone started the one-week emergency withdrawal from your vault. If it was not \
             you, cancel it before the week is up: `anzen hww revoke-policy` with your hardware \
             wallet, or `anzen phone emergency cancel` if you still have your phone.",
        ),
        KnownKind::EmergencyWithdrawal => WatchEvent::new(
            Level::Notice,
            "Emergency withdrawal completed",
            "The emergency amount reached your phone wallet after its one-week wait. If you did \
             not expect this, move your remaining coins with your hardware wallet.",
        ),
    }
}

/// A spend of allowance months only: a claim, a return to the vault or a hardware-wallet rescue.
fn describe_allowance_spend(
    targets: &WatchTargets,
    transaction: &Transaction,
    spent: &[(&bitcoin::TxIn, VaultUtxo)],
) -> Option<WatchEvent> {
    let mut paths = Vec::new();
    for (input, coin) in spent {
        let pot @ Pot::Allowance { .. } = targets.pot(&coin.txout.script_pubkey)? else {
            return None;
        };
        paths.push(targets.spend_path(pot, input));
    }
    let months = paths.len();
    if months == 0 {
        return None;
    }
    let to_vault = transaction
        .output
        .iter()
        .all(|output| targets.pot(&output.script_pubkey) == Some(Pot::Vault));
    let plural = if months == 1 { "" } else { "s" };
    Some(
        if paths
            .iter()
            .all(|path| *path == Some(SpendPath::HwwRecovery))
        {
            WatchEvent::new(
                Level::Notice,
                format!("{months} allowance month{plural} moved by the hardware wallet"),
                "Your hardware wallet pulled allowance months back, which is what the panic button \
             does. If that was not you, someone has your hardware wallet: move your remaining \
             coins with your phone.",
            )
        } else if paths
            .iter()
            .all(|path| *path == Some(SpendPath::PhoneRecovery))
            && to_vault
        {
            WatchEvent::new(
                Level::Info,
                format!("{months} unused allowance month{plural} returned to the vault"),
                "Your phone sent months you did not use back into the vault. Nothing to do.",
            )
        } else if paths
            .iter()
            .all(|path| *path == Some(SpendPath::PhoneRecovery))
        {
            WatchEvent::new(
                Level::Notice,
                "Allowance month claimed",
                "Your phone took this month's allowance. If you did not do this, someone has your \
             phone: pull the remaining months back with your hardware wallet, \
             `anzen hww revoke-policy <vault address>`.",
            )
        } else {
            WatchEvent::new(
                Level::Alert,
                "Allowance months moved in an unknown way",
                "The watcher does not recognise how these allowance months were spent. Check your \
             vault now.",
            )
        },
    )
}

/// A spend of vault or savings coins that is not in the plan, judged by the leaf it used.
fn describe_spend(
    targets: &WatchTargets,
    spent: &[(&bitcoin::TxIn, VaultUtxo)],
) -> Option<WatchEvent> {
    // The most alarming input decides.
    let mut worst: Option<(u8, Pot, Option<SpendPath>)> = None;
    for (input, coin) in spent {
        let pot = targets.pot(&coin.txout.script_pubkey)?;
        if pot == Pot::Controller {
            continue;
        }
        let path = targets.spend_path(pot, input);
        let rank = match path {
            Some(SpendPath::Cooperative) => 1,
            Some(SpendPath::PhoneYubikey | SpendPath::HwwYubikey) => 2,
            Some(SpendPath::Heir) => 3,
            Some(SpendPath::HwwRecovery) => 4,
            Some(SpendPath::PhoneRecovery) => 5,
            None => 6,
        };
        if worst.is_none_or(|(old, _, _)| rank > old) {
            worst = Some((rank, pot, path));
        }
    }
    let (_, pot, path) = worst?;
    let name = pot_name(pot);
    Some(match path {
        Some(SpendPath::Cooperative) => WatchEvent::new(
            Level::Notice,
            format!("{name} coins moved with both keys"),
            "Your phone and hardware wallet signed a move that is not in this watcher's plan, \
             such as a sweep, a key change or a new yearly ceremony. If that was you, nothing to \
             do (on a separate watcher, export a fresh watch plan). If not, both of your keys \
             may be exposed.",
        ),
        Some(SpendPath::PhoneYubikey) => WatchEvent::new(
            Level::Notice,
            format!("{name} coins moved with your phone and YubiKey"),
            "Your phone and YubiKey signed together, which is how you move coins when the \
             hardware wallet is lost. If that was you, nothing to do. If not, both your phone \
             and your YubiKey may be exposed: move every remaining coin with your hardware \
             wallet now.",
        ),
        Some(SpendPath::HwwYubikey) => WatchEvent::new(
            Level::Notice,
            format!("{name} coins moved with your hardware wallet and YubiKey"),
            "Your hardware wallet and YubiKey signed together, which is how you move coins when \
             the phone is lost. If that was you, nothing to do. If not, both your hardware \
             wallet and your YubiKey may be exposed: move every remaining coin with your phone \
             now.",
        ),
        Some(SpendPath::PhoneRecovery) => WatchEvent::new(
            Level::Alert,
            format!("{name} coins moved with the phone alone"),
            "The phone's backup path was used. It opens only after the coins sat unrenewed for \
             months. If this was not you, someone has your phone key: move every remaining coin \
             with your hardware wallet now.",
        ),
        Some(SpendPath::HwwRecovery) => WatchEvent::new(
            Level::Alert,
            format!("{name} coins moved with the hardware wallet alone"),
            "The hardware wallet's backup path was used. If this was not you, someone has your \
             hardware wallet or its secret words: move every remaining coin now.",
        ),
        Some(SpendPath::Heir) => WatchEvent::new(
            Level::Alert,
            format!("Your heir claimed {name} coins"),
            "Your heir's own key moved coins after their long wait. This happens only when the \
             coins sat unmoved for about 15 months (savings: 16 months after their date).",
        ),
        None => WatchEvent::new(
            Level::Alert,
            format!("{name} coins moved in an unknown way"),
            "The watcher does not recognise how these coins were spent. Check your vault now.",
        ),
    })
}

fn describe_deposit(targets: &WatchTargets, transaction: &Transaction) -> Option<WatchEvent> {
    let mut pot = None;
    let mut amount = 0;
    for output in &transaction.output {
        match targets.pot(&output.script_pubkey) {
            Some(Pot::Controller) | None => {}
            Some(found) => {
                pot.get_or_insert(found);
                amount += output.value.to_sat();
            }
        }
    }
    let pot = pot?;
    let mut event = WatchEvent::new(
        Level::Info,
        format!("Deposit to {}", pot_name(pot)),
        match pot {
            Pot::Savings { unlock } => format!(
                "New coins arrived in your savings lock. Nobody can move them before {}.",
                date(unlock)
            ),
            _ => "New coins arrived in your vault.".to_owned(),
        },
    );
    event.amount_sats = Some(amount);
    Some(event)
}

/// Rollover reminders: a vault coin's phone-alone path opens 61,200 blocks after it last moved.
fn reminders(
    targets: &WatchTargets,
    state: &mut WatchState,
    height: u64,
    now: i64,
) -> Vec<WatchEvent> {
    let next_height = height + 1;
    let soonest = state
        .coins
        .iter()
        .filter(|coin| targets.pot(&coin.txout.script_pubkey) == Some(Pot::Vault))
        .map(|coin| coin.confirmation_height + u64::from(PHONE_RECOVERY_BLOCKS))
        .min();
    let Some(opens_at) = soonest else {
        return Vec::new();
    };
    let event = if next_height >= opens_at {
        WatchEvent::new(
            Level::Alert,
            "Phone-alone path is open",
            "Some vault coins went more than 14 months without a rollover, so your phone alone \
             can now move them (and later your hardware wallet alone, or your heir). Run a \
             ceremony with your hardware wallet to protect them again.",
        )
    } else if opens_at - next_height <= CEREMONY_WARNING_BLOCKS {
        let days = (opens_at - next_height) / BLOCKS_PER_DAY;
        WatchEvent::new(
            Level::Notice,
            "Yearly renewal due",
            format!(
                "In about {days} days your phone alone could move some vault coins. Before \
                 then, run `anzen phone renew` or a ceremony with your hardware wallet."
            ),
        )
    } else {
        return Vec::new();
    };
    let key = event.title.clone();
    if state
        .reminders
        .get(&key)
        .is_some_and(|last| now - last < REMINDER_INTERVAL_SECS)
    {
        return Vec::new();
    }
    state.reminders.insert(key, now);
    vec![event]
}

/// Load the watch plan: built live from the vault folder when the vault is here, otherwise the
/// imported copy.
pub fn load_package(data_dir: &Path) -> Result<WatchPackage> {
    if super::storage::config_exists(data_dir) {
        let config = super::storage::load_config(data_dir)?;
        return WatchPackage::from_vault(data_dir, &config);
    }
    let path = data_dir.join(WATCH_PACKAGE_FILE);
    if !path.is_file() {
        bail!(
            "no vault and no watch plan in {}; import one with `anzen watch import`",
            data_dir.display()
        );
    }
    let package: WatchPackage = read_json(&path)?;
    WatchTargets::new(&package)?;
    Ok(package)
}

/// On a watcher-only computer: store a watch plan exported from the phone. A newer export of
/// the same vault replaces the old one.
pub fn import_package(data_dir: &Path, package: &WatchPackage) -> Result<()> {
    if super::storage::config_exists(data_dir) {
        bail!(
            "{} holds the vault itself; run `anzen watch run` there directly",
            data_dir.display()
        );
    }
    WatchTargets::new(package)?;
    let path = data_dir.join(WATCH_PACKAGE_FILE);
    if path.is_file() {
        let old: WatchPackage = read_json(&path)?;
        if old.network != package.network || old.vault_descriptor != package.vault_descriptor {
            // A key rotation changes the vault; say so rather than silently switching.
            bail!(
                "this folder watches a different vault; use a new folder, or delete {}",
                path.display()
            );
        }
    }
    write_json(&path, package)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        chain::WatchedTransaction,
        keys::DeviceKeys,
        policy::{SavingsPolicy, VaultPolicy},
    };
    use bitcoin::{
        Amount, BlockHash, Sequence, TxIn, TxOut, Witness, absolute::LockTime, key::Secp256k1,
        transaction::Version,
    };

    const UNLOCK: u32 = 1_924_992_000; // 2031-01-01
    const ALLOWANCE_UNLOCK: u32 = 1_800_000_000; // 2027-01-15

    struct Fixture {
        package: WatchPackage,
        vault: VaultPolicy,
        savings: SavingsPolicy,
        controller: ScriptBuf,
        trigger: Txid,
        rung: RungPolicy,
    }

    fn fixture() -> Fixture {
        let secp = Secp256k1::new();
        let phone = DeviceKeys::generate(&secp).unwrap();
        let hww = DeviceKeys::generate(&secp).unwrap();
        let heir = DeviceKeys::generate(&secp).unwrap();
        let vault = VaultPolicy::with_heir(
            phone.vault_pubkey,
            hww.vault_pubkey,
            Some(heir.vault_pubkey),
            Network::Regtest,
        )
        .unwrap();
        let savings = SavingsPolicy::with_heir(
            phone.vault_pubkey,
            hww.vault_pubkey,
            Some(heir.vault_pubkey),
            UNLOCK,
            Network::Regtest,
        )
        .unwrap();
        let controller = ControllerPolicy::new_for_network(
            phone.vault_pubkey,
            hww.vault_pubkey,
            crate::core::policy::InternalKey::Legacy,
            Network::Regtest,
        )
        .unwrap();
        let trigger = Txid::from_byte_array([9; 32]);
        let package = WatchPackage {
            version: 1,
            kind: WATCH_PACKAGE_KIND.to_owned(),
            network: "regtest".to_owned(),
            vault_descriptor: vault.descriptor_string(),
            controller_address: controller.address.to_string(),
            savings_descriptors: vec![savings.descriptor_string()],
            known: vec![KnownTransaction {
                txid: trigger.to_string(),
                kind: KnownKind::EmergencyTrigger,
            }],
            allowance_unlocks: vec![ALLOWANCE_UNLOCK],
        };
        Fixture {
            package,
            vault,
            savings,
            controller: controller.address.script_pubkey(),
            trigger,
            rung: RungPolicy::new_for_network(
                phone.vault_pubkey,
                hww.vault_pubkey,
                ALLOWANCE_UNLOCK,
                crate::core::policy::InternalKey::Legacy,
                Network::Regtest,
            )
            .unwrap(),
        }
    }

    fn cursor(height: u64) -> WatchCursor {
        WatchCursor {
            height,
            block_hash: BlockHash::from_byte_array([height as u8; 32]),
        }
    }

    fn coin(byte: u8, script: &ScriptBuf, height: u64) -> VaultUtxo {
        VaultUtxo {
            outpoint: OutPoint::new(Txid::from_byte_array([byte; 32]), 0),
            txout: TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: script.clone(),
            },
            confirmation_height: height,
        }
    }

    /// A transaction spending `from` through `leaf_script`, paying `to`.
    fn spend(from: &[OutPoint], leaf_script: Option<&ScriptBuf>, to: &[&ScriptBuf]) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: from
                .iter()
                .map(|outpoint| {
                    let mut witness = Witness::new();
                    if let Some(script) = leaf_script {
                        witness.push([1u8; 64]);
                        witness.push(script.as_bytes());
                        witness.push([0xc0u8; 33]);
                    }
                    TxIn {
                        previous_output: *outpoint,
                        sequence: Sequence::MAX,
                        witness,
                        ..Default::default()
                    }
                })
                .collect(),
            output: to
                .iter()
                .map(|script| TxOut {
                    value: Amount::from_sat(500_000),
                    script_pubkey: (*script).clone(),
                })
                .collect(),
        }
    }

    fn state_with(f: &Fixture, coins: Vec<VaultUtxo>) -> (WatchTargets, WatchState) {
        let targets = WatchTargets::new(&f.package).unwrap();
        let mut state = WatchState::default();
        apply_baseline(
            &targets,
            &mut state,
            WatchBaseline {
                cursor: cursor(100),
                coins,
                history: Vec::new(),
            },
            Rebaseline::PlanChanged,
        );
        (targets, state)
    }

    fn activity(transactions: Vec<(Transaction, Option<u64>)>) -> WatchActivity {
        WatchActivity {
            cursor: cursor(101),
            transactions: transactions
                .into_iter()
                .map(|(transaction, height)| WatchedTransaction {
                    transaction,
                    height,
                })
                .collect(),
            caught_up: true,
        }
    }

    fn vault_script(f: &Fixture) -> ScriptBuf {
        f.vault.address.script_pubkey()
    }

    #[test]
    fn allowance_months_are_watched_and_described() {
        let f = fixture();
        let script = f.rung.address.script_pubkey();
        let cases = [
            (
                SpendPath::PhoneRecovery,
                ScriptBuf::new(),
                Level::Notice,
                "Allowance month claimed",
            ),
            (
                SpendPath::PhoneRecovery,
                vault_script(&f),
                Level::Info,
                "1 unused allowance month returned to the vault",
            ),
            (
                SpendPath::HwwRecovery,
                vault_script(&f),
                Level::Notice,
                "1 allowance month moved by the hardware wallet",
            ),
        ];
        for (path, to, level, title) in cases {
            let (targets, mut state) = state_with(&f, vec![coin(1, &script, 50)]);
            assert!(targets.scripts().contains(&script));
            let leaf = f.rung.leaf(path).unwrap().script;
            let tx = spend(&[coin(1, &script, 50).outpoint], Some(&leaf), &[&to]);
            let events = apply_activity(&targets, &mut state, activity(vec![(tx, Some(101))]));
            assert_eq!(events.len(), 1, "{path:?}");
            assert_eq!(events[0].level, level);
            assert_eq!(events[0].title, title);
        }
    }

    #[test]
    fn each_leaf_gets_its_own_alert() {
        let f = fixture();
        let script = vault_script(&f);
        let cases = [
            (
                SpendPath::Cooperative,
                Level::Notice,
                "Vault coins moved with both keys",
            ),
            (
                SpendPath::PhoneRecovery,
                Level::Alert,
                "Vault coins moved with the phone alone",
            ),
            (
                SpendPath::HwwRecovery,
                Level::Alert,
                "Vault coins moved with the hardware wallet alone",
            ),
            (
                SpendPath::Heir,
                Level::Alert,
                "Your heir claimed Vault coins",
            ),
        ];
        for (path, level, title) in cases {
            let (targets, mut state) = state_with(&f, vec![coin(1, &script, 50)]);
            let leaf = f.vault.leaf(path).unwrap().script;
            let tx = spend(
                &[coin(1, &script, 50).outpoint],
                Some(&leaf),
                &[&ScriptBuf::new()],
            );
            let events = apply_activity(&targets, &mut state, activity(vec![(tx, Some(101))]));
            assert_eq!(events.len(), 1, "{path:?}");
            assert_eq!(events[0].level, level);
            assert_eq!(events[0].title, title);
            assert_eq!(events[0].amount_sats, Some(1_000_000));
            assert!(state.coins.is_empty());
        }
        // A script the vault never wrote.
        let (targets, mut state) = state_with(&f, vec![coin(1, &script, 50)]);
        let tx = spend(
            &[coin(1, &script, 50).outpoint],
            Some(&ScriptBuf::from_bytes(vec![0x51])),
            &[],
        );
        let events = apply_activity(&targets, &mut state, activity(vec![(tx, None)]));
        assert_eq!(events[0].level, Level::Alert);
        assert_eq!(events[0].title, "Vault coins moved in an unknown way");
    }

    #[test]
    fn savings_spends_name_their_lock() {
        let f = fixture();
        let script = f.savings.address.script_pubkey();
        let (targets, mut state) = state_with(&f, vec![coin(2, &script, 50)]);
        let leaf = f.savings.leaf(SpendPath::HwwRecovery).unwrap().script;
        let tx = spend(&[coin(2, &script, 50).outpoint], Some(&leaf), &[]);
        let events = apply_activity(&targets, &mut state, activity(vec![(tx, Some(101))]));
        assert_eq!(
            events[0].title,
            "Savings until 2031-01-01 coins moved with the hardware wallet alone"
        );
    }

    #[test]
    fn a_planned_emergency_trigger_alerts_once_from_the_mempool_to_confirmation() {
        let f = fixture();
        let script = vault_script(&f);
        let (mut targets, mut state) = state_with(&f, vec![coin(1, &script, 50)]);
        let tx = spend(
            &[coin(1, &script, 50).outpoint],
            Some(&f.vault.leaf(SpendPath::Cooperative).unwrap().script),
            &[&script, &script],
        );
        targets
            .known
            .insert(tx.compute_txid(), KnownKind::EmergencyTrigger);
        let events = apply_activity(&targets, &mut state, activity(vec![(tx.clone(), None)]));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].level, Level::Alert);
        assert_eq!(events[0].title, "Emergency withdrawal started");
        assert!(!events[0].confirmed);
        // Mempool sightings do not change the coins.
        assert_eq!(state.coins.len(), 1);
        assert!(!state.handled().contains(&tx.compute_txid()));

        let events = apply_activity(
            &targets,
            &mut state,
            activity(vec![(tx.clone(), Some(101))]),
        );
        assert!(events.is_empty(), "no second alert on confirmation");
        assert_eq!(
            state.coins.len(),
            2,
            "the staging and change outputs are watched"
        );
        assert!(state.handled().contains(&tx.compute_txid()));
        let _ = f.trigger;
    }

    #[test]
    fn deposits_and_cancels_are_described() {
        let f = fixture();
        let savings = f.savings.address.script_pubkey();
        let (targets, mut state) = state_with(&f, vec![coin(3, &f.controller, 50)]);
        let deposit = spend(
            &[OutPoint::new(Txid::from_byte_array([4; 32]), 1)],
            None,
            &[&savings],
        );
        let cancel = spend(&[coin(3, &f.controller, 50).outpoint], None, &[]);
        let events = apply_activity(
            &targets,
            &mut state,
            activity(vec![(deposit, Some(101)), (cancel, Some(101))]),
        );
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].title, "Deposit to Savings until 2031-01-01");
        assert_eq!(events[0].amount_sats, Some(500_000));
        assert_eq!(
            events[1].title,
            "An allowance or emergency withdrawal was cancelled"
        );
        assert_eq!(events[1].amount_sats, None);
        assert_eq!(
            state.coins.len(),
            1,
            "the deposit is watched, the connector is gone"
        );
    }

    #[test]
    fn alert_text_never_carries_amounts_addresses_or_txids() {
        let f = fixture();
        let script = vault_script(&f);
        let (targets, mut state) = state_with(&f, vec![coin(1, &script, 50)]);
        let tx = spend(
            &[coin(1, &script, 50).outpoint],
            Some(&f.vault.leaf(SpendPath::PhoneRecovery).unwrap().script),
            &[&script],
        );
        let txid = tx.compute_txid().to_string();
        let events = apply_activity(&targets, &mut state, activity(vec![(tx, Some(101))]));
        for event in events {
            let text = format!("{} {}", event.title, event.message);
            assert!(!text.contains(&txid));
            assert!(!text.contains(&f.vault.address.to_string()));
            assert!(!text.contains("1000000") && !text.contains("0.01"));
        }
    }

    #[test]
    fn losing_track_reports_what_changed_meanwhile() {
        let f = fixture();
        let script = vault_script(&f);
        let (targets, mut state) = state_with(&f, vec![coin(1, &script, 50), coin(2, &script, 50)]);
        let events = apply_baseline(
            &targets,
            &mut state,
            WatchBaseline {
                cursor: cursor(5_000),
                coins: vec![coin(2, &script, 50), coin(7, &script, 4_000)],
                history: Vec::new(),
            },
            Rebaseline::LostTrack,
        );
        assert_eq!(events.len(), 1);
        assert!(
            events[0]
                .message
                .contains("1 vault or savings coin(s) moved and 1 arrived")
        );
        let coins = state.coins.clone();
        let same = apply_baseline(
            &targets,
            &mut state,
            WatchBaseline {
                cursor: cursor(5_001),
                coins,
                history: Vec::new(),
            },
            Rebaseline::LostTrack,
        );
        assert!(same.is_empty());
    }

    #[test]
    fn rollover_reminders_repeat_weekly_at_most() {
        let f = fixture();
        let script = vault_script(&f);
        let (targets, mut state) = state_with(&f, vec![coin(1, &script, 1_000)]);
        let opens = 1_000 + u64::from(PHONE_RECOVERY_BLOCKS);
        assert!(reminders(&targets, &mut state, opens - CEREMONY_WARNING_BLOCKS - 2, 0).is_empty());
        let due = reminders(&targets, &mut state, opens - 30 * 144 - 1, 0);
        assert_eq!(due[0].title, "Yearly renewal due");
        assert!(due[0].message.contains("about 30 days"));
        assert!(reminders(&targets, &mut state, opens - 29 * 144, 86_400).is_empty());
        assert_eq!(
            reminders(
                &targets,
                &mut state,
                opens - 20 * 144,
                REMINDER_INTERVAL_SECS
            )
            .len(),
            1
        );
        let open = reminders(&targets, &mut state, opens, REMINDER_INTERVAL_SECS);
        assert_eq!(open[0].level, Level::Alert);
    }

    #[test]
    fn a_watch_plan_must_be_an_anzen_vault() {
        let f = fixture();
        assert!(WatchTargets::new(&f.package).is_ok());
        let mut wrong = f.package.clone();
        wrong.vault_descriptor = f.savings.descriptor_string();
        assert!(WatchTargets::new(&wrong).is_err());
        let mut wrong = f.package.clone();
        wrong.kind = "something-else".to_owned();
        assert!(WatchTargets::new(&wrong).is_err());
        let mut wrong = f.package.clone();
        wrong.network = "bitcoin".to_owned();
        assert!(WatchTargets::new(&wrong).is_err());
    }

    #[test]
    fn importing_refuses_a_vault_folder_and_a_different_vault() {
        let f = fixture();
        let dir = tempfile::tempdir().unwrap();
        import_package(dir.path(), &f.package).unwrap();
        import_package(dir.path(), &f.package).unwrap();
        assert_eq!(load_package(dir.path()).unwrap(), f.package);
        let other = fixture();
        assert!(import_package(dir.path(), &other.package).is_err());

        let vault_dir = tempfile::tempdir().unwrap();
        crate::test_support::initialize(vault_dir.path()).unwrap();
        assert!(import_package(vault_dir.path(), &f.package).is_err());
        // The owner's folder builds its plan live.
        let live = load_package(vault_dir.path()).unwrap();
        assert!(WatchTargets::new(&live).is_ok());
        assert!(live.known.is_empty());
    }
}
