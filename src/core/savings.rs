//! Hard-locked savings: deposit addresses that nothing can spend before a calendar date, and
//! the per-coin age report that shows how long each vault or savings coin stays protected.
//!
//! A savings lock never needs a ceremony or renewal. Every spending path is dated with an
//! absolute time (see `SavingsPolicy`), so deposits can keep arriving at the same address.

use super::{
    chain::ChainTip,
    policy::{SAVINGS_HWW_RECOVERY_SECS, SAVINGS_PHONE_RECOVERY_SECS, SavingsPolicy},
    storage::VaultConfig,
    types::VaultUtxo,
};
use anyhow::{Context, Result, bail};
use bitcoin::{Address, Network, OutPoint, key::XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Average seconds per block, used only to turn block counts into approximate days.
const SECONDS_PER_BLOCK: u64 = 600;
/// A vault coin this close to its phone-only recovery height should join a ceremony soon.
pub const CEREMONY_WARNING_BLOCKS: u64 = 60 * 144;

/// One hard-locked savings address. It records the keys it was created with, so a later phone
/// rotation (which cannot move locked coins) never changes the address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavingsLock {
    pub unlock: u32,
    pub phone_vault_pubkey: String,
    pub hww_vault_pubkey: String,
    pub address: String,
    /// Recurring deposits go here by default.
    #[serde(default)]
    pub default_deposit: bool,
}

impl SavingsLock {
    pub fn new(config: &VaultConfig, unlock: u32) -> Result<Self> {
        let phone_vault_pubkey = config.phone_vault_pubkey.clone();
        let hww_vault_pubkey = config.hww_vault_pubkey.clone();
        let policy = SavingsPolicy::new_for_network(
            XOnlyPublicKey::from_str(&phone_vault_pubkey)?,
            XOnlyPublicKey::from_str(&hww_vault_pubkey)?,
            unlock,
            config.bitcoin_network()?,
        )?;
        Ok(Self {
            unlock,
            phone_vault_pubkey,
            hww_vault_pubkey,
            address: policy.address.to_string(),
            default_deposit: false,
        })
    }

    /// Rebuild the policy and check it still produces the stored address.
    pub fn policy(&self, network: Network) -> Result<SavingsPolicy> {
        let policy = SavingsPolicy::new_for_network(
            XOnlyPublicKey::from_str(&self.phone_vault_pubkey)?,
            XOnlyPublicKey::from_str(&self.hww_vault_pubkey)?,
            self.unlock,
            network,
        )?;
        if policy.address.to_string() != self.address {
            bail!("savings lock {} does not match its keys", self.address);
        }
        Ok(policy)
    }

    pub fn address(&self, network: Network) -> Result<Address> {
        Ok(self.policy(network)?.address)
    }
}

/// Add a savings lock unlocking at `unlock` (a Unix time after `now`). The first lock, or any
/// lock created with `make_default`, becomes the default deposit address.
pub fn add_lock(
    config: &mut VaultConfig,
    unlock: u32,
    now: i64,
    make_default: bool,
) -> Result<SavingsLock> {
    if i64::from(unlock) <= now {
        bail!("the unlock date must be in the future");
    }
    if config.savings_locks.iter().any(|lock| {
        lock.unlock == unlock
            && lock.phone_vault_pubkey == config.phone_vault_pubkey
            && lock.hww_vault_pubkey == config.hww_vault_pubkey
    }) {
        bail!("a savings lock with this unlock date already exists");
    }
    let mut lock = SavingsLock::new(config, unlock)?;
    lock.default_deposit = make_default || config.savings_locks.is_empty();
    if lock.default_deposit {
        for existing in &mut config.savings_locks {
            existing.default_deposit = false;
        }
    }
    config.savings_locks.push(lock.clone());
    config.savings_locks.sort_by_key(|lock| lock.unlock);
    Ok(lock)
}

/// Where recurring deposits should go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositTarget {
    Savings(SavingsLock),
    /// No savings lock exists yet; vault deposits need a ceremony within about 14 months.
    Vault(String),
}

pub fn deposit_target(config: &VaultConfig) -> DepositTarget {
    config
        .savings_locks
        .iter()
        .find(|lock| lock.default_deposit)
        .cloned()
        .map_or_else(
            || DepositTarget::Vault(config.vault_address.clone()),
            DepositTarget::Savings,
        )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoinPot {
    Vault,
    Savings { unlock: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoinStatus {
    /// Vault coin: needs both keys until its phone-only recovery opens.
    Protected {
        recovery_height: u64,
        blocks_left: u64,
    },
    /// Vault coin close to its recovery height: include it in a ceremony soon.
    CeremonyDue {
        recovery_height: u64,
        blocks_left: u64,
    },
    /// Vault coin past its recovery height: the phone key alone can move it.
    RecoveryOpen { recovery_height: u64 },
    /// Savings coin before its date: nobody can move it.
    Locked { unlock: u32, seconds_left: u64 },
    /// Savings coin after its date: both keys can move it; single-key recovery opens later.
    Unlocked { phone_recovery_at: u32 },
    /// Savings coin past its single-key recovery date.
    SavingsRecoveryOpen { phone_recovery_at: u32 },
}

impl CoinStatus {
    /// Lower is more urgent.
    fn urgency(&self) -> (u8, u64) {
        match *self {
            CoinStatus::RecoveryOpen { .. } | CoinStatus::SavingsRecoveryOpen { .. } => (0, 0),
            CoinStatus::CeremonyDue { blocks_left, .. } => (1, blocks_left),
            CoinStatus::Protected { blocks_left, .. } => (2, blocks_left * SECONDS_PER_BLOCK),
            CoinStatus::Unlocked { .. } => (2, u64::MAX),
            CoinStatus::Locked { seconds_left, .. } => (3, seconds_left),
        }
    }

    /// Approximate days until the next change, when there is one.
    pub fn days_left(&self) -> Option<u64> {
        match *self {
            CoinStatus::Protected { blocks_left, .. }
            | CoinStatus::CeremonyDue { blocks_left, .. } => {
                Some(blocks_left * SECONDS_PER_BLOCK / 86_400)
            }
            CoinStatus::Locked { seconds_left, .. } => Some(seconds_left / 86_400),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinAge {
    pub outpoint: OutPoint,
    pub value_sats: u64,
    pub pot: CoinPot,
    pub status: CoinStatus,
}

/// Describe every vault and savings coin, most urgent first. `next_height` and `median_time`
/// describe the next block, which is the earliest any spend could confirm.
pub fn coin_ages(
    config: &VaultConfig,
    tip: &ChainTip,
    vault: &[VaultUtxo],
    savings: &[(SavingsLock, Vec<VaultUtxo>)],
) -> Result<Vec<CoinAge>> {
    let next_height = tip.height + 1;
    let now = tip.median_time;
    let mut coins = Vec::new();
    for utxo in vault {
        let recovery_height = utxo
            .confirmation_height
            .checked_add(u64::from(config.phone_recovery_blocks))
            .context("vault recovery height overflowed")?;
        let status = if next_height >= recovery_height {
            CoinStatus::RecoveryOpen { recovery_height }
        } else {
            let blocks_left = recovery_height - next_height;
            if blocks_left <= CEREMONY_WARNING_BLOCKS {
                CoinStatus::CeremonyDue {
                    recovery_height,
                    blocks_left,
                }
            } else {
                CoinStatus::Protected {
                    recovery_height,
                    blocks_left,
                }
            }
        };
        coins.push(CoinAge {
            outpoint: utxo.outpoint,
            value_sats: utxo.txout.value.to_sat(),
            pot: CoinPot::Vault,
            status,
        });
    }
    for (lock, utxos) in savings {
        let phone_recovery_at = lock
            .unlock
            .checked_add(SAVINGS_PHONE_RECOVERY_SECS)
            .context("savings recovery date overflowed")?;
        // Savings recovery is dated, so HWW recovery (a month later) never comes first.
        const { assert!(SAVINGS_HWW_RECOVERY_SECS > SAVINGS_PHONE_RECOVERY_SECS) };
        // A CLTV spend needs the median time past strictly beyond the date.
        let status = if now <= u64::from(lock.unlock) {
            CoinStatus::Locked {
                unlock: lock.unlock,
                seconds_left: u64::from(lock.unlock) - now,
            }
        } else if now <= u64::from(phone_recovery_at) {
            CoinStatus::Unlocked { phone_recovery_at }
        } else {
            CoinStatus::SavingsRecoveryOpen { phone_recovery_at }
        };
        for utxo in utxos {
            coins.push(CoinAge {
                outpoint: utxo.outpoint,
                value_sats: utxo.txout.value.to_sat(),
                pot: CoinPot::Savings {
                    unlock: lock.unlock,
                },
                status,
            });
        }
    }
    coins.sort_by_key(|coin| coin.status.urgency());
    Ok(coins)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::initialize;
    use bitcoin::{Amount, BlockHash, ScriptBuf, TxOut, Txid, hashes::Hash};

    const JAN_2030: u32 = 1_893_456_000;

    fn tip(height: u64, median_time: u64) -> ChainTip {
        ChainTip {
            network: Network::Regtest,
            height,
            median_time,
            best_block_hash: BlockHash::all_zeros(),
        }
    }

    fn utxo(byte: u8, height: u64) -> VaultUtxo {
        VaultUtxo {
            outpoint: OutPoint::new(Txid::from_byte_array([byte; 32]), 0),
            txout: TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: ScriptBuf::new(),
            },
            confirmation_height: height,
        }
    }

    #[test]
    fn first_lock_becomes_the_default_deposit_address() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = initialize(dir.path()).unwrap().config;
        assert!(matches!(deposit_target(&config), DepositTarget::Vault(_)));
        let first = add_lock(&mut config, JAN_2030, 0, false).unwrap();
        assert!(first.default_deposit);
        assert_eq!(
            deposit_target(&config),
            DepositTarget::Savings(first.clone())
        );
        let later = add_lock(&mut config, JAN_2030 + 86_400 * 365, 0, true).unwrap();
        assert_eq!(deposit_target(&config), DepositTarget::Savings(later));
        assert!(!config.savings_locks[0].default_deposit);
        assert_ne!(first.address, config.vault_address);
        assert_eq!(
            first
                .address(config.bitcoin_network().unwrap())
                .unwrap()
                .to_string(),
            first.address
        );
    }

    #[test]
    fn locks_reject_past_dates_duplicates_and_altered_keys() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = initialize(dir.path()).unwrap().config;
        assert!(add_lock(&mut config, JAN_2030, i64::from(JAN_2030), false).is_err());
        add_lock(&mut config, JAN_2030, 0, false).unwrap();
        assert!(add_lock(&mut config, JAN_2030, 0, false).is_err());
        let mut tampered = config.savings_locks[0].clone();
        tampered.hww_vault_pubkey = tampered.phone_vault_pubkey.clone();
        assert!(tampered.policy(config.bitcoin_network().unwrap()).is_err());
    }

    #[test]
    fn coin_ages_put_the_most_urgent_coin_first() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = initialize(dir.path()).unwrap().config;
        let lock = add_lock(&mut config, JAN_2030, 0, false).unwrap();
        let recovery = u64::from(config.phone_recovery_blocks);
        let height = 200_000;
        let coins = coin_ages(
            &config,
            &tip(height, u64::from(JAN_2030) - 86_400 * 10),
            &[
                utxo(1, height),                  // fresh deposit
                utxo(2, height + 100 - recovery), // 100 blocks from recovery
                utxo(3, height - recovery),       // recovery already open
            ],
            &[(lock, vec![utxo(4, 10)])],
        )
        .unwrap();
        let statuses = coins.iter().map(|coin| coin.status).collect::<Vec<_>>();
        assert!(matches!(statuses[0], CoinStatus::RecoveryOpen { .. }));
        assert!(matches!(
            statuses[1],
            CoinStatus::CeremonyDue {
                blocks_left: 99,
                ..
            }
        ));
        assert!(matches!(statuses[2], CoinStatus::Protected { .. }));
        assert!(matches!(
            statuses[3],
            CoinStatus::Locked {
                seconds_left: 864_000,
                ..
            }
        ));
        assert_eq!(statuses[3].days_left(), Some(10));
    }

    #[test]
    fn savings_unlock_then_open_recovery_by_date() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = initialize(dir.path()).unwrap().config;
        let lock = add_lock(&mut config, JAN_2030, 0, false).unwrap();
        let status_at = |time: u64| {
            coin_ages(
                &config,
                &tip(1, time),
                &[],
                &[(lock.clone(), vec![utxo(1, 1)])],
            )
            .unwrap()[0]
                .status
        };
        // A CLTV path opens once the median time past is strictly beyond its date.
        assert!(matches!(
            status_at(u64::from(JAN_2030)),
            CoinStatus::Locked { .. }
        ));
        assert!(matches!(
            status_at(u64::from(JAN_2030) + 1),
            CoinStatus::Unlocked { .. }
        ));
        assert!(matches!(
            status_at(u64::from(JAN_2030 + SAVINGS_PHONE_RECOVERY_SECS)),
            CoinStatus::Unlocked { .. }
        ));
        assert!(matches!(
            status_at(u64::from(JAN_2030 + SAVINGS_PHONE_RECOVERY_SECS) + 1),
            CoinStatus::SavingsRecoveryOpen { .. }
        ));
    }
}
