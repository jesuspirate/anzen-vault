use anzen::{
    cold_wallet,
    core::{
        EMERGENCY_ACCESS_DELAY_SECONDS, MONTHLY_ALLOWANCE_DELAY_SECONDS,
        chain::{BitcoinCoreBackend, Blockchain, RpcConfig},
        ladder,
        policy::SpendPath,
        storage::{initialize_vault, set_policy_limits},
    },
    hot_wallet::{self, HotWallet, HotWalletBackend},
};
use bitcoin::{Address, Amount, Network, TxOut};
use chrono::{DateTime, Utc};
use std::{env, str::FromStr};

fn rpc_from_env() -> BitcoinCoreBackend {
    BitcoinCoreBackend::connect(
        &RpcConfig {
            url: env::var("ANZEN_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:18443".to_owned()),
            user: env::var("ANZEN_RPC_USER").unwrap_or_else(|_| "anzen".to_owned()),
            password: env::var("ANZEN_RPC_PASSWORD").unwrap_or_else(|_| "anzen".to_owned()),
        },
        Network::Regtest,
    )
    .unwrap()
}

#[test]
#[ignore = "requires a disposable Bitcoin Core regtest node"]
fn real_regtest_ladder_claims_returns_and_enforces_each_month_date() {
    let dir = tempfile::tempdir().unwrap();
    hot_wallet::initialize(dir.path(), Network::Regtest).unwrap();
    cold_wallet::initialize(dir.path(), Network::Regtest).unwrap();
    let config = initialize_vault(dir.path()).unwrap();
    let rpc = rpc_from_env();
    let vault_address = Address::from_str(&config.vault_address)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap();
    let mut hot = HotWallet::open_or_create(dir.path()).unwrap();
    let mining_address = hot.next_receive_address().unwrap();

    rpc.mine(1, &vault_address).unwrap();
    rpc.mine(100, &mining_address).unwrap();
    assert_eq!(rpc.scan_vault(&config).unwrap().len(), 1);

    let chain_time = rpc.chain_info().unwrap().median_time as i64;
    let captured_now = Utc::now().timestamp().max(chain_time);
    let now = DateTime::from_timestamp(captured_now, 0).unwrap();
    let batch_dir = dir.path().join("batch");
    let prepared =
        hot_wallet::propose_policy(dir.path(), &rpc, now, 10_000_000, 0, 1, &batch_dir).unwrap();
    assert_eq!(prepared.allowance_count, 12);
    let approved = cold_wallet::approve_policy(dir.path(), &batch_dir).unwrap();
    assert!(approved.hww_approved);
    let schedule = hot_wallet::activate_policy(dir.path(), &rpc, &batch_dir).unwrap();
    rpc.mine(1, &mining_address).unwrap();
    let retried = hot_wallet::activate_policy(dir.path(), &rpc, &batch_dir).unwrap();
    assert_eq!(retried.rollover_txid, schedule.rollover_txid);
    let encrypted_backup = dir
        .path()
        .join("phone/transactions")
        .join(&schedule.rollover_txid)
        .join("approved-policy.json");
    assert_cmd::Command::cargo_bin("anzen")
        .unwrap()
        .arg("--data-dir")
        .arg(dir.path())
        .args(["phone", "activate-policy"])
        .arg(encrypted_backup)
        .assert()
        .success();
    // The remainder is back in the vault; the months carry no controller state.
    assert_eq!(rpc.scan_vault(&config).unwrap().len(), 1);
    assert!(rpc.scan_connectors(&config).unwrap().is_empty());
    assert_eq!(hot_wallet::live_rungs(dir.path(), &rpc).unwrap().len(), 12);
    let entries = schedule.entries.clone();
    for (index, entry) in entries.iter().enumerate() {
        assert_eq!(
            i64::from(entry.unlock) - captured_now,
            (index as i64 + 1) * i64::from(MONTHLY_ALLOWANCE_DELAY_SECONDS)
        );
    }

    let premature = hot_wallet::claim_month(dir.path(), &rpc, 1, false, None).unwrap_err();
    assert!(format!("{premature:#}").contains("unlocks after"));
    // Consensus, not just the app, holds a month until its date.
    let config_now = anzen::core::storage::load_config(dir.path()).unwrap();
    let early = ladder::LiveRung::new(&config_now, &entries[3]).unwrap();
    let phone =
        anzen::core::storage::load_device_keys(dir.path(), anzen::core::storage::PHONE_DEVICE_FILE)
            .unwrap();
    let spend = ladder::build_rung_spend(
        std::slice::from_ref(&early),
        SpendPath::PhoneRecovery,
        vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: mining_address.script_pubkey(),
        }],
        1,
    )
    .unwrap();
    let early_tx = ladder::sign_as_phone(spend, &[early], &phone).unwrap();
    let rejected = rpc.broadcast(&early_tx).unwrap_err();
    assert!(format!("{rejected:#}").contains("non-final"));

    advance_mtp(&rpc, entries[0].unlock, &mining_address);
    let claimed = hot_wallet::claim_month(dir.path(), &rpc, 1, false, Some(1_000_000)).unwrap();
    assert_eq!(claimed.returned_sats, 9_000_000);
    assert_eq!(claimed.sent_sats + claimed.fee_sats, 1_000_000);
    rpc.mine(1, &mining_address).unwrap();
    let again = hot_wallet::claim_month(dir.path(), &rpc, 1, false, None).unwrap_err();
    assert!(format!("{again:#}").contains("not available"));
    assert!(
        hot_wallet::return_unclaimed_months(dir.path(), &rpc, false)
            .unwrap()
            .is_none()
    );

    // Month 2 goes back once month 3 has unlocked; month 3 only on request.
    advance_mtp(&rpc, entries[2].unlock, &mining_address);
    let balance_before = vault_balance(&rpc, &config);
    let returned = hot_wallet::return_unclaimed_months(dir.path(), &rpc, false)
        .unwrap()
        .unwrap();
    assert_eq!(returned.month_count, 1);
    rpc.mine(1, &mining_address).unwrap();
    let returned_all = hot_wallet::return_unclaimed_months(dir.path(), &rpc, true)
        .unwrap()
        .unwrap();
    assert_eq!(returned_all.month_count, 1);
    rpc.mine(1, &mining_address).unwrap();
    assert_eq!(
        vault_balance(&rpc, &config),
        balance_before + returned.returned_sats + returned_all.returned_sats
    );
    assert_eq!(hot_wallet::live_rungs(dir.path(), &rpc).unwrap().len(), 9);
}

#[test]
#[ignore = "requires a disposable Bitcoin Core regtest node"]
fn real_regtest_enforces_emergency_delay_and_cancellation() {
    let dir = tempfile::tempdir().unwrap();
    hot_wallet::initialize(dir.path(), Network::Regtest).unwrap();
    cold_wallet::initialize(dir.path(), Network::Regtest).unwrap();
    let config = initialize_vault(dir.path()).unwrap();
    let rpc = rpc_from_env();
    let vault_address = Address::from_str(&config.vault_address)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap();
    let mut hot = HotWallet::open_or_create(dir.path()).unwrap();
    let mining_address = hot.next_receive_address().unwrap();

    rpc.mine(1, &vault_address).unwrap();
    rpc.mine(100, &mining_address).unwrap();

    let chain_time = rpc.chain_info().unwrap().median_time as i64;
    let captured_now = Utc::now().timestamp().max(chain_time);
    let now = DateTime::from_timestamp(captured_now, 0).unwrap();
    let batch_dir = dir.path().join("emergency-cancel-batch");
    hot_wallet::propose_policy(dir.path(), &rpc, now, 10_000_000, 50_000_000, 1, &batch_dir)
        .unwrap();
    cold_wallet::approve_policy(dir.path(), &batch_dir).unwrap();
    hot_wallet::activate_policy(dir.path(), &rpc, &batch_dir).unwrap();
    set_policy_limits(dir.path(), 10_000_000, 50_000_000).unwrap();
    rpc.mine(1, &mining_address).unwrap();
    assert_eq!(rpc.scan_connectors(&config).unwrap().len(), 1);

    hot_wallet::initiate_emergency_access(dir.path(), &rpc).unwrap();
    rpc.mine(1, &mining_address).unwrap();

    let premature = hot_wallet::withdraw_emergency_access(dir.path(), &rpc).unwrap_err();
    let premature = format!("{premature:#}");
    assert!(premature.contains("non-BIP68-final") || premature.contains("non-final"));

    let balance_before_cancellation = vault_balance(&rpc, &config);
    hot_wallet::cancel_emergency_access(dir.path(), &rpc).unwrap();
    rpc.mine(1, &mining_address).unwrap();
    assert!(rpc.scan_connectors(&config).unwrap().is_empty());
    assert_eq!(vault_balance(&rpc, &config), balance_before_cancellation);
    let cancelled = hot_wallet::withdraw_emergency_access(dir.path(), &rpc).unwrap_err();
    assert!(format!("{cancelled:#}").contains("missingorspent"));
}

#[test]
#[ignore = "requires a disposable Bitcoin Core regtest node"]
fn real_regtest_releases_emergency_access_after_one_week() {
    let dir = tempfile::tempdir().unwrap();
    hot_wallet::initialize(dir.path(), Network::Regtest).unwrap();
    cold_wallet::initialize(dir.path(), Network::Regtest).unwrap();
    let config = initialize_vault(dir.path()).unwrap();
    let rpc = rpc_from_env();
    let vault_address = Address::from_str(&config.vault_address)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap();
    let mut hot = HotWallet::open_or_create(dir.path()).unwrap();
    let mining_address = hot.next_receive_address().unwrap();

    rpc.mine(1, &vault_address).unwrap();
    rpc.mine(100, &mining_address).unwrap();
    let chain_time = rpc.chain_info().unwrap().median_time as i64;
    let captured_now = Utc::now().timestamp().max(chain_time);
    let now = DateTime::from_timestamp(captured_now, 0).unwrap();
    let batch_dir = dir.path().join("emergency-withdraw-batch");
    hot_wallet::propose_policy(dir.path(), &rpc, now, 10_000_000, 50_000_000, 1, &batch_dir)
        .unwrap();
    cold_wallet::approve_policy(dir.path(), &batch_dir).unwrap();
    hot_wallet::activate_policy(dir.path(), &rpc, &batch_dir).unwrap();
    set_policy_limits(dir.path(), 10_000_000, 50_000_000).unwrap();
    rpc.mine(1, &mining_address).unwrap();

    let relative_lock_base = rpc.chain_info().unwrap().median_time;
    hot_wallet::initiate_emergency_access(dir.path(), &rpc).unwrap();
    rpc.mine(1, &mining_address).unwrap();
    let premature = hot_wallet::withdraw_emergency_access(dir.path(), &rpc).unwrap_err();
    let premature = format!("{premature:#}");
    assert!(premature.contains("non-BIP68-final") || premature.contains("non-final"));

    let unlock_time = u32::try_from(relative_lock_base).unwrap() + EMERGENCY_ACCESS_DELAY_SECONDS;
    advance_mtp(&rpc, unlock_time, &mining_address);
    hot_wallet::withdraw_emergency_access(dir.path(), &rpc).unwrap();
    rpc.mine(1, &mining_address).unwrap();
    assert!(rpc.scan_connectors(&config).unwrap().is_empty());

    let mut hot = HotWallet::open_or_create(dir.path()).unwrap();
    rpc.sync_hot_wallet(&mut hot).unwrap();
    assert!(hot.wallet.balance().total().to_sat() >= 50_000_000);
}

#[test]
#[ignore = "requires a disposable Bitcoin Core regtest node"]
fn real_regtest_hww_pulls_back_every_month_and_revokes_emergency_access() {
    let dir = tempfile::tempdir().unwrap();
    hot_wallet::initialize(dir.path(), Network::Regtest).unwrap();
    cold_wallet::initialize(dir.path(), Network::Regtest).unwrap();
    let config = initialize_vault(dir.path()).unwrap();
    let rpc = rpc_from_env();
    let vault_address = Address::from_str(&config.vault_address)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap();
    let mut hot = HotWallet::open_or_create(dir.path()).unwrap();
    let mining_address = hot.next_receive_address().unwrap();
    let safe_destination = hot.next_change_address().unwrap();
    rpc.mine(1, &vault_address).unwrap();
    rpc.mine(100, &mining_address).unwrap();

    let chain_time = rpc.chain_info().unwrap().median_time as i64;
    let now = DateTime::from_timestamp(Utc::now().timestamp().max(chain_time), 0).unwrap();
    let batch_dir = dir.path().join("hww-revoke-batch");
    hot_wallet::propose_policy(dir.path(), &rpc, now, 10_000_000, 50_000_000, 1, &batch_dir)
        .unwrap();
    cold_wallet::approve_policy(dir.path(), &batch_dir).unwrap();
    let schedule = hot_wallet::activate_policy(dir.path(), &rpc, &batch_dir).unwrap();
    rpc.mine(1, &mining_address).unwrap();
    let controllers = rpc.scan_connectors(&config).unwrap();
    assert_eq!(controllers.len(), 1);
    let balance_before_revocation = vault_balance(&rpc, &config);

    // The HWW knows its months without the phone's schedule.
    let approved = cold_wallet::approved_rungs(dir.path()).unwrap();
    assert_eq!(approved.len(), schedule.entries.len());
    let months = approved
        .iter()
        .map(|entry| ladder::LiveRung::new(&config, entry).unwrap())
        .collect::<Vec<_>>();
    let (rescue, _fee) =
        cold_wallet::rescue_months(dir.path(), &months, &vault_address, 1).unwrap();
    assert_eq!(rescue.output.len(), 1);
    assert_eq!(
        rescue.output[0].script_pubkey,
        vault_address.script_pubkey()
    );
    rpc.broadcast(&rescue).unwrap();
    let revocation =
        cold_wallet::revoke_policy(dir.path(), &config, &controllers, &safe_destination).unwrap();
    assert_eq!(revocation.output.len(), 1);
    assert_eq!(
        revocation.output[0].script_pubkey,
        safe_destination.script_pubkey()
    );
    rpc.broadcast(&revocation).unwrap();
    rpc.mine(1, &mining_address).unwrap();
    assert!(rpc.scan_connectors(&config).unwrap().is_empty());
    assert!(hot_wallet::live_rungs(dir.path(), &rpc).unwrap().is_empty());
    assert_eq!(
        vault_balance(&rpc, &config),
        balance_before_revocation + rescue.output[0].value.to_sat()
    );

    advance_mtp(&rpc, schedule.entries[0].unlock, &mining_address);
    let allowance = hot_wallet::claim_month(dir.path(), &rpc, 1, false, None).unwrap_err();
    assert!(format!("{allowance:#}").contains("not available"));
    let emergency = hot_wallet::initiate_emergency_access(dir.path(), &rpc).unwrap_err();
    assert!(format!("{emergency:#}").contains("missingorspent"));
}

fn vault_balance(rpc: &BitcoinCoreBackend, config: &anzen::core::storage::VaultConfig) -> u64 {
    rpc.scan_vault(config)
        .unwrap()
        .iter()
        .map(|utxo| utxo.txout.value.to_sat())
        .sum()
}

fn advance_mtp(rpc: &BitcoinCoreBackend, timestamp: u32, mining_address: &Address) {
    rpc.set_mock_time(u64::from(timestamp) + 60).unwrap();
    while rpc.chain_info().unwrap().median_time <= u64::from(timestamp) {
        rpc.mine(1, mining_address).unwrap();
    }
}
