use anzen::{
    core::chain::{BitcoinCoreBackend, Blockchain, RpcConfig},
    simple_wallet::{self, Frequency},
};
use bitcoin::Network;
use std::env;

const OWNER: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
const OTHER: &str =
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";

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
fn real_regtest_simple_mode_opens_one_payout_at_a_time_and_rescues_the_rest() {
    let rpc = rpc_from_env();
    let dir = tempfile::tempdir().unwrap();
    let init = simple_wallet::initialize(
        dir.path(),
        Network::Regtest,
        OWNER,
        true,
        Frequency::Monthly,
    )
    .unwrap();
    let rescue_words = init.rescue_words.unwrap();
    // Somewhere else to mine to and pay out to.
    let elsewhere = tempfile::tempdir().unwrap();
    let other = simple_wallet::initialize(
        elsewhere.path(),
        Network::Regtest,
        OTHER,
        false,
        Frequency::Monthly,
    )
    .unwrap()
    .inbox;

    rpc.mine(1, &init.inbox).unwrap();
    rpc.mine(100, &other).unwrap();
    let deposit = simple_wallet::inbox_coins(dir.path(), &rpc).unwrap();
    assert_eq!(deposit.len(), 1);
    let deposit_sats = deposit[0].txout.value.to_sat();

    let tip = rpc.chain_tip().unwrap();
    let now = u32::try_from(tip.median_time.max(chrono::Utc::now().timestamp() as u64)).unwrap();
    let amount = deposit_sats / 5;
    let plan = simple_wallet::lock(dir.path(), &rpc, amount, now, false).unwrap();
    assert_eq!(plan.payouts.len(), 5);
    let step = Frequency::Monthly.seconds();
    for (index, payout) in plan.payouts.iter().enumerate() {
        assert_eq!(payout.unlock, now + step * (index as u32 + 1));
    }
    assert_eq!(
        plan.payouts
            .iter()
            .map(|payout| payout.value_sats)
            .sum::<u64>()
            + plan.fee_sats,
        deposit_sats
    );
    rpc.mine(1, &other).unwrap();
    assert!(
        simple_wallet::inbox_coins(dir.path(), &rpc)
            .unwrap()
            .is_empty()
    );

    // Nothing is open yet, so the phone cannot claim anything.
    let error = simple_wallet::claim(dir.path(), &rpc, &other).unwrap_err();
    assert!(
        error.to_string().contains("no payout is open yet"),
        "{error:#}"
    );

    // Move the chain past the first payout's date.
    let first = plan.payouts[0].unlock;
    rpc.set_mock_time(u64::from(first) + 3_600).unwrap();
    rpc.mine(11, &other).unwrap();
    let claimed = simple_wallet::claim(dir.path(), &rpc, &other).unwrap();
    assert_eq!(claimed.payout_count, 1);
    rpc.mine(1, &other).unwrap();
    let statuses = simple_wallet::payout_statuses(dir.path(), &rpc).unwrap();
    assert_eq!(statuses.iter().filter(|status| status.live).count(), 4);
    assert!(
        statuses
            .iter()
            .filter(|status| status.live)
            .all(|status| !status.open)
    );

    // The rescue paper moves the four locked payouts at once, before their dates.
    let wrong = simple_wallet::rescue(dir.path(), &rpc, OTHER, &other).unwrap_err();
    assert!(
        wrong.to_string().contains("not this wallet's rescue words"),
        "{wrong:#}"
    );
    let rescued = simple_wallet::rescue(dir.path(), &rpc, &rescue_words, &other).unwrap();
    assert_eq!(rescued.payout_count, 4);
    rpc.mine(1, &other).unwrap();
    assert!(
        simple_wallet::payout_statuses(dir.path(), &rpc)
            .unwrap()
            .iter()
            .all(|status| !status.live)
    );
}
