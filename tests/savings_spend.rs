//! Spending hard-locked savings after their date: the phone and HWW build and sign real
//! transactions through the app's own code, and Bitcoin Core's script interpreter
//! (libbitcoinconsensus 26) checks each one.

use anzen::{
    cold_wallet,
    core::{
        policy::{SAVINGS_HWW_RECOVERY_SECS, SAVINGS_PHONE_RECOVERY_SECS},
        savings::{self, SavingsLock},
        savings_spend::{
            SavingsSpendPackage, approve_savings_spend, create_savings_spend,
            finalize_savings_spend, sign_savings_recovery, validate_savings_spend,
        },
        storage::{
            HWW_DEVICE_FILE, PHONE_DEVICE_FILE, VaultConfig, initialize_vault, load_device_keys,
        },
        types::VaultUtxo,
    },
    hot_wallet,
};
use bitcoin::{
    Address, Amount, Network, OutPoint, Psbt, Transaction, TxOut, Txid, absolute::LockTime,
    hashes::Hash,
};
use std::{path::Path, str::FromStr};

const UNLOCK: u32 = 1_924_992_000; // 2031-01-01 00:00 UTC
const FEE_RATE: u64 = 3;

fn setup(dir: &Path) -> (VaultConfig, SavingsLock, Vec<VaultUtxo>) {
    hot_wallet::initialize(dir, Network::Regtest).unwrap();
    cold_wallet::initialize(dir, Network::Regtest).unwrap();
    let mut config = initialize_vault(dir).unwrap();
    let lock = savings::add_lock(&mut config, UNLOCK, 0, false).unwrap();
    let script = lock.address(Network::Regtest).unwrap().script_pubkey();
    let utxos = (1..=2_u8)
        .map(|byte| VaultUtxo {
            outpoint: OutPoint::new(Txid::from_byte_array([byte; 32]), 0),
            txout: TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: script.clone(),
            },
            confirmation_height: 200,
        })
        .collect();
    (config, lock, utxos)
}

fn destination() -> Address {
    Address::from_str("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080")
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap()
}

fn verify(transaction: &Transaction, utxos: &[VaultUtxo]) {
    let bytes = bitcoin::consensus::serialize(transaction);
    let spent = utxos
        .iter()
        .map(|utxo| bitcoinconsensus::Utxo {
            script_pubkey: utxo.txout.script_pubkey.as_bytes().as_ptr(),
            script_pubkey_len: utxo.txout.script_pubkey.len() as u32,
            value: utxo.txout.value.to_sat() as i64,
        })
        .collect::<Vec<_>>();
    for (index, utxo) in utxos.iter().enumerate() {
        bitcoinconsensus::verify(
            utxo.txout.script_pubkey.as_bytes(),
            utxo.txout.value.to_sat(),
            &bytes,
            Some(&spent),
            index,
        )
        .unwrap_or_else(|error| panic!("input {index} rejected by consensus: {error:?}"));
    }
}

fn phone_proposal(
    dir: &Path,
    config: &VaultConfig,
    lock: &SavingsLock,
    utxos: &[VaultUtxo],
) -> SavingsSpendPackage {
    let phone = load_device_keys(dir, PHONE_DEVICE_FILE).unwrap();
    create_savings_spend(
        config,
        lock,
        utxos,
        u64::from(UNLOCK) + 1,
        &destination(),
        FEE_RATE,
        &phone,
    )
    .unwrap()
}

#[test]
fn phone_and_hww_spend_savings_after_the_unlock_date() {
    let dir = tempfile::tempdir().unwrap();
    let (config, lock, utxos) = setup(dir.path());
    let proposal = phone_proposal(dir.path(), &config, &lock, &utxos);
    assert_eq!(proposal.input_count, 2);
    assert_eq!(proposal.fee_rate_sat_vb, FEE_RATE);
    assert_eq!(proposal.sent_sats + proposal.fee_sats, 2_000_000);
    assert!(finalize_savings_spend(&config, &proposal).is_err());

    let hww = load_device_keys(dir.path(), HWW_DEVICE_FILE).unwrap();
    let approved = approve_savings_spend(&config, &proposal, &hww).unwrap();
    let (transaction, result) = finalize_savings_spend(&config, &approved).unwrap();
    assert_eq!(transaction.lock_time, LockTime::from_time(UNLOCK).unwrap());
    assert_eq!(result.sent_sats, proposal.sent_sats);
    // The fee estimate must cover the real witness.
    assert!(proposal.fee_sats >= transaction.vsize() as u64 * FEE_RATE);
    verify(&transaction, &utxos);
}

#[test]
fn nothing_is_built_before_the_chain_passes_the_unlock_date() {
    let dir = tempfile::tempdir().unwrap();
    let (config, lock, utxos) = setup(dir.path());
    let phone = load_device_keys(dir.path(), PHONE_DEVICE_FILE).unwrap();
    for median_time in [0, u64::from(UNLOCK) - 86_400, u64::from(UNLOCK)] {
        let error = create_savings_spend(
            &config,
            &lock,
            &utxos,
            median_time,
            &destination(),
            FEE_RATE,
            &phone,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("nothing can move it before then")
        );
    }
}

#[test]
fn the_hww_rejects_a_tampered_proposal() {
    let dir = tempfile::tempdir().unwrap();
    let (config, lock, utxos) = setup(dir.path());
    let proposal = phone_proposal(dir.path(), &config, &lock, &utxos);
    let hww = load_device_keys(dir.path(), HWW_DEVICE_FILE).unwrap();

    // The package claims a different destination than the transaction pays.
    let mut redirected = proposal.clone();
    redirected.destination =
        "bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qzf4jry".into();
    assert!(approve_savings_spend(&config, &redirected, &hww).is_err());

    // The transaction pays a different amount than the package shows.
    let mut skimmed = proposal.clone();
    let mut psbt = Psbt::from_str(&skimmed.psbt).unwrap();
    psbt.unsigned_tx.output[0].value = Amount::from_sat(proposal.sent_sats - 50_000);
    skimmed.psbt = psbt.to_string();
    assert!(approve_savings_spend(&config, &skimmed, &hww).is_err());

    // An absurd fee rate is refused even when it is internally consistent.
    let mut costly = proposal.clone();
    costly.fee_rate_sat_vb = 5_000;
    assert!(validate_savings_spend(&config, &costly).is_err());

    // A lock time other than the lock's own date.
    let mut early = proposal.clone();
    let mut psbt = Psbt::from_str(&early.psbt).unwrap();
    psbt.unsigned_tx.lock_time = LockTime::ZERO;
    early.psbt = psbt.to_string();
    assert!(approve_savings_spend(&config, &early, &hww).is_err());

    // A savings lock the HWW does not know.
    let mut unknown = proposal;
    unknown.unlock += 86_400;
    assert!(approve_savings_spend(&config, &unknown, &hww).is_err());
}

#[test]
fn each_device_alone_recovers_only_after_its_own_date() {
    let dir = tempfile::tempdir().unwrap();
    let (config, lock, utxos) = setup(dir.path());
    let phone = load_device_keys(dir.path(), PHONE_DEVICE_FILE).unwrap();
    let hww = load_device_keys(dir.path(), HWW_DEVICE_FILE).unwrap();
    let phone_date = u64::from(UNLOCK + SAVINGS_PHONE_RECOVERY_SECS);
    let hww_date = u64::from(UNLOCK + SAVINGS_HWW_RECOVERY_SECS);
    let recover = |path, median_time, keys| {
        sign_savings_recovery(
            &config,
            &lock,
            &utxos,
            median_time,
            path,
            &destination(),
            FEE_RATE,
            keys,
        )
    };
    use anzen::core::policy::SpendPath::{Cooperative, HwwRecovery, PhoneRecovery};

    assert!(recover(PhoneRecovery, phone_date, &phone).is_err());
    let (transaction, _) = recover(PhoneRecovery, phone_date + 1, &phone).unwrap();
    verify(&transaction, &utxos);

    assert!(recover(HwwRecovery, hww_date, &hww).is_err());
    let (transaction, _) = recover(HwwRecovery, hww_date + 1, &hww).unwrap();
    verify(&transaction, &utxos);

    // Wrong device for the path, or the cooperative path with one device.
    assert!(recover(PhoneRecovery, hww_date + 1, &hww).is_err());
    assert!(recover(HwwRecovery, hww_date + 1, &phone).is_err());
    assert!(recover(Cooperative, hww_date + 1, &phone).is_err());
}

#[test]
fn coins_from_another_address_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (config, lock, mut utxos) = setup(dir.path());
    utxos[1].txout.script_pubkey = destination().script_pubkey();
    let phone = load_device_keys(dir.path(), PHONE_DEVICE_FILE).unwrap();
    assert!(
        create_savings_spend(
            &config,
            &lock,
            &utxos,
            u64::from(UNLOCK) + 1,
            &destination(),
            FEE_RATE,
            &phone,
        )
        .is_err()
    );
}

#[test]
fn a_rotated_phone_still_finds_the_key_that_created_the_lock() {
    let dir = tempfile::tempdir().unwrap();
    let (_, lock, _) = setup(dir.path());
    let original = dir.path().join(PHONE_DEVICE_FILE);
    let archive = dir.path().join("history/rotation-test");
    std::fs::create_dir_all(archive.join(PHONE_DEVICE_FILE).parent().unwrap()).unwrap();
    std::fs::rename(&original, archive.join(PHONE_DEVICE_FILE)).unwrap();
    // The replacement phone key from a rotation.
    let other = tempfile::tempdir().unwrap();
    hot_wallet::initialize(other.path(), Network::Regtest).unwrap();
    std::fs::copy(other.path().join(PHONE_DEVICE_FILE), &original).unwrap();
    assert_ne!(
        load_device_keys(dir.path(), PHONE_DEVICE_FILE)
            .unwrap()
            .vault_pubkey
            .to_string(),
        lock.phone_vault_pubkey
    );
    let found = hot_wallet::phone_keys_for_lock(dir.path(), &lock).unwrap();
    assert_eq!(found.vault_pubkey.to_string(), lock.phone_vault_pubkey);

    std::fs::remove_dir_all(dir.path().join("history")).unwrap();
    assert!(hot_wallet::phone_keys_for_lock(dir.path(), &lock).is_err());
}
