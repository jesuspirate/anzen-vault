//! Hard-locked savings: every spend is built as a real Taproot script-path
//! spend and checked with Bitcoin Core's own script interpreter
//! (libbitcoinconsensus 26). A rejection here is a rejection by every node.

use anzen::core::policy::{
    SAVINGS_HWW_RECOVERY_SECS, SAVINGS_PHONE_RECOVERY_SECS, SavingsPolicy, SpendPath,
};
use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute::LockTime,
    hashes::Hash,
    key::{Keypair, Secp256k1},
    secp256k1::{All, Message, rand::thread_rng},
    sighash::{Prevouts, SighashCache, TapSighashType},
    transaction::Version,
};

const UNLOCK: u32 = 1_924_992_000; // 2031-01-01 00:00 UTC

struct Devices {
    secp: Secp256k1<All>,
    phone: Keypair,
    hww: Keypair,
    thief: Keypair,
}

fn devices() -> Devices {
    let secp = Secp256k1::new();
    let mut rng = thread_rng();
    Devices {
        phone: Keypair::new(&secp, &mut rng),
        hww: Keypair::new(&secp, &mut rng),
        thief: Keypair::new(&secp, &mut rng),
        secp,
    }
}

fn policy(d: &Devices) -> SavingsPolicy {
    SavingsPolicy::new_for_network(
        d.phone.x_only_public_key().0,
        d.hww.x_only_public_key().0,
        UNLOCK,
        Network::Regtest,
    )
    .unwrap()
}

/// Spend the savings output through `path`, signed by `signers` in witness
/// order (for the 2-of-2 leaf: hww first, then phone, since the phone key is
/// checked first and so its signature must sit on top of the stack).
fn spend(
    d: &Devices,
    p: &SavingsPolicy,
    path: SpendPath,
    signers: &[&Keypair],
    lock_time: u32,
    sequence: Sequence,
) -> Result<(), bitcoinconsensus::Error> {
    let spent = TxOut {
        value: Amount::from_sat(1_000_000),
        script_pubkey: p.address.script_pubkey(),
    };
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_consensus(lock_time),
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([9; 32]),
                vout: 0,
            },
            sequence,
            ..Default::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(999_000),
            script_pubkey: ScriptBuf::new_op_return([]),
        }],
    };
    let leaf = p.leaf(path).unwrap();
    let sighash = SighashCache::new(&tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[&spent]),
            leaf.leaf_hash,
            TapSighashType::Default,
        )
        .unwrap();
    let msg = Message::from_digest(sighash.to_byte_array());
    let mut w = Witness::new();
    for k in signers {
        w.push(d.secp.sign_schnorr(&msg, k).as_ref());
    }
    w.push(leaf.script.as_bytes());
    w.push(leaf.control_block.serialize());
    tx.input[0].witness = w;

    let bytes = bitcoin::consensus::serialize(&tx);
    let spk = spent.script_pubkey.as_bytes();
    let utxos = [bitcoinconsensus::Utxo {
        script_pubkey: spk.as_ptr(),
        script_pubkey_len: spk.len() as u32,
        value: spent.value.to_sat() as i64,
    }];
    bitcoinconsensus::verify(spk, spent.value.to_sat(), &bytes, Some(&utxos), 0)
}

const RBF: Sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;

#[test]
fn both_devices_cannot_spend_before_unlock() {
    let d = devices();
    let p = policy(&d);
    assert!(
        spend(
            &d,
            &p,
            SpendPath::Cooperative,
            &[&d.hww, &d.phone],
            UNLOCK - 1,
            RBF
        )
        .is_err()
    );
    assert!(spend(&d, &p, SpendPath::Cooperative, &[&d.hww, &d.phone], 0, RBF).is_err());
}

#[test]
fn both_devices_can_spend_from_unlock() {
    let d = devices();
    let p = policy(&d);
    assert_eq!(
        spend(
            &d,
            &p,
            SpendPath::Cooperative,
            &[&d.hww, &d.phone],
            UNLOCK,
            RBF
        ),
        Ok(())
    );
}

#[test]
fn one_device_or_a_thief_cannot_use_the_cooperative_path() {
    let d = devices();
    let p = policy(&d);
    assert!(
        spend(
            &d,
            &p,
            SpendPath::Cooperative,
            &[&d.thief, &d.phone],
            UNLOCK,
            RBF
        )
        .is_err()
    );
    assert!(
        spend(
            &d,
            &p,
            SpendPath::Cooperative,
            &[&d.hww, &d.thief],
            UNLOCK,
            RBF
        )
        .is_err()
    );
}

#[test]
fn phone_alone_waits_425_days_after_unlock() {
    let d = devices();
    let p = policy(&d);
    let t = UNLOCK + SAVINGS_PHONE_RECOVERY_SECS;
    assert_eq!(p.earliest_lock_time(SpendPath::PhoneRecovery), t);
    assert!(spend(&d, &p, SpendPath::PhoneRecovery, &[&d.phone], t - 1, RBF).is_err());
    assert_eq!(
        spend(&d, &p, SpendPath::PhoneRecovery, &[&d.phone], t, RBF),
        Ok(())
    );
    assert!(spend(&d, &p, SpendPath::PhoneRecovery, &[&d.hww], t, RBF).is_err());
}

#[test]
fn hww_alone_waits_455_days_after_unlock() {
    let d = devices();
    let p = policy(&d);
    let t = UNLOCK + SAVINGS_HWW_RECOVERY_SECS;
    assert!(spend(&d, &p, SpendPath::HwwRecovery, &[&d.hww], t - 1, RBF).is_err());
    assert_eq!(
        spend(&d, &p, SpendPath::HwwRecovery, &[&d.hww], t, RBF),
        Ok(())
    );
    assert!(spend(&d, &p, SpendPath::HwwRecovery, &[&d.thief], t, RBF).is_err());
}

#[test]
fn final_sequence_cannot_bypass_the_lock() {
    let d = devices();
    let p = policy(&d);
    assert!(
        spend(
            &d,
            &p,
            SpendPath::Cooperative,
            &[&d.hww, &d.phone],
            UNLOCK,
            Sequence::MAX
        )
        .is_err()
    );
}

#[test]
fn block_height_unlocks_are_rejected() {
    let d = devices();
    assert!(
        SavingsPolicy::new_for_network(
            d.phone.x_only_public_key().0,
            d.hww.x_only_public_key().0,
            900_000,
            Network::Regtest
        )
        .is_err()
    );
}
