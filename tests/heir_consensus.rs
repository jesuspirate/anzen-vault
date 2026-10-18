//! The heir path: every spend is built as a real Taproot script-path spend
//! and checked with Bitcoin Core's own script interpreter
//! (libbitcoinconsensus 26). A rejection here is a rejection by every node.

use anzen::core::{
    HEIR_RECOVERY_BLOCKS, HWW_RECOVERY_BLOCKS, PHONE_RECOVERY_BLOCKS,
    keys::DeviceKeys,
    policy::{
        SAVINGS_HEIR_RECOVERY_SECS, SAVINGS_HWW_RECOVERY_SECS, SAVINGS_PHONE_RECOVERY_SECS,
        SavingsPolicy, SpendPath, TaprootPolicy, VaultAddressTemplate, VaultPolicy,
    },
};
use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute::LockTime,
    hashes::Hash,
    key::Secp256k1,
    secp256k1::{All, Message},
    sighash::{Prevouts, SighashCache, TapSighashType},
    transaction::Version,
};

const UNLOCK: u32 = 1_924_992_000; // 2031-01-01 00:00 UTC
const RBF: Sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;

struct Keys {
    secp: Secp256k1<All>,
    phone: DeviceKeys,
    hww: DeviceKeys,
    heir: DeviceKeys,
    thief: DeviceKeys,
}

fn keys() -> Keys {
    let secp = Secp256k1::new();
    Keys {
        phone: DeviceKeys::generate(&secp).unwrap(),
        hww: DeviceKeys::generate(&secp).unwrap(),
        heir: DeviceKeys::generate(&secp).unwrap(),
        thief: DeviceKeys::generate(&secp).unwrap(),
        secp,
    }
}

fn vault(k: &Keys) -> VaultPolicy {
    VaultPolicy::with_heir(
        k.phone.vault_pubkey,
        k.hww.vault_pubkey,
        Some(k.heir.vault_pubkey),
        Network::Regtest,
    )
    .unwrap()
}

fn savings(k: &Keys) -> SavingsPolicy {
    SavingsPolicy::with_heir(
        k.phone.vault_pubkey,
        k.hww.vault_pubkey,
        Some(k.heir.vault_pubkey),
        UNLOCK,
        Network::Regtest,
    )
    .unwrap()
}

/// Spend `policy`'s output through `path`, signed by `signers` in witness order (for the 2-of-2
/// leaf: hww first, then phone). Each key signs with the child its leaf names.
fn spend(
    k: &Keys,
    policy: &dyn TaprootPolicy,
    path: SpendPath,
    signers: &[&DeviceKeys],
    lock_time: u32,
    sequence: Sequence,
) -> Result<(), bitcoinconsensus::Error> {
    let spent = TxOut {
        value: Amount::from_sat(1_000_000),
        script_pubkey: policy.address().script_pubkey(),
    };
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_consensus(lock_time),
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([7; 32]),
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
    let leaf = policy.leaf(path).unwrap();
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
    for signer in signers {
        w.push(
            k.secp
                .sign_schnorr(&msg, signer.vault_keypair.for_path(path))
                .as_ref(),
        );
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

fn after_blocks(blocks: u16) -> Sequence {
    Sequence::from_height(blocks)
}

#[test]
fn heir_waits_65535_blocks_after_vault_coins_last_moved() {
    let k = keys();
    let v = vault(&k);
    assert_eq!(HEIR_RECOVERY_BLOCKS, 65_535);
    assert!(
        spend(
            &k,
            &v,
            SpendPath::Heir,
            &[&k.heir],
            0,
            after_blocks(HEIR_RECOVERY_BLOCKS - 1)
        )
        .is_err()
    );
    assert_eq!(
        spend(
            &k,
            &v,
            SpendPath::Heir,
            &[&k.heir],
            0,
            after_blocks(HEIR_RECOVERY_BLOCKS)
        ),
        Ok(())
    );
    // A final sequence disables the relative lock, so it cannot skip the wait.
    assert!(spend(&k, &v, SpendPath::Heir, &[&k.heir], 0, Sequence::MAX).is_err());
}

#[test]
fn only_the_heir_key_opens_the_heir_leaf() {
    let k = keys();
    let v = vault(&k);
    let mature = after_blocks(HEIR_RECOVERY_BLOCKS);
    for other in [&k.phone, &k.hww, &k.thief] {
        assert!(spend(&k, &v, SpendPath::Heir, &[other], 0, mature).is_err());
    }
}

#[test]
fn the_heir_cannot_use_any_owner_path() {
    let k = keys();
    let v = vault(&k);
    let mature = after_blocks(HWW_RECOVERY_BLOCKS);
    assert!(spend(&k, &v, SpendPath::Cooperative, &[&k.hww, &k.heir], 0, RBF).is_err());
    assert!(spend(&k, &v, SpendPath::Cooperative, &[&k.heir, &k.phone], 0, RBF).is_err());
    assert!(spend(&k, &v, SpendPath::PhoneRecovery, &[&k.heir], 0, mature).is_err());
    assert!(spend(&k, &v, SpendPath::HwwRecovery, &[&k.heir], 0, mature).is_err());
}

#[test]
fn naming_an_heir_keeps_every_owner_path_working() {
    let k = keys();
    let v = vault(&k);
    assert_eq!(
        spend(&k, &v, SpendPath::Cooperative, &[&k.hww, &k.phone], 0, RBF),
        Ok(())
    );
    assert!(
        spend(
            &k,
            &v,
            SpendPath::PhoneRecovery,
            &[&k.phone],
            0,
            after_blocks(PHONE_RECOVERY_BLOCKS - 1)
        )
        .is_err()
    );
    assert_eq!(
        spend(
            &k,
            &v,
            SpendPath::PhoneRecovery,
            &[&k.phone],
            0,
            after_blocks(PHONE_RECOVERY_BLOCKS)
        ),
        Ok(())
    );
    assert_eq!(
        spend(
            &k,
            &v,
            SpendPath::HwwRecovery,
            &[&k.hww],
            0,
            after_blocks(HWW_RECOVERY_BLOCKS)
        ),
        Ok(())
    );
}

#[test]
fn an_heir_changes_the_vault_address_and_no_heir_leaves_it_as_before() {
    let k = keys();
    let plain =
        VaultPolicy::new_for_network(k.phone.vault_pubkey, k.hww.vault_pubkey, Network::Regtest)
            .unwrap();
    let explicit_none = VaultPolicy::with_heir(
        k.phone.vault_pubkey,
        k.hww.vault_pubkey,
        None,
        Network::Regtest,
    )
    .unwrap();
    assert_eq!(plain.address, explicit_none.address);
    assert!(!plain.has_heir());
    assert!(plain.leaf(SpendPath::Heir).is_err());

    let with_heir = vault(&k);
    assert!(with_heir.has_heir());
    assert_ne!(with_heir.address, plain.address);
    // The vanity search's fast encoder builds the same address.
    let template = VaultAddressTemplate::with_heir(
        k.hww.vault_pubkey,
        Some(k.heir.vault_pubkey),
        Network::Regtest,
    )
    .unwrap();
    assert_eq!(
        template.address(&k.secp, k.phone.vault_pubkey, Network::Regtest),
        with_heir.address
    );
}

#[test]
fn heir_waits_485_days_after_the_savings_unlock_date() {
    let k = keys();
    let s = savings(&k);
    let t = UNLOCK + SAVINGS_HEIR_RECOVERY_SECS;
    assert_eq!(s.earliest_lock_time(SpendPath::Heir), t);
    const { assert!(SAVINGS_HEIR_RECOVERY_SECS > SAVINGS_HWW_RECOVERY_SECS) };
    assert!(spend(&k, &s, SpendPath::Heir, &[&k.heir], t - 1, RBF).is_err());
    assert_eq!(spend(&k, &s, SpendPath::Heir, &[&k.heir], t, RBF), Ok(()));
    assert!(spend(&k, &s, SpendPath::Heir, &[&k.hww], t, RBF).is_err());
    assert!(spend(&k, &s, SpendPath::Heir, &[&k.heir], t, Sequence::MAX).is_err());
}

#[test]
fn an_heir_does_not_change_the_savings_owner_paths() {
    let k = keys();
    let s = savings(&k);
    assert!(
        spend(
            &k,
            &s,
            SpendPath::Cooperative,
            &[&k.hww, &k.phone],
            UNLOCK - 1,
            RBF
        )
        .is_err()
    );
    assert_eq!(
        spend(
            &k,
            &s,
            SpendPath::Cooperative,
            &[&k.hww, &k.phone],
            UNLOCK,
            RBF
        ),
        Ok(())
    );
    let phone_at = UNLOCK + SAVINGS_PHONE_RECOVERY_SECS;
    assert_eq!(
        spend(&k, &s, SpendPath::PhoneRecovery, &[&k.phone], phone_at, RBF),
        Ok(())
    );
    let hww_at = UNLOCK + SAVINGS_HWW_RECOVERY_SECS;
    assert_eq!(
        spend(&k, &s, SpendPath::HwwRecovery, &[&k.hww], hww_at, RBF),
        Ok(())
    );
    // The heir's key cannot open the savings lock early through an owner path.
    assert!(spend(&k, &s, SpendPath::HwwRecovery, &[&k.heir], hww_at, RBF).is_err());
}
