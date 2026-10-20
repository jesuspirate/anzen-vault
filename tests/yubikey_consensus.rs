//! The optional YubiKey: any two of phone, hardware wallet and YubiKey can move the coins.
//! Every spend is built as a real Taproot script-path spend and checked with Bitcoin Core's own
//! script interpreter (libbitcoinconsensus 26). A rejection here is a rejection by every node.

use anzen::core::{
    HWW_RECOVERY_BLOCKS, PHONE_RECOVERY_BLOCKS,
    keys::DeviceKeys,
    policy::{
        PolicyKeys, SavingsPolicy, SpendPath, TaprootPolicy, VaultAddressTemplate, VaultPolicy,
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
    yubikey: DeviceKeys,
    heir: DeviceKeys,
    thief: DeviceKeys,
}

fn keys() -> Keys {
    let secp = Secp256k1::new();
    Keys {
        phone: DeviceKeys::generate(&secp).unwrap(),
        hww: DeviceKeys::generate(&secp).unwrap(),
        yubikey: DeviceKeys::generate(&secp).unwrap(),
        heir: DeviceKeys::generate(&secp).unwrap(),
        thief: DeviceKeys::generate(&secp).unwrap(),
        secp,
    }
}

fn policy_keys(k: &Keys, heir: bool) -> PolicyKeys {
    PolicyKeys {
        yubikey: Some(k.yubikey.vault_pubkey),
        heir: heir.then_some(k.heir.vault_pubkey),
        ..PolicyKeys::new(k.phone.vault_pubkey, k.hww.vault_pubkey)
    }
}

fn vault(k: &Keys) -> VaultPolicy {
    VaultPolicy::build(&policy_keys(k, false), Network::Regtest).unwrap()
}

fn savings(k: &Keys) -> SavingsPolicy {
    SavingsPolicy::build(&policy_keys(k, false), UNLOCK, Network::Regtest).unwrap()
}

/// Spend `policy`'s output through `path`, signed by `signers` in witness order (for a 2-of-2
/// leaf: the second key first, then the first). Each key signs with the child its leaf names.
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

#[test]
fn phone_and_yubikey_move_vault_coins_at_once() {
    let k = keys();
    let v = vault(&k);
    assert!(v.has_yubikey());
    assert_eq!(
        spend(
            &k,
            &v,
            SpendPath::PhoneYubikey,
            &[&k.yubikey, &k.phone],
            0,
            RBF
        ),
        Ok(())
    );
}

#[test]
fn hww_and_yubikey_move_vault_coins_at_once() {
    let k = keys();
    let v = vault(&k);
    assert_eq!(
        spend(&k, &v, SpendPath::HwwYubikey, &[&k.yubikey, &k.hww], 0, RBF),
        Ok(())
    );
}

#[test]
fn one_key_alone_cannot_open_a_yubikey_pair() {
    let k = keys();
    let v = vault(&k);
    for path in [SpendPath::PhoneYubikey, SpendPath::HwwYubikey] {
        // A single signature, the same key twice, or a stranger's key all fail.
        assert!(spend(&k, &v, path, &[&k.yubikey], 0, RBF).is_err());
        assert!(spend(&k, &v, path, &[&k.yubikey, &k.yubikey], 0, RBF).is_err());
        assert!(spend(&k, &v, path, &[&k.thief, &k.yubikey], 0, RBF).is_err());
        assert!(spend(&k, &v, path, &[&k.yubikey, &k.thief], 0, RBF).is_err());
    }
    // Each pair names its own two keys, so the other pair's keys do not fit.
    assert!(
        spend(
            &k,
            &v,
            SpendPath::PhoneYubikey,
            &[&k.yubikey, &k.hww],
            0,
            RBF
        )
        .is_err()
    );
    assert!(
        spend(
            &k,
            &v,
            SpendPath::HwwYubikey,
            &[&k.yubikey, &k.phone],
            0,
            RBF
        )
        .is_err()
    );
    // The YubiKey cannot stand in for either key on the cooperative leaf.
    assert!(
        spend(
            &k,
            &v,
            SpendPath::Cooperative,
            &[&k.yubikey, &k.phone],
            0,
            RBF
        )
        .is_err()
    );
    assert!(
        spend(
            &k,
            &v,
            SpendPath::Cooperative,
            &[&k.hww, &k.yubikey],
            0,
            RBF
        )
        .is_err()
    );
}

#[test]
fn a_yubikey_keeps_every_other_path_working() {
    let k = keys();
    let v = vault(&k);
    assert_eq!(
        spend(&k, &v, SpendPath::Cooperative, &[&k.hww, &k.phone], 0, RBF),
        Ok(())
    );
    assert_eq!(
        spend(
            &k,
            &v,
            SpendPath::PhoneRecovery,
            &[&k.phone],
            0,
            Sequence::from_height(PHONE_RECOVERY_BLOCKS)
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
            Sequence::from_height(HWW_RECOVERY_BLOCKS)
        ),
        Ok(())
    );
    assert!(v.leaf(SpendPath::Heir).is_err());
}

#[test]
fn a_yubikey_vault_can_also_name_an_heir() {
    let k = keys();
    let v = VaultPolicy::build(&policy_keys(&k, true), Network::Regtest).unwrap();
    assert!(v.has_heir() && v.has_yubikey());
    assert_eq!(
        spend(&k, &v, SpendPath::HwwYubikey, &[&k.yubikey, &k.hww], 0, RBF),
        Ok(())
    );
    assert_eq!(
        spend(
            &k,
            &v,
            SpendPath::Heir,
            &[&k.heir],
            0,
            Sequence::from_height(anzen::core::HEIR_RECOVERY_BLOCKS)
        ),
        Ok(())
    );
    // The descriptor reads back with the same keys.
    let back =
        VaultPolicy::from_descriptor_for_network(&v.descriptor_string(), Network::Regtest).unwrap();
    assert_eq!(back.address, v.address);
    let keys = back.keys(Network::Regtest).unwrap();
    assert_eq!(keys.yubikey, Some(k.yubikey.vault_pubkey));
    assert_eq!(keys.heir, Some(k.heir.vault_pubkey));
}

#[test]
fn a_yubikey_changes_the_vault_address_and_the_vanity_template_agrees() {
    let k = keys();
    let plain =
        VaultPolicy::new_for_network(k.phone.vault_pubkey, k.hww.vault_pubkey, Network::Regtest)
            .unwrap();
    let with_yubikey = vault(&k);
    assert!(!plain.has_yubikey());
    assert!(plain.leaf(SpendPath::PhoneYubikey).is_err());
    assert_ne!(plain.address, with_yubikey.address);
    let template = VaultAddressTemplate::with_keys(
        k.hww.vault_pubkey,
        Some(k.yubikey.vault_pubkey),
        None,
        Network::Regtest,
    )
    .unwrap();
    assert_eq!(
        template.address(&k.secp, k.phone.vault_pubkey, Network::Regtest),
        with_yubikey.address
    );
}

#[test]
fn the_same_key_cannot_be_both_yubikey_and_another_key() {
    let k = keys();
    for duplicate in [k.phone.vault_pubkey, k.hww.vault_pubkey] {
        let keys = PolicyKeys {
            yubikey: Some(duplicate),
            ..PolicyKeys::new(k.phone.vault_pubkey, k.hww.vault_pubkey)
        };
        assert!(VaultPolicy::build(&keys, Network::Regtest).is_err());
    }
    let keys = PolicyKeys {
        yubikey: Some(k.heir.vault_pubkey),
        heir: Some(k.heir.vault_pubkey),
        ..PolicyKeys::new(k.phone.vault_pubkey, k.hww.vault_pubkey)
    };
    assert!(VaultPolicy::build(&keys, Network::Regtest).is_err());
}

#[test]
fn yubikey_pairs_open_savings_only_on_the_unlock_date() {
    let k = keys();
    let s = savings(&k);
    for (path, signers) in [
        (SpendPath::PhoneYubikey, [&k.yubikey, &k.phone]),
        (SpendPath::HwwYubikey, [&k.yubikey, &k.hww]),
    ] {
        assert_eq!(s.earliest_lock_time(path), UNLOCK);
        assert!(spend(&k, &s, path, &signers, UNLOCK - 1, RBF).is_err());
        assert_eq!(spend(&k, &s, path, &signers, UNLOCK, RBF), Ok(()));
        // A final sequence disables the lock time, so it cannot skip the date.
        assert!(spend(&k, &s, path, &signers, UNLOCK, Sequence::MAX).is_err());
    }
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
}
