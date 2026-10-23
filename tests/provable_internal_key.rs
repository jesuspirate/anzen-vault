//! New vaults write the NUMS internal key with a chain code a BitBox02 recognizes as provably
//! unspendable. Vaults made before keep the old chain code, so their addresses never change.

use anzen::core::{
    keys::DeviceKeys,
    policy::{
        BIP341_NUMS_KEY, ControllerPolicy, InternalKey, PolicyKeys, RungPolicy, SavingsPolicy,
        SpendPath, TaprootPolicy, VaultAddressTemplate, VaultPolicy, nums_xpub,
    },
    storage::VaultConfig,
};
use bitcoin::{
    Network,
    hashes::{Hash, HashEngine, sha256},
    key::Secp256k1,
};
use miniscript::{Descriptor, DescriptorPublicKey};

const UNLOCK: u32 = 1_924_992_000; // 2031-01-01 00:00 UTC

struct Keys {
    phone: DeviceKeys,
    hww: DeviceKeys,
    yubikey: DeviceKeys,
    heir: DeviceKeys,
}

fn keys() -> Keys {
    let secp = Secp256k1::new();
    Keys {
        phone: DeviceKeys::generate(&secp).unwrap(),
        hww: DeviceKeys::generate(&secp).unwrap(),
        yubikey: DeviceKeys::generate(&secp).unwrap(),
        heir: DeviceKeys::generate(&secp).unwrap(),
    }
}

fn policy_keys(k: &Keys, yubikey: bool, heir: bool, internal_key: InternalKey) -> PolicyKeys {
    PolicyKeys {
        yubikey: yubikey.then_some(k.yubikey.vault_pubkey),
        heir: heir.then_some(k.heir.vault_pubkey),
        internal_key,
        ..PolicyKeys::new(k.phone.vault_pubkey, k.hww.vault_pubkey)
    }
}

fn internal_xpub(descriptor: &Descriptor<DescriptorPublicKey>) -> bitcoin::bip32::Xpub {
    let Descriptor::Tr(tr) = descriptor else {
        panic!("not Taproot");
    };
    let DescriptorPublicKey::MultiXPub(key) = tr.internal_key() else {
        panic!("internal key is not an extended key");
    };
    key.xkey
}

/// The BitBox02 firmware's check, written out: the internal xpub is H at depth 0, and its chain
/// code is sha256 of the account public key of every leaf key, leaf by leaf.
fn bitbox_sees_provably_unspendable(descriptor: &Descriptor<DescriptorPublicKey>) -> bool {
    let Descriptor::Tr(tr) = descriptor else {
        return false;
    };
    let internal = internal_xpub(descriptor);
    let mut engine = sha256::Hash::engine();
    for (_, miniscript) in tr.iter_scripts() {
        for key in miniscript.iter_pk() {
            let DescriptorPublicKey::MultiXPub(key) = key else {
                return false;
            };
            engine.input(&key.xkey.public_key.serialize());
        }
    }
    internal.depth == 0
        && internal.parent_fingerprint == Default::default()
        && u32::from(internal.child_number) == 0
        && internal.public_key.serialize()[1..]
            == bitcoin::hex::FromHex::from_hex(BIP341_NUMS_KEY)
                .map(|bytes: Vec<u8>| bytes)
                .unwrap()[..]
        && internal.chain_code.to_bytes() == sha256::Hash::from_engine(engine).to_byte_array()
}

#[test]
fn new_style_policies_pass_the_bitbox02_unspendable_check() {
    let k = keys();
    for (yubikey, heir) in [(false, false), (true, false), (false, true), (true, true)] {
        let keys = policy_keys(&k, yubikey, heir, InternalKey::Provable);
        let vault = VaultPolicy::build(&keys, Network::Regtest).unwrap();
        assert!(bitbox_sees_provably_unspendable(&vault.descriptor));
        let savings = SavingsPolicy::build(&keys, UNLOCK, Network::Regtest).unwrap();
        assert!(bitbox_sees_provably_unspendable(&savings.descriptor));
    }
    let controller = ControllerPolicy::new_for_network(
        k.phone.vault_pubkey,
        k.hww.vault_pubkey,
        InternalKey::Provable,
        Network::Regtest,
    )
    .unwrap();
    assert!(bitbox_sees_provably_unspendable(&controller.descriptor));
    let rung = RungPolicy::new_for_network(
        k.phone.vault_pubkey,
        k.hww.vault_pubkey,
        UNLOCK,
        InternalKey::Provable,
        Network::Regtest,
    )
    .unwrap();
    assert!(bitbox_sees_provably_unspendable(&rung.descriptor));
}

#[test]
fn old_style_policies_keep_their_chain_code_and_address() {
    let k = keys();
    let keys = policy_keys(&k, false, false, InternalKey::Legacy);
    let vault = VaultPolicy::build(&keys, Network::Regtest).unwrap();
    assert_eq!(
        internal_xpub(&vault.descriptor),
        nums_xpub(Network::Regtest)
    );
    assert!(!bitbox_sees_provably_unspendable(&vault.descriptor));
    let new = VaultPolicy::build(
        &policy_keys(&k, false, false, InternalKey::Provable),
        Network::Regtest,
    )
    .unwrap();
    assert_ne!(vault.address, new.address);
}

#[test]
fn each_style_is_read_back_from_its_descriptor() {
    let k = keys();
    for internal_key in [InternalKey::Legacy, InternalKey::Provable] {
        for (yubikey, heir) in [(false, false), (true, true)] {
            let keys = policy_keys(&k, yubikey, heir, internal_key);
            let vault = VaultPolicy::build(&keys, Network::Regtest).unwrap();
            let parsed = VaultPolicy::from_descriptor_for_network(
                &vault.descriptor_string(),
                Network::Regtest,
            )
            .unwrap();
            assert_eq!(parsed.keys(Network::Regtest).unwrap(), keys);
            let savings = SavingsPolicy::build(&keys, UNLOCK, Network::Regtest).unwrap();
            let parsed = SavingsPolicy::from_descriptor_for_network(
                &savings.descriptor_string(),
                Network::Regtest,
            )
            .unwrap();
            assert_eq!(parsed.keys(), keys);
            assert_eq!(parsed.address, savings.address);
        }
    }
}

#[test]
fn a_tampered_chain_code_is_not_an_anzen_descriptor() {
    let k = keys();
    let vault = VaultPolicy::build(
        &policy_keys(&k, false, false, InternalKey::Provable),
        Network::Regtest,
    )
    .unwrap();
    let real = internal_xpub(&vault.descriptor).to_string();
    let mut forged = internal_xpub(&vault.descriptor);
    forged.chain_code = bitcoin::bip32::ChainCode::from([7; 32]);
    let text = vault
        .descriptor_string()
        .split('#')
        .next()
        .unwrap()
        .replace(&real, &forged.to_string());
    let parsed = VaultPolicy::from_descriptor_for_network(&text, Network::Regtest).unwrap();
    assert!(parsed.keys(Network::Regtest).is_err());
}

#[test]
fn the_fast_vanity_template_matches_every_new_style_vault() {
    let k = keys();
    let secp = Secp256k1::new();
    for (yubikey, heir) in [(false, false), (true, false), (false, true), (true, true)] {
        let keys = policy_keys(&k, yubikey, heir, InternalKey::Provable);
        let vault = VaultPolicy::build(&keys, Network::Regtest).unwrap();
        let template = VaultAddressTemplate::with_keys(
            k.hww.vault_pubkey,
            keys.yubikey,
            keys.heir,
            InternalKey::Provable,
            Network::Regtest,
        )
        .unwrap();
        assert_eq!(
            template.address(&secp, k.phone.vault_pubkey, Network::Regtest),
            vault.address,
            "yubikey: {yubikey}, heir: {heir}"
        );
    }
}

#[test]
fn every_new_style_leaf_commits_to_the_address() {
    let k = keys();
    let secp = Secp256k1::verification_only();
    let keys = policy_keys(&k, true, true, InternalKey::Provable);
    let vault = VaultPolicy::build(&keys, Network::Regtest).unwrap();
    let output_key = vault
        .address
        .script_pubkey()
        .as_bytes()
        .get(2..)
        .map(|bytes| bitcoin::XOnlyPublicKey::from_slice(bytes).unwrap())
        .unwrap();
    for path in [
        SpendPath::Cooperative,
        SpendPath::PhoneRecovery,
        SpendPath::HwwRecovery,
        SpendPath::Heir,
        SpendPath::PhoneYubikey,
        SpendPath::HwwYubikey,
    ] {
        let leaf = TaprootPolicy::leaf(&vault, path).unwrap();
        assert!(
            leaf.control_block
                .verify_taproot_commitment(&secp, output_key, &leaf.script),
            "{path:?}"
        );
    }
}

#[test]
fn a_config_without_the_field_is_an_old_vault() {
    let k = keys();
    let vault = VaultPolicy::build(
        &policy_keys(&k, false, false, InternalKey::Legacy),
        Network::Regtest,
    )
    .unwrap();
    let old = serde_json::json!({
        "version": 1,
        "network": "regtest",
        "phone_vault_pubkey": k.phone.vault_pubkey.to_string(),
        "hww_vault_pubkey": k.hww.vault_pubkey.to_string(),
        "phone_hot_external_descriptor": "",
        "phone_hot_internal_descriptor": "",
        "vault_descriptor": vault.descriptor_string(),
        "vault_address": vault.address.to_string(),
        "phone_recovery_blocks": 61200,
        "hww_recovery_blocks": 65535,
    });
    let config: VaultConfig = serde_json::from_value(old.clone()).unwrap();
    assert_eq!(config.internal_key, InternalKey::Legacy);
    assert_eq!(
        VaultPolicy::build(&config.policy_keys().unwrap(), Network::Regtest)
            .unwrap()
            .address,
        vault.address
    );
    // Saving it again leaves the file as it was.
    let saved = serde_json::to_value(&config).unwrap();
    assert!(saved.get("internal_key").is_none());

    let mut new = config.clone();
    new.internal_key = InternalKey::Provable;
    let saved = serde_json::to_value(&new).unwrap();
    assert_eq!(saved["internal_key"], "provable");
}
