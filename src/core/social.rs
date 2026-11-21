//! Versioned cloud-recovery envelopes and OpenPGP friend-key wrapping.
//!
//! The sensitive phone mnemonic and public vault descriptor are encrypted once with a random
//! symmetric key. The HWW and every configured recovery friend receive independent encrypted
//! copies of that same key. Friends are therefore 1-of-N recovery contacts; this is deliberately
//! not a threshold-sharing scheme.

use super::{
    crypto::{self, EncryptedBlob},
    keys::DeviceKeys,
    storage::VaultConfig,
};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use pgp::{
    composed::{
        ArmorOptions, Deserializable, KeyType, Message, MessageBuilder, SecretKeyParamsBuilder,
        SignedPublicKey, SignedSecretKey, SubkeyParamsBuilder,
    },
    crypto::{ecc_curve::ECCCurve, sym::SymmetricKeyAlgorithm},
    types::{
        EcdhPublicParams, EddsaLegacyPublicParams, KeyDetails, Password, PublicKeyTrait,
        PublicParams,
    },
};
use rand::thread_rng;
use serde::{Deserialize, Serialize};

const PAYLOAD_PURPOSE: &str = "cloud/vault-recovery-payload/v1";
const HWW_KEY_PURPOSE: &str = "cloud/vault-recovery-key/hww/v1";
const FRIEND_MANIFEST_PURPOSE: &str = "cloud/vault-recovery-friends/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryPayload {
    pub version: u8,
    pub kind: String,
    pub network: String,
    pub phone_mnemonic: String,
    #[serde(default)]
    pub phone_vault_key_index: u32,
    pub phone_vault_pubkey: String,
    pub vault_descriptor: String,
    pub vault_address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FriendKeyWrapper {
    pub fingerprint: String,
    pub public_key_armored: String,
    pub encrypted_symmetric_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudRecoveryBackup {
    pub version: u8,
    pub kind: String,
    pub encrypted_payload: EncryptedBlob,
    pub hww_encrypted_symmetric_key: EncryptedBlob,
    pub friends: Vec<FriendKeyWrapper>,
    pub encrypted_friend_manifest: EncryptedBlob,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedFriendKey {
    pub fingerprint: String,
    pub public_key_armored: String,
    pub private_key_armored: String,
}

impl RecoveryPayload {
    pub fn new(config: &VaultConfig, phone: &DeviceKeys) -> Result<Self> {
        if phone.vault_pubkey.to_string() != config.phone_vault_pubkey {
            bail!("phone key does not match the configured vault policy");
        }
        Ok(Self {
            version: 1,
            kind: "vault-recovery-payload".to_owned(),
            network: config.network.clone(),
            phone_mnemonic: phone.mnemonic.to_string(),
            phone_vault_key_index: phone.vault_key_index,
            phone_vault_pubkey: phone.vault_pubkey.to_string(),
            vault_descriptor: config.vault_descriptor.clone(),
            vault_address: config.vault_address.clone(),
        })
    }

    pub fn validate_against(&self, config: &VaultConfig) -> Result<()> {
        if self.version != 1
            || self.kind != "vault-recovery-payload"
            || self.network != config.network
            || self.phone_vault_pubkey != config.phone_vault_pubkey
            || self.vault_descriptor != config.vault_descriptor
            || self.vault_address != config.vault_address
        {
            bail!("recovery payload does not match the configured vault");
        }
        let phone = DeviceKeys::parse_for_network_at_index(
            &bitcoin::key::Secp256k1::new(),
            &self.phone_mnemonic,
            config.bitcoin_network()?,
            self.phone_vault_key_index,
        )?;
        if phone.vault_pubkey.to_string() != self.phone_vault_pubkey {
            bail!("recovery payload mnemonic does not match its phone public key");
        }
        Ok(())
    }
}

pub fn create_backup(
    payload: &RecoveryPayload,
    hww_seed: &[u8],
    friend_public_keys: &[String],
) -> Result<CloudRecoveryBackup> {
    let symmetric_key = crypto::random_key();
    let payload_bytes = serde_json::to_vec(payload)?;
    let encrypted_payload = crypto::encrypt(&*symmetric_key, PAYLOAD_PURPOSE, &payload_bytes)?;
    let hww_encrypted_symmetric_key = crypto::encrypt(hww_seed, HWW_KEY_PURPOSE, &*symmetric_key)?;
    let mut friends = Vec::with_capacity(friend_public_keys.len());
    for public_key in friend_public_keys {
        friends.push(wrap_for_friend(
            public_key.as_bytes(),
            symmetric_key.as_ref(),
        )?);
    }
    friends.sort_by(|left, right| left.fingerprint.cmp(&right.fingerprint));
    friends.dedup_by(|left, right| left.fingerprint == right.fingerprint);
    let encrypted_friend_manifest = encrypt_friend_manifest(symmetric_key.as_ref(), &friends)?;
    Ok(CloudRecoveryBackup {
        version: 1,
        kind: "vault-cloud-recovery".to_owned(),
        encrypted_payload,
        hww_encrypted_symmetric_key,
        friends,
        encrypted_friend_manifest,
    })
}

pub fn add_friend(
    backup: &mut CloudRecoveryBackup,
    hww_seed: &[u8],
    public_key: &[u8],
) -> Result<String> {
    validate_backup(backup)?;
    let symmetric_key = crypto::decrypt(
        hww_seed,
        HWW_KEY_PURPOSE,
        &backup.hww_encrypted_symmetric_key,
    )?;
    if symmetric_key.len() != 32 {
        bail!("cloud backup contains an invalid symmetric key");
    }
    validate_friend_manifest(backup, &symmetric_key)?;
    let wrapper = wrap_for_friend(public_key, &symmetric_key)?;
    if backup
        .friends
        .iter()
        .any(|friend| friend.fingerprint == wrapper.fingerprint)
    {
        bail!(
            "recovery friend {} is already configured",
            wrapper.fingerprint
        );
    }
    let fingerprint = wrapper.fingerprint.clone();
    backup.friends.push(wrapper);
    backup
        .friends
        .sort_by(|left, right| left.fingerprint.cmp(&right.fingerprint));
    backup.encrypted_friend_manifest = encrypt_friend_manifest(&symmetric_key, &backup.friends)?;
    Ok(fingerprint)
}

pub fn decrypt_with_hww(backup: &CloudRecoveryBackup, hww_seed: &[u8]) -> Result<RecoveryPayload> {
    validate_backup(backup)?;
    let symmetric_key = crypto::decrypt(
        hww_seed,
        HWW_KEY_PURPOSE,
        &backup.hww_encrypted_symmetric_key,
    )?;
    validate_friend_manifest(backup, &symmetric_key)?;
    decrypt_payload(backup, &symmetric_key)
}

/// What a recovery friend's key unlocked, and whether that key is an older type that only opens
/// backups made before Anzen stopped accepting it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriendRecovery {
    pub payload: RecoveryPayload,
    /// `Some("RSA")` (or another older type) when the friend's key is no longer accepted for new
    /// backups. The caller must show [`OLDER_FRIEND_KEY_WARNING`].
    pub older_key_kind: Option<&'static str>,
}

/// Shown to a recovery friend whose older key still opened a backup made before Anzen started
/// refusing older keys.
pub const OLDER_FRIEND_KEY_WARNING: &str = "Warning: your recovery key is an older type that \
     Anzen no longer accepts for new backups. It still opened this backup because the backup was \
     made before that change, so the vault is not stranded. Please make a new modern key now \
     (`anzen social generate-friend-key`, or GnuPG's ed25519 + cv25519 keys) and ask the vault \
     owner to add it and remove the old one.";

pub fn decrypt_with_friend(
    backup: &CloudRecoveryBackup,
    private_key: &[u8],
) -> Result<FriendRecovery> {
    validate_backup(backup)?;
    let (secret, _) = SignedSecretKey::from_reader_single(private_key)
        .context("failed to parse recovery friend's OpenPGP private key")?;
    let older_key_kind = older_key_kind(
        std::iter::once(secret.primary_key.public_key().public_params()).chain(
            secret
                .secret_subkeys
                .iter()
                .map(|subkey| subkey.key.public_key().public_params())
                .chain(
                    secret
                        .public_subkeys
                        .iter()
                        .map(|subkey| subkey.key.public_params()),
                ),
        ),
    );
    // The fingerprint is a hash of the public primary key; no private-key operation runs yet.
    let fingerprint = secret.fingerprint().to_string();
    let wrapper = backup
        .friends
        .iter()
        .find(|friend| friend.fingerprint == fingerprint);
    let wrapper = match (wrapper, older_key_kind) {
        (Some(wrapper), _) => wrapper,
        // An older key that this backup does not already list is refused before any signature
        // check or decryption touches it. Only friends added before the change keep working.
        (None, Some(kind)) => {
            return Err(older_key_error(kind)).context(LEGACY_FRIEND_KEY_RECOVERY_HINT);
        }
        (None, None) => bail!("cloud backup has no wrapper for friend {fingerprint}"),
    };
    secret
        .verify()
        .context("recovery friend's OpenPGP private key failed self-signature validation")?;
    let encrypted_key = STANDARD
        .decode(&wrapper.encrypted_symmetric_key)
        .context("friend key wrapper is not valid base64")?;
    let mut message = Message::from_bytes(std::io::Cursor::new(encrypted_key))
        .context("friend key wrapper is not a valid OpenPGP message")?
        .decrypt(&Password::empty(), &secret)
        .context("friend OpenPGP key could not decrypt the recovery key")?;
    if message.is_compressed() {
        message = message
            .decompress()
            .context("failed to decompress friend recovery key message")?;
    }
    let symmetric_key = message
        .as_data_vec()
        .context("friend recovery key message contained no data")?;
    if symmetric_key.len() != 32 {
        bail!("friend recovery wrapper contains an invalid symmetric key");
    }
    validate_friend_manifest(backup, &symmetric_key)?;
    Ok(FriendRecovery {
        payload: decrypt_payload(backup, &symmetric_key)?,
        older_key_kind,
    })
}

/// A recovery friend listed in an existing backup whose key is an older type. They can still
/// open that backup, but the owner should swap in a new modern key, and a phone-key rotation
/// leaves them out of the new backup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OlderFriend {
    pub fingerprint: String,
    pub name: Option<String>,
    pub kind: &'static str,
}

/// Friends in `backup` whose stored public key is an older type (RSA, DSA, ElGamal, NIST curves,
/// Ed448/X448). Only the stored public key is parsed; nothing is verified, encrypted or decrypted.
pub fn older_friends(backup: &CloudRecoveryBackup) -> Vec<OlderFriend> {
    backup
        .friends
        .iter()
        .filter_map(|friend| {
            let kind = stored_friend_key_kind(friend)?;
            Some(OlderFriend {
                fingerprint: friend.fingerprint.clone(),
                name: friend_user_id(friend.public_key_armored.as_bytes()),
                kind,
            })
        })
        .collect()
}

/// Public keys of the friends that can be carried into a new backup (modern keys only).
pub fn modern_friend_public_keys(backup: &CloudRecoveryBackup) -> Vec<String> {
    backup
        .friends
        .iter()
        .filter(|friend| stored_friend_key_kind(friend).is_none())
        .map(|friend| friend.public_key_armored.clone())
        .collect()
}

/// Remove a recovery friend's wrapper and re-authenticate the friend list. Copies of the old
/// backup file that exist elsewhere still list the friend until the next phone-key rotation.
pub fn remove_friend(
    backup: &mut CloudRecoveryBackup,
    hww_seed: &[u8],
    fingerprint: &str,
) -> Result<()> {
    validate_backup(backup)?;
    let symmetric_key = crypto::decrypt(
        hww_seed,
        HWW_KEY_PURPOSE,
        &backup.hww_encrypted_symmetric_key,
    )?;
    if symmetric_key.len() != 32 {
        bail!("cloud backup contains an invalid symmetric key");
    }
    validate_friend_manifest(backup, &symmetric_key)?;
    let wanted = fingerprint.trim().to_ascii_lowercase();
    let before = backup.friends.len();
    backup
        .friends
        .retain(|friend| friend.fingerprint.to_ascii_lowercase() != wanted);
    if backup.friends.len() == before {
        bail!("no recovery friend with fingerprint {fingerprint} is in this backup");
    }
    backup.encrypted_friend_manifest = encrypt_friend_manifest(&symmetric_key, &backup.friends)?;
    Ok(())
}

/// `Some(kind)` when a stored friend public key is an older type. A key that no longer parses is
/// reported as older too, so it is never silently carried forward.
fn stored_friend_key_kind(friend: &FriendKeyWrapper) -> Option<&'static str> {
    match SignedPublicKey::from_reader_single(friend.public_key_armored.as_bytes()) {
        Ok((public, _)) => older_key_kind(
            std::iter::once(public.primary_key.public_params()).chain(
                public
                    .public_subkeys
                    .iter()
                    .map(|subkey| subkey.key.public_params()),
            ),
        ),
        Err(_) => Some("unreadable"),
    }
}

/// The name a recovery friend's OpenPGP key was issued to, for the printed recovery kit. This is
/// a label the friend chose, not a verified identity.
pub fn friend_user_id(public_key: &[u8]) -> Option<String> {
    let (public, _) = SignedPublicKey::from_reader_single(public_key).ok()?;
    public
        .details
        .users
        .first()
        .map(|user| String::from_utf8_lossy(user.id.id()).into_owned())
}

pub fn friend_fingerprint(public_key: &[u8]) -> Result<String> {
    let (public, _) = SignedPublicKey::from_reader_single(public_key)
        .context("failed to parse recovery friend's OpenPGP public key")?;
    // Refuse legacy algorithms before any signature check or encryption touches them.
    require_modern_public_friend_key(&public)?;
    public
        .verify()
        .context("recovery friend's OpenPGP public key failed self-signature validation")?;
    if !public
        .public_subkeys
        .iter()
        .any(|subkey| subkey.is_encryption_key())
    {
        bail!("recovery friend's OpenPGP key has no encryption-capable subkey");
    }
    Ok(public.fingerprint().to_string())
}

pub fn generate_friend_key(name: &str) -> Result<GeneratedFriendKey> {
    if name.trim().is_empty() {
        bail!("recovery friend name must not be empty");
    }
    let mut encryption_subkey = SubkeyParamsBuilder::default();
    encryption_subkey
        .key_type(KeyType::ECDH(ECCCurve::Curve25519))
        .can_sign(false)
        .can_encrypt(true)
        .can_authenticate(false);
    let mut params = SecretKeyParamsBuilder::default();
    params
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(false)
        .can_encrypt(false)
        .primary_user_id(name.trim().to_owned())
        .subkeys(vec![encryption_subkey.build()?]);
    let secret = params
        .build()?
        .generate(thread_rng())?
        .sign(&mut thread_rng(), &Password::empty())?;
    let public = SignedPublicKey::from(secret.clone());
    let fingerprint = secret.fingerprint().to_string();
    Ok(GeneratedFriendKey {
        fingerprint,
        public_key_armored: public.to_armored_string(ArmorOptions::default())?,
        private_key_armored: secret.to_armored_string(ArmorOptions::default())?,
    })
}

fn wrap_for_friend(public_key: &[u8], symmetric_key: &[u8]) -> Result<FriendKeyWrapper> {
    let (public, _) = SignedPublicKey::from_reader_single(public_key)
        .context("failed to parse recovery friend's OpenPGP public key")?;
    // Refuse legacy algorithms before any signature check or encryption touches them.
    require_modern_public_friend_key(&public)?;
    wrap_for_parsed_friend(&public, symmetric_key)
}

fn wrap_for_parsed_friend(
    public: &SignedPublicKey,
    symmetric_key: &[u8],
) -> Result<FriendKeyWrapper> {
    public
        .verify()
        .context("recovery friend's OpenPGP public key failed self-signature validation")?;
    let encryption_subkey = public
        .public_subkeys
        .iter()
        .find(|subkey| subkey.is_encryption_key())
        .context("recovery friend's OpenPGP key has no encryption-capable subkey")?;
    let mut builder = MessageBuilder::from_bytes("vault-recovery-key", symmetric_key.to_vec())
        .seipd_v1(thread_rng(), SymmetricKeyAlgorithm::AES256);
    builder
        .encrypt_to_key(thread_rng(), encryption_subkey)
        .context("failed to wrap recovery key for friend")?;
    let encrypted = builder
        .to_vec(thread_rng())
        .context("failed to serialize friend recovery key wrapper")?;
    Ok(FriendKeyWrapper {
        fingerprint: public.fingerprint().to_string(),
        public_key_armored: public.to_armored_string(ArmorOptions::default())?,
        encrypted_symmetric_key: STANDARD.encode(encrypted),
    })
}

/// Shown when a friend's own private key is refused during recovery. The vault owner (not the
/// friend) can fix this, so point the friend at the owner and the hardware wallet path.
const LEGACY_FRIEND_KEY_RECOVERY_HINT: &str = "this recovery friend's key is an older type, and \
     this backup does not list it. Older keys only open backups that already listed them before \
     Anzen stopped accepting older keys. Ask the vault owner to recover with their hardware wallet \
     instead, or to add you again with a new modern key";

/// Recovery friends may only use Curve25519 keys: Ed25519 for the primary (certifying) key and
/// X25519 (cv25519) for encryption. These run on the `curve25519-dalek` family, which has no open
/// advisories.
///
/// Everything else is refused for new backups:
/// - RSA: the `rsa` 0.9 crate under `pgp` has the unfixed Marvin timing attack
///   (RUSTSEC-2023-0071).
/// - Ed448/X448 and NIST curves: their code in `pgp` (`cx448`, `p256`/`p384`/`p521`) runs on
///   `crypto-bigint` 0.5, which has timing advisories (RUSTSEC-2026-0387).
/// - DSA and ElGamal: obsolete.
///
/// The check runs on the parsed key material before any signature verification, encryption or
/// decryption. The one exception is a friend already listed in a backup made before this rule:
/// their key may still decrypt that backup (see [`decrypt_with_friend`]), never anything new.
fn is_modern_friend_key(params: &PublicParams) -> bool {
    matches!(
        params,
        PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 { .. })
            | PublicParams::Ed25519(_)
            | PublicParams::X25519(_)
            | PublicParams::ECDH(EcdhPublicParams::Curve25519 { .. })
    )
}

fn older_key_kind<'a>(keys: impl IntoIterator<Item = &'a PublicParams>) -> Option<&'static str> {
    keys.into_iter()
        .find(|params| !is_modern_friend_key(params))
        .map(legacy_key_kind)
}

fn legacy_key_kind(params: &PublicParams) -> &'static str {
    match params {
        PublicParams::RSA(_) => "RSA",
        PublicParams::DSA(_) => "DSA",
        PublicParams::Elgamal(_) => "ElGamal",
        PublicParams::Ed448(_) | PublicParams::X448(_) => "Ed448/X448",
        PublicParams::ECDSA(_) | PublicParams::ECDH(_) => "NIST-curve (ECDSA/ECDH)",
        _ => "unsupported",
    }
}

fn require_modern_friend_key<'a>(keys: impl IntoIterator<Item = &'a PublicParams>) -> Result<()> {
    match older_key_kind(keys) {
        Some(kind) => Err(older_key_error(kind)),
        None => Ok(()),
    }
}

fn older_key_error(kind: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "This recovery friend's OpenPGP key is an older {kind} key, and Anzen only accepts \
             modern ed25519 keys. Older key types run on code with known weaknesses, so Anzen \
             refuses them before using them. Nothing was changed.\n\
             How to fix it: your friend makes a new key, either with \
             `anzen social generate-friend-key --name \"Their Name\" --public-key friend.pub.asc \
             --private-key friend.sec.asc`, or in GnuPG with \
             `gpg --quick-gen-key \"Their Name <email>\" ed25519 cert` followed by \
             `gpg --quick-add-key <FINGERPRINT> cv25519 encr`. Then send the new public key.",
    )
}

fn require_modern_public_friend_key(public: &SignedPublicKey) -> Result<()> {
    require_modern_friend_key(
        std::iter::once(public.primary_key.public_params()).chain(
            public
                .public_subkeys
                .iter()
                .map(|subkey| subkey.key.public_params()),
        ),
    )
}

fn decrypt_payload(backup: &CloudRecoveryBackup, symmetric_key: &[u8]) -> Result<RecoveryPayload> {
    let plaintext = crypto::decrypt(symmetric_key, PAYLOAD_PURPOSE, &backup.encrypted_payload)?;
    serde_json::from_slice(&plaintext).context("decrypted cloud recovery payload is invalid")
}

fn encrypt_friend_manifest(
    symmetric_key: &[u8],
    friends: &[FriendKeyWrapper],
) -> Result<EncryptedBlob> {
    crypto::encrypt(
        symmetric_key,
        FRIEND_MANIFEST_PURPOSE,
        &serde_json::to_vec(friends)?,
    )
}

fn validate_friend_manifest(backup: &CloudRecoveryBackup, symmetric_key: &[u8]) -> Result<()> {
    let authenticated = crypto::decrypt(
        symmetric_key,
        FRIEND_MANIFEST_PURPOSE,
        &backup.encrypted_friend_manifest,
    )?;
    let expected = serde_json::to_vec(&backup.friends)?;
    if authenticated.as_slice() != expected {
        bail!("cloud recovery friend list failed authentication");
    }
    Ok(())
}

fn validate_backup(backup: &CloudRecoveryBackup) -> Result<()> {
    if backup.version != 1 || backup.kind != "vault-cloud-recovery" {
        bail!("unsupported cloud recovery backup");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::initialize;

    #[test]
    fn hww_and_each_friend_decrypt_the_same_authenticated_payload() {
        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize(dir.path()).unwrap();
        let phone = crate::core::storage::load_device_keys(
            dir.path(),
            crate::core::storage::PHONE_DEVICE_FILE,
        )
        .unwrap();
        let hww = crate::core::storage::load_device_keys(
            dir.path(),
            crate::core::storage::HWW_DEVICE_FILE,
        )
        .unwrap();
        let alice = generate_friend_key("Alice <alice@example.test>").unwrap();
        let bob = generate_friend_key("Bob <bob@example.test>").unwrap();
        let payload = RecoveryPayload::new(&initialized.config, &phone).unwrap();
        let backup = create_backup(
            &payload,
            &hww.seed,
            &[alice.public_key_armored, bob.public_key_armored],
        )
        .unwrap();

        assert_eq!(decrypt_with_hww(&backup, &hww.seed).unwrap(), payload);
        assert_eq!(
            decrypt_with_friend(&backup, alice.private_key_armored.as_bytes())
                .unwrap()
                .payload,
            payload
        );
        assert_eq!(
            decrypt_with_friend(&backup, bob.private_key_armored.as_bytes())
                .unwrap()
                .payload,
            payload
        );
    }

    #[test]
    fn encrypted_recovery_payload_preserves_a_vanity_vault_key_index() {
        use crate::core::{policy::VaultPolicy, recovery::rotated_config};
        use std::str::FromStr;

        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize(dir.path()).unwrap();
        let secp = bitcoin::key::Secp256k1::new();
        let phone = crate::core::storage::load_device_keys(
            dir.path(),
            crate::core::storage::PHONE_DEVICE_FILE,
        )
        .unwrap()
        .with_vault_key_index(&secp, 42)
        .unwrap();
        let hww = crate::core::storage::load_device_keys(
            dir.path(),
            crate::core::storage::HWW_DEVICE_FILE,
        )
        .unwrap();
        let hww_pubkey =
            crate::core::keys::VaultKey::from_str(&initialized.config.hww_vault_pubkey).unwrap();
        let policy = VaultPolicy::new(phone.vault_pubkey, hww_pubkey).unwrap();
        let config = rotated_config(&initialized.config, &phone, &policy).unwrap();
        let backup = create_backup(
            &RecoveryPayload::new(&config, &phone).unwrap(),
            &hww.seed,
            &[],
        )
        .unwrap();

        let recovered = decrypt_with_hww(&backup, &hww.seed).unwrap();
        assert_eq!(recovered.phone_vault_key_index, 42);
        recovered.validate_against(&config).unwrap();
    }

    #[test]
    fn an_unconfigured_friend_cannot_decrypt_the_backup() {
        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize(dir.path()).unwrap();
        let phone = crate::core::storage::load_device_keys(
            dir.path(),
            crate::core::storage::PHONE_DEVICE_FILE,
        )
        .unwrap();
        let hww = crate::core::storage::load_device_keys(
            dir.path(),
            crate::core::storage::HWW_DEVICE_FILE,
        )
        .unwrap();
        let stranger = generate_friend_key("Mallory").unwrap();
        let backup = create_backup(
            &RecoveryPayload::new(&initialized.config, &phone).unwrap(),
            &hww.seed,
            &[],
        )
        .unwrap();
        assert!(decrypt_with_friend(&backup, stranger.private_key_armored.as_bytes()).is_err());
    }

    #[test]
    fn friend_list_tampering_fails_authentication() {
        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize(dir.path()).unwrap();
        let phone = crate::core::storage::load_device_keys(
            dir.path(),
            crate::core::storage::PHONE_DEVICE_FILE,
        )
        .unwrap();
        let hww = crate::core::storage::load_device_keys(
            dir.path(),
            crate::core::storage::HWW_DEVICE_FILE,
        )
        .unwrap();
        let alice = generate_friend_key("Alice").unwrap();
        let backup = create_backup(
            &RecoveryPayload::new(&initialized.config, &phone).unwrap(),
            &hww.seed,
            &[alice.public_key_armored],
        )
        .unwrap();

        let mut deleted = backup.clone();
        deleted.friends.clear();
        assert!(decrypt_with_hww(&deleted, &hww.seed).is_err());

        let mut inserted = backup.clone();
        inserted.friends.push(inserted.friends[0].clone());
        assert!(decrypt_with_hww(&inserted, &hww.seed).is_err());

        let mut modified = backup;
        modified.friends[0].fingerprint.push('0');
        assert!(decrypt_with_hww(&modified, &hww.seed).is_err());
    }

    #[test]
    fn friend_emergency_access_still_obeys_the_phone_recovery_delay() {
        use crate::core::{
            PHONE_RECOVERY_BLOCKS,
            recovery::{self, SweepPath},
            types::VaultUtxo,
        };
        use bitcoin::{Address, Amount, OutPoint, TxOut, Txid, hashes::Hash};
        use std::str::FromStr;

        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize(dir.path()).unwrap();
        let phone = crate::core::storage::load_device_keys(
            dir.path(),
            crate::core::storage::PHONE_DEVICE_FILE,
        )
        .unwrap();
        let hww = crate::core::storage::load_device_keys(
            dir.path(),
            crate::core::storage::HWW_DEVICE_FILE,
        )
        .unwrap();
        let friend = generate_friend_key("Alice").unwrap();
        let backup = create_backup(
            &RecoveryPayload::new(&initialized.config, &phone).unwrap(),
            &hww.seed,
            &[friend.public_key_armored],
        )
        .unwrap();
        let recovered = decrypt_with_friend(&backup, friend.private_key_armored.as_bytes())
            .unwrap()
            .payload;
        let recovered_phone = DeviceKeys::parse_for_network_at_index(
            &bitcoin::key::Secp256k1::new(),
            &recovered.phone_mnemonic,
            initialized.config.bitcoin_network().unwrap(),
            recovered.phone_vault_key_index,
        )
        .unwrap();
        let destination = Address::from_str(&initialized.config.vault_address)
            .unwrap()
            .require_network(initialized.config.bitcoin_network().unwrap())
            .unwrap();
        let utxo = VaultUtxo {
            outpoint: OutPoint::new(Txid::all_zeros(), 0),
            txout: TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: destination.script_pubkey(),
            },
            confirmation_height: 1,
        };
        assert!(
            recovery::prepare_sweep(
                &initialized.config,
                std::slice::from_ref(&utxo),
                u64::from(PHONE_RECOVERY_BLOCKS) - 1,
                SweepPath::PhoneRecovery,
                &destination,
            )
            .is_err()
        );
        let plan = recovery::prepare_sweep(
            &initialized.config,
            &[utxo],
            u64::from(PHONE_RECOVERY_BLOCKS),
            SweepPath::PhoneRecovery,
            &destination,
        )
        .unwrap();
        let (_, result) =
            recovery::sign_recovery_sweep(plan, SweepPath::PhoneRecovery, &recovered_phone)
                .unwrap();
        assert_eq!(result.input_count, 1);
    }

    const GINA_PUBLIC: &str = include_str!("../../tests/fixtures/friend-keys/gina.pub.asc");
    const GINA_SECRET: &str = include_str!("../../tests/fixtures/friend-keys/gina.sec.asc");
    const RITA_RSA_PUBLIC: &str = include_str!("../../tests/fixtures/friend-keys/rita.pub.asc");
    const RITA_RSA_SECRET: &str = include_str!("../../tests/fixtures/friend-keys/rita.sec.asc");
    const MAX_RSA_SUBKEY_PUBLIC: &str =
        include_str!("../../tests/fixtures/friend-keys/max.pub.asc");
    const PAT_P256_PUBLIC: &str = include_str!("../../tests/fixtures/friend-keys/pat.pub.asc");
    const EVE_GNUPG_ED448_PUBLIC: &str =
        include_str!("../../tests/fixtures/friend-keys/eve.pub.asc");

    /// A backup as Anzen made it before older friend keys were refused: `older_public` is wrapped
    /// without the modern-key check, next to the modern friend Gina.
    fn backup_made_before_the_rule(
        older_public: &str,
    ) -> (
        tempfile::TempDir,
        RecoveryPayload,
        Vec<u8>,
        CloudRecoveryBackup,
    ) {
        let (dir, payload, hww_seed, backup) = backup_fixture(&[GINA_PUBLIC.to_owned()]);
        let mut backup = backup.unwrap();
        let symmetric_key = crypto::decrypt(
            &hww_seed,
            HWW_KEY_PURPOSE,
            &backup.hww_encrypted_symmetric_key,
        )
        .unwrap();
        let (public, _) = SignedPublicKey::from_reader_single(older_public.as_bytes()).unwrap();
        backup
            .friends
            .push(wrap_for_parsed_friend(&public, &symmetric_key).unwrap());
        backup
            .friends
            .sort_by(|left, right| left.fingerprint.cmp(&right.fingerprint));
        backup.encrypted_friend_manifest =
            encrypt_friend_manifest(&symmetric_key, &backup.friends).unwrap();
        (dir, payload, hww_seed, backup)
    }

    fn generate_ed448_friend_key() -> (String, String) {
        let mut encryption_subkey = SubkeyParamsBuilder::default();
        encryption_subkey
            .key_type(KeyType::X448)
            .can_sign(false)
            .can_encrypt(true)
            .can_authenticate(false);
        let mut params = SecretKeyParamsBuilder::default();
        params
            .key_type(KeyType::Ed448)
            .can_certify(true)
            .can_sign(false)
            .can_encrypt(false)
            .primary_user_id("Ed448 Friend".to_owned())
            .subkeys(vec![encryption_subkey.build().unwrap()]);
        let secret = params
            .build()
            .unwrap()
            .generate(thread_rng())
            .unwrap()
            .sign(&mut thread_rng(), &Password::empty())
            .unwrap();
        let public = SignedPublicKey::from(secret.clone());
        (
            public.to_armored_string(ArmorOptions::default()).unwrap(),
            secret.to_armored_string(ArmorOptions::default()).unwrap(),
        )
    }

    fn backup_fixture(
        friends: &[String],
    ) -> (
        tempfile::TempDir,
        RecoveryPayload,
        Vec<u8>,
        Result<CloudRecoveryBackup>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let initialized = initialize(dir.path()).unwrap();
        let phone = crate::core::storage::load_device_keys(
            dir.path(),
            crate::core::storage::PHONE_DEVICE_FILE,
        )
        .unwrap();
        let hww = crate::core::storage::load_device_keys(
            dir.path(),
            crate::core::storage::HWW_DEVICE_FILE,
        )
        .unwrap();
        let payload = RecoveryPayload::new(&initialized.config, &phone).unwrap();
        let backup = create_backup(&payload, &hww.seed, friends);
        (dir, payload, hww.seed.to_vec(), backup)
    }

    fn assert_refused_as(error: anyhow::Error, kind: &str) {
        let message = format!("{error:#}");
        assert!(message.contains(kind), "{message}");
        assert!(
            message.contains("only accepts modern ed25519 keys"),
            "{message}"
        );
        assert!(message.contains("cv25519 encr"), "{message}");
    }

    #[test]
    fn gnupg_ed25519_friend_keys_are_accepted_and_can_recover() {
        assert!(friend_fingerprint(GINA_PUBLIC.as_bytes()).is_ok());
        let (_dir, payload, _, backup) = backup_fixture(&[GINA_PUBLIC.to_owned()]);
        let backup = backup.unwrap();
        assert_eq!(
            decrypt_with_friend(&backup, GINA_SECRET.as_bytes()).unwrap(),
            FriendRecovery {
                payload,
                older_key_kind: None,
            }
        );
    }

    #[test]
    fn rsa_friend_keys_are_refused_everywhere_they_can_be_added() {
        assert_refused_as(
            friend_fingerprint(RITA_RSA_PUBLIC.as_bytes()).unwrap_err(),
            "older RSA key",
        );
        let (_dir, _, _, backup) = backup_fixture(&[RITA_RSA_PUBLIC.to_owned()]);
        assert_refused_as(backup.unwrap_err(), "older RSA key");

        let (_dir, _, hww_seed, backup) = backup_fixture(&[GINA_PUBLIC.to_owned()]);
        let mut backup = backup.unwrap();
        let before = backup.clone();
        assert_refused_as(
            add_friend(&mut backup, &hww_seed, RITA_RSA_PUBLIC.as_bytes()).unwrap_err(),
            "older RSA key",
        );
        assert_eq!(
            backup, before,
            "a refused friend must leave the backup unchanged"
        );
    }

    #[test]
    fn a_modern_primary_key_with_an_rsa_subkey_is_refused() {
        assert_refused_as(
            friend_fingerprint(MAX_RSA_SUBKEY_PUBLIC.as_bytes()).unwrap_err(),
            "older RSA key",
        );
        let (_dir, _, _, backup) = backup_fixture(&[MAX_RSA_SUBKEY_PUBLIC.to_owned()]);
        assert_refused_as(backup.unwrap_err(), "older RSA key");
    }

    #[test]
    fn nist_curve_friend_keys_are_refused() {
        assert_refused_as(
            friend_fingerprint(PAT_P256_PUBLIC.as_bytes()).unwrap_err(),
            "NIST-curve",
        );
    }

    #[test]
    fn an_rsa_private_key_is_refused_before_any_decryption() {
        let (_dir, _, _, backup) = backup_fixture(&[GINA_PUBLIC.to_owned()]);
        let error = decrypt_with_friend(&backup.unwrap(), RITA_RSA_SECRET.as_bytes()).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("recover with their hardware wallet"),
            "{message}"
        );
        assert_refused_as(error, "older RSA key");
    }

    #[test]
    fn ed448_and_x448_friend_keys_are_refused_for_new_backups() {
        let (public, secret) = generate_ed448_friend_key();
        assert_refused_as(
            friend_fingerprint(public.as_bytes()).unwrap_err(),
            "older Ed448/X448 key",
        );
        let (_dir, _, _, backup) = backup_fixture(std::slice::from_ref(&public));
        assert_refused_as(backup.unwrap_err(), "older Ed448/X448 key");

        let (_dir, _, hww_seed, backup) = backup_fixture(&[GINA_PUBLIC.to_owned()]);
        let mut backup = backup.unwrap();
        let before = backup.clone();
        assert_refused_as(
            add_friend(&mut backup, &hww_seed, public.as_bytes()).unwrap_err(),
            "older Ed448/X448 key",
        );
        assert_eq!(backup, before);
        assert_refused_as(
            decrypt_with_friend(&backup, secret.as_bytes()).unwrap_err(),
            "older Ed448/X448 key",
        );
    }

    #[test]
    fn gnupg_ed448_friend_keys_are_not_accepted() {
        // GnuPG 2.4 makes Ed448 keys in its own v5 format. Whether `pgp` refuses to parse them or
        // our check refuses them, they must never be accepted.
        assert!(friend_fingerprint(EVE_GNUPG_ED448_PUBLIC.as_bytes()).is_err());
        let (_dir, _, _, backup) = backup_fixture(&[EVE_GNUPG_ED448_PUBLIC.to_owned()]);
        assert!(backup.is_err());
    }

    #[test]
    fn an_rsa_friend_in_a_backup_made_before_the_rule_can_still_recover() {
        let (_dir, payload, hww_seed, backup) = backup_made_before_the_rule(RITA_RSA_PUBLIC);

        let recovered = decrypt_with_friend(&backup, RITA_RSA_SECRET.as_bytes()).unwrap();
        assert_eq!(recovered.payload, payload);
        assert_eq!(recovered.older_key_kind, Some("RSA"));
        // The modern friend and the HWW are unaffected.
        assert_eq!(
            decrypt_with_friend(&backup, GINA_SECRET.as_bytes())
                .unwrap()
                .older_key_kind,
            None
        );
        assert_eq!(decrypt_with_hww(&backup, &hww_seed).unwrap(), payload);
    }

    #[test]
    fn an_ed448_friend_in_a_backup_made_before_the_rule_can_still_recover() {
        let (public, secret) = generate_ed448_friend_key();
        let (_dir, payload, _, backup) = backup_made_before_the_rule(&public);
        let recovered = decrypt_with_friend(&backup, secret.as_bytes()).unwrap();
        assert_eq!(recovered.payload, payload);
        assert_eq!(recovered.older_key_kind, Some("Ed448/X448"));
    }

    #[test]
    fn older_friends_are_listed_and_left_out_of_new_backups() {
        let (_dir, _, _, backup) = backup_made_before_the_rule(RITA_RSA_PUBLIC);
        let rita_fingerprint = SignedPublicKey::from_reader_single(RITA_RSA_PUBLIC.as_bytes())
            .unwrap()
            .0
            .fingerprint()
            .to_string();
        let older = older_friends(&backup);
        assert_eq!(older.len(), 1);
        assert_eq!(older[0].fingerprint, rita_fingerprint);
        assert_eq!(older[0].kind, "RSA");

        let carried = modern_friend_public_keys(&backup);
        assert_eq!(carried.len(), 1);
        assert_eq!(
            friend_fingerprint(carried[0].as_bytes()).unwrap(),
            friend_fingerprint(GINA_PUBLIC.as_bytes()).unwrap()
        );
    }

    #[test]
    fn removing_an_older_friend_keeps_the_backup_authenticated() {
        let (_dir, payload, hww_seed, mut backup) = backup_made_before_the_rule(RITA_RSA_PUBLIC);
        let rita_fingerprint = older_friends(&backup)[0].fingerprint.clone();

        remove_friend(
            &mut backup,
            &hww_seed,
            &rita_fingerprint.to_ascii_uppercase(),
        )
        .unwrap();
        assert!(older_friends(&backup).is_empty());
        assert_eq!(decrypt_with_hww(&backup, &hww_seed).unwrap(), payload);
        assert_eq!(
            decrypt_with_friend(&backup, GINA_SECRET.as_bytes())
                .unwrap()
                .payload,
            payload
        );
        // Rita is no longer listed, so her older key is refused outright.
        assert_refused_as(
            decrypt_with_friend(&backup, RITA_RSA_SECRET.as_bytes()).unwrap_err(),
            "older RSA key",
        );
        assert!(remove_friend(&mut backup, &hww_seed, &rita_fingerprint).is_err());
    }

    #[test]
    fn removing_a_friend_needs_the_hww() {
        let (_dir, _, _, mut backup) = backup_made_before_the_rule(RITA_RSA_PUBLIC);
        let before = backup.clone();
        let fingerprint = older_friends(&backup)[0].fingerprint.clone();
        assert!(remove_friend(&mut backup, &[7u8; 64], &fingerprint).is_err());
        assert_eq!(backup, before);
    }
}
