//! Device health checks.
//!
//! Keys fail quietly: a phone gets wiped, a hardware wallet's flash degrades, a PIN is forgotten.
//! A health check asks each device to sign a fresh challenge with both of its per-path vault keys
//! (the cooperative key and its single-key recovery key) and verifies each signature against the
//! keys the vault policy derives from the device's configured key expression. That proves the
//! private keys still exist and still match every vault leaf the device signs. Results are kept as a dated history so the app can remind the owner
//! when a check is due. A check never moves coins and costs nothing.

use super::{
    keys::{VaultKey, VaultKeypairs},
    policy::SpendPath,
    storage::{VaultConfig, read_json, write_json},
};
use anyhow::{Context, Result, bail};
use bitcoin::{
    hashes::{Hash, sha256},
    key::{Keypair, Secp256k1},
    secp256k1::{Message, schnorr::Signature},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{fmt, path::Path, str::FromStr};

pub const HEALTH_FILE: &str = "health.json";
/// Check every device at least every six months.
pub const HEALTH_CHECK_INTERVAL_SECS: i64 = 182 * 86_400;
const CHALLENGE_TAG: &str = "anzen/health-check/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Device {
    Phone,
    Hww,
}

impl Device {
    pub const ALL: [Self; 2] = [Self::Phone, Self::Hww];

    pub fn label(self) -> &'static str {
        match self {
            Self::Phone => "Phone",
            Self::Hww => "Hardware wallet",
        }
    }

    /// The recovery leaf this device signs alone.
    fn recovery_path(self) -> SpendPath {
        match self {
            Self::Phone => SpendPath::PhoneRecovery,
            Self::Hww => SpendPath::HwwRecovery,
        }
    }

    pub fn configured_pubkey(self, config: &VaultConfig) -> &str {
        match self {
            Self::Phone => &config.phone_vault_pubkey,
            Self::Hww => &config.hww_vault_pubkey,
        }
    }
}

impl fmt::Display for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Phone => "phone",
            Self::Hww => "hww",
        })
    }
}

/// A fresh, single-use message a device signs to prove it still holds its vault key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub device: Device,
    pub vault_key: VaultKey,
    pub issued_at: i64,
    pub nonce: [u8; 32],
}

impl Challenge {
    pub fn new(config: &VaultConfig, device: Device, now: i64) -> Result<Self> {
        let mut nonce = [0; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        Ok(Self {
            device,
            vault_key: VaultKey::from_str(device.configured_pubkey(config))
                .context("configured vault key is invalid")?,
            issued_at: now,
            nonce,
        })
    }

    /// The per-path keys a device must prove, in a fixed order: cooperative, then recovery.
    pub fn paths(&self) -> [SpendPath; 2] {
        [SpendPath::Cooperative, self.device.recovery_path()]
    }

    /// The tagged digest one per-path key signs. Binding the device role, the derived key, and
    /// time keeps a signature from one check or path from being replayed as another.
    pub fn message(&self, path: SpendPath) -> Message {
        let mut data = Vec::with_capacity(CHALLENGE_TAG.len() + 8 + 32 + 8 + 32);
        data.extend_from_slice(CHALLENGE_TAG.as_bytes());
        data.extend_from_slice(self.device.to_string().as_bytes());
        data.extend_from_slice(&self.vault_key.for_path(path).serialize());
        data.extend_from_slice(&self.issued_at.to_be_bytes());
        data.extend_from_slice(&self.nonce);
        Message::from_digest(sha256::Hash::hash(&data).to_byte_array())
    }
}

/// One signature per key in `Challenge::paths`, in the same order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthProof {
    pub signatures: [Signature; 2],
}

/// Device-side signing. Each device calls this with its own vault keypairs; it refuses to sign a
/// challenge addressed to a different key.
pub fn sign_challenge(challenge: &Challenge, keypairs: &VaultKeypairs) -> Result<HealthProof> {
    let secp = Secp256k1::new();
    let sign = |path: SpendPath| -> Result<Signature> {
        let keypair: &Keypair = keypairs.for_path(path);
        if keypair.x_only_public_key().0 != challenge.vault_key.for_path(path) {
            bail!(
                "{} key does not match the vault; this device is not the one the vault expects",
                challenge.device.label()
            );
        }
        Ok(secp.sign_schnorr(&challenge.message(path), keypair))
    };
    let [first, second] = challenge.paths();
    Ok(HealthProof {
        signatures: [sign(first)?, sign(second)?],
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthRecord {
    pub device: Device,
    pub vault_pubkey: String,
    pub checked_at: i64,
    pub nonce: String,
    /// Cooperative-key signature, then recovery-key signature.
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthHistory {
    pub version: u8,
    pub records: Vec<HealthRecord>,
}

/// Verify a device's answer and turn it into a history record.
pub fn verify(challenge: &Challenge, proof: &HealthProof) -> Result<HealthRecord> {
    let secp = Secp256k1::verification_only();
    for (path, signature) in challenge.paths().into_iter().zip(&proof.signatures) {
        secp.verify_schnorr(
            signature,
            &challenge.message(path),
            &challenge.vault_key.for_path(path),
        )
        .with_context(|| {
            format!(
                "{} failed its health check: the signature does not match the vault key",
                challenge.device.label()
            )
        })?;
    }
    Ok(HealthRecord {
        device: challenge.device,
        vault_pubkey: challenge.vault_key.to_string(),
        checked_at: challenge.issued_at,
        nonce: bitcoin::hex::DisplayHex::to_lower_hex_string(&challenge.nonce[..]),
        signatures: proof.signatures.iter().map(ToString::to_string).collect(),
    })
}

pub fn load_history(data_dir: &Path) -> Result<HealthHistory> {
    let path = data_dir.join(HEALTH_FILE);
    if !path.exists() {
        return Ok(HealthHistory {
            version: 1,
            records: Vec::new(),
        });
    }
    read_json(&path)
}

pub fn append_record(data_dir: &Path, record: HealthRecord) -> Result<()> {
    let mut history = load_history(data_dir)?;
    history.version = 1;
    history.records.push(record);
    write_json(&data_dir.join(HEALTH_FILE), &history)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceHealth {
    /// No passing check exists for the device's current key.
    NeverChecked,
    Healthy {
        checked_at: i64,
        due_at: i64,
    },
    Due {
        checked_at: i64,
        due_at: i64,
    },
}

impl DeviceHealth {
    pub fn last_checked(self) -> Option<i64> {
        match self {
            Self::NeverChecked => None,
            Self::Healthy { checked_at, .. } | Self::Due { checked_at, .. } => Some(checked_at),
        }
    }

    pub fn needs_check(self) -> bool {
        !matches!(self, Self::Healthy { .. })
    }
}

/// Health of one device right now. Only checks of the key the vault currently uses count, so a
/// rotated phone starts over as unchecked.
pub fn device_health(
    config: &VaultConfig,
    history: &HealthHistory,
    device: Device,
    now: i64,
) -> DeviceHealth {
    let key = device.configured_pubkey(config);
    let Some(checked_at) = history
        .records
        .iter()
        .filter(|record| record.device == device && record.vault_pubkey == key)
        .map(|record| record.checked_at)
        .max()
    else {
        return DeviceHealth::NeverChecked;
    };
    let due_at = checked_at.saturating_add(HEALTH_CHECK_INTERVAL_SECS);
    if now >= due_at {
        DeviceHealth::Due { checked_at, due_at }
    } else {
        DeviceHealth::Healthy { checked_at, due_at }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::keys::DeviceKeys;

    fn config_for(phone: &DeviceKeys, hww: &DeviceKeys) -> VaultConfig {
        VaultConfig {
            version: 1,
            network: "regtest".to_owned(),
            phone_vault_pubkey: phone.vault_pubkey.to_string(),
            hww_vault_pubkey: hww.vault_pubkey.to_string(),
            phone_hot_external_descriptor: String::new(),
            phone_hot_internal_descriptor: String::new(),
            vault_descriptor: String::new(),
            vault_address: String::new(),
            phone_recovery_blocks: 61_200,
            hww_recovery_blocks: 65_535,
            monthly_limit_sats: 0,
            emergency_access_limit_sats: 0,
            savings_locks: Vec::new(),
            heir: None,
        }
    }

    fn devices() -> (DeviceKeys, DeviceKeys) {
        let secp = Secp256k1::new();
        (
            DeviceKeys::generate_for_network(&secp, bitcoin::Network::Regtest).unwrap(),
            DeviceKeys::generate_for_network(&secp, bitcoin::Network::Regtest).unwrap(),
        )
    }

    #[test]
    fn matching_device_passes_and_is_healthy_for_six_months() {
        let (phone, hww) = devices();
        let config = config_for(&phone, &hww);
        let challenge = Challenge::new(&config, Device::Hww, 1_000).unwrap();
        let signature = sign_challenge(&challenge, &hww.vault_keypair).unwrap();
        let record = verify(&challenge, &signature).unwrap();
        let history = HealthHistory {
            version: 1,
            records: vec![record],
        };
        assert_eq!(
            device_health(&config, &history, Device::Hww, 1_000 + 86_400),
            DeviceHealth::Healthy {
                checked_at: 1_000,
                due_at: 1_000 + HEALTH_CHECK_INTERVAL_SECS
            }
        );
        assert!(
            device_health(
                &config,
                &history,
                Device::Hww,
                1_000 + HEALTH_CHECK_INTERVAL_SECS
            )
            .needs_check()
        );
        assert_eq!(
            device_health(&config, &history, Device::Phone, 2_000),
            DeviceHealth::NeverChecked
        );
    }

    #[test]
    fn wrong_device_refuses_to_sign_and_forged_signatures_fail() {
        let (phone, hww) = devices();
        let config = config_for(&phone, &hww);
        let challenge = Challenge::new(&config, Device::Hww, 1_000).unwrap();
        assert!(sign_challenge(&challenge, &phone.vault_keypair).is_err());

        let other = Challenge::new(&config, Device::Hww, 1_000).unwrap();
        let stale = sign_challenge(&other, &hww.vault_keypair).unwrap();
        assert!(
            verify(&challenge, &stale).is_err(),
            "signatures are single-use"
        );
    }

    #[test]
    fn rotated_key_starts_unchecked() {
        let (phone, hww) = devices();
        let mut config = config_for(&phone, &hww);
        let challenge = Challenge::new(&config, Device::Phone, 1_000).unwrap();
        let record = verify(
            &challenge,
            &sign_challenge(&challenge, &phone.vault_keypair).unwrap(),
        )
        .unwrap();
        let history = HealthHistory {
            version: 1,
            records: vec![record],
        };
        let (new_phone, _) = devices();
        config.phone_vault_pubkey = new_phone.vault_pubkey.to_string();
        assert_eq!(
            device_health(&config, &history, Device::Phone, 2_000),
            DeviceHealth::NeverChecked
        );
    }
}
