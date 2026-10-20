use super::{HWW_RECOVERY_BLOCKS, PHONE_RECOVERY_BLOCKS, keys::DeviceKeys, policy::VaultPolicy};
use anyhow::{Context, Result, bail};
use bitcoin::{Network, key::Secp256k1};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
};

pub const CONFIG_FILE: &str = "anzen.json";
const LEGACY_CONFIG_FILE: &str = "vault.json";
pub const PHONE_DEVICE_FILE: &str = "phone/device.json";
pub const HWW_DEVICE_FILE: &str = "hww/device.json";
pub const HWW_PUBLIC_FILE: &str = "hww/public.json";
pub const PHONE_BACKUP_FILE: &str = "cloud/phone-seed-backup.json";
/// The heir's public key, recorded before the vault is created so it is in every policy.
pub const HEIR_PUBLIC_FILE: &str = "heir/public.json";
/// The software stand-in for the heir's own wallet. In real use this lives with the heir.
pub const HEIR_DEVICE_FILE: &str = "heir/device.json";
pub const HEIR_PUBLIC_KIND: &str = "heir-public-key";
/// The owner's optional third key. Recorded before `anzen init`, like the heir's.
pub const YUBIKEY_PUBLIC_FILE: &str = "yubikey/public.json";
/// The software stand-in for a YubiKey's key, kept on the computer that uses the YubiKey.
pub const YUBIKEY_DEVICE_FILE: &str = "yubikey/device.json";
pub const YUBIKEY_PUBLIC_KIND: &str = "yubikey-public-key";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    pub version: u8,
    pub network: String,
    pub phone_vault_pubkey: String,
    pub hww_vault_pubkey: String,
    pub phone_hot_external_descriptor: String,
    pub phone_hot_internal_descriptor: String,
    pub vault_descriptor: String,
    pub vault_address: String,
    pub phone_recovery_blocks: u16,
    pub hww_recovery_blocks: u16,
    #[serde(default, alias = "hard_limit_sats")]
    pub monthly_limit_sats: u64,
    #[serde(default)]
    pub emergency_access_limit_sats: u64,
    /// Hard-locked savings outputs, one per unlock date. See `core::savings`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub savings_locks: Vec<crate::core::savings::SavingsLock>,
    /// The person who inherits the vault, if the owner named one. Their key is in every vault
    /// and savings policy from the start; see `VaultPolicy::with_heir`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heir: Option<HeirConfig>,
    /// The owner's optional third key. With it, any two of phone, HWW and YubiKey can move the
    /// coins; see `VaultPolicy::build`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yubikey_vault_pubkey: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeirConfig {
    pub name: String,
    pub vault_pubkey: String,
}

impl HeirConfig {
    pub fn parsed_vault_pubkey(&self) -> Result<crate::core::keys::VaultKey> {
        crate::core::keys::VaultKey::from_str(&self.vault_pubkey).context("invalid heir key")
    }
}

impl VaultConfig {
    pub fn bitcoin_network(&self) -> Result<Network> {
        parse_network_name(&self.network)
    }

    pub fn heir_key(&self) -> Result<Option<crate::core::keys::VaultKey>> {
        self.heir
            .as_ref()
            .map(HeirConfig::parsed_vault_pubkey)
            .transpose()
    }

    pub fn yubikey_key(&self) -> Result<Option<crate::core::keys::VaultKey>> {
        self.yubikey_vault_pubkey
            .as_deref()
            .map(|key| crate::core::keys::VaultKey::from_str(key).context("invalid YubiKey key"))
            .transpose()
    }

    /// Every key the vault policy is built from.
    pub fn policy_keys(&self) -> Result<crate::core::policy::PolicyKeys> {
        Ok(crate::core::policy::PolicyKeys {
            phone: crate::core::keys::VaultKey::from_str(&self.phone_vault_pubkey)
                .context("invalid configured phone key")?,
            hww: crate::core::keys::VaultKey::from_str(&self.hww_vault_pubkey)
                .context("invalid configured HWW key")?,
            yubikey: self.yubikey_key()?,
            heir: self.heir_key()?,
        })
    }

    /// The vault's keys with a new phone key in place of the configured one, for a rotation.
    pub fn policy_keys_with_phone(
        &self,
        phone: crate::core::keys::VaultKey,
    ) -> Result<crate::core::policy::PolicyKeys> {
        Ok(crate::core::policy::PolicyKeys {
            phone,
            ..self.policy_keys()?
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YubikeyPublicFile {
    pub version: u8,
    pub kind: String,
    pub network: String,
    pub vault_pubkey: String,
}

/// The YubiKey recorded for a new vault, if `yubikey/public.json` exists.
pub fn load_yubikey(
    data_dir: &Path,
    network: Network,
) -> Result<Option<crate::core::keys::VaultKey>> {
    let path = data_dir.join(YUBIKEY_PUBLIC_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let file: YubikeyPublicFile = read_json(&path)?;
    if file.version != 1 || file.kind != YUBIKEY_PUBLIC_KIND {
        bail!("unsupported YubiKey public key file");
    }
    if parse_network_name(&file.network)? != network {
        bail!("the YubiKey was set up for a different network than the vault");
    }
    Ok(Some(
        crate::core::keys::VaultKey::from_str(&file.vault_pubkey).context("invalid YubiKey key")?,
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFile {
    pub kind: String,
    #[serde(default = "default_network_name")]
    pub network: String,
    pub mnemonic: String,
    #[serde(default)]
    pub vault_key_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicDeviceFile {
    pub version: u8,
    pub kind: String,
    pub network: String,
    pub vault_pubkey: String,
}

impl PublicDeviceFile {
    pub fn bitcoin_network(&self) -> Result<Network> {
        parse_network_name(&self.network)
    }

    pub fn parsed_vault_pubkey(&self) -> Result<crate::core::keys::VaultKey> {
        crate::core::keys::VaultKey::from_str(&self.vault_pubkey)
            .context("invalid public device vault key")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeirPublicFile {
    pub version: u8,
    pub kind: String,
    pub network: String,
    pub name: String,
    pub vault_pubkey: String,
}

/// The heir named for a new vault, if `heir/public.json` exists.
pub fn load_heir(data_dir: &Path, network: Network) -> Result<Option<HeirConfig>> {
    let path = data_dir.join(HEIR_PUBLIC_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let file: HeirPublicFile = read_json(&path)?;
    if file.version != 1 || file.kind != HEIR_PUBLIC_KIND {
        bail!("unsupported heir public key file");
    }
    if parse_network_name(&file.network)? != network {
        bail!("the heir key was set up for a different network than the vault");
    }
    let heir = HeirConfig {
        name: file.name,
        vault_pubkey: file.vault_pubkey,
    };
    heir.parsed_vault_pubkey()?;
    Ok(Some(heir))
}

impl DeviceFile {
    pub fn bitcoin_network(&self) -> Result<Network> {
        parse_network_name(&self.network)
    }
}

#[derive(Debug)]
pub struct InitializedDevice {
    pub mnemonic: String,
    pub vault_pubkey: String,
    pub vault_key_index: u32,
}

pub fn initialize_vault(data_dir: &Path) -> Result<VaultConfig> {
    initialize_vault_for_network(data_dir, Network::Regtest)
}

pub fn initialize_vault_for_network(data_dir: &Path, network: Network) -> Result<VaultConfig> {
    validate_supported_network(network)?;
    if data_dir.join(CONFIG_FILE).exists() || data_dir.join(LEGACY_CONFIG_FILE).exists() {
        bail!("vault already initialized at {}", data_dir.display());
    }
    let secp = Secp256k1::new();
    let phone_file = load_device(data_dir, PHONE_DEVICE_FILE)
        .context("initialize the phone before the vault")?;
    if phone_file.bitcoin_network()? != network {
        bail!("phone, HWW, and vault must be initialized for the same network");
    }
    let phone = DeviceKeys::parse_for_network_at_index(
        &secp,
        &phone_file.mnemonic,
        network,
        phone_file.vault_key_index,
    )?;
    let hww_vault_key = hww_vault_key(data_dir, network)?;
    let heir = load_heir(data_dir, network)?;
    let heir_key = heir
        .as_ref()
        .map(HeirConfig::parsed_vault_pubkey)
        .transpose()?;
    if heir_key.is_some_and(|key| key == phone.vault_pubkey || key == hww_vault_key) {
        bail!("the heir must have their own key, not one of the vault devices' keys");
    }
    let yubikey = load_yubikey(data_dir, network)?;
    let policy = VaultPolicy::build(
        &crate::core::policy::PolicyKeys {
            phone: phone.vault_pubkey,
            hww: hww_vault_key,
            yubikey,
            heir: heir_key,
        },
        network,
    )?;
    let (hot_external, hot_internal) = phone.hot_descriptors(&secp)?;
    let config = VaultConfig {
        version: 1,
        network: network_name(network).to_owned(),
        phone_vault_pubkey: phone.vault_pubkey.to_string(),
        hww_vault_pubkey: hww_vault_key.to_string(),
        phone_hot_external_descriptor: hot_external,
        phone_hot_internal_descriptor: hot_internal,
        vault_descriptor: policy.descriptor_string(),
        vault_address: policy.address.to_string(),
        phone_recovery_blocks: PHONE_RECOVERY_BLOCKS,
        hww_recovery_blocks: HWW_RECOVERY_BLOCKS,
        monthly_limit_sats: 0,
        emergency_access_limit_sats: 0,
        savings_locks: Vec::new(),
        heir,
        yubikey_vault_pubkey: yubikey.map(|key| key.to_string()),
    };
    write_json(&data_dir.join(CONFIG_FILE), &config)?;

    Ok(config)
}

/// A vault config rebuilt from the public descriptors in the recovery kit, for a device that
/// holds only one key (the heir's, or the YubiKey's computer). It has no phone wallet and cannot
/// sign for any key but its own. `heir` is copied in when the heir is the one restoring.
pub fn restore_public_config(
    network: Network,
    vault_descriptor: &str,
    savings_descriptors: &[String],
    heir: Option<HeirConfig>,
) -> Result<VaultConfig> {
    use crate::core::{policy::SavingsPolicy, savings::SavingsLock};
    let vault = VaultPolicy::from_descriptor_for_network(vault_descriptor, network)?;
    let keys = vault.keys(network)?;
    if let Some(heir) = &heir
        && keys.heir.map(|key| key.to_string()) != Some(heir.vault_pubkey.clone())
    {
        bail!("this vault does not name this heir's key");
    }
    let mut savings_locks = Vec::with_capacity(savings_descriptors.len());
    for text in savings_descriptors {
        let policy = SavingsPolicy::from_descriptor_for_network(text, network)?;
        let lock_keys = policy.keys();
        if lock_keys.yubikey != keys.yubikey || lock_keys.heir != keys.heir {
            bail!("a savings lock does not belong to this vault");
        }
        savings_locks.push(SavingsLock {
            unlock: policy.unlock,
            phone_vault_pubkey: lock_keys.phone.to_string(),
            hww_vault_pubkey: lock_keys.hww.to_string(),
            yubikey_vault_pubkey: lock_keys.yubikey.map(|key| key.to_string()),
            heir_vault_pubkey: lock_keys.heir.map(|key| key.to_string()),
            address: policy.address.to_string(),
            default_deposit: false,
        });
    }
    savings_locks.sort_by_key(|lock| lock.unlock);
    Ok(VaultConfig {
        version: 1,
        network: network_name(network).to_owned(),
        phone_vault_pubkey: keys.phone.to_string(),
        hww_vault_pubkey: keys.hww.to_string(),
        phone_hot_external_descriptor: String::new(),
        phone_hot_internal_descriptor: String::new(),
        vault_descriptor: vault.descriptor_string(),
        vault_address: vault.address.to_string(),
        phone_recovery_blocks: PHONE_RECOVERY_BLOCKS,
        hww_recovery_blocks: HWW_RECOVERY_BLOCKS,
        monthly_limit_sats: 0,
        emergency_access_limit_sats: 0,
        savings_locks,
        heir,
        yubikey_vault_pubkey: keys.yubikey.map(|key| key.to_string()),
    })
}

/// The HWW's vault key: from its key store when the HWW is the software stand-in, otherwise
/// from the public record a hardware wallet left at setup.
fn hww_vault_key(data_dir: &Path, network: Network) -> Result<crate::core::keys::VaultKey> {
    let public = data_dir.join(HWW_PUBLIC_FILE);
    let public_key = if public.exists() {
        let public_hww = load_public_device(data_dir, HWW_PUBLIC_FILE)?;
        if public_hww.bitcoin_network()? != network {
            bail!("phone, HWW, and vault must be initialized for the same network");
        }
        Some(public_hww.parsed_vault_pubkey()?)
    } else {
        None
    };
    if !data_dir.join(HWW_DEVICE_FILE).exists() {
        return public_key.context("initialize the HWW before the vault");
    }
    let hww_file = load_device(data_dir, HWW_DEVICE_FILE)?;
    if hww_file.bitcoin_network()? != network {
        bail!("phone, HWW, and vault must be initialized for the same network");
    }
    let hww = DeviceKeys::parse_for_network_at_index(
        &Secp256k1::new(),
        &hww_file.mnemonic,
        network,
        hww_file.vault_key_index,
    )?;
    if public_key.is_some_and(|key| key != hww.vault_pubkey) {
        bail!("HWW public metadata does not match the initialized HWW key");
    }
    Ok(hww.vault_pubkey)
}

pub fn load_config(data_dir: &Path) -> Result<VaultConfig> {
    read_json(&config_path(data_dir))
}

pub fn config_exists(data_dir: &Path) -> bool {
    data_dir.join(CONFIG_FILE).exists() || data_dir.join(LEGACY_CONFIG_FILE).exists()
}

pub fn set_monthly_limit(data_dir: &Path, monthly_limit_sats: u64) -> Result<VaultConfig> {
    let emergency_access_limit_sats = load_config(data_dir)?.emergency_access_limit_sats;
    set_policy_limits(data_dir, monthly_limit_sats, emergency_access_limit_sats)
}

pub fn set_policy_limits(
    data_dir: &Path,
    monthly_limit_sats: u64,
    emergency_access_limit_sats: u64,
) -> Result<VaultConfig> {
    let mut config = load_config(data_dir)?;
    config.monthly_limit_sats = monthly_limit_sats;
    config.emergency_access_limit_sats = emergency_access_limit_sats;
    write_json(&config_path(data_dir), &config)?;
    Ok(config)
}

pub fn save_config(data_dir: &Path, config: &VaultConfig) -> Result<()> {
    write_json(&config_path(data_dir), config)
}

fn config_path(data_dir: &Path) -> PathBuf {
    let current = data_dir.join(CONFIG_FILE);
    if current.exists() {
        return current;
    }

    let legacy = data_dir.join(LEGACY_CONFIG_FILE);
    if legacy.exists() {
        return legacy;
    }

    current
}

pub fn load_device(data_dir: &Path, relative_path: &str) -> Result<DeviceFile> {
    read_json(&data_dir.join(relative_path))
}

pub fn load_public_device(data_dir: &Path, relative_path: &str) -> Result<PublicDeviceFile> {
    read_json(&data_dir.join(relative_path))
}

pub fn load_device_keys(data_dir: &Path, relative_path: &str) -> Result<DeviceKeys> {
    let file = load_device(data_dir, relative_path)?;
    DeviceKeys::parse_for_network_at_index(
        &Secp256k1::new(),
        &file.mnemonic,
        file.bitcoin_network()?,
        file.vault_key_index,
    )
}

pub fn network_name(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "mainnet",
        Network::Regtest => "regtest",
        Network::Signet => "signet",
        _ => "unsupported",
    }
}

pub fn parse_network_name(name: &str) -> Result<Network> {
    match name {
        "mainnet" | "bitcoin" => Ok(Network::Bitcoin),
        "regtest" => Ok(Network::Regtest),
        "signet" => Ok(Network::Signet),
        _ => bail!("unsupported vault network: {name}"),
    }
}

pub fn validate_supported_network(network: Network) -> Result<()> {
    match network {
        Network::Bitcoin | Network::Regtest | Network::Signet => Ok(()),
        other => bail!("unsupported vault network: {other}"),
    }
}

fn default_network_name() -> String {
    "regtest".to_owned()
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    write_private(path, &serde_json::to_vec_pretty(value)?)
}

/// Replace a file atomically on the same filesystem. The temporary file is private from
/// creation, and is flushed before the rename so interrupted writes cannot truncate live keys
/// or the active schedule. Persist the directory entry as well on Unix.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    #[cfg(unix)]
    let mut created_parents = Vec::new();
    #[cfg(unix)]
    for ancestor in parent.ancestors() {
        if ancestor.as_os_str().is_empty() || ancestor.exists() {
            break;
        }
        created_parents.push(
            ancestor
                .parent()
                .filter(|directory| !directory.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new(".")),
        );
    }
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    // A new epoch may also create several directories. Flush their containing directories so
    // the staged files do not depend on directory entries that are still only in memory.
    #[cfg(unix)]
    for directory in created_parents.into_iter().rev() {
        fs::File::open(directory)?.sync_all()?;
    }
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .write_all(bytes)
        .with_context(|| format!("failed to write {}", path.display()))?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .with_context(|| format!("failed to replace {}", path.display()))?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("invalid JSON in {}", path.display()))
}

pub fn hot_db_path(data_dir: &Path) -> PathBuf {
    data_dir.join("phone/hot-wallet.sqlite")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_files_are_atomically_replaced_and_remain_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        write_json(&path, &vec![1_u64; 100]).unwrap();
        let old_handle = fs::File::open(&path).unwrap();
        write_json(&path, &vec![2_u64; 100]).unwrap();
        assert_eq!(read_json::<Vec<u64>>(&path).unwrap(), vec![2; 100]);
        // An open reader still sees the complete old inode, not truncated/partially written JSON.
        assert_eq!(
            serde_json::from_reader::<_, Vec<u64>>(old_handle).unwrap(),
            vec![1; 100]
        );
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn private_writes_create_nested_state_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("phone/transactions/epoch/schedule.json");
        write_json(&path, &vec![1_u64, 2, 3]).unwrap();
        assert_eq!(read_json::<Vec<u64>>(&path).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn failed_replacement_preserves_destination_and_cleans_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-file");
        fs::create_dir(&path).unwrap();
        write_private(&path.join("retained"), b"unchanged").unwrap();
        assert!(write_private(&path, b"replacement").is_err());
        assert_eq!(fs::read(path.join("retained")).unwrap(), b"unchanged");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
