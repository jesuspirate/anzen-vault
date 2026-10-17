use anyhow::{Context, Result, bail};
use bdk_wallet::bip39::{Language, Mnemonic};
use bitcoin::{
    Network,
    bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub},
    key::Secp256k1,
    secp256k1::{All, Keypair, Signing, Verification, XOnlyPublicKey},
};
use rand::{RngCore, rngs::OsRng};
use std::{fmt, str::FromStr};

use super::policy::SpendPath;

/// Child of a vault account key used by leaves both devices sign together, and by the
/// controller policy. Spelled `/<0;1>/*` in a BIP388 wallet policy, used at index 0.
pub const COOPERATIVE_BRANCH: u32 = 0;
/// Child used by the single-key recovery leaves, spelled `/<2;3>/*`. A stock Ledger refuses a
/// wallet policy that uses the same key with the same derivation in two leaves, so the recovery
/// leaves need their own branch.
pub const RECOVERY_BRANCH: u32 = 2;
/// Every vault policy is used at a single address index.
pub const ADDRESS_INDEX: u32 = 0;

/// A device's vault account key as a BIP388 key expression, `[fingerprint/path]xpub`.
///
/// Hardware wallets with stock firmware only sign for wallet policies written with extended
/// keys, so every vault, savings and controller policy is built from these instead of from
/// bare x-only keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultKey {
    pub fingerprint: Fingerprint,
    /// Path from the master key to `xpub`. Stored in a fixed-size form so the key stays `Copy`.
    origin: [u32; 5],
    pub xpub: Xpub,
}

impl VaultKey {
    pub fn new(fingerprint: Fingerprint, origin: &DerivationPath, xpub: Xpub) -> Result<Self> {
        let steps: Vec<u32> = origin.into_iter().map(|child| u32::from(*child)).collect();
        let origin: [u32; 5] = steps
            .try_into()
            .map_err(|_| anyhow::anyhow!("vault key origin must have exactly five steps"))?;
        Ok(Self {
            fingerprint,
            origin,
            xpub,
        })
    }

    pub fn origin(&self) -> DerivationPath {
        self.origin
            .iter()
            .map(|step| ChildNumber::from(*step))
            .collect::<Vec<_>>()
            .into()
    }

    /// The x-only key at `branch/ADDRESS_INDEX` below the account key.
    pub fn child<C: Verification>(&self, secp: &Secp256k1<C>, branch: u32) -> XOnlyPublicKey {
        let path = [
            ChildNumber::from_normal_idx(branch).expect("branch is a small constant"),
            ChildNumber::from_normal_idx(ADDRESS_INDEX).expect("index is a small constant"),
        ];
        let child = self
            .xpub
            .derive_pub(secp, &path)
            .expect("unhardened derivation from a valid xpub");
        child.public_key.x_only_public_key().0
    }

    /// Key used in the cooperative leaf and the controller policy.
    pub fn cooperative(&self) -> XOnlyPublicKey {
        self.child(&Secp256k1::verification_only(), COOPERATIVE_BRANCH)
    }

    /// Key used in this device's single-key recovery leaf.
    pub fn recovery(&self) -> XOnlyPublicKey {
        self.child(&Secp256k1::verification_only(), RECOVERY_BRANCH)
    }

    /// Key that signs the leaf for `path`.
    pub fn for_path(&self, path: SpendPath) -> XOnlyPublicKey {
        match path {
            SpendPath::Cooperative => self.cooperative(),
            SpendPath::PhoneRecovery | SpendPath::HwwRecovery => self.recovery(),
        }
    }

    /// Descriptor key expression for one branch pair: `[fp/path]xpub/<b;b+1>/*`.
    pub fn branch_expression(&self, branch: u32) -> String {
        format!("{self}/<{branch};{}>/*", branch + 1)
    }
}

impl fmt::Display for VaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let origin = self.origin().to_string();
        let origin = origin.trim_start_matches("m/");
        write!(f, "[{}/{}]{}", self.fingerprint, origin, self.xpub)
    }
}

impl FromStr for VaultKey {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> Result<Self> {
        let rest = text
            .strip_prefix('[')
            .context("vault key must start with its [fingerprint/path] origin")?;
        let (origin, xpub) = rest
            .split_once(']')
            .context("vault key origin is not closed")?;
        let (fingerprint, path) = origin
            .split_once('/')
            .context("vault key origin has no derivation path")?;
        let fingerprint = Fingerprint::from_str(fingerprint).context("invalid key fingerprint")?;
        let path = DerivationPath::from_str(&format!("m/{path}"))
            .context("invalid key origin derivation path")?;
        let xpub = Xpub::from_str(xpub).context("invalid vault xpub")?;
        if xpub.depth as usize != path.len() {
            bail!("vault key origin does not match the xpub depth");
        }
        Self::new(fingerprint, &path, xpub)
    }
}

impl serde::Serialize for VaultKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for VaultKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_str(&text).map_err(serde::de::Error::custom)
    }
}

/// The private keys behind a [`VaultKey`]: one per branch, so each leaf is signed with the key
/// it names.
#[derive(Debug, Clone, Copy)]
pub struct VaultKeypairs {
    pub cooperative: Keypair,
    pub recovery: Keypair,
}

impl VaultKeypairs {
    pub fn from_account<C: Signing>(secp: &Secp256k1<C>, account: &Xpriv) -> Result<Self> {
        let at = |branch: u32| -> Result<Keypair> {
            let path = [
                ChildNumber::from_normal_idx(branch)?,
                ChildNumber::from_normal_idx(ADDRESS_INDEX)?,
            ];
            let child = account.derive_priv(secp, &path)?;
            Ok(Keypair::from_secret_key(secp, &child.private_key))
        };
        Ok(Self {
            cooperative: at(COOPERATIVE_BRANCH)?,
            recovery: at(RECOVERY_BRANCH)?,
        })
    }

    pub fn for_path(&self, path: SpendPath) -> &Keypair {
        match path {
            SpendPath::Cooperative => &self.cooperative,
            SpendPath::PhoneRecovery | SpendPath::HwwRecovery => &self.recovery,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeviceKeys {
    pub network: Network,
    pub mnemonic: Mnemonic,
    pub vault_key_index: u32,
    pub seed: [u8; 64],
    pub master_xpriv: Xpriv,
    /// Vault account key at `m/86'/coin'/100'/0/vault_key_index`.
    pub vault_xpriv: Xpriv,
    pub vault_keypair: VaultKeypairs,
    pub vault_pubkey: VaultKey,
}

impl DeviceKeys {
    pub fn generate(secp: &Secp256k1<All>) -> Result<Self> {
        Self::generate_for_network(secp, Network::Regtest)
    }

    pub fn generate_for_network(secp: &Secp256k1<All>, network: Network) -> Result<Self> {
        Self::generate_for_network_at_index(secp, network, 0)
    }

    pub fn generate_for_network_at_index(
        secp: &Secp256k1<All>,
        network: Network,
        vault_key_index: u32,
    ) -> Result<Self> {
        let mut entropy = [0_u8; 32];
        OsRng.fill_bytes(&mut entropy);
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .context("failed to generate mnemonic")?;
        Self::from_mnemonic(secp, mnemonic, network, vault_key_index)
    }

    pub fn parse(secp: &Secp256k1<All>, words: &str) -> Result<Self> {
        Self::parse_for_network(secp, words, Network::Regtest)
    }

    pub fn parse_for_network(secp: &Secp256k1<All>, words: &str, network: Network) -> Result<Self> {
        Self::parse_for_network_at_index(secp, words, network, 0)
    }

    pub fn parse_for_network_at_index(
        secp: &Secp256k1<All>,
        words: &str,
        network: Network,
        vault_key_index: u32,
    ) -> Result<Self> {
        let mnemonic =
            Mnemonic::parse_in_normalized(Language::English, words).context("invalid mnemonic")?;
        Self::from_mnemonic(secp, mnemonic, network, vault_key_index)
    }

    pub fn hot_descriptors(&self, secp: &Secp256k1<All>) -> Result<(String, String)> {
        let coin_type = coin_type(self.network)?;
        let account_path = DerivationPath::from_str(&format!("m/86'/{coin_type}'/0'"))?;
        let account_xpriv = self.master_xpriv.derive_priv(secp, &account_path)?;
        let account_xpub = Xpub::from_priv(secp, &account_xpriv);
        let fingerprint = self.master_xpriv.fingerprint(secp);
        Ok((
            format!("tr([{fingerprint}/86'/{coin_type}'/0']{account_xpub}/0/*)"),
            format!("tr([{fingerprint}/86'/{coin_type}'/0']{account_xpub}/1/*)"),
        ))
    }

    pub fn hot_private_descriptors(&self, secp: &Secp256k1<All>) -> Result<(String, String)> {
        let coin_type = coin_type(self.network)?;
        let account_path = DerivationPath::from_str(&format!("m/86'/{coin_type}'/0'"))?;
        let account_xpriv = self.master_xpriv.derive_priv(secp, &account_path)?;
        let fingerprint = self.master_xpriv.fingerprint(secp);
        Ok((
            format!("tr([{fingerprint}/86'/{coin_type}'/0']{account_xpriv}/0/*)"),
            format!("tr([{fingerprint}/86'/{coin_type}'/0']{account_xpriv}/1/*)"),
        ))
    }

    pub fn vault_parent_xpriv(&self, secp: &Secp256k1<All>) -> Result<Xpriv> {
        Ok(self
            .master_xpriv
            .derive_priv(secp, &vault_parent_path(self.network)?)?)
    }

    /// The public parent of every vault account key, with its origin, for fast vanity grinding.
    pub fn vault_parent(&self, secp: &Secp256k1<All>) -> Result<VaultKeyParent> {
        Ok(VaultKeyParent {
            fingerprint: self.master_xpriv.fingerprint(secp),
            path: vault_parent_path(self.network)?,
            xpub: Xpub::from_priv(secp, &self.vault_parent_xpriv(secp)?),
        })
    }

    pub fn derive_vault_key_from_parent(
        secp: &Secp256k1<All>,
        network: Network,
        master: &Xpriv,
        parent: &Xpriv,
        vault_key_index: u32,
    ) -> Result<(Xpriv, VaultKeypairs, VaultKey)> {
        let child = ChildNumber::from_normal_idx(vault_key_index)
            .context("vault key index must be below 2^31")?;
        let vault_xpriv = parent.derive_priv(secp, &[child])?;
        let vault_keypair = VaultKeypairs::from_account(secp, &vault_xpriv)?;
        let path = vault_parent_path(network)?.child(child);
        let vault_pubkey = VaultKey::new(
            master.fingerprint(secp),
            &path,
            Xpub::from_priv(secp, &vault_xpriv),
        )?;
        Ok((vault_xpriv, vault_keypair, vault_pubkey))
    }

    pub fn with_vault_key_index(
        mut self,
        secp: &Secp256k1<All>,
        vault_key_index: u32,
    ) -> Result<Self> {
        let parent = self.vault_parent_xpriv(secp)?;
        let (vault_xpriv, vault_keypair, vault_pubkey) = Self::derive_vault_key_from_parent(
            secp,
            self.network,
            &self.master_xpriv,
            &parent,
            vault_key_index,
        )?;
        self.vault_key_index = vault_key_index;
        self.vault_xpriv = vault_xpriv;
        self.vault_keypair = vault_keypair;
        self.vault_pubkey = vault_pubkey;
        Ok(self)
    }

    fn from_mnemonic(
        secp: &Secp256k1<All>,
        mnemonic: Mnemonic,
        network: Network,
        vault_key_index: u32,
    ) -> Result<Self> {
        let seed = mnemonic.to_seed_normalized("");
        let master_xpriv = Xpriv::new_master(network, &seed)?;
        let parent = master_xpriv.derive_priv(secp, &vault_parent_path(network)?)?;
        let (vault_xpriv, vault_keypair, vault_pubkey) = Self::derive_vault_key_from_parent(
            secp,
            network,
            &master_xpriv,
            &parent,
            vault_key_index,
        )?;
        Ok(Self {
            network,
            mnemonic,
            vault_key_index,
            seed,
            master_xpriv,
            vault_xpriv,
            vault_keypair,
            vault_pubkey,
        })
    }
}

/// Public parent of the vault account keys, `m/86'/coin'/100'/0`.
#[derive(Debug, Clone)]
pub struct VaultKeyParent {
    pub fingerprint: Fingerprint,
    pub path: DerivationPath,
    pub xpub: Xpub,
}

impl VaultKeyParent {
    pub fn vault_key<C: Verification>(&self, secp: &Secp256k1<C>, index: u32) -> Result<VaultKey> {
        let child = ChildNumber::from_normal_idx(index)?;
        VaultKey::new(
            self.fingerprint,
            &self.path.child(child),
            self.xpub.derive_pub(secp, &[child])?,
        )
    }
}

fn vault_parent_path(network: Network) -> Result<DerivationPath> {
    let coin_type = coin_type(network)?;
    Ok(DerivationPath::from_str(&format!(
        "m/86'/{coin_type}'/100'/0"
    ))?)
}

fn coin_type(network: Network) -> Result<u32> {
    match network {
        Network::Bitcoin => Ok(0),
        Network::Regtest | Network::Signet | Network::Testnet | Network::Testnet4 => Ok(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mnemonic_recreates_vault_key_and_hot_descriptors() {
        let secp = Secp256k1::new();
        let generated = DeviceKeys::generate(&secp).unwrap();
        let restored = DeviceKeys::parse(&secp, &generated.mnemonic.to_string()).unwrap();
        assert_eq!(generated.vault_pubkey, restored.vault_pubkey);
        assert_eq!(
            generated.hot_descriptors(&secp).unwrap(),
            restored.hot_descriptors(&secp).unwrap()
        );
        assert_eq!(
            generated.hot_private_descriptors(&secp).unwrap(),
            restored.hot_private_descriptors(&secp).unwrap()
        );
    }

    #[test]
    fn vault_key_round_trips_as_a_key_expression() {
        let secp = Secp256k1::new();
        let keys = DeviceKeys::generate(&secp).unwrap();
        let text = keys.vault_pubkey.to_string();
        assert!(text.starts_with(&format!(
            "[{}/86'/1'/100'/0/0]tpub",
            keys.master_xpriv.fingerprint(&secp)
        )));
        assert_eq!(VaultKey::from_str(&text).unwrap(), keys.vault_pubkey);
        assert!(VaultKey::from_str(&keys.vault_pubkey.cooperative().to_string()).is_err());
        let parent = keys.vault_parent(&secp).unwrap();
        assert_eq!(parent.vault_key(&secp, 0).unwrap(), keys.vault_pubkey);
    }

    #[test]
    fn vault_key_is_separate_from_hot_account() {
        let secp = Secp256k1::new();
        let keys = DeviceKeys::generate(&secp).unwrap();
        let (external, internal) = keys.hot_descriptors(&secp).unwrap();
        assert_ne!(external, internal);
        assert!(!external.contains(&keys.vault_pubkey.xpub.to_string()));
    }

    #[test]
    fn mainnet_uses_bip86_coin_type_zero_and_mainnet_extended_keys() {
        let secp = Secp256k1::new();
        let keys = DeviceKeys::generate_for_network(&secp, Network::Bitcoin).unwrap();
        let (external, _) = keys.hot_descriptors(&secp).unwrap();
        assert!(external.contains("/86'/0'/0']xpub"));
        assert!(!external.contains("tpub"));
    }

    #[test]
    fn indexed_vault_key_is_distinct_and_recoverable_from_the_same_mnemonic() {
        let secp = Secp256k1::new();
        let base = DeviceKeys::generate(&secp).unwrap();
        let indexed = base.clone().with_vault_key_index(&secp, 42).unwrap();
        let restored = DeviceKeys::parse_for_network_at_index(
            &secp,
            &base.mnemonic.to_string(),
            Network::Regtest,
            42,
        )
        .unwrap();

        assert_ne!(base.vault_pubkey, indexed.vault_pubkey);
        assert_eq!(indexed.vault_pubkey, restored.vault_pubkey);
        assert_eq!(indexed.vault_key_index, 42);
    }
}
