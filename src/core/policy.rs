use super::{
    HEIR_RECOVERY_BLOCKS, HWW_RECOVERY_BLOCKS, PHONE_RECOVERY_BLOCKS,
    keys::{COOPERATIVE_BRANCH, RECOVERY_BRANCH, VaultKey},
};
use anyhow::{Context, Result, bail};
use bitcoin::{
    Address, Network, NetworkKind, ScriptBuf,
    bip32::{ChainCode, ChildNumber, Fingerprint, Xpub},
    hashes::{Hash, sha256},
    key::{TapTweak, TweakedPublicKey},
    opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_CSV, OP_NUMEQUAL, OP_VERIFY},
    script::Builder,
    secp256k1::{PublicKey, Secp256k1, Verification, XOnlyPublicKey},
    taproot::{ControlBlock, LeafVersion, TapLeafHash, TapNodeHash},
};
use miniscript::{
    Descriptor,
    descriptor::{DefiniteDescriptorKey, DescriptorPublicKey},
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub const BIP341_NUMS_KEY: &str =
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

/// BIP341's NUMS point H as an extended key, the Taproot internal key of every Anzen policy.
///
/// Wallet policies only take extended keys, so H gets the chain code `sha256(H)`. Any child of H
/// is `H + t·G` with public `t`, and nobody knows the discrete log of H, so the key path stays
/// unspendable at every index. A stock Ledger recognizes H and labels it "Dummy key".
pub fn nums_xpub(network: Network) -> Xpub {
    let point = PublicKey::from_str(&format!("02{BIP341_NUMS_KEY}")).expect("H is a valid point");
    Xpub {
        network: NetworkKind::from(network),
        depth: 0,
        parent_fingerprint: Fingerprint::default(),
        child_number: ChildNumber::from_normal_idx(0).expect("zero is a valid index"),
        public_key: point,
        chain_code: ChainCode::from(sha256::Hash::hash(&point.serialize()).to_byte_array()),
    }
}

/// The NUMS internal key as it appears in a descriptor and in a BIP388 wallet policy.
fn nums_expression(network: Network) -> String {
    format!("{}/<0;1>/*", nums_xpub(network))
}

/// The receive descriptor of a multipath policy, at the single address index Anzen uses.
fn receive_descriptor(
    descriptor: &Descriptor<DescriptorPublicKey>,
) -> Result<Descriptor<DefiniteDescriptorKey>> {
    descriptor
        .clone()
        .into_single_descriptors()?
        .into_iter()
        .next()
        .context("descriptor has no receive branch")?
        .at_derivation_index(super::keys::ADDRESS_INDEX)
        .context("descriptor could not be made definite")
}

fn taproot_spend(
    descriptor: &Descriptor<DescriptorPublicKey>,
) -> Result<miniscript::descriptor::Tr<bitcoin::PublicKey>> {
    match receive_descriptor(descriptor)?.derived_descriptor(&Secp256k1::verification_only())? {
        Descriptor::Tr(tr) => Ok(tr),
        _ => bail!("policy descriptor is not Taproot"),
    }
}

fn policy_address(
    descriptor: &Descriptor<DescriptorPublicKey>,
    network: Network,
) -> Result<Address> {
    Ok(receive_descriptor(descriptor)?
        .derived_descriptor(&Secp256k1::verification_only())?
        .address(network)?)
}

/// A Taproot script policy whose leaves are selected by [`SpendPath`]. Both the vault and the
/// hard-locked savings policies have one cooperative leaf, two single-key recovery leaves and an
/// optional heir leaf, so PSBT construction, signing and verification are shared between them.
pub trait TaprootPolicy {
    fn leaf(&self, path: SpendPath) -> Result<VaultLeaf>;
    fn definite_descriptor(&self) -> Result<Descriptor<DefiniteDescriptorKey>>;
    /// The multipath descriptor, as registered with a hardware wallet.
    fn descriptor(&self) -> &Descriptor<DescriptorPublicKey>;
    fn address(&self) -> &Address;
    /// Name a hardware wallet shows when it registers or signs for this policy.
    fn wallet_name(&self) -> String;
}

impl TaprootPolicy for VaultPolicy {
    fn leaf(&self, path: SpendPath) -> Result<VaultLeaf> {
        VaultPolicy::leaf(self, path)
    }

    fn definite_descriptor(&self) -> Result<Descriptor<DefiniteDescriptorKey>> {
        VaultPolicy::definite_descriptor(self)
    }

    fn descriptor(&self) -> &Descriptor<DescriptorPublicKey> {
        &self.descriptor
    }

    fn address(&self) -> &Address {
        &self.address
    }

    fn wallet_name(&self) -> String {
        "Anzen vault".to_owned()
    }
}

impl TaprootPolicy for SavingsPolicy {
    fn leaf(&self, path: SpendPath) -> Result<VaultLeaf> {
        SavingsPolicy::leaf(self, path)
    }

    fn definite_descriptor(&self) -> Result<Descriptor<DefiniteDescriptorKey>> {
        SavingsPolicy::definite_descriptor(self)
    }

    fn descriptor(&self) -> &Descriptor<DescriptorPublicKey> {
        &self.descriptor
    }

    fn address(&self) -> &Address {
        &self.address
    }

    fn wallet_name(&self) -> String {
        let date = chrono::DateTime::from_timestamp(i64::from(self.unlock), 0)
            .map(|time| time.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| self.unlock.to_string());
        format!("Anzen savings {date}")
    }
}

impl ControllerPolicy {
    pub fn wallet_name(&self) -> String {
        "Anzen connector".to_owned()
    }
}

#[derive(Debug, Clone)]
pub struct VaultPolicy {
    pub descriptor: Descriptor<DescriptorPublicKey>,
    pub address: Address,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SpendPath {
    Cooperative,
    PhoneRecovery,
    HwwRecovery,
    /// The heir's own key, after the longest delay. Only present when the owner named an heir.
    Heir,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControllerPath {
    Phone,
    Hww,
}

#[derive(Debug, Clone)]
pub struct VaultLeaf {
    pub path: SpendPath,
    pub depth: u8,
    pub script: ScriptBuf,
    pub leaf_hash: TapLeafHash,
    pub control_block: ControlBlock,
}

#[derive(Debug, Clone)]
pub struct ControllerLeaf {
    pub path: ControllerPath,
    pub depth: u8,
    pub script: ScriptBuf,
    pub leaf_hash: TapLeafHash,
    pub control_block: ControlBlock,
}

/// The fixed 1-of-2 Taproot policy used by every connector UTXO in one vault.
///
/// It deliberately reuses the vault's phone and HWW public keys. Connector state is represented
/// by an outpoint, not by a derived key: every connector is sent to this same address until the
/// vault keys rotate.
#[derive(Debug, Clone)]
pub struct ControllerPolicy {
    pub descriptor: Descriptor<DescriptorPublicKey>,
    pub address: Address,
    phone: VaultKey,
    hww: VaultKey,
}

/// Fast encoder for the fixed Anzen script tree used while grinding phone vault keys.
///
/// The scripts and tree shape must remain byte-for-byte equivalent to [`VaultPolicy`]. Tests
/// compare this optimized path with the canonical Miniscript descriptor construction.
#[derive(Debug, Clone)]
pub struct VaultAddressTemplate {
    internal_key: XOnlyPublicKey,
    hww_cooperative: XOnlyPublicKey,
    hww_recovery_node: TapNodeHash,
    heir_node: Option<TapNodeHash>,
}

impl VaultAddressTemplate {
    pub fn new(hww: VaultKey, network: Network) -> Result<Self> {
        Self::with_heir(hww, None, network)
    }

    pub fn with_heir(hww: VaultKey, heir: Option<VaultKey>, network: Network) -> Result<Self> {
        let secp = Secp256k1::verification_only();
        let internal_key = nums_xpub(network)
            .derive_pub(
                &secp,
                &[
                    ChildNumber::from_normal_idx(0)?,
                    ChildNumber::from_normal_idx(super::keys::ADDRESS_INDEX)?,
                ],
            )?
            .public_key
            .x_only_public_key()
            .0;
        let hww_recovery_node = TapNodeHash::from_script(
            &recovery_script(hww.child(&secp, RECOVERY_BRANCH), HWW_RECOVERY_BLOCKS),
            LeafVersion::TapScript,
        );
        let heir_node = heir.map(|heir| {
            TapNodeHash::from_script(
                &recovery_script(heir.child(&secp, RECOVERY_BRANCH), HEIR_RECOVERY_BLOCKS),
                LeafVersion::TapScript,
            )
        });
        Ok(Self {
            internal_key,
            hww_cooperative: hww.child(&secp, COOPERATIVE_BRANCH),
            hww_recovery_node,
            heir_node,
        })
    }

    pub fn output_key<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        phone: VaultKey,
    ) -> TweakedPublicKey {
        let cooperative_node = TapNodeHash::from_script(
            &cooperative_script(phone.child(secp, COOPERATIVE_BRANCH), self.hww_cooperative),
            LeafVersion::TapScript,
        );
        let phone_recovery_node = TapNodeHash::from_script(
            &recovery_script(phone.child(secp, RECOVERY_BRANCH), PHONE_RECOVERY_BLOCKS),
            LeafVersion::TapScript,
        );
        let mut recovery_node =
            TapNodeHash::from_node_hashes(phone_recovery_node, self.hww_recovery_node);
        if let Some(heir_node) = self.heir_node {
            recovery_node = TapNodeHash::from_node_hashes(recovery_node, heir_node);
        }
        let merkle_root = TapNodeHash::from_node_hashes(cooperative_node, recovery_node);
        self.internal_key.tap_tweak(secp, Some(merkle_root)).0
    }

    pub fn address<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        phone: VaultKey,
        network: Network,
    ) -> Address {
        Address::p2tr_tweaked(self.output_key(secp, phone), network)
    }
}

/// A descriptor key without its `/<a;b>/*` branch suffix: the account key expression.
fn account_expression(key: &DescriptorPublicKey) -> String {
    let text = key.to_string();
    text.split_once("/<")
        .map_or(text.clone(), |(base, _)| base.to_owned())
}

/// The phone and HWW account keys of the two-key leaf, in that order.
fn cooperative_accounts(
    tr: &miniscript::descriptor::Tr<DescriptorPublicKey>,
) -> Result<Vec<String>> {
    Ok(tr
        .iter_scripts()
        .map(|(_, miniscript)| miniscript.iter_pk().collect::<Vec<_>>())
        .find(|keys| keys.len() == 2)
        .context("descriptor has no two-key leaf")?
        .iter()
        .map(account_expression)
        .collect())
}

/// Read the phone, HWW and heir account keys back out of an Anzen policy descriptor. The
/// caller rebuilds the policy from them and compares, so a descriptor of any other shape is
/// rejected there.
fn policy_keys(
    descriptor: &Descriptor<DescriptorPublicKey>,
) -> Result<(VaultKey, VaultKey, Option<VaultKey>)> {
    let Descriptor::Tr(tr) = descriptor else {
        bail!("descriptor is not Taproot");
    };
    let cooperative = cooperative_accounts(tr)?;
    let mut heir = None;
    for (_, miniscript) in tr.iter_scripts() {
        let keys: Vec<_> = miniscript.iter_pk().collect();
        if let [key] = keys.as_slice() {
            let account = account_expression(key);
            if !cooperative.contains(&account) {
                if heir.is_some_and(|existing: String| existing != account) {
                    bail!("descriptor names more than one heir");
                }
                heir = Some(account);
            }
        }
    }
    Ok((
        VaultKey::from_str(&cooperative[0])?,
        VaultKey::from_str(&cooperative[1])?,
        heir.as_deref().map(VaultKey::from_str).transpose()?,
    ))
}

fn cooperative_script(phone: XOnlyPublicKey, hww: XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_x_only_key(&phone)
        .push_opcode(OP_CHECKSIG)
        .push_x_only_key(&hww)
        .push_opcode(OP_CHECKSIGADD)
        .push_int(2)
        .push_opcode(OP_NUMEQUAL)
        .into_script()
}

fn recovery_script(key: XOnlyPublicKey, delay: u16) -> ScriptBuf {
    Builder::new()
        .push_int(i64::from(delay))
        .push_opcode(OP_CSV)
        .push_opcode(OP_VERIFY)
        .push_x_only_key(&key)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

impl VaultPolicy {
    pub fn new(phone: VaultKey, hww: VaultKey) -> Result<Self> {
        Self::new_for_network(phone, hww, Network::Regtest)
    }

    /// ```text
    /// tr(NUMS/<0;1>/*, { multi_a(2, phone/<0;1>/*, hww/<0;1>/*),
    ///                    { and_v(v:older(61200), pk(phone/<2;3>/*)),
    ///                      and_v(v:older(65535), pk(hww/<2;3>/*)) } })
    /// ```
    /// used at address index 0 of the receive branch.
    pub fn new_for_network(phone: VaultKey, hww: VaultKey, network: Network) -> Result<Self> {
        Self::with_heir(phone, hww, None, network)
    }

    /// The vault policy, with an heir leaf when the owner named an heir:
    ///
    /// ```text
    /// tr(NUMS/<0;1>/*, { multi_a(2, phone/<0;1>/*, hww/<0;1>/*),
    ///                    { { and_v(v:older(61200), pk(phone/<2;3>/*)),
    ///                        and_v(v:older(65535), pk(hww/<2;3>/*)) },
    ///                      and_v(v:older(65535), pk(heir/<2;3>/*)) } })
    /// ```
    ///
    /// The heir's clock is the coin's age, like the recovery leaves: it restarts whenever the
    /// coins move, which only happens through the owner's signed transactions.
    pub fn with_heir(
        phone: VaultKey,
        hww: VaultKey,
        heir: Option<VaultKey>,
        network: Network,
    ) -> Result<Self> {
        let nums = nums_expression(network);
        let (phone_c, hww_c) = (
            phone.branch_expression(COOPERATIVE_BRANCH),
            hww.branch_expression(COOPERATIVE_BRANCH),
        );
        let (phone_r, hww_r) = (
            phone.branch_expression(RECOVERY_BRANCH),
            hww.branch_expression(RECOVERY_BRANCH),
        );
        let mut recovery = format!(
            "{{and_v(v:older({PHONE_RECOVERY_BLOCKS}),pk({phone_r})),and_v(v:older({HWW_RECOVERY_BLOCKS}),pk({hww_r}))}}"
        );
        if let Some(heir) = heir {
            let heir_r = heir.branch_expression(RECOVERY_BRANCH);
            recovery =
                format!("{{{recovery},and_v(v:older({HEIR_RECOVERY_BLOCKS}),pk({heir_r}))}}");
        }
        let descriptor_text = format!("tr({nums},{{multi_a(2,{phone_c},{hww_c}),{recovery}}})");
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&descriptor_text)
            .with_context(|| format!("invalid vault descriptor: {descriptor_text}"))?;
        let address = policy_address(&descriptor, network)?;
        Ok(Self {
            descriptor,
            address,
        })
    }

    pub fn from_descriptor(descriptor_text: &str) -> Result<Self> {
        Self::from_descriptor_for_network(descriptor_text, Network::Regtest)
    }

    pub fn from_descriptor_for_network(descriptor_text: &str, network: Network) -> Result<Self> {
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(descriptor_text)
            .with_context(|| format!("invalid vault descriptor: {descriptor_text}"))?;
        let address = policy_address(&descriptor, network)?;
        Ok(Self {
            descriptor,
            address,
        })
    }

    pub fn definite_descriptor(&self) -> Result<Descriptor<DefiniteDescriptorKey>> {
        receive_descriptor(&self.descriptor)
    }

    /// Find the leaf for `path`. Leaves are told apart by their keys, not their position: the
    /// cooperative leaf holds the phone and HWW keys, a recovery leaf reuses one of those
    /// account keys on its recovery branch, and the heir leaf is the only one with a key that is
    /// not in the cooperative leaf. Each leaf must also be exactly the script Anzen writes.
    pub fn leaf(&self, path: SpendPath) -> Result<VaultLeaf> {
        let Descriptor::Tr(multipath) = &self.descriptor else {
            bail!("vault descriptor is not Taproot");
        };
        let tr = taproot_spend(&self.descriptor)?;
        let spend_info = tr.spend_info();
        let cooperative_accounts = cooperative_accounts(multipath)?;

        for ((_, multipath_leaf), (depth, miniscript)) in
            multipath.iter_scripts().zip(tr.iter_scripts())
        {
            let accounts: Vec<String> = multipath_leaf
                .iter_pk()
                .map(|key| account_expression(&key))
                .collect();
            let keys: Vec<XOnlyPublicKey> = miniscript
                .iter_pk()
                .map(|key| key.inner.x_only_public_key().0)
                .collect();
            let (leaf_path, expected) = match (accounts.as_slice(), keys.as_slice()) {
                ([_, _], [phone, hww]) => {
                    (SpendPath::Cooperative, cooperative_script(*phone, *hww))
                }
                ([account], [key]) if *account == cooperative_accounts[0] => (
                    SpendPath::PhoneRecovery,
                    recovery_script(*key, PHONE_RECOVERY_BLOCKS),
                ),
                ([account], [key]) if *account == cooperative_accounts[1] => (
                    SpendPath::HwwRecovery,
                    recovery_script(*key, HWW_RECOVERY_BLOCKS),
                ),
                ([_], [key]) => (SpendPath::Heir, recovery_script(*key, HEIR_RECOVERY_BLOCKS)),
                _ => bail!("vault descriptor has an unexpected leaf"),
            };
            if leaf_path != path {
                continue;
            }
            let script = miniscript.encode();
            if script != expected {
                bail!("the vault's {path:?} leaf is not the script Anzen expects");
            }
            let leaf_version = LeafVersion::TapScript;
            let leaf_hash = TapLeafHash::from_script(&script, leaf_version);
            let control_block = spend_info
                .control_block(&(script.clone(), leaf_version))
                .context("vault leaf has no Taproot control block")?;
            return Ok(VaultLeaf {
                path,
                depth,
                script,
                leaf_hash,
                control_block,
            });
        }
        bail!("vault descriptor does not contain the requested {path:?} leaf")
    }

    /// The phone, HWW and heir keys of an Anzen vault descriptor, checked by rebuilding it.
    pub fn keys(&self, network: Network) -> Result<(VaultKey, VaultKey, Option<VaultKey>)> {
        let (phone, hww, heir) = policy_keys(&self.descriptor)?;
        let rebuilt = Self::with_heir(phone, hww, heir, network)?;
        if rebuilt.descriptor != self.descriptor {
            bail!("this is not an Anzen vault descriptor");
        }
        Ok((phone, hww, heir))
    }

    /// Whether this vault has an heir leaf.
    pub fn has_heir(&self) -> bool {
        self.leaf(SpendPath::Heir).is_ok()
    }

    pub fn descriptor_string(&self) -> String {
        self.descriptor.to_string()
    }
}

/// Seconds after the savings unlock date before the phone alone can recover a savings output
/// (425 days, about 14 months), mirroring the vault's phone-priority recovery window.
pub const SAVINGS_PHONE_RECOVERY_SECS: u32 = 425 * 86_400;
/// Seconds after the savings unlock date before the HWW alone can recover (455 days).
pub const SAVINGS_HWW_RECOVERY_SECS: u32 = 455 * 86_400;
/// Seconds after the savings unlock date before the heir's own key can claim (485 days), a month
/// after both of the owner's devices.
pub const SAVINGS_HEIR_RECOVERY_SECS: u32 = 485 * 86_400;

/// A hard-locked savings output. Nothing can spend it before `unlock`, not even both devices
/// together. Every path uses an absolute calendar time (CLTV), so these outputs never need the
/// annual rollover: deposits can arrive at any time and stay locked until the same date.
///
/// ```text
/// tr(NUMS, { and_v(v:multi_a(2,phone,hww), after(unlock)),
///            { and_v(v:pk(phone), after(unlock + 425d)),
///              and_v(v:pk(hww),   after(unlock + 455d)) } })
/// ```
///
/// With an heir, the recovery branch becomes
/// `{ { phone leaf, hww leaf }, and_v(v:pk(heir), after(unlock + 485d)) }`.
#[derive(Debug, Clone)]
pub struct SavingsPolicy {
    pub descriptor: Descriptor<DescriptorPublicKey>,
    pub address: Address,
    pub unlock: u32,
    phone: VaultKey,
    hww: VaultKey,
    heir: Option<VaultKey>,
}

impl SavingsPolicy {
    pub fn new_for_network(
        phone: VaultKey,
        hww: VaultKey,
        unlock: u32,
        network: Network,
    ) -> Result<Self> {
        Self::with_heir(phone, hww, None, unlock, network)
    }

    pub fn with_heir(
        phone: VaultKey,
        hww: VaultKey,
        heir: Option<VaultKey>,
        unlock: u32,
        network: Network,
    ) -> Result<Self> {
        if unlock < bitcoin::absolute::LOCK_TIME_THRESHOLD {
            bail!("savings unlock must be a Unix time, not a block height");
        }
        let phone_after = unlock
            .checked_add(SAVINGS_PHONE_RECOVERY_SECS)
            .context("savings unlock too far in the future")?;
        let hww_after = unlock
            .checked_add(SAVINGS_HWW_RECOVERY_SECS)
            .context("savings unlock too far in the future")?;
        let heir_after = unlock
            .checked_add(SAVINGS_HEIR_RECOVERY_SECS)
            .context("savings unlock too far in the future")?;
        let nums = nums_expression(network);
        let (phone_c, hww_c) = (
            phone.branch_expression(COOPERATIVE_BRANCH),
            hww.branch_expression(COOPERATIVE_BRANCH),
        );
        let (phone_r, hww_r) = (
            phone.branch_expression(RECOVERY_BRANCH),
            hww.branch_expression(RECOVERY_BRANCH),
        );
        let mut recovery = format!(
            "{{and_v(v:pk({phone_r}),after({phone_after})),and_v(v:pk({hww_r}),after({hww_after}))}}"
        );
        if let Some(heir) = heir {
            let heir_r = heir.branch_expression(RECOVERY_BRANCH);
            recovery = format!("{{{recovery},and_v(v:pk({heir_r}),after({heir_after}))}}");
        }
        let descriptor_text = format!(
            "tr({nums},{{and_v(v:multi_a(2,{phone_c},{hww_c}),after({unlock})),{recovery}}})"
        );
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&descriptor_text)
            .with_context(|| format!("invalid savings descriptor: {descriptor_text}"))?;
        let address = policy_address(&descriptor, network)?;
        Ok(Self {
            descriptor,
            address,
            unlock,
            phone,
            hww,
            heir,
        })
    }

    /// Rebuild a savings policy from its descriptor, as printed in the recovery kit.
    pub fn from_descriptor_for_network(descriptor_text: &str, network: Network) -> Result<Self> {
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(descriptor_text)
            .with_context(|| format!("invalid savings descriptor: {descriptor_text}"))?;
        let (phone, hww, heir) = policy_keys(&descriptor)?;
        let text = descriptor.to_string();
        let unlock = text
            .split_once("after(")
            .and_then(|(_, rest)| rest.split_once(')'))
            .and_then(|(number, _)| number.parse::<u32>().ok())
            .context("savings descriptor has no unlock date")?;
        let policy = Self::with_heir(phone, hww, heir, unlock, network)?;
        if policy.descriptor != descriptor {
            bail!("this is not an Anzen savings descriptor");
        }
        Ok(policy)
    }

    pub fn keys(&self) -> (VaultKey, VaultKey, Option<VaultKey>) {
        (self.phone, self.hww, self.heir)
    }

    pub fn definite_descriptor(&self) -> Result<Descriptor<DefiniteDescriptorKey>> {
        receive_descriptor(&self.descriptor)
    }

    /// The earliest nLockTime a spend through `path` can use.
    pub fn earliest_lock_time(&self, path: SpendPath) -> u32 {
        match path {
            SpendPath::Cooperative => self.unlock,
            SpendPath::PhoneRecovery => self.unlock + SAVINGS_PHONE_RECOVERY_SECS,
            SpendPath::HwwRecovery => self.unlock + SAVINGS_HWW_RECOVERY_SECS,
            SpendPath::Heir => self.unlock + SAVINGS_HEIR_RECOVERY_SECS,
        }
    }

    pub fn leaf(&self, path: SpendPath) -> Result<VaultLeaf> {
        let tr = taproot_spend(&self.descriptor)?;
        let spend_info = tr.spend_info();
        let single_key = match path {
            SpendPath::Cooperative => None,
            SpendPath::PhoneRecovery => Some(self.phone.recovery()),
            SpendPath::HwwRecovery => Some(self.hww.recovery()),
            SpendPath::Heir => Some(
                self.heir
                    .context("this savings lock has no heir")?
                    .recovery(),
            ),
        };
        for (depth, miniscript) in tr.iter_scripts() {
            let script = miniscript.encode();
            let is_multi = script
                .instructions()
                .any(|i| matches!(i, Ok(bitcoin::script::Instruction::Op(OP_CHECKSIGADD))));
            let matches = match single_key {
                None => is_multi,
                Some(key) => {
                    !is_multi
                        && script
                            .as_bytes()
                            .windows(32)
                            .any(|w| w == key.serialize().as_slice())
                }
            };
            if !matches {
                continue;
            }
            let leaf_version = LeafVersion::TapScript;
            let leaf_hash = TapLeafHash::from_script(&script, leaf_version);
            let control_block = spend_info
                .control_block(&(script.clone(), leaf_version))
                .context("savings leaf has no Taproot control block")?;
            return Ok(VaultLeaf {
                path,
                depth,
                script,
                leaf_hash,
                control_block,
            });
        }
        bail!("savings descriptor does not contain the requested {path:?} leaf")
    }

    pub fn descriptor_string(&self) -> String {
        self.descriptor.to_string()
    }
}

impl ControllerPolicy {
    pub fn new(phone: VaultKey, hww: VaultKey) -> Result<Self> {
        Self::new_for_network(phone, hww, Network::Regtest)
    }

    /// `tr(NUMS/<0;1>/*, { pk(phone/<0;1>/*), pk(hww/<0;1>/*) })`, signed with the same keys as
    /// the vault's cooperative leaf.
    pub fn new_for_network(phone: VaultKey, hww: VaultKey, network: Network) -> Result<Self> {
        let nums = nums_expression(network);
        let phone_c = phone.branch_expression(COOPERATIVE_BRANCH);
        let hww_c = hww.branch_expression(COOPERATIVE_BRANCH);
        let descriptor_text = format!("tr({nums},{{pk({phone_c}),pk({hww_c})}})");
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&descriptor_text)
            .with_context(|| format!("invalid controller descriptor: {descriptor_text}"))?;
        let address = policy_address(&descriptor, network)?;
        Ok(Self {
            descriptor,
            address,
            phone,
            hww,
        })
    }

    pub fn definite_descriptor(&self) -> Result<Descriptor<DefiniteDescriptorKey>> {
        receive_descriptor(&self.descriptor)
    }

    pub fn leaf(&self, path: ControllerPath) -> Result<ControllerLeaf> {
        let key = match path {
            ControllerPath::Phone => self.phone.cooperative(),
            ControllerPath::Hww => self.hww.cooperative(),
        };
        let target_script = Builder::new()
            .push_x_only_key(&key)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        let tr = taproot_spend(&self.descriptor)?;
        let spend_info = tr.spend_info();
        for (depth, miniscript) in tr.iter_scripts() {
            let script = miniscript.encode();
            if script != target_script {
                continue;
            }
            let leaf_version = LeafVersion::TapScript;
            let leaf_hash = TapLeafHash::from_script(&script, leaf_version);
            let control_block = spend_info
                .control_block(&(script.clone(), leaf_version))
                .context("controller leaf has no Taproot control block")?;
            return Ok(ControllerLeaf {
                path,
                depth,
                script,
                leaf_hash,
                control_block,
            });
        }
        bail!("controller descriptor does not contain the requested {path:?} leaf")
    }

    pub fn descriptor_string(&self) -> String {
        self.descriptor.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::keys::DeviceKeys;
    use bitcoin::key::Secp256k1;

    #[test]
    fn descriptor_is_static_and_has_expected_policy() {
        let secp = Secp256k1::new();
        let phone = DeviceKeys::generate(&secp).unwrap();
        let hww = DeviceKeys::generate(&secp).unwrap();
        let first = VaultPolicy::new(phone.vault_pubkey, hww.vault_pubkey).unwrap();
        let second = VaultPolicy::new(phone.vault_pubkey, hww.vault_pubkey).unwrap();
        assert_eq!(first.address, second.address);
        let text = first.descriptor_string();
        assert!(text.contains("multi_a(2"));
        assert!(text.contains("older(61200)"));
        assert!(text.contains("older(65535)"));
        assert!(text.starts_with(&format!("tr({}/<0;1>/*", nums_xpub(Network::Regtest))));
        assert_eq!(first.leaf(SpendPath::Cooperative).unwrap().depth, 1);
        assert_eq!(first.leaf(SpendPath::PhoneRecovery).unwrap().depth, 2);
        assert_eq!(first.leaf(SpendPath::HwwRecovery).unwrap().depth, 2);
        assert_ne!(
            first.leaf(SpendPath::PhoneRecovery).unwrap().leaf_hash,
            first.leaf(SpendPath::HwwRecovery).unwrap().leaf_hash
        );
    }

    /// The shape a stock Ledger accepts as a BIP388 wallet policy: extended keys with origins
    /// written with `'`, and a distinct derivation for each leaf that reuses a key.
    #[test]
    fn descriptors_are_ledger_wallet_policies() {
        let secp = Secp256k1::new();
        let phone = DeviceKeys::generate(&secp).unwrap();
        let hww = DeviceKeys::generate(&secp).unwrap();
        let (p, h) = (phone.vault_pubkey, hww.vault_pubkey);
        let vault = VaultPolicy::new(p, h).unwrap().descriptor_string();
        let savings = SavingsPolicy::new_for_network(p, h, 1_924_992_000, Network::Regtest)
            .unwrap()
            .descriptor_string();
        let controller = ControllerPolicy::new(p, h).unwrap().descriptor_string();
        let template = |text: &str| {
            text.split('#')
                .next()
                .unwrap()
                .replace(&nums_xpub(Network::Regtest).to_string(), "@2")
                .replace(&p.to_string(), "@1")
                .replace(&h.to_string(), "@0")
        };
        assert_eq!(
            template(&vault),
            "tr(@2/<0;1>/*,{multi_a(2,@1/<0;1>/*,@0/<0;1>/*),{and_v(v:older(61200),pk(@1/<2;3>/*)),and_v(v:older(65535),pk(@0/<2;3>/*))}})"
        );
        assert_eq!(
            template(&savings),
            "tr(@2/<0;1>/*,{and_v(v:multi_a(2,@1/<0;1>/*,@0/<0;1>/*),after(1924992000)),{and_v(v:pk(@1/<2;3>/*),after(1961712000)),and_v(v:pk(@0/<2;3>/*),after(1964304000))}})"
        );
        assert_eq!(
            template(&controller),
            "tr(@2/<0;1>/*,{pk(@1/<0;1>/*),pk(@0/<0;1>/*)})"
        );
        assert!(p.to_string().contains("/86'/1'/100'/0/0]tpub"));
    }

    /// An heir adds one leaf beside the two recovery leaves and leaves every other leaf as is.
    #[test]
    fn heir_policies_are_ledger_wallet_policies() {
        let secp = Secp256k1::new();
        let [phone, hww, heir] = [0; 3].map(|_| DeviceKeys::generate(&secp).unwrap());
        let (p, h, e) = (phone.vault_pubkey, hww.vault_pubkey, heir.vault_pubkey);
        let template = |text: &str| {
            text.split('#')
                .next()
                .unwrap()
                .replace(&nums_xpub(Network::Regtest).to_string(), "@2")
                .replace(&p.to_string(), "@1")
                .replace(&h.to_string(), "@0")
                .replace(&e.to_string(), "@3")
        };
        let vault = VaultPolicy::with_heir(p, h, Some(e), Network::Regtest).unwrap();
        assert_eq!(
            template(&vault.descriptor_string()),
            "tr(@2/<0;1>/*,{multi_a(2,@1/<0;1>/*,@0/<0;1>/*),{{and_v(v:older(61200),pk(@1/<2;3>/*)),and_v(v:older(65535),pk(@0/<2;3>/*))},and_v(v:older(65535),pk(@3/<2;3>/*))}})"
        );
        let savings =
            SavingsPolicy::with_heir(p, h, Some(e), 1_924_992_000, Network::Regtest).unwrap();
        assert_eq!(
            template(&savings.descriptor_string()),
            "tr(@2/<0;1>/*,{and_v(v:multi_a(2,@1/<0;1>/*,@0/<0;1>/*),after(1924992000)),{{and_v(v:pk(@1/<2;3>/*),after(1961712000)),and_v(v:pk(@0/<2;3>/*),after(1964304000))},and_v(v:pk(@3/<2;3>/*),after(1966896000))}})"
        );
        // Every path resolves to its own leaf, and the heir's leaf holds the heir's key.
        let paths = [
            SpendPath::Cooperative,
            SpendPath::PhoneRecovery,
            SpendPath::HwwRecovery,
            SpendPath::Heir,
        ];
        let hashes: std::collections::BTreeSet<_> = paths
            .iter()
            .map(|path| vault.leaf(*path).unwrap().leaf_hash)
            .collect();
        assert_eq!(hashes.len(), 4);
        assert_eq!(
            vault.leaf(SpendPath::Heir).unwrap().script,
            recovery_script(e.recovery(), HEIR_RECOVERY_BLOCKS)
        );
        assert_eq!(
            vault.leaf(SpendPath::HwwRecovery).unwrap().script,
            recovery_script(h.recovery(), HWW_RECOVERY_BLOCKS)
        );
        let savings_hashes: std::collections::BTreeSet<_> = paths
            .iter()
            .map(|path| savings.leaf(*path).unwrap().leaf_hash)
            .collect();
        assert_eq!(savings_hashes.len(), 4);
    }

    #[test]
    fn leaves_use_a_separate_key_per_branch() {
        let secp = Secp256k1::new();
        let phone = DeviceKeys::generate(&secp).unwrap();
        let hww = DeviceKeys::generate(&secp).unwrap();
        let policy = VaultPolicy::new(phone.vault_pubkey, hww.vault_pubkey).unwrap();
        assert_ne!(
            phone.vault_pubkey.cooperative(),
            phone.vault_pubkey.recovery()
        );
        assert_eq!(
            policy.leaf(SpendPath::Cooperative).unwrap().script,
            cooperative_script(
                phone.vault_pubkey.cooperative(),
                hww.vault_pubkey.cooperative()
            )
        );
        assert_eq!(
            policy.leaf(SpendPath::PhoneRecovery).unwrap().script,
            recovery_script(phone.vault_pubkey.recovery(), PHONE_RECOVERY_BLOCKS)
        );
        assert_eq!(
            phone.vault_keypair.recovery.x_only_public_key().0,
            phone.vault_pubkey.recovery()
        );
    }

    #[test]
    fn the_internal_key_is_derived_from_the_nums_point() {
        let tr = taproot_spend(
            &VaultPolicy::new(
                DeviceKeys::generate(&Secp256k1::new())
                    .unwrap()
                    .vault_pubkey,
                DeviceKeys::generate(&Secp256k1::new())
                    .unwrap()
                    .vault_pubkey,
            )
            .unwrap()
            .descriptor,
        )
        .unwrap();
        let expected = nums_xpub(Network::Regtest)
            .derive_pub(
                &Secp256k1::new(),
                &[
                    ChildNumber::from_normal_idx(0).unwrap(),
                    ChildNumber::from_normal_idx(0).unwrap(),
                ],
            )
            .unwrap()
            .public_key
            .x_only_public_key()
            .0;
        assert_eq!(tr.internal_key().inner.x_only_public_key().0, expected);
        assert_eq!(
            nums_xpub(Network::Regtest)
                .public_key
                .x_only_public_key()
                .0
                .to_string(),
            BIP341_NUMS_KEY
        );
    }

    #[test]
    fn the_same_script_policy_encodes_for_mainnet_and_signet() {
        let secp = Secp256k1::new();
        let phone = DeviceKeys::generate_for_network(&secp, Network::Bitcoin).unwrap();
        let hww = DeviceKeys::generate_for_network(&secp, Network::Bitcoin).unwrap();
        let policy =
            VaultPolicy::new_for_network(phone.vault_pubkey, hww.vault_pubkey, Network::Bitcoin)
                .unwrap();
        assert!(policy.address.to_string().starts_with("bc1p"));
        assert!(policy.descriptor_string().contains("]xpub"));

        let phone = DeviceKeys::generate_for_network(&secp, Network::Signet).unwrap();
        let hww = DeviceKeys::generate_for_network(&secp, Network::Signet).unwrap();
        let policy =
            VaultPolicy::new_for_network(phone.vault_pubkey, hww.vault_pubkey, Network::Signet)
                .unwrap();
        assert!(policy.address.to_string().starts_with("tb1p"));
    }

    #[test]
    fn fast_address_template_matches_the_canonical_miniscript_policy() {
        let secp = Secp256k1::new();
        for network in [Network::Regtest, Network::Bitcoin] {
            let phone = DeviceKeys::generate_for_network(&secp, network).unwrap();
            let hww = DeviceKeys::generate_for_network(&secp, network).unwrap();
            let policy =
                VaultPolicy::new_for_network(phone.vault_pubkey, hww.vault_pubkey, network)
                    .unwrap();
            let template = VaultAddressTemplate::new(hww.vault_pubkey, network).unwrap();

            assert_eq!(
                template.address(&secp, phone.vault_pubkey, network),
                policy.address
            );
            assert_eq!(
                recovery_script(hww.vault_pubkey.recovery(), HWW_RECOVERY_BLOCKS),
                policy.leaf(SpendPath::HwwRecovery).unwrap().script
            );
        }
    }

    #[test]
    fn controller_reuses_vault_keys_with_two_single_signature_paths() {
        let secp = Secp256k1::new();
        let phone = DeviceKeys::generate(&secp).unwrap();
        let hww = DeviceKeys::generate(&secp).unwrap();
        let controller = ControllerPolicy::new(phone.vault_pubkey, hww.vault_pubkey).unwrap();

        assert!(
            controller
                .descriptor_string()
                .contains(&phone.vault_pubkey.to_string())
        );
        assert!(
            controller
                .descriptor_string()
                .contains(&hww.vault_pubkey.to_string())
        );
        assert_ne!(
            controller.leaf(ControllerPath::Phone).unwrap().leaf_hash,
            controller.leaf(ControllerPath::Hww).unwrap().leaf_hash
        );
        assert_eq!(controller.leaf(ControllerPath::Phone).unwrap().depth, 1);
        assert_eq!(controller.leaf(ControllerPath::Hww).unwrap().depth, 1);
    }
}
