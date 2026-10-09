use super::{HWW_RECOVERY_BLOCKS, PHONE_RECOVERY_BLOCKS};
use anyhow::{Context, Result, bail};
use bitcoin::{
    Address, Network, ScriptBuf,
    key::{TapTweak, TweakedPublicKey},
    opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_CSV, OP_NUMEQUAL, OP_VERIFY},
    script::Builder,
    secp256k1::{Secp256k1, Verification, XOnlyPublicKey},
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

/// A Taproot script policy whose leaves are selected by [`SpendPath`]. Both the vault and the
/// hard-locked savings policies have one cooperative leaf and two single-key recovery leaves, so
/// PSBT construction, signing and verification are shared between them.
pub trait TaprootPolicy {
    fn leaf(&self, path: SpendPath) -> Result<VaultLeaf>;
    fn definite_descriptor(&self) -> Result<Descriptor<DefiniteDescriptorKey>>;
}

impl TaprootPolicy for VaultPolicy {
    fn leaf(&self, path: SpendPath) -> Result<VaultLeaf> {
        VaultPolicy::leaf(self, path)
    }

    fn definite_descriptor(&self) -> Result<Descriptor<DefiniteDescriptorKey>> {
        VaultPolicy::definite_descriptor(self)
    }
}

impl TaprootPolicy for SavingsPolicy {
    fn leaf(&self, path: SpendPath) -> Result<VaultLeaf> {
        SavingsPolicy::leaf(self, path)
    }

    fn definite_descriptor(&self) -> Result<Descriptor<DefiniteDescriptorKey>> {
        SavingsPolicy::definite_descriptor(self)
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
    phone: XOnlyPublicKey,
    hww: XOnlyPublicKey,
}

/// Fast encoder for the fixed Anzen script tree used while grinding phone vault keys.
///
/// The scripts and tree shape must remain byte-for-byte equivalent to [`VaultPolicy`]. Tests
/// compare this optimized path with the canonical Miniscript descriptor construction.
#[derive(Debug, Clone)]
pub struct VaultAddressTemplate {
    internal_key: XOnlyPublicKey,
    hww_pubkey: XOnlyPublicKey,
    hww_recovery_node: TapNodeHash,
}

impl VaultAddressTemplate {
    pub fn new(hww_pubkey: XOnlyPublicKey) -> Result<Self> {
        let internal_key = XOnlyPublicKey::from_str(BIP341_NUMS_KEY)
            .context("invalid BIP341 NUMS internal key")?;
        let hww_recovery_node = TapNodeHash::from_script(
            &recovery_script(hww_pubkey, HWW_RECOVERY_BLOCKS),
            LeafVersion::TapScript,
        );
        Ok(Self {
            internal_key,
            hww_pubkey,
            hww_recovery_node,
        })
    }

    pub fn output_key<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        phone_pubkey: XOnlyPublicKey,
    ) -> TweakedPublicKey {
        let cooperative_node = TapNodeHash::from_script(
            &cooperative_script(phone_pubkey, self.hww_pubkey),
            LeafVersion::TapScript,
        );
        let phone_recovery_node = TapNodeHash::from_script(
            &recovery_script(phone_pubkey, PHONE_RECOVERY_BLOCKS),
            LeafVersion::TapScript,
        );
        let recovery_node =
            TapNodeHash::from_node_hashes(phone_recovery_node, self.hww_recovery_node);
        let merkle_root = TapNodeHash::from_node_hashes(cooperative_node, recovery_node);
        self.internal_key.tap_tweak(secp, Some(merkle_root)).0
    }

    pub fn address<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        phone_pubkey: XOnlyPublicKey,
        network: Network,
    ) -> Address {
        Address::p2tr_tweaked(self.output_key(secp, phone_pubkey), network)
    }
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
    pub fn new(phone: XOnlyPublicKey, hww: XOnlyPublicKey) -> Result<Self> {
        Self::new_for_network(phone, hww, Network::Regtest)
    }

    pub fn new_for_network(
        phone: XOnlyPublicKey,
        hww: XOnlyPublicKey,
        network: Network,
    ) -> Result<Self> {
        let descriptor_text = format!(
            "tr({BIP341_NUMS_KEY},{{multi_a(2,{phone},{hww}),{{and_v(v:older({PHONE_RECOVERY_BLOCKS}),pk({phone})),and_v(v:older({HWW_RECOVERY_BLOCKS}),pk({hww}))}}}})"
        );
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&descriptor_text)
            .with_context(|| format!("invalid vault descriptor: {descriptor_text}"))?;
        let address = descriptor
            .derived_descriptor(&Secp256k1::verification_only(), 0)?
            .address(network)?;
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
        let address = descriptor
            .derived_descriptor(&Secp256k1::verification_only(), 0)?
            .address(network)?;
        Ok(Self {
            descriptor,
            address,
        })
    }

    pub fn definite_descriptor(&self) -> Result<Descriptor<DefiniteDescriptorKey>> {
        self.descriptor
            .at_derivation_index(0)
            .context("vault descriptor could not be made definite")
    }

    pub fn leaf(&self, path: SpendPath) -> Result<VaultLeaf> {
        let derived = self
            .descriptor
            .derived_descriptor(&Secp256k1::verification_only(), 0)?;
        let tr = match derived {
            Descriptor::Tr(tr) => tr,
            _ => bail!("vault descriptor is not Taproot"),
        };
        let spend_info = tr.spend_info();
        let target_depth = match path {
            SpendPath::Cooperative => 1,
            SpendPath::PhoneRecovery | SpendPath::HwwRecovery => 2,
        };
        let target_delay = match path {
            SpendPath::Cooperative => None,
            SpendPath::PhoneRecovery => Some(PHONE_RECOVERY_BLOCKS),
            SpendPath::HwwRecovery => Some(HWW_RECOVERY_BLOCKS),
        };

        for (depth, miniscript) in tr.iter_scripts() {
            if depth != target_depth {
                continue;
            }
            let script = miniscript.encode();
            if let Some(delay) = target_delay {
                let delay_script_num = bitcoin::script::Builder::new()
                    .push_int(i64::from(delay))
                    .into_script();
                if !script
                    .as_bytes()
                    .windows(delay_script_num.len())
                    .any(|window| window == delay_script_num.as_bytes())
                {
                    continue;
                }
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

    pub fn descriptor_string(&self) -> String {
        self.descriptor.to_string()
    }
}

/// Seconds after the savings unlock date before the phone alone can recover a savings output
/// (425 days, about 14 months), mirroring the vault's phone-priority recovery window.
pub const SAVINGS_PHONE_RECOVERY_SECS: u32 = 425 * 86_400;
/// Seconds after the savings unlock date before the HWW alone can recover (455 days).
pub const SAVINGS_HWW_RECOVERY_SECS: u32 = 455 * 86_400;

/// A hard-locked savings output. Nothing can spend it before `unlock`, not even both devices
/// together. Every path uses an absolute calendar time (CLTV), so these outputs never need the
/// annual rollover: deposits can arrive at any time and stay locked until the same date.
///
/// ```text
/// tr(NUMS, { and_v(v:multi_a(2,phone,hww), after(unlock)),
///            { and_v(v:pk(phone), after(unlock + 425d)),
///              and_v(v:pk(hww),   after(unlock + 455d)) } })
/// ```
#[derive(Debug, Clone)]
pub struct SavingsPolicy {
    pub descriptor: Descriptor<DescriptorPublicKey>,
    pub address: Address,
    pub unlock: u32,
    phone: XOnlyPublicKey,
    hww: XOnlyPublicKey,
}

impl SavingsPolicy {
    pub fn new_for_network(
        phone: XOnlyPublicKey,
        hww: XOnlyPublicKey,
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
        let descriptor_text = format!(
            "tr({BIP341_NUMS_KEY},{{and_v(v:multi_a(2,{phone},{hww}),after({unlock})),{{and_v(v:pk({phone}),after({phone_after})),and_v(v:pk({hww}),after({hww_after}))}}}})"
        );
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&descriptor_text)
            .with_context(|| format!("invalid savings descriptor: {descriptor_text}"))?;
        let address = descriptor
            .derived_descriptor(&Secp256k1::verification_only(), 0)?
            .address(network)?;
        Ok(Self {
            descriptor,
            address,
            unlock,
            phone,
            hww,
        })
    }

    pub fn definite_descriptor(&self) -> Result<Descriptor<DefiniteDescriptorKey>> {
        self.descriptor
            .at_derivation_index(0)
            .context("savings descriptor could not be made definite")
    }

    /// The earliest nLockTime a spend through `path` can use.
    pub fn earliest_lock_time(&self, path: SpendPath) -> u32 {
        match path {
            SpendPath::Cooperative => self.unlock,
            SpendPath::PhoneRecovery => self.unlock + SAVINGS_PHONE_RECOVERY_SECS,
            SpendPath::HwwRecovery => self.unlock + SAVINGS_HWW_RECOVERY_SECS,
        }
    }

    pub fn leaf(&self, path: SpendPath) -> Result<VaultLeaf> {
        let derived = self
            .descriptor
            .derived_descriptor(&Secp256k1::verification_only(), 0)?;
        let tr = match derived {
            Descriptor::Tr(tr) => tr,
            _ => bail!("savings descriptor is not Taproot"),
        };
        let spend_info = tr.spend_info();
        let single_key = match path {
            SpendPath::Cooperative => None,
            SpendPath::PhoneRecovery => Some(self.phone),
            SpendPath::HwwRecovery => Some(self.hww),
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
    pub fn new(phone: XOnlyPublicKey, hww: XOnlyPublicKey) -> Result<Self> {
        Self::new_for_network(phone, hww, Network::Regtest)
    }

    pub fn new_for_network(
        phone: XOnlyPublicKey,
        hww: XOnlyPublicKey,
        network: Network,
    ) -> Result<Self> {
        let descriptor_text = format!("tr({BIP341_NUMS_KEY},{{pk({phone}),pk({hww})}})");
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&descriptor_text)
            .with_context(|| format!("invalid controller descriptor: {descriptor_text}"))?;
        let address = descriptor
            .derived_descriptor(&Secp256k1::verification_only(), 0)?
            .address(network)?;
        Ok(Self {
            descriptor,
            address,
            phone,
            hww,
        })
    }

    pub fn definite_descriptor(&self) -> Result<Descriptor<DefiniteDescriptorKey>> {
        self.descriptor
            .at_derivation_index(0)
            .context("controller descriptor could not be made definite")
    }

    pub fn leaf(&self, path: ControllerPath) -> Result<ControllerLeaf> {
        let key = match path {
            ControllerPath::Phone => self.phone,
            ControllerPath::Hww => self.hww,
        };
        let target_script = Builder::new()
            .push_x_only_key(&key)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        let derived = self
            .descriptor
            .derived_descriptor(&Secp256k1::verification_only(), 0)?;
        let tr = match derived {
            Descriptor::Tr(tr) => tr,
            _ => bail!("controller descriptor is not Taproot"),
        };
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
        assert!(text.starts_with("tr(50929b74"));
        assert_eq!(first.leaf(SpendPath::Cooperative).unwrap().depth, 1);
        assert_eq!(first.leaf(SpendPath::PhoneRecovery).unwrap().depth, 2);
        assert_eq!(first.leaf(SpendPath::HwwRecovery).unwrap().depth, 2);
        assert_ne!(
            first.leaf(SpendPath::PhoneRecovery).unwrap().leaf_hash,
            first.leaf(SpendPath::HwwRecovery).unwrap().leaf_hash
        );
    }

    #[test]
    fn the_same_script_policy_encodes_for_mainnet() {
        let secp = Secp256k1::new();
        let phone = DeviceKeys::generate_for_network(&secp, Network::Bitcoin).unwrap();
        let hww = DeviceKeys::generate_for_network(&secp, Network::Bitcoin).unwrap();
        let policy =
            VaultPolicy::new_for_network(phone.vault_pubkey, hww.vault_pubkey, Network::Bitcoin)
                .unwrap();
        assert!(policy.address.to_string().starts_with("bc1p"));
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
            let template = VaultAddressTemplate::new(hww.vault_pubkey).unwrap();

            assert_eq!(
                template.address(&secp, phone.vault_pubkey, network),
                policy.address
            );
            assert_eq!(
                cooperative_script(phone.vault_pubkey, hww.vault_pubkey),
                policy.leaf(SpendPath::Cooperative).unwrap().script
            );
            assert_eq!(
                recovery_script(phone.vault_pubkey, PHONE_RECOVERY_BLOCKS),
                policy.leaf(SpendPath::PhoneRecovery).unwrap().script
            );
            assert_eq!(
                recovery_script(hww.vault_pubkey, HWW_RECOVERY_BLOCKS),
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
