//! What a vault device must be able to do, so the same flows run with the software key store
//! used in tests and demos, or with a hardware wallet that never reveals its keys.

use super::{
    keys::{DeviceKeys, VaultKey},
    policy::{ControllerPath, ControllerPolicy, SpendPath, TaprootPolicy},
    transactions::{sign_controller_psbt_inputs, sign_vault_psbt_inputs},
};
use anyhow::Result;
use bitcoin::Psbt;
use zeroize::Zeroizing;

pub trait VaultSigner {
    /// The account key this device contributes to every vault policy.
    fn vault_key(&self) -> VaultKey;

    /// Add this device's signature for the `path` leaf of `policy` to each listed input.
    fn sign_vault_inputs(
        &self,
        psbt: &mut Psbt,
        policy: &dyn TaprootPolicy,
        path: SpendPath,
        input_indexes: &[usize],
    ) -> Result<()>;

    /// Add this device's signature for its connector leaf to each listed input.
    fn sign_controller_inputs(
        &self,
        psbt: &mut Psbt,
        policy: &ControllerPolicy,
        path: ControllerPath,
        input_indexes: &[usize],
    ) -> Result<()>;

    /// Secret that wraps this device's copy of the cloud backup key. Only the device can produce
    /// it, and it is the same every time.
    fn backup_secret(&self) -> Result<Zeroizing<Vec<u8>>>;

    fn sign_all_vault_inputs(
        &self,
        psbt: &mut Psbt,
        policy: &dyn TaprootPolicy,
        path: SpendPath,
    ) -> Result<()> {
        let indexes = (0..psbt.inputs.len()).collect::<Vec<_>>();
        self.sign_vault_inputs(psbt, policy, path, &indexes)
    }
}

impl VaultSigner for DeviceKeys {
    fn vault_key(&self) -> VaultKey {
        self.vault_pubkey
    }

    fn sign_vault_inputs(
        &self,
        psbt: &mut Psbt,
        policy: &dyn TaprootPolicy,
        path: SpendPath,
        input_indexes: &[usize],
    ) -> Result<()> {
        sign_vault_psbt_inputs(psbt, policy, path, &self.vault_keypair, input_indexes)
    }

    fn sign_controller_inputs(
        &self,
        psbt: &mut Psbt,
        policy: &ControllerPolicy,
        path: ControllerPath,
        input_indexes: &[usize],
    ) -> Result<()> {
        sign_controller_psbt_inputs(
            psbt,
            policy,
            path,
            &self.vault_keypair.cooperative,
            input_indexes,
        )
    }

    fn backup_secret(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(self.seed.to_vec()))
    }
}
