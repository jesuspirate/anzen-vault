//! Seed a freshly started BitBox02 simulator, for the end-to-end tests. The simulator approves
//! every prompt itself and restores its fixed test mnemonic:
//! boring mistake dish oyster truth pigeon viable emerge sort crash wire portion cannon couple
//! enact box walk height pull today solid off enable tide
//!
//! Usage: ANZEN_BITBOX=tcp:127.0.0.1:15423 cargo run --example bitbox_simulator_seed

use bitbox_api::{BitBox, NoiseConfigNoCache, runtime::TokioRuntime};

fn main() -> anyhow::Result<()> {
    let endpoint = std::env::var("ANZEN_BITBOX")?;
    let endpoint = endpoint
        .strip_prefix("tcp:")
        .ok_or_else(|| anyhow::anyhow!("ANZEN_BITBOX must be tcp:HOST:PORT"))?
        .to_owned();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            let bitbox = BitBox::<TokioRuntime>::from_simulator(
                Some(&endpoint),
                Box::new(NoiseConfigNoCache),
            )
            .await?;
            let paired = bitbox.unlock_and_pair().await?.wait_confirm().await?;
            if !paired.device_info().await?.initialized {
                paired.restore_from_mnemonic().await?;
            }
            println!("BitBox02 simulator {} seeded", paired.version());
            Ok(())
        })
}
