//! Fee selection for presigned policy transactions.
//!
//! Presigned vault transactions use Taproot `SIGHASH_DEFAULT`, so their fee is frozen when the
//! HWW signs them. Instead of guessing a fee a year ahead, the phone pays the difference at
//! broadcast time with a child transaction (CPFP) that spends an output it controls, and submits
//! parent and child together as a package so the parent may sit below the mempool minimum.

use anyhow::{Result, bail};

/// Never estimate below this rate, whatever the backend says.
pub const MIN_FEE_RATE_SAT_VB: u64 = 1;
/// Never pay more than this without an explicit override; protects against a lying backend.
pub const MAX_FEE_RATE_SAT_VB: u64 = 1_000;
/// Default confirmation target, in blocks, for monthly releases and the emergency trigger.
pub const DEFAULT_CONFIRMATION_TARGET: u16 = 6;

/// Convert a BTC/kvB estimate (Bitcoin Core and Electrum's unit) to whole sat/vB, rounding up
/// and clamping into `[MIN_FEE_RATE_SAT_VB, MAX_FEE_RATE_SAT_VB]`. Negative or non-finite
/// estimates (Electrum returns -1 when it has no data) yield `None`.
pub fn sat_per_vb_from_btc_per_kvb(btc_per_kvb: f64) -> Option<u64> {
    if !btc_per_kvb.is_finite() || btc_per_kvb <= 0.0 {
        return None;
    }
    // Round to whole sat/kvB first so float noise (0.00001 BTC = 1000.0000001 sat) cannot
    // push the result up a whole sat/vB.
    let sat_per_kvb = (btc_per_kvb * 100_000_000.0).round() as u64;
    let sat_per_vb = sat_per_kvb.div_ceil(1_000);
    Some(sat_per_vb.clamp(MIN_FEE_RATE_SAT_VB, MAX_FEE_RATE_SAT_VB))
}

/// Fee the child must pay so that parent and child together reach `target_sat_vb`.
///
/// Returns 0 when the parent already pays enough on its own; the caller then broadcasts the
/// parent alone.
pub fn cpfp_child_fee(
    parent_vsize: u64,
    parent_fee: u64,
    child_vsize: u64,
    target_sat_vb: u64,
) -> Result<u64> {
    if target_sat_vb > MAX_FEE_RATE_SAT_VB {
        bail!("fee rate {target_sat_vb} sat/vB exceeds the {MAX_FEE_RATE_SAT_VB} sat/vB safety cap");
    }
    if parent_fee >= parent_vsize.saturating_mul(target_sat_vb) {
        return Ok(0);
    }
    // The parent underpays here, so this is always more than the child's own share.
    let package_fee = (parent_vsize + child_vsize).saturating_mul(target_sat_vb);
    Ok(package_fee - parent_fee)
}

/// Whether the child's output after paying `child_fee` from `spendable` would still be above
/// the P2TR dust threshold. If not, the release is too small to bump at this fee rate.
pub fn child_output_after_fee(spendable: u64, child_fee: u64) -> Result<u64> {
    const P2TR_DUST_SATS: u64 = 330;
    match spendable.checked_sub(child_fee) {
        Some(remaining) if remaining >= P2TR_DUST_SATS => Ok(remaining),
        _ => bail!(
            "a {child_fee}-sat bump would leave less than {P2TR_DUST_SATS} sats of the {spendable}-sat output"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_btc_per_kvb_and_rounds_up() {
        assert_eq!(sat_per_vb_from_btc_per_kvb(0.00001), Some(1));
        assert_eq!(sat_per_vb_from_btc_per_kvb(0.000_123), Some(13));
        assert_eq!(sat_per_vb_from_btc_per_kvb(0.0005), Some(50));
    }

    #[test]
    fn rejects_missing_estimates_and_clamps_extremes() {
        assert_eq!(sat_per_vb_from_btc_per_kvb(-1.0), None);
        assert_eq!(sat_per_vb_from_btc_per_kvb(0.0), None);
        assert_eq!(sat_per_vb_from_btc_per_kvb(f64::NAN), None);
        assert_eq!(sat_per_vb_from_btc_per_kvb(0.000_000_01), Some(MIN_FEE_RATE_SAT_VB));
        assert_eq!(sat_per_vb_from_btc_per_kvb(5.0), Some(MAX_FEE_RATE_SAT_VB));
    }

    #[test]
    fn child_tops_the_package_up_to_the_target() {
        // 200 vB parent presigned at 1 sat/vB, 110 vB child, market at 20 sat/vB.
        let fee = cpfp_child_fee(200, 200, 110, 20).unwrap();
        assert_eq!(fee, 20 * 310 - 200);
        assert_eq!((200 + fee) / 310, 20);
    }

    #[test]
    fn no_child_needed_when_parent_already_pays_enough() {
        assert_eq!(cpfp_child_fee(200, 4_000, 110, 20).unwrap(), 0);
    }

    #[test]
    fn child_covers_its_own_size_plus_the_parent_shortfall() {
        // Parent is 10 sats short of 20 sat/vB; the child pays its own 2,200 plus those 10.
        assert_eq!(cpfp_child_fee(200, 3_990, 110, 20).unwrap(), 2_210);
    }

    #[test]
    fn refuses_absurd_fee_rates() {
        assert!(cpfp_child_fee(200, 200, 110, MAX_FEE_RATE_SAT_VB + 1).is_err());
    }

    #[test]
    fn small_releases_cannot_be_bumped_into_dust() {
        assert_eq!(child_output_after_fee(10_000_000, 6_000).unwrap(), 9_994_000);
        assert!(child_output_after_fee(6_200, 6_000).is_err());
    }
}
