//! Explicit root-only receive profile. The signed root stays fixed; both
//! native refunds pay the current joint USER key at the reduced native delay.
use super::{
    DepositAnchor, InitialRootLeafExitV1, NativeLeafKeys, ValidatedExitPackage, validate_exit,
};
use anyhow::{Result, ensure};

/// Structural/signature validation only. The caller must authenticate that
/// native Spark actually committed the claim and that this is a root with no
/// direct-node or other competing recovery branch. This does not prove live
/// backing, final ownership, chain state or safe recovery-window admission.
///
/// The first ordinary receive normally has windows 1900/1950. Lower multiples
/// of 100 are explicit here; 100 requires renewal before our signing profile
/// can make another native transfer. Fresh 2000/2050 deposits use the original
/// constructor, preserving its canonical bytes and strict validation.
pub fn validate_received_root_exit_keys(
    anchor: &DepositAnchor,
    keys: &NativeLeafKeys,
    package: &InitialRootLeafExitV1,
    native_delay: u32,
) -> Result<ValidatedExitPackage> {
    ensure!(
        (200..=1900).contains(&native_delay) && native_delay.is_multiple_of(100),
        "unsupported received-root refund window; renewal or another profile required"
    );
    validate_exit(
        anchor,
        keys,
        package,
        b"ZARK/spark/received-root-exit/v1",
        keys.binding(),
        native_delay,
    )
}

/// Qualify the claim's two same-window intermediate refunds as well as its
/// final refunds. A completed claim does not revoke already signed transactions.
/// In particular, an intermediate refund to a separately held identity key
/// would remain a unilateral exit even when the final refunds pay joint USER.
///
/// The trusted native observer must authenticate that `incoming` is the actual
/// transfer package, and must still check earlier history and the active anchor.
/// This deliberately narrow profile requires both intermediate variants to pay
/// the very same joint USER key. Other custody arrangements need their own
/// checked recovery model; changing a delay or omitting history is not sufficient.
pub fn validate_received_root_claim_custody(
    anchor: &DepositAnchor,
    keys: &NativeLeafKeys,
    final_prefix: &InitialRootLeafExitV1,
    incoming: &InitialRootLeafExitV1,
    native_delay: u32,
) -> Result<ValidatedExitPackage> {
    let checked = validate_received_root_exit_keys(anchor, keys, final_prefix, native_delay)?;
    ensure!(
        incoming.root_node == final_prefix.root_node,
        "receive custody history has a different signed root"
    );
    validate_received_root_exit_keys(anchor, keys, incoming, native_delay)
        .map_err(|e| anyhow::anyhow!("unsafe or incomplete intermediate receive refunds: {e}"))?;
    Ok(checked)
}
