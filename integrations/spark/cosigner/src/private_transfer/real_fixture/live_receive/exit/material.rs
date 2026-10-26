//! Independently checked terminal evidence after a share-release exit.
use super::*;
pub(super) fn verify_completion(
    before: &Value,
    after: &Value,
    received: &Value,
    receiver: &[u8],
    recipient: &Value,
) -> Result<()> {
    ensure!(
        received["operators_completed"] == 3
            && bytes(received, "owner")? == receiver
            && bytes(received, "user")? == bytes(recipient, "user")?,
        "ordinary recipient ownership was not observed"
    );
    let a = before["completed_transfers"]
        .as_array()
        .context("native before counts")?;
    let b = after["completed_transfers"]
        .as_array()
        .context("native after counts")?;
    ensure!(
        a.len() == 3 && b.len() == 3,
        "native observation quorum count"
    );
    for i in 0..3 {
        ensure!(
            a[i].as_u64().and_then(|n| n.checked_add(1)) == b[i].as_u64(),
            "native completion count differs from one exit transfer"
        );
    }
    ensure!(
        before["public_leaf_sha256"] != after["public_leaf_sha256"],
        "native exit did not rotate leaf ownership"
    );
    Ok(())
}
