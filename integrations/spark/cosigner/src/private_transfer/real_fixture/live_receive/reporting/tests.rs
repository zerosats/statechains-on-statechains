//! Regression coverage for the desktop entry report.
use super::*;
use crate::private_transfer::real_fixture::live_receive::private_directory;
use std::fs;

fn fixture() -> Result<PathBuf> {
    let parent =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../work/review-fixes/report-tests");
    fs::create_dir_all(&parent)?;
    let root = parent.join(uuid());
    private_directory(&root)?;
    Ok(root)
}

#[test]
fn an_entry_report_is_never_replaced() -> Result<()> {
    let root = fixture()?;
    let report = RunReport::begin(&root)?;
    report.save(json!({"status":"blocked_unsafe_receive_custody"}))?;
    let saved: Value = serde_json::from_slice(&fs::read(root.join("public-report.json"))?)?;
    assert_eq!(saved["status"], "blocked_unsafe_receive_custody");
    assert_eq!(saved["execution"], "desktop_entry");
    assert_eq!(saved["security_qualified"], false);
    assert!(RunReport::begin(&root).is_err());
    assert!(report.save(json!("not an object")).is_err());
    fs::remove_dir_all(root)?;
    Ok(())
}
