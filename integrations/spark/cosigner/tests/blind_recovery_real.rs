//! Real proof primitive check. Does not establish Spark ownership or live funds.
use anyhow::{Context, Result, ensure};
use std::{fs, path::PathBuf};
use zark_protocol::{
    assets::read_bounded,
    hash,
    proof::ArtifactPin,
    spark_recovery::{PinnedRecoveryVerifier, RecoveryAuthorization},
};

#[test]
#[ignore = "requires an explicit real dual-refund proof and pinned BB/CRS paths"]
fn pinned_real_recovery_relation_rejects_substitution() -> Result<()> {
    let directory = PathBuf::from(std::env::var("ZARK_SPARK_BLIND_PROOF")?);
    let bb = PathBuf::from(std::env::var("ZARK_TEST_BB")?);
    let crs = PathBuf::from(std::env::var("ZARK_TEST_CRS")?);
    let report: serde_json::Value =
        serde_json::from_slice(&read_bounded(&directory.join("report.json"), 1024 * 1024)?)?;
    ensure!(
        report["status"] == "passed",
        "real proof runner did not pass"
    );
    let pin = |value: &serde_json::Value| -> Result<[u8; 32]> {
        zark_protocol::hex32(value.as_str().context("missing fixture asset pin")?)
    };
    let statement = read_bounded(&directory.join("statement.bin"), 620)?;
    let expected = RecoveryAuthorization::decode(&statement)?;
    let proof = read_bounded(&directory.join("proof/proof"), 458 * 32)?;
    let verifier = PinnedRecoveryVerifier::new(
        expected.context.deployment,
        ArtifactPin {
            path: bb,
            sha256: pin(&report["toolchain"]["verifier_sha256"])?,
        },
        ArtifactPin {
            path: directory.join("proof/vk"),
            sha256: pin(&report["vk_sha256"])?,
        },
        crs,
    )?;
    let scratch = directory.join(format!(
        "native-verifier-{}",
        hex::encode(zark_protocol::random32())
    ));
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(&scratch)?;
    // Keep this isolated scratch directory even on failure for diagnostics.
    let verified = verifier.verify(&expected, &proof, &scratch)?;
    assert_eq!(verified.statement_digest(), hash(&[&statement]));
    let mut changed = expected.clone();
    changed.context.successor_state[0] ^= 1;
    assert!(verifier.verify(&changed, &proof, &scratch).is_err());
    let mut changed = expected.clone();
    changed.context.deployment[0] ^= 1;
    assert!(verifier.verify(&changed, &proof, &scratch).is_err());
    let mut bad = proof.clone();
    bad[0] ^= 1;
    assert!(verifier.verify(&expected, &bad, &scratch).is_err());
    assert!(
        verifier
            .verify(&expected, &proof[..proof.len() - 1], &scratch)
            .is_err()
    );
    println!("Pinned native recovery verifier accepted a real proof and rejected substitutions.");
    Ok(())
}
