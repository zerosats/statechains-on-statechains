use super::{PrivateRecovery, RecoveryJournal, backing_tests::setup, recovery_tests::parameters};
use anyhow::Result;
use k256::{ProjectivePoint, schnorr::SigningKey};
use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};
use zark_protocol::{point_bytes, random_scalar, random32, spark_wire::Predecessor};
use zeroize::Zeroizing;

fn directory() -> Result<PathBuf> {
    let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../work/zark-spark/private-transfer-wallet-tests");
    fs::create_dir_all(&parent)?;
    let root = parent.join(hex::encode(random32()));
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    Ok(root)
}

#[test]
fn receiver_journal_locks_and_retains_exact_authenticated_prepare_and_nonces() -> Result<()> {
    let (keys, backing) = setup()?;
    let user = Zeroizing::new(
        keys.wallet
            .additive_scalar(keys.authority.user_authority())?,
    );
    let server = Zeroizing::new(
        keys.signer
            .additive_scalar(keys.authority.user_authority())?,
    );
    let draft = PrivateRecovery::prepare(
        &backing,
        parameters(
            &backing,
            *user,
            point_bytes(ProjectivePoint::GENERATOR * *server)?,
        )?,
    )?;
    let session = Zeroizing::new(<[u8; 32]>::from(
        SigningKey::from_bytes(&[9; 32])?.to_bytes(),
    ));
    let root = directory()?.join("receiver");
    let mut journal =
        RecoveryJournal::create(&root, Predecessor::Transfer, &backing, draft, *session)?;
    let prepare = journal.prepare_request()?.encode()?;
    assert_eq!(journal.prepare_request()?.encode()?, prepare);
    assert!(RecoveryJournal::open(&root).is_err());
    drop(journal);
    let mut resumed = RecoveryJournal::open(&root)?;
    assert_eq!(resumed.prepare_request()?.encode()?, prepare);
    let nonces = Zeroizing::new([random_scalar(), random_scalar()]);
    let points = [
        point_bytes(ProjectivePoint::GENERATOR * nonces[0])?,
        point_bytes(ProjectivePoint::GENERATOR * nonces[1])?,
    ];
    resumed.bind_nonces(points)?;
    let authorization = resumed.recovery().authorization()?.encode()?;
    drop(resumed);
    let mut reopened = RecoveryJournal::open(&root)?;
    assert_eq!(
        reopened.recovery().authorization()?.encode()?,
        authorization
    );
    reopened.bind_nonces(points)?;
    let mut different = points;
    different.swap(0, 1);
    assert!(reopened.bind_nonces(different).is_err());
    assert_eq!(
        reopened.recovery().authorization()?.encode()?,
        authorization
    );
    Ok(())
}

#[test]
fn cached_prepare_is_not_released_after_a_failed_durable_write_on_same_object_retry() -> Result<()>
{
    let (keys, backing) = setup()?;
    let user = Zeroizing::new(
        keys.wallet
            .additive_scalar(keys.authority.user_authority())?,
    );
    let server = Zeroizing::new(
        keys.signer
            .additive_scalar(keys.authority.user_authority())?,
    );
    let draft = PrivateRecovery::prepare(
        &backing,
        parameters(
            &backing,
            *user,
            point_bytes(ProjectivePoint::GENERATOR * *server)?,
        )?,
    )?;
    let session = Zeroizing::new(<[u8; 32]>::from(
        SigningKey::from_bytes(&[9; 32])?.to_bytes(),
    ));
    let root = directory()?.join("receiver");
    let mut journal =
        RecoveryJournal::create(&root, Predecessor::Transfer, &backing, draft, *session)?;
    let record = root.join("private-receiver.json");
    // Retain the valid initial private record. An empty directory at the target
    // deterministically makes atomic rename fail after the request is cached.
    fs::rename(&record, root.join("initial-private-record-retained.json"))?;
    fs::create_dir(&record)?;
    assert!(journal.prepare_request().is_err());
    assert!(
        journal.prepare_request().is_err(),
        "cached request escaped before durable retry succeeded"
    );
    // Only remove the empty obstruction created above, never retained state.
    fs::remove_dir(&record)?;
    let request = journal.prepare_request()?;
    let bytes = Zeroizing::new(fs::read(&record)?);
    let disk: serde_json::Value = serde_json::from_slice(&bytes)?;
    let saved: Vec<u8> = serde_json::from_value(disk["requests"]["6"].clone())?;
    assert_eq!(saved, request.encode()?);
    drop(journal);
    assert_eq!(
        RecoveryJournal::open(&root)?.prepare_request()?.encode()?,
        saved
    );
    Ok(())
}
