use super::*;
use aes_gcm::{
    AesGcm, KeyInit,
    aead::{AeadInPlace, consts::U16},
    aes::Aes256,
};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use std::{
    fs,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

fn directory() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../work/zark-spark/standard-claim-tests");
    fs::create_dir_all(&root).unwrap();
    let mut random = [0; 16];
    OsRng.fill_bytes(&mut random);
    let directory = root.join(hex::encode(random));
    fs::create_dir(&directory).unwrap();
    directory
}

fn fixture(threshold: usize) -> (ClaimPlan, TweakProofs, Vec<Scalar>) {
    // IDs deliberately do not encode polynomial indices, and their sorted
    // order is the reverse of configured indices. Accidentally using either
    // as the polynomial x-coordinate must fail the native compatibility test.
    let coefficients = vec![
        Scalar::from(17u64),
        Scalar::from(19u64),
        Scalar::from(23u64),
    ][..threshold]
        .to_vec();
    let operators = (1..=3u16)
        .map(|index| {
            (
                hex::encode(Scalar::from(45 - u64::from(index)).to_bytes()),
                Operator {
                    share_index: index,
                    encryption_key: compressed(ProjectivePoint::GENERATOR * operator_secret(index)),
                },
            )
        })
        .collect();
    let plan = ClaimPlan {
        deployment: [1; 32],
        operation: [2; 32],
        transfer_id: "10000000-0000-4000-8000-000000000001".into(),
        leaf_id: "20000000-0000-4000-8000-000000000002".into(),
        incoming_user_key: compressed(ProjectivePoint::GENERATOR * Scalar::from(99u64)),
        joint_user_key: compressed(ProjectivePoint::GENERATOR * Scalar::from(82u64)),
        threshold,
        operators,
    };
    let proofs = TweakProofs {
        coefficients: coefficients
            .iter()
            .map(|x| compressed(ProjectivePoint::GENERATOR * x))
            .collect(),
    };
    (plan, proofs, coefficients)
}

fn operator_secret(index: u16) -> Scalar {
    Scalar::from(100 + u64::from(index))
}
fn evaluation(coefficients: &[Scalar], index: u16) -> Scalar {
    coefficients.iter().rev().fold(Scalar::ZERO, |sum, value| {
        sum * Scalar::from(u64::from(index)) + value
    })
}

fn decrypt(secret: Scalar, ciphertext: &[u8]) -> Result<Vec<u8>> {
    type Cipher = AesGcm<Aes256, U16>;
    let ephemeral = k256::PublicKey::from_sec1_bytes(&ciphertext[..65])?.to_projective();
    let shared = ephemeral * secret;
    let mut material = ciphertext[..65].to_vec();
    material.extend_from_slice(shared.to_affine().to_encoded_point(false).as_bytes());
    let mut key = [0; 32];
    Hkdf::<Sha256>::new(None, &material)
        .expand(&[], &mut key)
        .unwrap();
    let nonce: [u8; 16] = ciphertext[65..81].try_into()?;
    let tag: [u8; 16] = ciphertext[81..97].try_into()?;
    let mut plaintext = ciphertext[97..].to_vec();
    Cipher::new_from_slice(&key)
        .unwrap()
        .decrypt_in_place_detached(&nonce.into(), b"", &mut plaintext, &tag.into())
        .map_err(|_| anyhow::anyhow!("cipher authentication failed"))?;
    Ok(plaintext)
}

fn journals(
    root: &Path,
    plan: &ClaimPlan,
    proofs: &TweakProofs,
    coefficients: &[Scalar],
) -> Vec<OperatorClaimJournal> {
    plan.operators
        .iter()
        .map(|(id, operator)| {
            OperatorClaimJournal::create(
                &root.join(id),
                plan,
                proofs,
                id,
                Zeroizing::new(
                    evaluation(coefficients, operator.share_index)
                        .to_bytes()
                        .into(),
                ),
            )
            .unwrap()
        })
        .collect()
}

#[test]
fn encrypted_standard_packages_use_configured_indices_and_upstream_wire() {
    let mut vectors = Vec::new();
    for threshold in [2, 3] {
        let root = directory();
        let (plan, proofs, coefficients) = fixture(threshold);
        let journals = journals(&root, &plan, &proofs, &coefficients);
        let packages =
            collect_packages(&plan, &proofs, &journals.iter().collect::<Vec<_>>()).unwrap();
        let public_shares = proofs.public_shares(&plan).unwrap();
        let mut operator_vectors = BTreeMap::new();
        for (id, operator) in &plan.operators {
            let cipher = &packages[id];
            let expected = wire::encode(
                &plan.leaf_id,
                &evaluation(&coefficients, operator.share_index)
                    .to_bytes()
                    .into(),
                &proofs.coefficients,
                &public_shares,
            );
            assert_eq!(
                decrypt(operator_secret(operator.share_index), cipher).unwrap(),
                expected.as_slice()
            );
            let mut changed = cipher.clone();
            *changed.last_mut().unwrap() ^= 1;
            assert!(decrypt(operator_secret(operator.share_index), &changed).is_err());
            assert!(decrypt(operator_secret(operator.share_index) + Scalar::ONE, cipher).is_err());
            operator_vectors.insert(id, serde_json::json!({
                "index":operator.share_index,
                "synthetic_operator_secret":hex::encode(operator_secret(operator.share_index).to_bytes()),
                "ciphertext":hex::encode(cipher), "plaintext":hex::encode(&*expected),
            }));
        }
        vectors.push(serde_json::json!({"threshold":threshold,"leaf_id":plan.leaf_id,
            "incoming_user_key":hex::encode(&plan.incoming_user_key),"joint_user_key":hex::encode(&plan.joint_user_key),
            "operators":operator_vectors}));
    }
    if let Some(path) = std::env::var_os("ZARK_SPARK_STANDARD_CLAIM_VECTOR") {
        let path = PathBuf::from(path);
        let allowed = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../work")
            .canonicalize()
            .unwrap();
        assert!(
            path.parent()
                .unwrap()
                .canonicalize()
                .unwrap()
                .starts_with(allowed)
        );
        let bytes = serde_json::to_vec_pretty(&serde_json::json!({
            "schema":"zark-spark/standard-claim-fixture/v1","synthetic":true,"live_ingress":false,"cases":vectors,
        })).unwrap();
        use std::io::Write;
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
    }
}

#[test]
fn rejects_wrong_share_wrong_index_and_substituted_key_before_creating_state() {
    let root = directory();
    let (plan, proofs, coefficients) = fixture(2);
    let (id, operator) = plan.operators.first_key_value().unwrap();
    assert!(
        OperatorClaimJournal::create(
            &root.join("bad"),
            &plan,
            &proofs,
            id,
            Zeroizing::new([0; 32])
        )
        .is_err()
    );
    assert!(!root.join("bad").exists());
    let wrong_x = zark_protocol::scalar(&hex::decode(id).unwrap()).unwrap();
    let wrong = coefficients[0] + coefficients[1] * wrong_x;
    assert!(seal(&plan, &proofs, id, Zeroizing::new(wrong.to_bytes().into())).is_err());
    let correct = evaluation(&coefficients, operator.share_index)
        .to_bytes()
        .into();
    let mut changed = plan.clone();
    changed.joint_user_key = compressed(ProjectivePoint::GENERATOR * Scalar::from(83u64));
    assert!(seal(&changed, &proofs, id, Zeroizing::new(correct)).is_err());
    let mut changed = plan.clone();
    changed.operators.get_mut(id).unwrap().share_index = 1;
    assert!(changed.validate().is_err()); // duplicates another recipient's index
    let mut changed = proofs.clone();
    changed.coefficients.pop();
    assert!(seal(&plan, &changed, id, Zeroizing::new(correct)).is_err());
    let zero_at_one = TweakProofs {
        coefficients: vec![
            proofs.coefficients[0].clone(),
            compressed(-point(&proofs.coefficients[0]).unwrap()),
        ],
    };
    assert!(zero_at_one.validate(&plan).is_err());
    let mut changed = plan.clone();
    changed.leaf_id = "é0000000-0000-4000-8000-000000000002".into();
    assert!(changed.validate().is_err());
}

#[test]
fn exact_reopen_pins_cluster_operation_proofs_and_retains_process_lock() {
    let root = directory();
    let (plan, proofs, coefficients) = fixture(2);
    let (id, operator) = plan.operators.first_key_value().unwrap();
    let path = root.join("one");
    let create = || {
        OperatorClaimJournal::create(
            &path,
            &plan,
            &proofs,
            id,
            Zeroizing::new(
                evaluation(&coefficients, operator.share_index)
                    .to_bytes()
                    .into(),
            ),
        )
    };
    let journal = create().unwrap();
    let original = journal.package().unwrap();
    assert_eq!(original, journal.package().unwrap());
    assert!(OperatorClaimJournal::open(&path, &plan, &proofs, id).is_err());
    assert!(create().is_err());
    drop(journal);
    let mut changed = plan.clone();
    changed.operation = [3; 32];
    assert!(OperatorClaimJournal::open(&path, &changed, &proofs, id).is_err());
    let mut changed = plan.clone();
    changed.operators.get_mut(id).unwrap().encryption_key =
        compressed(ProjectivePoint::GENERATOR * Scalar::from(500u64));
    assert!(OperatorClaimJournal::open(&path, &changed, &proofs, id).is_err());
    let mut changed = proofs.clone();
    changed.coefficients[1] = compressed(ProjectivePoint::GENERATOR * Scalar::from(43u64));
    assert!(OperatorClaimJournal::open(&path, &plan, &changed, id).is_err());
    let journal = OperatorClaimJournal::open(&path, &plan, &proofs, id).unwrap();
    assert_eq!(journal.package().unwrap(), original);
    drop(journal);
    fs::rename(
        path.join("standard-claim-package.json"),
        path.join("retained.json"),
    )
    .unwrap();
    assert!(OperatorClaimJournal::open(&path, &plan, &proofs, id).is_err());
    assert!(create().is_err());
}

#[test]
fn collection_rejects_missing_duplicate_mixed_and_failed_save_retries() {
    let root = directory();
    let (plan, proofs, coefficients) = fixture(2);
    let journals = journals(&root, &plan, &proofs, &coefficients);
    assert!(collect_packages(&plan, &proofs, &[&journals[0], &journals[1]]).is_err());
    assert!(collect_packages(&plan, &proofs, &[&journals[0], &journals[0], &journals[2]]).is_err());
    let refs = journals.iter().collect::<Vec<_>>();
    let original = collect_packages(&plan, &proofs, &refs).unwrap();
    let mut changed = plan.clone();
    changed.operation = [4; 32];
    assert!(collect_packages(&changed, &proofs, &refs).is_err());
    let id = plan.operators.keys().next().unwrap();
    let record = root.join(id).join("standard-claim-package.json");
    let saved = record.with_extension("saved");
    fs::rename(&record, &saved).unwrap();
    fs::create_dir(&record).unwrap();
    assert!(journals[0].package().is_err());
    assert!(collect_packages(&plan, &proofs, &refs).is_err());
    // Restore only this test's saved record. No existing state is discarded.
    fs::remove_dir(&record).unwrap();
    fs::rename(saved, record).unwrap();
    assert_eq!(collect_packages(&plan, &proofs, &refs).unwrap(), original);
}
