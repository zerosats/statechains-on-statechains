use super::*;
use crate::{point_bytes, random_scalar, spark_wire::OwnerAuthorization};
use k256::{ProjectivePoint, schnorr::SigningKey};
fn authorization() -> Result<SigningAuthorization> {
    let session = SigningKey::from_bytes(&random_scalar().to_bytes())?;
    let config = Config {
        origin_key: session.verifying_key().to_bytes().into(),
        role_hashes: [[1; 32], [2; 32], [3; 32], [4; 32]],
    };
    Ok(SigningAuthorization {
        context: ExitContext {
            deployment: [1; 32],
            coin: [2; 32],
            current_state: [3; 32],
            operation: [4; 32],
            session: session.verifying_key().to_bytes().into(),
            revision: 7,
        },
        backing: [5; 32],
        policy: [6; 32],
        capability: [7; 32],
        plan: [8; 32],
        server: point_bytes(ProjectivePoint::GENERATOR)?,
        config,
        nonce: point_bytes(ProjectivePoint::GENERATOR * k256::Scalar::from(2u64))?,
        challenge: [0; 32],
        blinding: [9; 32],
    })
}
#[test]
fn canonical_statement_rejects_version_size_point_and_challenge_substitution() -> Result<()> {
    let a = authorization()?;
    let bytes = a.encode()?;
    assert_eq!(bytes.len(), ENCODED_LEN);
    assert!(SigningAuthorization::decode(&bytes)? == a);
    let mut bad = bytes.clone();
    bad.push(0);
    assert!(SigningAuthorization::decode(&bad).is_err());
    let mut bad = bytes.clone();
    bad[0] = 2;
    assert!(SigningAuthorization::decode(&bad).is_err());
    let mut bad = bytes.clone();
    bad[300..364].fill(0);
    assert!(SigningAuthorization::decode(&bad).is_err());
    let mut bad = bytes;
    bad[588..620].fill(255);
    assert!(SigningAuthorization::decode(&bad).is_err());
    Ok(())
}
#[test]
fn owner_preparation_cannot_relabel_existing_native_purpose_or_change_plan() -> Result<()> {
    let a = authorization()?;
    let key = SigningKey::from_bytes(&random_scalar().to_bytes())?;
    let owner = OwnerAuthorization::sign_single_user(&a.context, &a.plan, &a.blinding, &key)?;
    let capability = crate::spark_lineage::public_capability_commitment(
        &a.context.deployment,
        &a.context.coin,
        &owner.public_key,
    )?;
    verify_owner(
        &a.context,
        &a.plan,
        &a.blinding,
        &capability,
        &owner.public_key,
        &owner.signature,
    )?;
    assert!(
        verify_owner(
            &a.context,
            &[10; 32],
            &a.blinding,
            &capability,
            &owner.public_key,
            &owner.signature
        )
        .is_err()
    );
    assert!(
        verify_owner(
            &a.context,
            &a.plan,
            &[10; 32],
            &capability,
            &owner.public_key,
            &owner.signature
        )
        .is_err()
    );
    let old = OwnerAuthorization::sign_native(&a.context, &a.plan, &[a.blinding, [11; 32]], &key)?;
    assert!(
        verify_owner(
            &a.context,
            &a.plan,
            &a.blinding,
            &capability,
            &old.public_key,
            &old.signature
        )
        .is_err()
    );
    Ok(())
}
