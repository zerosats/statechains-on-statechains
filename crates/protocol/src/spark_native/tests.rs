use super::*;
use crate::{owner_auth, point_bytes};
use k256::{ProjectivePoint, Scalar};

fn statement() -> ExitAuthorization {
    let affine = |n: u64| point_bytes(ProjectivePoint::GENERATOR * Scalar::from(n)).unwrap();
    let session = owner_auth::normalized_key(&owner_auth::generate_secret())
        .unwrap()
        .verifying_key()
        .to_bytes()
        .into();
    ExitAuthorization {
        context: ExitContext {
            deployment: [1; 32],
            coin: [2; 32],
            current_state: [3; 32],
            operation: [4; 32],
            session,
            revision: 19,
        },
        backing: [5; 32],
        policy: [6; 32],
        capability: [7; 32],
        plan: [8; 32],
        cluster: [9; 32],
        server: affine(3),
        config: Config {
            origin_key: session,
            role_hashes: std::array::from_fn(|i| {
                let mut value = [0; 32];
                value[31] = i as u8 + 1;
                value
            }),
        },
        branches: [
            NativeBranch {
                server_nonce: affine(5),
                challenge: [0; 32],
                blinding_commitment: [10; 32],
            },
            NativeBranch {
                server_nonce: affine(7),
                challenge: [0; 32],
                blinding_commitment: [11; 32],
            },
        ],
    }
}

#[test]
fn native_canonical_statement_keeps_zero_challenges_and_rejects_nonce_sign_reuse() {
    let mut value = statement();
    let encoded = value.encode().unwrap();
    assert_eq!(encoded.len(), 812);
    assert_eq!(ExitAuthorization::decode(&encoded).unwrap(), value);
    let mut wrong = encoded.clone();
    wrong[0] = 10;
    assert!(ExitAuthorization::decode(&wrong).is_err());
    wrong = encoded;
    wrong[620..652].fill(255);
    assert!(ExitAuthorization::decode(&wrong).is_err());
    value.branches[1].server_nonce =
        point_bytes(-point(&value.branches[0].server_nonce).unwrap()).unwrap();
    assert!(value.encode().is_err());
}

#[test]
fn native_prepare_owner_signature_binds_hidden_plan_both_slots_and_starting_revision() {
    let mut value = statement();
    let secret = owner_auth::generate_secret();
    let key = owner_auth::normalized_key(&secret).unwrap();
    let public = key.verifying_key().to_bytes().into();
    let capability = spark_lineage::public_capability_commitment(
        &value.context.deployment,
        &value.context.coin,
        &public,
    )
    .unwrap();
    let mut slots = value
        .branches
        .clone()
        .map(|branch| branch.blinding_commitment);
    let signature = key
        .sign_raw(
            &value.context.owner_message(&value.plan, &slots).unwrap(),
            &[0; 32],
        )
        .unwrap()
        .to_bytes();
    value
        .context
        .verify_owner(&value.plan, &slots, &capability, &public, &signature)
        .unwrap();
    value.plan[0] ^= 1;
    assert!(
        value
            .context
            .verify_owner(&value.plan, &slots, &capability, &public, &signature)
            .is_err()
    );
    value.plan[0] ^= 1;
    slots.swap(0, 1);
    assert!(
        value
            .context
            .verify_owner(&value.plan, &slots, &capability, &public, &signature)
            .is_err()
    );
    slots.swap(0, 1);
    value.context.revision += 1;
    assert!(
        value
            .context
            .verify_owner(&value.plan, &slots, &capability, &public, &signature)
            .is_err()
    );
}

#[test]
fn ordinary_native_refunds_have_distinct_blinding_domains() -> anyhow::Result<()> {
    let plan = [91; 32];
    let first = ordinary_branch_plan(&plan, 0)?;
    let second = ordinary_branch_plan(&plan, 1)?;
    assert_ne!(first, second);
    assert_ne!(first, crate::spark_receive::branch_plan(&plan, 0)?);
    assert!(ordinary_branch_plan(&[0; 32], 0).is_err());
    assert!(ordinary_branch_plan(&plan, 2).is_err());
    let value = statement();
    let opening = crate::spark_single_user::Opening {
        alpha: Scalar::from(11u64).to_bytes().into(),
        beta: Scalar::from(12u64).to_bytes().into(),
        binding: Scalar::from(13u64).to_bytes().into(),
        salt: [92; 32],
    };
    assert_ne!(
        opening.commitment(&value.context, &first, &value.server)?,
        opening.commitment(&value.context, &second, &value.server)?
    );
    // Legacy native precommitments cannot authorize the ordinary transcript.
    let legacy = WalletOpening {
        alpha: opening.alpha,
        beta: opening.beta,
        binding: opening.binding,
        salt: opening.salt,
    };
    assert_ne!(
        opening.commitment(&value.context, &first, &value.server)?,
        legacy.commitment(&value.context, &plan, &value.server, 0)?
    );
    Ok(())
}
