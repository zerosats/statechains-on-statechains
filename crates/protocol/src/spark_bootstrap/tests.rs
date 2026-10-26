use super::*;
use crate::{owner_auth, point_bytes};
use k256::{ProjectivePoint, Scalar};
fn scalar_bytes(value: u64) -> Digest {
    Scalar::from(value).to_bytes().into()
}
fn context() -> BootstrapContext {
    let deployment = [1; 32];
    let coin = [2; 32];
    BootstrapContext {
        deployment,
        coin,
        allocation_state: spark_lineage::origin_previous_state(&deployment, &coin).unwrap(),
        operation: [3; 32],
        session: owner_auth::normalized_key(&owner_auth::generate_secret())
            .unwrap()
            .verifying_key()
            .to_bytes()
            .into(),
        revision: 1,
    }
}
#[test]
fn bootstrap_third_slot_is_fresh_and_binds_the_future_backing_before_nonce_release() {
    let context = context();
    let opening = WalletOpening {
        alpha: scalar_bytes(3),
        beta: scalar_bytes(5),
        binding: scalar_bytes(7),
        salt: [8; 32],
    };
    let server = point_bytes(ProjectivePoint::GENERATOR).unwrap();
    let plan = [9; 32];
    let backing = [10; 32];
    let third = opening
        .commitment(&context, &backing, &plan, &server, 2)
        .unwrap();
    assert_ne!(
        third,
        opening
            .commitment(&context, &backing, &plan, &server, 1)
            .unwrap()
    );
    assert_ne!(
        third,
        opening
            .commitment(&context, &[11; 32], &plan, &server, 2)
            .unwrap()
    );
    assert!(
        opening
            .commitment(&context, &backing, &plan, &server, 3)
            .is_err()
    );
    let owner = owner_auth::normalized_key(&owner_auth::generate_secret()).unwrap();
    let public = owner.verifying_key().to_bytes().into();
    let capability =
        spark_lineage::public_capability_commitment(&context.deployment, &context.coin, &public)
            .unwrap();
    let mut slots = [[12; 32], [13; 32], third];
    let signature = owner
        .sign_raw(
            &context
                .owner_message(&backing, &capability, &plan, &server, &slots)
                .unwrap(),
            &[0; 32],
        )
        .unwrap()
        .to_bytes();
    context
        .verify_owner(
            &backing,
            &capability,
            &plan,
            &server,
            &slots,
            &public,
            &signature,
        )
        .unwrap();
    slots[2][0] ^= 1;
    assert!(
        context
            .verify_owner(
                &backing,
                &capability,
                &plan,
                &server,
                &slots,
                &public,
                &signature
            )
            .is_err()
    );
}
#[test]
fn bootstrap_canonical940_accepts_zero_challenges_but_rejects_any_pair_of_reused_nonces() {
    let context = context();
    let config = Config {
        origin_key: context.session,
        role_hashes: std::array::from_fn(|i| scalar_bytes(i as u64 + 1)),
    };
    let mut authorization = BootstrapAuthorization {
        context,
        backing: [1; 32],
        policy: [2; 32],
        capability: [3; 32],
        plan: [4; 32],
        cluster: [5; 32],
        server: point_bytes(ProjectivePoint::GENERATOR * Scalar::from(11u64)).unwrap(),
        config,
        branches: std::array::from_fn(|i| BootstrapBranch {
            server_nonce: point_bytes(ProjectivePoint::GENERATOR * Scalar::from(i as u64 + 1))
                .unwrap(),
            challenge: [0; 32],
            blinding_commitment: [i as u8 + 6; 32],
        }),
    };
    let encoded = authorization.encode().unwrap();
    assert_eq!(encoded.len(), 940);
    assert_eq!(
        BootstrapAuthorization::decode(&encoded).unwrap(),
        authorization
    );
    authorization.branches[2].server_nonce =
        point_bytes(-point(&authorization.branches[1].server_nonce).unwrap()).unwrap();
    assert!(authorization.encode().is_err());
    let mut wrong = encoded;
    wrong[0] = 10;
    assert!(BootstrapAuthorization::decode(&wrong).is_err());
    authorization.context.revision = 2;
    assert!(authorization.context.encode().is_err());
}
