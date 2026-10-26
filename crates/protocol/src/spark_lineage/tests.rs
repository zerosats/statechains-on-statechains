use super::*;
use crate::{
    owner_auth, point_bytes,
    spark_recovery::{BranchAuthorization, RecoveryContext},
};
use k256::{ProjectivePoint, Scalar};

fn config() -> Config {
    Config {
        origin_key: owner_auth::normalized_key(&owner_auth::generate_secret())
            .unwrap()
            .verifying_key()
            .to_bytes()
            .into(),
        role_hashes: std::array::from_fn(|i| {
            let mut bytes = [0; 32];
            bytes[31] = i as u8 + 1;
            bytes
        }),
    }
}

fn intent() -> Intent {
    Intent {
        deployment: [1; 32],
        coin: [2; 32],
        previous_state: [3; 32],
        operation: [4; 32],
        recipient_claim: [5; 32],
        revision: 19,
    }
}

fn handover() -> Handover {
    Handover {
        intent: intent(),
        backing: [6; 32],
        mask: [7; 32],
        masked_share: [8; 32],
        bridge: [9; 32],
        previous_capability: [10; 32],
        server_share: [11; 32],
        policy: [12; 32],
        draft_token: [13; 32],
        config: config(),
    }
}

fn issuance() -> Issuance {
    let affine = |n: u64| point_bytes(ProjectivePoint::GENERATOR * Scalar::from(n)).unwrap();
    Issuance {
        recovery: RecoveryAuthorization {
            context: RecoveryContext {
                deployment: [1; 32],
                coin: [2; 32],
                previous_state: [3; 32],
                operation: [4; 32],
                session: [5; 32],
                successor_state: [6; 32],
                revision: 19,
            },
            backing: [7; 32],
            recovery: [8; 32],
            policy: [9; 32],
            server: affine(3),
            branches: [
                BranchAuthorization {
                    server_nonce: affine(5),
                    challenge: [0; 32],
                    nonce_commitment: [10; 32],
                },
                BranchAuthorization {
                    server_nonce: affine(7),
                    challenge: [0; 32],
                    nonce_commitment: [11; 32],
                },
            ],
        },
        recipient_claim: [12; 32],
        mask: [13; 32],
        masked_share: [14; 32],
        bridge: [15; 32],
        delta: [16; 32],
        previous_capability: [17; 32],
        next_capability: [18; 32],
        server_share: [19; 32],
        config: config(),
    }
}

#[test]
fn wrong_version_or_role_registry_is_rejected_before_proof_execution() {
    let value = handover();
    let bytes = value.encode().unwrap();
    assert_eq!(Handover::decode(&bytes).unwrap(), value);
    let mut wrong_version = bytes;
    wrong_version[0] = 10;
    assert!(Handover::decode(&wrong_version).is_err());
    let mut cfg = config();
    cfg.role_hashes[1] = cfg.role_hashes[0];
    assert!(cfg.encode().is_err());
    cfg = config();
    cfg.role_hashes[0] = [255; 32];
    assert!(cfg.encode().is_err());
}

#[test]
fn owner_reservation_binds_intent_and_fresh_session_before_mask_release() {
    let mut request = intent();
    let secret = owner_auth::generate_secret();
    let key = owner_auth::normalized_key(&secret).unwrap();
    let public = key.verifying_key().to_bytes().into();
    let cap = public_capability_commitment(&request.deployment, &request.coin, &public).unwrap();
    let session: Digest = owner_auth::normalized_key(&owner_auth::generate_secret())
        .unwrap()
        .verifying_key()
        .to_bytes()
        .into();
    let signature: [u8; 64] = key
        .sign_raw(
            &request.owner_reservation_message(&session).unwrap(),
            &[0; 32],
        )
        .unwrap()
        .to_bytes();
    request
        .verify_owner_reservation(&session, &cap, &public, &signature)
        .unwrap();
    request.operation[0] ^= 1;
    assert!(
        request
            .verify_owner_reservation(&session, &cap, &public, &signature)
            .is_err()
    );
    request.operation[0] ^= 1;
    request.revision += 1;
    assert!(
        request
            .verify_owner_reservation(&session, &cap, &public, &signature)
            .is_err()
    );
}

#[test]
fn both_actual_response_bytes_bind_final_state_and_origin_attestation() {
    // Encoding/commitment test only: these random scalars are NOT claimed to be
    // valid issuance. Real partial equations are verified by the composed role.
    let mut auth = issuance();
    let partials = [
        Scalar::from(3u64).to_bytes().into(),
        Scalar::from(4u64).to_bytes().into(),
    ];
    let first = Certificate::from_issuance(&auth, &partials).unwrap();
    let changed = [partials[0], Scalar::from(5u64).to_bytes().into()];
    assert_ne!(
        Certificate::from_issuance(&auth, &changed).unwrap().state,
        first.state
    );
    auth.config.role_hashes.swap(1, 2);
    let substituted = Certificate::from_issuance(&auth, &partials).unwrap();
    assert_ne!(
        substituted.origin_message().unwrap(),
        first.origin_message().unwrap()
    );
}
