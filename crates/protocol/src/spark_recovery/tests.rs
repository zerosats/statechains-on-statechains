use super::*;
use crate::{even, point_bytes};
use k256::ProjectivePoint;

fn affine(value: u64) -> [u8; 64] {
    point_bytes(ProjectivePoint::GENERATOR * Scalar::from(value)).unwrap()
}

fn context() -> RecoveryContext {
    RecoveryContext {
        deployment: [1; 32],
        coin: [2; 32],
        previous_state: [3; 32],
        operation: [4; 32],
        session: [5; 32],
        successor_state: [6; 32],
        revision: 1,
    }
}

// This is a structurally valid statement. No proof or ownership is fabricated:
// decoding is deliberately not a proof-verification API.
fn authorization() -> RecoveryAuthorization {
    RecoveryAuthorization {
        context: context(),
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
                challenge: Scalar::ONE.to_bytes().into(),
                nonce_commitment: [11; 32],
            },
        ],
    }
}

fn target() -> TargetOpening {
    TargetOpening {
        salt: [12; 32],
        payout: point_bytes(
            even(ProjectivePoint::GENERATOR * Scalar::from(17u64))
                .unwrap()
                .0,
        )
        .unwrap(),
        fee: 100,
        delay: 100,
        owner_index: 1,
        initial: 100,
        gap: 10,
        margin: 2,
    }
}

#[test]
fn decoder_rejects_cross_version_and_truncated_or_extended_statements() {
    let bytes = authorization().encode().unwrap();
    assert_eq!(
        RecoveryAuthorization::decode(&bytes).unwrap(),
        authorization()
    );
    assert!(RecoveryAuthorization::decode(&bytes[..bytes.len() - 1]).is_err());
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(RecoveryAuthorization::decode(&extra).is_err());
    let mut another_version = bytes;
    another_version[0] = 10;
    assert!(RecoveryAuthorization::decode(&another_version).is_err());
}

#[test]
fn public_engine_revision_is_independent_of_private_owner_slot() {
    for revision in [0u64, 9, u32::MAX as u64 + 1, u64::MAX] {
        let mut bytes = authorization().encode().unwrap();
        bytes[292..300].copy_from_slice(&revision.to_le_bytes());
        assert_eq!(
            RecoveryAuthorization::decode(&bytes)
                .unwrap()
                .context
                .revision,
            revision
        );
        let mut ctx = context();
        ctx.revision = revision;
        assert!(target().commitment(&ctx, &[13; 32]).is_ok());
        let mut last_owner = target();
        last_owner.owner_index = 8;
        last_owner.delay = 30;
        assert!(last_owner.commitment(&ctx, &[13; 32]).is_ok());
    }
}

#[test]
fn hostile_private_owner_index_is_rejected_before_arithmetic() {
    for owner_index in [0, 9, u32::MAX] {
        let mut opening = target();
        opening.owner_index = owner_index;
        // A panic here would fail the test: hostile witnesses are ordinary errors.
        assert!(opening.commitment(&context(), &[13; 32]).is_err());
    }
    let mut inconsistent = target();
    inconsistent.owner_index = 2;
    assert!(inconsistent.commitment(&context(), &[13; 32]).is_err());
}

#[test]
fn decoder_accepts_zero_challenge_but_rejects_noncanonical_scalar() {
    let mut bytes = authorization().encode().unwrap();
    assert!(RecoveryAuthorization::decode(&bytes).is_ok());
    bytes[428..460].copy_from_slice(&[255; 32]);
    assert!(RecoveryAuthorization::decode(&bytes).is_err());
}

#[test]
fn nonce_reuse_is_rejected_even_when_one_point_is_negated() {
    let mut record = authorization();
    record.branches[1].server_nonce = record.branches[0].server_nonce;
    assert!(record.encode().is_err());
    record.branches[1].server_nonce =
        point_bytes(-point(&record.branches[0].server_nonce).unwrap()).unwrap();
    assert!(record.encode().is_err());
    record = authorization();
    record.branches[1].nonce_commitment = record.branches[0].nonce_commitment;
    assert!(record.encode().is_err());
}

#[test]
fn executable_recovery_rejects_wrong_parity_delay_fee_and_dust() {
    let refund = RefundOpening {
        txid: [14; 32],
        amount: 10_000,
    };
    let mut opening = target();
    opening.payout = point_bytes(-point(&opening.payout).unwrap()).unwrap();
    assert!(recovery_sighash(&refund, [15; 32], &opening).is_err());
    for delay in [0, 65536, u32::MAX] {
        let mut opening = target();
        opening.delay = delay;
        assert!(recovery_sighash(&refund, [15; 32], &opening).is_err());
    }
    for fee in [0, 10001, u64::MAX] {
        let mut opening = target();
        opening.fee = fee;
        assert!(recovery_sighash(&refund, [15; 32], &opening).is_err());
    }
    let dust = RefundOpening {
        txid: [14; 32],
        amount: 430,
    };
    assert!(recovery_sighash(&dust, [15; 32], &target()).is_err());
    // This is only the executable single-output recovery primitive's policy;
    // it must not become a restriction on small off-chain Spark payments.
}
