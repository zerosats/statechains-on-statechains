use super::*;
use crate::{
    legacy_signing::tests::fixture,
    wrapped_recovery::{RecoveryTarget, test_support::backing_with_keys},
};
use bitcoin::{
    Transaction,
    consensus::deserialize,
    hashes::Hash,
    secp256k1::{Parity, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey},
};
use k256::Scalar;
use zark_protocol::spark_recovery::RefundOpening;
use zark_protocol::{handoff::RecoverySchedule, point_bytes, random_scalar, tagged_hash};

fn target(revision: u64) -> RecoveryTarget {
    RecoveryTarget {
        revision,
        payout: PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[12; 32]).unwrap(),
        )
        .x_only_public_key()
        .0,
        fee_sats: 500,
    }
}
fn schedule() -> RecoverySchedule {
    RecoverySchedule {
        initial: 500,
        gap: 60,
        margin: 20,
    }
}
fn nonces(context: [u8; 32], secrets: &[Scalar; 2]) -> [BlindNonce; 2] {
    std::array::from_fn(|index| BlindNonce {
        context,
        variant: VARIANTS[index],
        nonce_id: [index as u8 + 20; 32],
        point: point_bytes(ProjectivePoint::GENERATOR * secrets[index])
            .unwrap()
            .to_vec(),
    })
}
fn context() -> RecoveryContext {
    RecoveryContext {
        deployment: [1; 32],
        coin: [2; 32],
        previous_state: [3; 32],
        operation: [4; 32],
        session: [5; 32],
        successor_state: [6; 32],
        // Engine CAS revision is unrelated to the private recovery owner slot.
        revision: 19,
    }
}
fn openings(plan: &RecoveryPlan) -> Result<(BackingOpening, TargetOpening)> {
    let txs: [Transaction; 2] = [
        deserialize(&plan.unsigned_transactions()[0])?,
        deserialize(&plan.unsigned_transactions()[1])?,
    ];
    let output = XOnlyPublicKey::from_slice(&txs[0].output[0].script_pubkey.as_bytes()[2..])?;
    let backing = BackingOpening {
        salt: [31; 32],
        refunds: std::array::from_fn(|index| RefundOpening {
            txid: txs[index].input[0].previous_output.txid.to_byte_array(),
            amount: txs[index].output[0].value.to_sat() + 500,
        }),
    };
    let target = TargetOpening {
        salt: [32; 32],
        payout: output.public_key(Parity::Even).serialize_uncompressed()[1..]
            .try_into()
            .unwrap(),
        fee: 500,
        delay: plan.delay_blocks(),
        owner_index: 1 + (schedule().initial - plan.delay_blocks()) / schedule().gap,
        initial: 500,
        gap: 60,
        margin: 20,
    };
    Ok((backing, target))
}
// Test-only stand-in for the existing signer's issuance equation. It receives
// exclusively the signer-visible request and its own two independent nonces;
// no sighash, wallet share or private transaction crosses this interface.
fn issue(
    request: &BlindRecoveryRequest,
    server: Scalar,
    secrets: &[Scalar; 2],
) -> Result<BlindRecoveryResponse> {
    Ok(BlindRecoveryResponse {
        request: request.digest()?,
        partials: std::array::from_fn(|index| {
            (secrets[index] + scalar(&request.variants[index].challenge).unwrap() * server)
                .to_bytes()
                .into()
        }),
    })
}

#[test]
fn actual_zark_blinding_signs_both_native_refunds_across_key_and_nonce_parities() -> Result<()> {
    let mut covered = [false; 8];
    for _ in 0..256 {
        let (keys, backing) = backing_with_keys(fixture())?;
        let user = keys.authority.user_authority();
        let plan = RecoveryPlan::new(&backing, user, schedule(), target(2))?;
        let binding = WalletBinding::new(&plan, user, [3; 32], [4; 32])?;
        let secrets = Zeroizing::new([random_scalar(), random_scalar()]);
        let offers = nonces(binding.commitment(), &secrets);
        let session = WalletSession::prepare(binding, &plan, &keys.wallet, user, offers)?;
        let raw_group_odd = user.public_key()?[0] == 3;
        let tweak = scalar(&tagged_hash(
            "TapTweak",
            &[&point_bytes(session.key.internal)?[..32]],
        ))?;
        let tweaked_odd =
            point_bytes(session.key.internal + ProjectivePoint::GENERATOR * tweak)?[63] & 1 != 0;
        for index in 0..2 {
            let raw_nonce = session.nonces[index]
                + ProjectivePoint::GENERATOR * session.blindings[index].alpha
                + session.server * session.blindings[index].beta;
            let nonce_odd = point_bytes(raw_nonce)?[63] & 1 != 0;
            covered
                [(raw_group_odd as usize) * 4 + (tweaked_odd as usize) * 2 + nonce_odd as usize] =
                true;
        }
        let wire = serde_json::to_value(session.request())?;
        let fields = wire.as_object().unwrap();
        assert_eq!(fields.len(), 2);
        assert!(fields.contains_key("context") && fields.contains_key("variants"));
        for variant in wire["variants"].as_array().unwrap() {
            assert_eq!(variant.as_object().unwrap().len(), 2);
            assert!(variant.get("nonce").is_some() && variant.get("challenge").is_some());
        }
        assert_ne!(
            session.request().variants[0].challenge,
            session.request().variants[1].challenge
        );
        let response = issue(
            session.request(),
            keys.signer.additive_scalar(user)?,
            &secrets,
        )?;
        let recovery = session.finish(&plan, &response)?;
        assert_eq!(recovery.delay_blocks(), 440);
        assert_eq!(recovery.payout_sats(), [63_500, 62_545]);
        assert_ne!(recovery.prevouts()[0], recovery.prevouts()[1]);
        assert_eq!(
            plan.validate(recovery.package())?.digest(),
            recovery.digest()
        );
        if covered.iter().all(|v| *v) {
            return Ok(());
        }
    }
    anyhow::bail!("missing parity cases: {covered:?}")
}

#[test]
fn nonce_context_order_identity_point_and_variant_substitutions_are_rejected() -> Result<()> {
    let (keys, backing) = backing_with_keys(fixture())?;
    let user = keys.authority.user_authority();
    let plan = RecoveryPlan::new(&backing, user, schedule(), target(1))?;
    for attack in 0..9 {
        let binding = WalletBinding::new(&plan, user, [3; 32], [4; 32])?;
        let secrets = Zeroizing::new([random_scalar(), random_scalar()]);
        let mut offers = nonces(binding.commitment(), &secrets);
        match attack {
            0 => offers[0].context[0] ^= 1,
            1 => offers.swap(0, 1),
            2 => offers[1].variant = RefundVariant::Cpfp,
            3 => offers[1].nonce_id = offers[0].nonce_id,
            4 => offers[0].nonce_id = [0; 32],
            5 => offers[1].point = offers[0].point.clone(),
            6 => offers[1].point = point_bytes(-point(&offers[0].point)?)?.to_vec(),
            7 => offers[0].point = vec![0; 64],
            _ => offers[0].point.push(0),
        }
        assert!(
            WalletSession::prepare(binding, &plan, &keys.wallet, user, offers).is_err(),
            "attack {attack}"
        );
    }
    Ok(())
}

#[test]
fn responses_and_wallet_completion_cannot_substitute_request_partial_or_plan() -> Result<()> {
    let (keys, backing) = backing_with_keys(fixture())?;
    let user = keys.authority.user_authority();
    let plan = RecoveryPlan::new(&backing, user, schedule(), target(1))?;
    let changed = RecoveryPlan::new(&backing, user, schedule(), target(2))?;
    for attack in 0..6 {
        let binding = WalletBinding::new(&plan, user, [3; 32], [4; 32])?;
        let secrets = Zeroizing::new([random_scalar(), random_scalar()]);
        let offers = nonces(binding.commitment(), &secrets);
        let session = WalletSession::prepare(binding, &plan, &keys.wallet, user, offers)?;
        let mut response = issue(
            session.request(),
            keys.signer.additive_scalar(user)?,
            &secrets,
        )?;
        match attack {
            0 => response.request[0] ^= 1,
            1 => response.partials.swap(0, 1),
            2 => response.partials[0] = [0; 32],
            3 => response.partials[1] = [255; 32],
            4 => response.partials[1] = response.partials[0],
            _ => {}
        }
        let selected = if attack == 5 { &changed } else { &plan };
        assert!(
            session.finish(selected, &response).is_err(),
            "attack {attack}"
        );
    }
    let binding = WalletBinding::new(&plan, user, [3; 32], [4; 32])?;
    let secrets = Zeroizing::new([random_scalar(), random_scalar()]);
    let offers = nonces(binding.commitment(), &secrets);
    assert!(WalletSession::prepare(binding, &changed, &keys.wallet, user, offers).is_err());
    Ok(())
}

#[test]
fn unrelated_user_authority_is_rejected_even_with_a_matching_binding() -> Result<()> {
    let (keys, backing) = backing_with_keys(fixture())?;
    let user = keys.authority.user_authority();
    let plan = RecoveryPlan::new(&backing, user, schedule(), target(1))?;
    let unrelated = fixture();
    let wrong = unrelated.authority.user_authority();
    let binding = WalletBinding::new(&plan, wrong, [3; 32], [4; 32])?;
    let secrets = Zeroizing::new([random_scalar(), random_scalar()]);
    let offers = nonces(binding.commitment(), &secrets);
    assert!(WalletSession::prepare(binding, &plan, &unrelated.wallet, wrong, offers).is_err());
    // Salted commitments do not create a stable public lookup for a backing.
    let first = WalletBinding::new(&plan, user, [3; 32], [4; 32])?;
    let second = WalletBinding::new(&plan, user, [3; 32], [4; 32])?;
    assert_ne!(first.commitment(), second.commitment());
    Ok(())
}

#[test]
fn canonical_zero_and_equal_challenges_remain_valid_transcript_values() -> Result<()> {
    let secrets = Zeroizing::new([random_scalar(), random_scalar()]);
    let offers = nonces([7; 32], &secrets);
    let mut request = BlindRecoveryRequest {
        context: [7; 32],
        variants: std::array::from_fn(|index| BlindChallenge {
            nonce: offers[index].clone(),
            challenge: [0; 32],
        }),
    };
    request.digest()?;
    for variant in &mut request.variants {
        variant.challenge = Scalar::ONE.to_bytes().into();
    }
    request.digest()?;
    request.variants[0].challenge = [255; 32];
    assert!(request.digest().is_err());
    Ok(())
}

#[test]
fn identical_user_keys_cannot_relabel_the_authenticated_backing_domain() -> Result<()> {
    let (keys, backing) = backing_with_keys(fixture())?;
    let user = keys.authority.user_authority();
    let plan = RecoveryPlan::new(&backing, user, schedule(), target(2))?;
    let owner = Zeroizing::new(keys.wallet.additive_scalar(user)?);
    let server = Zeroizing::new(keys.signer.additive_scalar(user)?);
    for change_coin in [false, true] {
        let mut scope = keys.wallet.public().scope.clone();
        if change_coin {
            scope.coin[0] ^= 1;
        } else {
            scope.deployment[0] ^= 1;
        }
        let wallet = Share::from_scalar(scope.clone(), 1, &owner.to_bytes().into())?;
        let signer = Share::from_scalar(scope.clone(), 2, &server.to_bytes().into())?;
        let authority = Authority::new(wallet.public().clone(), signer.public().clone())?;
        assert_eq!(authority.public_key()?, user.public_key()?);
        assert!(WalletBinding::new(&plan, &authority, [3; 32], [4; 32]).is_err());
        let (opening, target) = openings(&plan)?;
        let mut context = context();
        context.coin = scope.coin;
        context.deployment = scope.deployment;
        assert!(
            WalletBinding::for_proof(&plan, &wallet, &authority, context, opening, target).is_err()
        );
    }
    Ok(())
}

#[test]
fn canonical_proof_witness_matches_both_actual_wallet_sessions_and_native_spends() -> Result<()> {
    let (keys, backing) = backing_with_keys(fixture())?;
    let user = keys.authority.user_authority();
    let plan = RecoveryPlan::new(&backing, user, schedule(), target(2))?;
    let (opening, target) = openings(&plan)?;
    let binding = WalletBinding::for_proof(&plan, &keys.wallet, user, context(), opening, target)?;
    let frozen = binding.frozen_recovery()?.clone();
    assert_ne!(frozen.nonce_commitments[0], frozen.nonce_commitments[1]);
    let secrets = Zeroizing::new([random_scalar(), random_scalar()]);
    let offers = nonces(binding.commitment(), &secrets);
    let mut session = WalletSession::prepare(binding, &plan, &keys.wallet, user, offers)?;
    let (authorization, witness) = session.take_proof_material()?;
    assert_eq!(
        authorization.encode()?.len(),
        zark_protocol::spark_recovery::ENCODED_LEN
    );
    assert_eq!(authorization.context, frozen.context);
    assert_eq!(authorization.backing, frozen.backing);
    assert_eq!(authorization.recovery, frozen.recovery);
    assert_eq!(authorization.policy, frozen.policy);
    assert_eq!(authorization.server, frozen.server);
    for index in 0..2 {
        assert_eq!(
            authorization.branches[index].challenge,
            session.request().variants[index].challenge
        );
        assert_eq!(
            authorization.branches[index].nonce_commitment,
            frozen.nonce_commitments[index]
        );
    }
    assert!(session.take_proof_material().is_err());
    let prover = Zeroizing::new(witness.prover_toml(&authorization)?);
    assert!(prover.contains("alpha_0 = ") && prover.contains("nonce_salt_1 = "));
    let response = issue(
        session.request(),
        keys.signer.additive_scalar(user)?,
        &secrets,
    )?;
    session.finish(&plan, &response)?;
    Ok(())
}

#[test]
fn prover_cannot_replace_native_refund_payout_amount_delay_policy_or_state_domain() -> Result<()> {
    let (keys, backing) = backing_with_keys(fixture())?;
    let user = keys.authority.user_authority();
    let plan = RecoveryPlan::new(&backing, user, schedule(), target(2))?;
    for attack in 0..8 {
        let (mut backing, mut target) = openings(&plan)?;
        let mut context = context();
        match attack {
            0 => backing.refunds[0].txid[0] ^= 1,
            1 => backing.refunds[1].amount += 1,
            2 => target.fee += 1,
            3 => target.delay += 1,
            4 => target.margin += 1,
            5 => target.payout = point_bytes(ProjectivePoint::GENERATOR)?,
            6 => context.deployment[0] ^= 1,
            _ => target.owner_index += 1,
        }
        assert!(
            WalletBinding::for_proof(&plan, &keys.wallet, user, context, backing, target).is_err(),
            "attack {attack}"
        );
    }
    Ok(())
}

#[test]
fn public_cas_revision_is_bound_independently_of_the_private_owner_slot() -> Result<()> {
    let (keys, backing) = backing_with_keys(fixture())?;
    let user = keys.authority.user_authority();
    let plan = RecoveryPlan::new(&backing, user, schedule(), target(2))?;
    let (opening, target) = openings(&plan)?;
    assert_eq!(target.owner_index, 2);
    let mut context = context();
    context.revision = 19;
    let binding =
        WalletBinding::for_proof(&plan, &keys.wallet, user, context.clone(), opening, target)?;
    let secrets = Zeroizing::new([random_scalar(), random_scalar()]);
    let offers = nonces(binding.commitment(), &secrets);
    let mut session = WalletSession::prepare(binding, &plan, &keys.wallet, user, offers)?;
    let (authorization, witness) = session.take_proof_material()?;
    assert_eq!(authorization.context.revision, 19);
    assert_eq!(witness.target.owner_index, 2);
    assert_eq!(witness.target.delay, plan.delay_blocks());
    let (opening, target) = openings(&plan)?;
    context.revision += 1;
    let changed = WalletBinding::for_proof(&plan, &keys.wallet, user, context, opening, target)?;
    // The native recovery stays the same while its protocol state binding moves.
    assert_eq!(changed.frozen_recovery()?.backing, authorization.backing);
    assert_ne!(changed.frozen_recovery()?.recovery, authorization.recovery);
    let response = issue(
        session.request(),
        keys.signer.additive_scalar(user)?,
        &secrets,
    )?;
    session.finish(&plan, &response)?;
    Ok(())
}

/// Explicit prover input export only: private witness files stay under ignored
/// work/ and are not a claim that a Spark proof was generated or verified.
#[test]
#[ignore = "exports private wallet witness for the separately invoked pinned prover"]
fn export_native_blind_recovery_proof_fixture() -> Result<()> {
    use std::{fs, os::unix::fs::DirBuilderExt, path::Path};
    let (keys, backing) = backing_with_keys(fixture())?;
    let user = keys.authority.user_authority();
    let plan = RecoveryPlan::new(&backing, user, schedule(), target(2))?;
    let (opening, target) = openings(&plan)?;
    let binding = WalletBinding::for_proof(&plan, &keys.wallet, user, context(), opening, target)?;
    let secrets = Zeroizing::new([random_scalar(), random_scalar()]);
    let offers = nonces(binding.commitment(), &secrets);
    let mut session = WalletSession::prepare(binding, &plan, &keys.wallet, user, offers)?;
    let (authorization, witness) = session.take_proof_material()?;
    let parent = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../work/zark-spark/private-recovery-proof-input");
    fs::create_dir_all(&parent)?;
    let root = parent.join(hex::encode(random32()));
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    let prover = Zeroizing::new(witness.prover_toml(&authorization)?);
    zark_protocol::storage::atomic_write(&root.join("Prover.toml"), prover.as_bytes())?;
    zark_protocol::storage::atomic_write(&root.join("statement.bin"), &authorization.encode()?)?;
    println!("Private Spark recovery prover fixture: {}", root.display());
    Ok(())
}
