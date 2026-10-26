use super::{
    Commitment, Nonce, Reveal, Session, Transcript, aggregate_commitment, commitment_points,
    reveal_hash, session_binding,
};
use crate::{
    keys::{Authority, Purpose, Scope, Share},
    leaf_signing::{LeafAuthority, OperatorCommitments},
};
use bitcoin::{
    key::TapTweak,
    secp256k1::{Secp256k1, XOnlyPublicKey, schnorr::Signature},
};
use frost_secp256k1_tr::{self as frost, keys::EvenY};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rand::rngs::OsRng;
use std::collections::BTreeMap;

pub(crate) struct Fixture {
    pub wallet: Share,
    pub signer: Share,
    pub authority: LeafAuthority,
    pub operators: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    pub public: frost::keys::PublicKeyPackage,
}

pub(crate) fn fixture() -> Fixture {
    let scope = Scope {
        deployment: [1; 32],
        coin: [2; 32],
        purpose: Purpose::LeafSigning,
    };
    let wallet = Share::generate(scope.clone(), 1).unwrap();
    let signer = Share::generate(scope, 2).unwrap();
    let user = Authority::new(wallet.public().clone(), signer.public().clone()).unwrap();
    let (shares, public) =
        frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, OsRng)
            .unwrap();
    let combined = public.verifying_key().to_element()
        + k256::PublicKey::from_sec1_bytes(&user.public_key().unwrap())
            .unwrap()
            .to_projective();
    let authority = LeafAuthority::new(
        user,
        &public.verifying_key().serialize().unwrap(),
        combined.to_affine().to_encoded_point(true).as_bytes(),
    )
    .unwrap();
    Fixture {
        wallet,
        signer,
        authority,
        operators: shares
            .into_iter()
            .map(|(id, share)| (id, frost::keys::KeyPackage::try_from(share).unwrap()))
            .collect(),
        public,
    }
}

fn session() -> Session {
    Session {
        operation: [4; 32],
        sighash: [42; 32],
    }
}

fn reveal_pair(
    fixture: &Fixture,
) -> (
    super::RevealedNonce,
    super::RevealedNonce,
    [Commitment; 2],
    [Reveal; 2],
) {
    let first = Nonce::prepare(&fixture.wallet, &fixture.authority, session()).unwrap();
    let second = Nonce::prepare(&fixture.signer, &fixture.authority, session()).unwrap();
    let commitments = [first.commitment().clone(), second.commitment().clone()];
    let first = first.reveal(commitments.clone()).unwrap();
    let second = second.reveal(commitments.clone()).unwrap();
    let reveals = [first.public().clone(), second.public().clone()];
    (first, second, commitments, reveals)
}

pub(crate) fn operator_round(
    fixture: &Fixture,
) -> (
    BTreeMap<frost::Identifier, frost::round1::SigningNonces>,
    OperatorCommitments,
) {
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for (id, key) in fixture.operators.iter().take(2) {
        let (nonce, commitment) = frost::round1::commit(key.signing_share(), &mut OsRng);
        nonces.insert(*id, nonce);
        commitments.insert(*id, commitment);
    }
    (nonces, commitments)
}

#[test]
fn collapsed_additive_user_combines_with_pinned_legacy_operator_frost() {
    let mut covered = [false; 8];
    for _ in 0..256 {
        let fixture = fixture();
        let authority = &fixture.authority;
        let (first, second, commitments, reveals) = reveal_pair(&fixture);
        let aggregate_nonce =
            aggregate_commitment(authority, session(), &commitments, &reveals).unwrap();
        let (operator_nonces, operator_commitments) = operator_round(&fixture);
        let transcript = Transcript::new(
            authority,
            session(),
            commitments,
            reveals,
            operator_commitments,
        )
        .unwrap();
        let first = first.sign(&fixture.wallet, authority, &transcript).unwrap();
        let second = second
            .sign(&fixture.signer, authority, &transcript)
            .unwrap();
        let user = transcript.aggregate(authority, [&first, &second]).unwrap();
        assert_eq!(user.nonce_commitment, aggregate_nonce);
        let user_id = frost::Identifier::derive(b"user").unwrap();
        let mut shares = BTreeMap::from([(
            user_id,
            frost::round2::SignatureShare::deserialize(&user.signature_share).unwrap(),
        )]);
        let combined =
            frost::VerifyingKey::deserialize(&authority.combined_key().unwrap()).unwrap();
        // Exact pinned Spark STATECHAIN path: ordinary participants-groups
        // SigningPackage and sign_with_tweak, with no nested MPC scheme.
        for (id, nonce) in operator_nonces {
            let raw = &fixture.operators[&id];
            let key = frost::keys::KeyPackage::new(
                id,
                *raw.signing_share(),
                *raw.verifying_share(),
                combined,
                2,
            );
            shares.insert(
                id,
                frost::round2::sign_with_tweak(
                    transcript.signing_package(),
                    &nonce,
                    &key,
                    Some(&[]),
                )
                .unwrap(),
            );
        }
        let mut public_shares = fixture.public.verifying_shares().clone();
        public_shares.insert(
            user_id,
            frost::keys::VerifyingShare::deserialize(
                &authority.user_authority().public_key().unwrap(),
            )
            .unwrap(),
        );
        let public = frost::keys::PublicKeyPackage::new(public_shares, combined, None);
        let signature =
            frost::aggregate_with_tweak(transcript.signing_package(), &shares, &public, Some(&[]))
                .unwrap();
        let output = XOnlyPublicKey::from_slice(&authority.combined_key().unwrap()[1..])
            .unwrap()
            .tap_tweak(&Secp256k1::verification_only(), None)
            .0
            .to_x_only_public_key();
        Secp256k1::verification_only()
            .verify_schnorr(
                &Signature::from_slice(&signature.serialize().unwrap()).unwrap(),
                &bitcoin::secp256k1::Message::from_digest(session().sighash),
                &output,
            )
            .unwrap();
        let output_parity = usize::from(authority.output_key().unwrap()[0] == 3);
        covered[4 * usize::from(!combined.has_even_y())
            + 2 * output_parity
            + usize::from(transcript.negate_nonce)] = true;
        // Each participant is verified BEFORE the public responses are summed.
        let mut forged = first.clone();
        forged.response = [0; 32];
        assert!(transcript.aggregate(authority, [&forged, &second]).is_err());
        assert!(transcript.aggregate(authority, [&second, &first]).is_err());
        assert!(transcript.aggregate(authority, [&first, &first]).is_err());
        if covered == [true; 8] {
            return;
        }
    }
    panic!("did not cover legacy key/output/global-nonce parity branches");
}

#[test]
fn nonce_commit_reveal_rejects_role_and_opening_changes() {
    let fixture = fixture();
    let first = Nonce::prepare(&fixture.wallet, &fixture.authority, session()).unwrap();
    let second = Nonce::prepare(&fixture.signer, &fixture.authority, session()).unwrap();
    let mut commitments = [first.commitment().clone(), second.commitment().clone()];
    commitments[0].digest[0] ^= 1;
    assert!(first.reveal(commitments).is_err());
    let (_, _, commitments, mut reveals) = reveal_pair(&fixture);
    reveals[1].salt[0] ^= 1;
    assert!(aggregate_commitment(&fixture.authority, session(), &commitments, &reveals).is_err());
    let (_, _, mut commitments, reveals) = reveal_pair(&fixture);
    commitments.swap(0, 1);
    assert!(aggregate_commitment(&fixture.authority, session(), &commitments, &reveals).is_err());
}

#[test]
fn exact_authority_operation_sighash_operator_and_response_bindings() {
    let fixture = fixture();
    let (first, second, commitments, reveals) = reveal_pair(&fixture);
    let (_, operators) = operator_round(&fixture);
    let transcript = Transcript::new(
        &fixture.authority,
        session(),
        commitments.clone(),
        reveals.clone(),
        operators,
    )
    .unwrap();
    let first = first
        .sign(&fixture.wallet, &fixture.authority, &transcript)
        .unwrap();
    let second = second
        .sign(&fixture.signer, &fixture.authority, &transcript)
        .unwrap();
    let (_, altered_operators) = operator_round(&fixture);
    let altered = Transcript::new(
        &fixture.authority,
        session(),
        commitments.clone(),
        reveals.clone(),
        altered_operators,
    )
    .unwrap();
    assert!(
        altered
            .aggregate(&fixture.authority, [&first, &second])
            .is_err()
    );
    let other = self::fixture();
    assert!(
        transcript
            .aggregate(&other.authority, [&first, &second])
            .is_err()
    );
    let mut changed = session();
    changed.operation[0] ^= 1;
    assert!(aggregate_commitment(&fixture.authority, changed, &commitments, &reveals).is_err());
    changed = session();
    changed.sighash[0] ^= 1;
    assert!(aggregate_commitment(&fixture.authority, changed, &commitments, &reveals).is_err());
    let (nonce, _, _, _) = reveal_pair(&fixture);
    assert!(
        nonce
            .sign(&fixture.wallet, &other.authority, &transcript)
            .is_err()
    );
    let mut forged = first;
    forged.response = [255; 32];
    assert!(
        transcript
            .aggregate(&fixture.authority, [&forged, &second])
            .is_err()
    );
}

#[test]
fn malicious_nonce_pair_cancellation_is_rejected() {
    let fixture = fixture();
    let (first, _, mut commitments, mut reveals) = reveal_pair(&fixture);
    let parsed =
        frost::round1::SigningCommitments::deserialize(&first.public().nonce_commitment).unwrap();
    let (d, e) = commitment_points(&parsed).unwrap();
    let cancel = frost::round1::SigningCommitments::new(
        frost_core::round1::NonceCommitment::deserialize(
            (-d).to_affine().to_encoded_point(true).as_bytes(),
        )
        .unwrap(),
        frost_core::round1::NonceCommitment::deserialize(
            (-e).to_affine().to_encoded_point(true).as_bytes(),
        )
        .unwrap(),
    );
    reveals[1].nonce_commitment = cancel.serialize().unwrap();
    commitments[1].digest = reveal_hash(
        session_binding(&fixture.authority, session()).unwrap(),
        &reveals[1],
    );
    assert!(aggregate_commitment(&fixture.authority, session(), &commitments, &reveals).is_err());
}
