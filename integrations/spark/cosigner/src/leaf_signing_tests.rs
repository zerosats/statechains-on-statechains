use super::{LeafAuthority, Nonce, OperatorCommitments, package};
use crate::keys::{Authority, Purpose, Scope, Share};
use bitcoin::{
    key::TapTweak,
    secp256k1::{Secp256k1, XOnlyPublicKey, schnorr::Signature},
};
use frost_core::two_group::{self, SignerGroup};
use frost_secp256k1_tr::{
    self as frost,
    keys::{EvenY, Tweak},
};
use k256::{ProjectivePoint, Scalar, elliptic_curve::sec1::ToEncodedPoint};
use rand::rngs::OsRng;
use std::collections::BTreeMap;

struct Fixture {
    wallet: Share,
    signer: Share,
    authority: LeafAuthority,
    operators: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    operator_public: frost::keys::PublicKeyPackage,
}

fn fixture() -> Fixture {
    let scope = Scope {
        deployment: [1; 32],
        coin: [2; 32],
        purpose: Purpose::LeafSigning,
    };
    let wallet = Share::generate(scope.clone(), 1).unwrap();
    let signer = Share::generate(scope, 2).unwrap();
    let user = Authority::new(wallet.public().clone(), signer.public().clone()).unwrap();
    // Only the synthetic Spark operator group uses a test dealer. The wallet
    // and Zark signer generate independent secrets; no user dealer exists.
    let (operator_shares, operator_public) =
        frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, OsRng)
            .unwrap();
    let operator_key = operator_public.verifying_key().serialize().unwrap();
    let user_point = k256::PublicKey::from_sec1_bytes(&user.public_key().unwrap()).unwrap();
    let combined = user_point.to_projective() + operator_public.verifying_key().to_element();
    let authority = LeafAuthority::new(
        user,
        &operator_key,
        combined.to_affine().to_encoded_point(true).as_bytes(),
    )
    .unwrap();
    Fixture {
        wallet,
        signer,
        authority,
        operators: operator_shares
            .into_iter()
            .map(|(id, share)| (id, frost::keys::KeyPackage::try_from(share).unwrap()))
            .collect(),
        operator_public,
    }
}

// Exact translation of pinned spark-frost/src/signing.rs
// frost_key_package_from_proto(role=USER). This intentionally constructs the
// raw package independently of LeafAuthority::participant_package.
fn reference_user_package(share: &Share, authority: &LeafAuthority) -> frost::keys::KeyPackage {
    let position = share.public().position;
    let additive = share.additive_scalar(&authority.user).unwrap();
    let shamir = if position == 1 {
        additive * Scalar::from(2u64).invert().unwrap()
    } else {
        -additive
    };
    let signing = frost::keys::SigningShare::new(shamir);
    let raw = frost::keys::KeyPackage::new(
        frost::Identifier::try_from(position).unwrap(),
        signing,
        frost::keys::VerifyingShare::new(ProjectivePoint::GENERATOR * shamir),
        authority.combined,
        2,
    );
    let tweaked = raw.clone().tweak(Some(&[] as &[u8]));
    let even = raw.into_even_y(Some(authority.combined.has_even_y()));
    frost::keys::KeyPackage::new(
        *even.identifier(),
        *even.signing_share(),
        *even.verifying_share(),
        *tweaked.verifying_key(),
        2,
    )
}

#[test]
fn independent_user_bridge_matches_pinned_spark_and_bitcoin_for_key_parities() {
    let mut covered = [false; 4];
    let mut user_parity_differs = false;
    for _ in 0..128 {
        let fixture = fixture();
        let authority = &fixture.authority;
        let combined_parity = usize::from(!authority.combined.has_even_y());
        let output_parity = usize::from(!authority.output.has_even_y());
        user_parity_differs |=
            (authority.user.public_key().unwrap()[0] == 2) != authority.combined.has_even_y();
        covered[2 * combined_parity + output_parity] = true;
        let wallet_nonce = Nonce::prepare(&fixture.wallet, authority).unwrap();
        let signer_nonce = Nonce::prepare(&fixture.signer, authority).unwrap();
        let user_bytes = [
            wallet_nonce.commitment().unwrap(),
            signer_nonce.commitment().unwrap(),
        ];
        let mut operator_nonces = BTreeMap::new();
        let mut commitments = OperatorCommitments::new();
        for (id, key) in fixture.operators.iter().take(2) {
            let (nonce, commitment) = frost::round1::commit(key.signing_share(), &mut OsRng);
            operator_nonces.insert(*id, nonce);
            commitments.insert(*id, commitment);
        }
        // The same identifiers 1,2 occur in BOTH groups, as in pinned Spark.
        let message = [42; 32];
        let transcript = package(
            message,
            commitments.clone(),
            [&user_bytes[0], &user_bytes[1]],
        )
        .unwrap();
        let expected = two_group::sign(
            &transcript,
            &wallet_nonce.inner,
            &reference_user_package(&fixture.wallet, authority),
            SignerGroup::Secondary,
        )
        .unwrap();
        let first = wallet_nonce
            .sign(
                &fixture.wallet,
                authority,
                message,
                commitments.clone(),
                [&user_bytes[0], &user_bytes[1]],
            )
            .unwrap();
        assert_eq!(first, expected.serialize());
        let second = signer_nonce
            .sign(
                &fixture.signer,
                authority,
                message,
                commitments.clone(),
                [&user_bytes[0], &user_bytes[1]],
            )
            .unwrap();
        super::verify_user_partials(
            authority,
            message,
            commitments.clone(),
            [&user_bytes[0], &user_bytes[1]],
            [&first, &second],
        )
        .unwrap();
        for (partials, signed_message) in [
            ([vec![0; 32], second.clone()], message),
            ([first.clone(), vec![0; 32]], message),
            ([first.clone(), second.clone()], [43; 32]),
        ] {
            assert!(
                super::verify_user_partials(
                    authority,
                    signed_message,
                    commitments.clone(),
                    [&user_bytes[0], &user_bytes[1]],
                    [&partials[0], &partials[1]]
                )
                .is_err()
            );
        }
        assert!(
            super::verify_user_partials(
                authority,
                message,
                commitments.clone(),
                [&user_bytes[1], &user_bytes[0]],
                [&first, &second]
            )
            .is_err()
        );
        let mut changed_operators = commitments.clone();
        changed_operators.pop_first();
        assert!(
            super::verify_user_partials(
                authority,
                message,
                changed_operators,
                [&user_bytes[0], &user_bytes[1]],
                [&first, &second]
            )
            .is_err()
        );
        let user_shares = BTreeMap::from([
            (
                frost::Identifier::try_from(1u16).unwrap(),
                frost::round2::SignatureShare::deserialize(&first).unwrap(),
            ),
            (
                frost::Identifier::try_from(2u16).unwrap(),
                frost::round2::SignatureShare::deserialize(&second).unwrap(),
            ),
        ]);
        let mut operator_shares = BTreeMap::new();
        for (id, nonce) in operator_nonces {
            let raw = &fixture.operators[&id];
            let combined = frost::keys::KeyPackage::new(
                id,
                *raw.signing_share(),
                *raw.verifying_share(),
                authority.combined,
                2,
            )
            .tweak(Some(&[] as &[u8]));
            operator_shares.insert(
                id,
                two_group::sign(&transcript, &nonce, &combined, SignerGroup::Primary).unwrap(),
            );
        }
        let public = frost::keys::PublicKeyPackage::new(
            fixture.operator_public.verifying_shares().clone(),
            authority.combined,
            Some(2),
        )
        .tweak(Some(&[] as &[u8]));
        let signature =
            two_group::aggregate(&transcript, &operator_shares, &user_shares, &public).unwrap();
        let combined_xonly =
            XOnlyPublicKey::from_slice(&authority.combined_key().unwrap()[1..]).unwrap();
        let bitcoin_output = combined_xonly
            .tap_tweak(&Secp256k1::verification_only(), None)
            .0
            .to_x_only_public_key();
        assert_eq!(
            bitcoin_output.serialize().as_slice(),
            &authority.output_key().unwrap()[1..]
        );
        Secp256k1::verification_only()
            .verify_schnorr(
                &Signature::from_slice(&signature.serialize().unwrap()).unwrap(),
                &bitcoin::secp256k1::Message::from_digest(message),
                &bitcoin_output,
            )
            .unwrap();
        if covered == [true; 4] && user_parity_differs {
            return;
        }
    }
    panic!("did not cover combined/tweaked key parity branches");
}

#[test]
fn leaf_key_binding_and_wrong_purpose_reject_substitution() {
    let fixture = fixture();
    let authority = fixture.authority;
    assert!(LeafAuthority::new(authority.user.clone(), &authority.operator_key, &[2; 33]).is_err());
    assert!(
        LeafAuthority::new(
            authority.user.clone(),
            &[0; 33],
            &authority.combined_key().unwrap()
        )
        .is_err()
    );
    let scope = Scope {
        deployment: [1; 32],
        coin: [2; 32],
        purpose: Purpose::Identity,
    };
    let first = Share::generate(scope.clone(), 1).unwrap();
    let second = Share::generate(scope, 2).unwrap();
    let identity = Authority::new(first.public().clone(), second.public().clone()).unwrap();
    assert!(
        LeafAuthority::new(
            identity,
            &authority.operator_key,
            &authority.combined_key().unwrap()
        )
        .is_err()
    );
}

#[test]
fn nonce_rejects_changed_authority_empty_operator_group_and_own_commitment_swap() {
    let fixture = fixture();
    let authority = &fixture.authority;
    let nonce = Nonce::prepare(&fixture.wallet, authority).unwrap();
    let signer_nonce = Nonce::prepare(&fixture.signer, authority).unwrap();
    let users = [
        nonce.commitment().unwrap(),
        signer_nonce.commitment().unwrap(),
    ];
    assert!(
        nonce
            .sign(
                &fixture.wallet,
                authority,
                [1; 32],
                BTreeMap::new(),
                [&users[0], &users[1]]
            )
            .is_err()
    );
    // Each rejected call consumes the nonce; a new preparation is mandatory.
    let nonce = Nonce::prepare(&fixture.wallet, authority).unwrap();
    let mut operators = OperatorCommitments::new();
    let (id, key) = fixture.operators.iter().next().unwrap();
    let (_, commitment) = frost::round1::commit(key.signing_share(), &mut OsRng);
    operators.insert(*id, commitment);
    assert!(
        nonce
            .sign(
                &fixture.wallet,
                authority,
                [1; 32],
                operators.clone(),
                [&users[1], &users[1]]
            )
            .is_err()
    );
    let nonce = Nonce::prepare(&fixture.wallet, authority).unwrap();
    let other = self::fixture();
    assert!(
        nonce
            .sign(
                &fixture.wallet,
                &other.authority,
                [1; 32],
                operators,
                [&users[0], &users[1]]
            )
            .is_err()
    );
}
