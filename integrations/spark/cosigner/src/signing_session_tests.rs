use super::{MAX_PRIVATE_NONCE_BYTES, check_public, decode, encode, identity_binding};
use crate::{
    keys::{Authority, Purpose, Scope, Share},
    leaf_signing, legacy_signing, signing,
};
use frost_secp256k1_tr as frost;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rand::rngs::OsRng;
use std::collections::BTreeMap;

fn pair(purpose: Purpose) -> (Share, Share, Authority) {
    let scope = Scope {
        deployment: [1; 32],
        coin: [2; 32],
        purpose,
    };
    let first = Share::generate(scope.clone(), 1).unwrap();
    let second = Share::generate(scope, 2).unwrap();
    let authority = Authority::new(first.public().clone(), second.public().clone()).unwrap();
    (first, second, authority)
}

fn leaf() -> (
    Share,
    Share,
    leaf_signing::LeafAuthority,
    frost::keys::SigningShare,
) {
    let (first, second, user) = pair(Purpose::LeafSigning);
    let operator = frost::SigningKey::new(&mut OsRng);
    let operator_key = frost::VerifyingKey::from(&operator);
    let combined = operator_key.to_element()
        + k256::PublicKey::from_sec1_bytes(&user.public_key().unwrap())
            .unwrap()
            .to_projective();
    let authority = leaf_signing::LeafAuthority::new(
        user,
        &operator_key.serialize().unwrap(),
        combined.to_affine().to_encoded_point(true).as_bytes(),
    )
    .unwrap();
    (
        first,
        second,
        authority,
        frost::keys::SigningShare::deserialize(&operator.serialize()).unwrap(),
    )
}

fn session() -> legacy_signing::Session {
    legacy_signing::Session {
        operation: [4; 32],
        sighash: [5; 32],
    }
}

#[test]
fn identity_reopen_recomputes_identical_exact_request_response() {
    let (first, second, authority) = pair(Purpose::Identity);
    let nonce = signing::Nonce::prepare(&first, &authority).unwrap();
    let bytes = nonce.encode_private().unwrap();
    let restored = signing::Nonce::decode_private(&bytes, &first, &authority).unwrap();
    assert_eq!(*restored.encode_private().unwrap(), *bytes);
    let peer = signing::Nonce::prepare(&second, &authority).unwrap();
    let commitments = [nonce.commitment().unwrap(), peer.commitment().unwrap()];
    let message = [7; 32];
    let response = nonce
        .sign(
            &first,
            &authority,
            message,
            [&commitments[0], &commitments[1]],
        )
        .unwrap();
    let recovered = restored
        .sign(
            &first,
            &authority,
            message,
            [&commitments[0], &commitments[1]],
        )
        .unwrap();
    assert_eq!(response, recovered);
    let peer_response = peer
        .sign(
            &second,
            &authority,
            message,
            [&commitments[0], &commitments[1]],
        )
        .unwrap();
    signing::aggregate(
        &authority,
        message,
        [&commitments[0], &commitments[1]],
        [&recovered, &peer_response],
    )
    .unwrap();
    assert!(signing::Nonce::decode_private(&bytes, &second, &authority).is_err());
    let (_, _, other) = pair(Purpose::Identity);
    assert!(signing::Nonce::decode_private(&bytes, &first, &other).is_err());
}

#[test]
fn nested_reopen_preserves_commitments_and_exact_response() {
    let (first, second, authority, operator) = leaf();
    let nonce = leaf_signing::Nonce::prepare(&first, &authority).unwrap();
    let bytes = nonce.encode_private().unwrap();
    let restored = leaf_signing::Nonce::decode_private(&bytes, &first, &authority).unwrap();
    assert_eq!(*restored.encode_private().unwrap(), *bytes);
    let peer = leaf_signing::Nonce::prepare(&second, &authority).unwrap();
    let users = [nonce.commitment().unwrap(), peer.commitment().unwrap()];
    let (_, commitment) = frost::round1::commit(&operator, &mut OsRng);
    let operators = BTreeMap::from([(frost::Identifier::try_from(1u16).unwrap(), commitment)]);
    assert_eq!(
        nonce
            .sign(
                &first,
                &authority,
                [7; 32],
                operators.clone(),
                [&users[0], &users[1]]
            )
            .unwrap(),
        restored
            .sign(
                &first,
                &authority,
                [7; 32],
                operators,
                [&users[0], &users[1]]
            )
            .unwrap()
    );
    assert!(leaf_signing::Nonce::decode_private(&bytes, &second, &authority).is_err());
    let (_, _, other, _) = leaf();
    assert!(leaf_signing::Nonce::decode_private(&bytes, &first, &other).is_err());
}

#[test]
fn legacy_prepared_and_revealed_reopen_preserve_frozen_round() {
    let (first, second, authority, operator) = leaf();
    let nonce = legacy_signing::Nonce::prepare(&first, &authority, session()).unwrap();
    let peer = legacy_signing::Nonce::prepare(&second, &authority, session()).unwrap();
    let prepared_bytes = nonce.encode_private().unwrap();
    let restored =
        legacy_signing::Nonce::decode_private(&prepared_bytes, &first, &authority, session())
            .unwrap();
    assert_eq!(*restored.encode_private().unwrap(), *prepared_bytes);
    let commitments = [nonce.commitment().clone(), peer.commitment().clone()];
    let nonce = nonce.reveal(commitments.clone()).unwrap();
    let restored = restored.reveal(commitments.clone()).unwrap();
    assert_eq!(nonce.public(), restored.public());
    let revealed_bytes = nonce.encode_private().unwrap();
    let reopened = legacy_signing::RevealedNonce::decode_private(
        &revealed_bytes,
        &first,
        &authority,
        session(),
    )
    .unwrap();
    assert_eq!(*reopened.encode_private().unwrap(), *revealed_bytes);
    let peer = peer.reveal(commitments.clone()).unwrap();
    let reveals = [nonce.public().clone(), peer.public().clone()];
    let (_, commitment) = frost::round1::commit(&operator, &mut OsRng);
    let operators = BTreeMap::from([(frost::Identifier::try_from(1u16).unwrap(), commitment)]);
    let transcript =
        legacy_signing::Transcript::new(&authority, session(), commitments, reveals, operators)
            .unwrap();
    let original = nonce.sign(&first, &authority, &transcript).unwrap();
    for recovered in [restored, reopened] {
        let response = recovered.sign(&first, &authority, &transcript).unwrap();
        assert_eq!(response.response, original.response);
        assert_eq!(response.transcript, original.transcript);
    }
    assert!(
        legacy_signing::Nonce::decode_private(&revealed_bytes, &first, &authority, session())
            .is_err()
    );
    assert!(
        legacy_signing::RevealedNonce::decode_private(
            &prepared_bytes,
            &first,
            &authority,
            session()
        )
        .is_err()
    );
    let mut changed = session();
    changed.sighash[0] ^= 1;
    assert!(
        legacy_signing::Nonce::decode_private(&prepared_bytes, &first, &authority, changed)
            .is_err()
    );
    changed = session();
    changed.operation[0] ^= 1;
    assert!(
        legacy_signing::RevealedNonce::decode_private(&revealed_bytes, &first, &authority, changed)
            .is_err()
    );
}

#[test]
fn private_nonce_codecs_reject_noncanonical_corrupt_oversized_and_wrong_kind_records() {
    let (first, _, authority) = pair(Purpose::Identity);
    let nonce = signing::Nonce::prepare(&first, &authority).unwrap();
    let bytes = nonce.encode_private().unwrap();
    let mut whitespace = bytes.to_vec();
    whitespace.push(b' ');
    assert!(signing::Nonce::decode_private(&whitespace, &first, &authority).is_err());
    assert!(
        signing::Nonce::decode_private(&vec![0; MAX_PRIVATE_NONCE_BYTES + 1], &first, &authority)
            .is_err()
    );
    let mut record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    record["nonce"][0] = serde_json::json!(255);
    let corrupted = serde_json::to_vec(&record).unwrap();
    assert!(signing::Nonce::decode_private(&corrupted, &first, &authority).is_err());
    assert!(
        decode(
            &bytes,
            "nested-leaf",
            1,
            identity_binding(&authority).unwrap()
        )
        .is_err()
    );
}

#[test]
fn decoded_frost_cache_and_separate_public_commitment_must_match_secrets() {
    let (first, _, authority) = pair(Purpose::Identity);
    let package = first.package(&authority).unwrap();
    let (inner, commitment) = frost::round1::commit(package.signing_share(), &mut OsRng);
    let (other, other_commitment) = frost::round1::commit(package.signing_share(), &mut OsRng);
    let binding = identity_binding(&authority).unwrap();
    let bytes = encode(
        "identity",
        1,
        binding,
        &inner,
        &other_commitment.serialize().unwrap(),
    )
    .unwrap();
    assert!(signing::Nonce::decode_private(&bytes, &first, &authority).is_err());
    assert!(check_public(&other, &commitment.serialize().unwrap()).is_err());
    // Replace a cached commitment inside FROST's JSON representation while
    // preserving its secret nonce scalars; the canonical envelope stays valid.
    let mut cached = serde_json::to_value(&inner).unwrap();
    let different = serde_json::to_value(&other).unwrap();
    cached["commitments"] = different["commitments"].clone();
    let inconsistent: frost::round1::SigningNonces = serde_json::from_value(cached).unwrap();
    let bytes = encode(
        "identity",
        1,
        binding,
        &inconsistent,
        &commitment.serialize().unwrap(),
    )
    .unwrap();
    assert!(decode(&bytes, "identity", 1, binding).is_err());
}
