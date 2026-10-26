//! Exercise the production blind-response primitive, not a copied equation.
//! This does not exercise Engine proof admission or its durable workflow.
use super::*;
use crate::{
    initial_exit::NativeLeafKeys,
    keys::{Purpose, Scope},
};
use bitcoin::{
    key::TapTweak,
    secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature},
};
use rand::rngs::OsRng;
use std::collections::BTreeMap;

// Compile the actual private production primitive as a test-only module. Keep
// it private in zark-signer: exposing it as an API would bypass proof admission.
#[path = "../../../../../../crates/signer/src/engine/blind_issuance.rs"]
mod production_blind_issuance;

struct Fixture {
    key: CurrentUserKey,
    server: Digest,
    operators: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public: frost::keys::PublicKeyPackage,
}

fn fixture() -> Result<Fixture> {
    let wallet = random_scalar();
    let server = random_scalar();
    let user = ProjectivePoint::GENERATOR * wallet + ProjectivePoint::GENERATOR * server;
    let (shares, public) =
        frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, OsRng)?;
    let combined = public.verifying_key().to_element() + user;
    let native = NativeLeafKeys::new(
        Scope {
            deployment: [1; 32],
            coin: [2; 32],
            purpose: Purpose::LeafSigning,
        },
        &compressed(user)?,
        &public.verifying_key().serialize()?,
        &compressed(combined)?,
    )?;
    let key = CurrentUserKey::new(
        native,
        point_bytes(ProjectivePoint::GENERATOR * server)?,
        wallet.to_bytes().into(),
    )?;
    Ok(Fixture {
        key,
        server: server.to_bytes().into(),
        public,
        operators: shares
            .into_iter()
            .map(|(id, share)| Ok((id, frost::keys::KeyPackage::try_from(share)?)))
            .collect::<Result<_>>()?,
    })
}

fn issue(
    server: &Digest,
    nonce: &mut Option<Digest>,
    request: &SingleUserRequest,
) -> Result<Digest> {
    let point = point_bytes(request.original)?;
    let [response] = production_blind_issuance::issue(
        server,
        [nonce],
        [production_blind_issuance::FrozenResponse {
            nonce_point: &point,
            nonce_commitment: &request.blinding_commitment(),
            blinded_challenge: &request.blinded_challenge(),
        }],
    )?;
    Ok(response)
}

#[test]
fn production_blind_response_composes_one_user_for_all_parities() -> Result<()> {
    assert_eq!(
        frost::Identifier::derive(b"user")?.serialize().as_slice(),
        zark_protocol::spark_single_user::USER_IDENTIFIER
    );
    let mut covered = [false; 8];
    for _ in 0..256 {
        let f = fixture()?;
        let context = zark_protocol::spark_native::ExitContext {
            deployment: [1; 32],
            coin: [2; 32],
            current_state: [3; 32],
            operation: [4; 32],
            session: k256::schnorr::SigningKey::from_bytes(&[8; 32])?
                .verifying_key()
                .to_bytes()
                .into(),
            revision: 17,
        };
        let opening = zark_protocol::spark_single_user::Opening {
            alpha: random_scalar().to_bytes().into(),
            beta: random_scalar().to_bytes().into(),
            binding: random_scalar().to_bytes().into(),
            salt: random32(),
        };
        let precommit = SingleUserPrecommit::from_opening(&f.key, &context, &[9; 32], &opening)?;
        let frozen = precommit.commitment();
        let mut server_nonce: Option<Digest> = Some(random_scalar().to_bytes().into());
        let original = point_bytes(ProjectivePoint::GENERATOR * scalar(&server_nonce.unwrap())?)?;
        let user_nonce = precommit.attach(&f.key, &original)?;
        let user_commitment = user_nonce.commitment();
        let mut nonces = BTreeMap::new();
        let mut commitments = OperatorCommitments::new();
        for (id, key) in f.operators.iter().take(2) {
            let (nonce, public) = frost::round1::commit(key.signing_share(), &mut OsRng);
            nonces.insert(*id, nonce);
            commitments.insert(*id, public);
        }
        let message = [42; 32];
        let request = user_nonce.bind(&f.key, message, commitments.clone())?;
        assert_eq!(request.blinding_commitment(), frozen);
        let operators = commitments
            .iter()
            .map(|(id, c)| {
                Ok(zark_protocol::spark_native::Participant {
                    identifier: id.serialize().as_slice().try_into()?,
                    hiding: point_bytes(
                        k256::PublicKey::from_sec1_bytes(&c.hiding().serialize()?)?.to_projective(),
                    )?,
                    binding: point_bytes(
                        k256::PublicKey::from_sec1_bytes(&c.binding().serialize()?)?
                            .to_projective(),
                    )?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(
            request.blinded_challenge(),
            zark_protocol::spark_single_user::blinded_challenge(
                f.key.server_point()?,
                original,
                point_bytes(
                    k256::PublicKey::from_sec1_bytes(f.key.native_keys().combined_key())?
                        .to_projective()
                )?,
                message,
                &opening,
                &operators
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("test quorum"))?
            )?
        );
        let branch = 4 * usize::from(f.key.native_keys().combined_key()[0] == 3)
            + 2 * usize::from(f.key.output_key()?[0] == 3)
            + usize::from(request.nonce_sign == -Scalar::ONE);
        covered[branch] = true;
        let response = issue(&f.server, &mut server_nonce, &request)?;
        assert!(server_nonce.is_none());
        assert!(issue(&f.server, &mut server_nonce, &request).is_err());
        let contribution = request.complete(response)?;
        assert_eq!(contribution.commitment, user_commitment);
        let package = independent_package(message, &commitments, user_commitment)?;
        let combined = frost::VerifyingKey::deserialize(f.key.native_keys().combined_key())?;
        let mut partials = BTreeMap::new();
        for (id, nonce) in &nonces {
            let raw = &f.operators[id];
            let key = frost::keys::KeyPackage::new(
                *id,
                *raw.signing_share(),
                *raw.verifying_share(),
                combined,
                2,
            );
            partials.insert(
                *id,
                frost::round2::sign_with_tweak(&package, nonce, &key, Some(&[] as &[u8]))?,
            );
        }
        let operator_partials = partials.clone();
        partials.insert(user_identifier()?, contribution.signature_share);
        let mut verifying = f.public.verifying_shares().clone();
        verifying.insert(
            user_identifier()?,
            frost::keys::VerifyingShare::deserialize(f.key.native_keys().user_key())?,
        );
        let public = frost::keys::PublicKeyPackage::new(verifying, combined, None);
        // This is the unchanged ordinary Spark aggregate call, not two_group.
        let signature =
            frost::aggregate_with_tweak(&package, &partials, &public, Some(&[] as &[u8]))?;
        let output = XOnlyPublicKey::from_slice(&f.key.native_keys().combined_key()[1..])?
            .tap_tweak(&Secp256k1::verification_only(), None)
            .0
            .to_x_only_public_key();
        Secp256k1::verification_only().verify_schnorr(
            &Signature::from_slice(&signature.serialize()?)?,
            &Message::from_digest(message),
            &output,
        )?;
        for changed in [
            independent_package([43; 32], &commitments, user_commitment)?,
            independent_package(
                message,
                &commitments,
                frost::round1::commit(
                    f.operators.values().next().unwrap().signing_share(),
                    &mut OsRng,
                )
                .1,
            )?,
        ] {
            assert!(
                frost::aggregate_with_tweak(&changed, &partials, &public, Some(&[] as &[u8]))
                    .is_err()
            );
        }
        // Optional public vector for testing Spark's protobuf wrapper directly.
        // It contains signatures/commitments only, never signing keys or nonces.
        if let Some(path) = std::env::var_os("ZARK_SPARK_SINGLE_USER_VECTOR") {
            save_vector(
                &path,
                &f,
                message,
                &commitments,
                &operator_partials,
                &contribution,
                &signature,
            )?;
        }
        if covered == [true; 8] {
            return Ok(());
        }
    }
    anyhow::bail!("single-USER parity coverage incomplete: {covered:?}")
}

// Deliberately independent of the adapter's package constructor. These are
// the standard groups and identifier used by Spark's normal aggregate path.
fn independent_package(
    message: Digest,
    operators: &OperatorCommitments,
    user: frost::round1::SigningCommitments,
) -> Result<frost::SigningPackage> {
    let id = frost::Identifier::derive(b"user")?;
    let groups = vec![operators.keys().copied().collect(), BTreeSet::from([id])];
    let mut commitments = operators.clone();
    commitments.insert(id, user);
    Ok(frost::SigningPackage::new_with_participants_groups(
        commitments,
        Some(groups),
        &message,
    ))
}

fn save_vector(
    path: &std::ffi::OsStr,
    f: &Fixture,
    message: Digest,
    commitments: &OperatorCommitments,
    partials: &BTreeMap<frost::Identifier, frost::round2::SignatureShare>,
    user: &SingleUserContribution,
    signature: &frost::Signature,
) -> Result<()> {
    use serde_json::json;
    let commitment_json = |c: &frost::round1::SigningCommitments| -> Result<serde_json::Value> {
        Ok(
            json!({"hiding":hex::encode(c.hiding().serialize()?),"binding":hex::encode(c.binding().serialize()?)}),
        )
    };
    let operator_commitments = commitments
        .iter()
        .map(|(id, c)| Ok((hex::encode(id.serialize()), commitment_json(c)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let operator_partials = partials
        .iter()
        .map(|(id, s)| (hex::encode(id.serialize()), hex::encode(s.serialize())))
        .collect::<BTreeMap<_, _>>();
    let operator_public = f
        .public
        .verifying_shares()
        .iter()
        .map(|(id, s)| Ok((hex::encode(id.serialize()), hex::encode(s.serialize()?))))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let vector = json!({"schema":"zark-spark/single-user-signing-vector/v1", "message":hex::encode(message),
        "verifying_key":hex::encode(f.key.native_keys().combined_key()), "user_public_key":hex::encode(f.key.native_keys().user_key()),
        "user_commitments":commitment_json(&user.commitment)?, "user_signature_share":hex::encode(user.signature_share.serialize()),
        "commitments":operator_commitments,"signature_shares":operator_partials,"public_shares":operator_public,
        "signature":hex::encode(signature.serialize()?),"engine_proof_admission_exercised":false});
    std::fs::write(path, serde_json::to_vec_pretty(&vector)?)?;
    Ok(())
}

#[test]
fn changed_share_stale_key_and_bad_original_response_are_rejected() -> Result<()> {
    let f = fixture()?;
    let native = f.key.native_keys().clone();
    let delta = random_scalar();
    let refreshed = CurrentUserKey::new(
        native,
        point_bytes(point(&f.key.server_point()?)? - ProjectivePoint::GENERATOR * delta)?,
        (f.key.wallet_scalar() + delta).to_bytes().into(),
    )?;
    assert!(SingleUserPrecommit::new(&f.key, [0; 32]).is_err());
    let original = point_bytes(ProjectivePoint::GENERATOR * random_scalar())?;
    assert!(
        SingleUserPrecommit::new(&f.key, [3; 32])?
            .attach(&refreshed, &original)
            .is_err()
    );
    let prepared = SingleUserPrecommit::new(&f.key, [3; 32])?.attach(&f.key, &original)?;
    assert!(
        prepared
            .bind(&refreshed, [42; 32], BTreeMap::new())
            .is_err()
    );
    let mut nonce: Option<Digest> = Some(random_scalar().to_bytes().into());
    let original = point_bytes(ProjectivePoint::GENERATOR * scalar(&nonce.unwrap())?)?;
    let key = f.operators.values().next().unwrap();
    let (_, operator) = frost::round1::commit(key.signing_share(), &mut OsRng);
    let ops = BTreeMap::from([(*key.identifier(), operator)]);
    let request = SingleUserPrecommit::new(&f.key, [3; 32])?
        .attach(&f.key, &original)?
        .bind(&f.key, [42; 32], ops)?;
    let response = issue(&f.server, &mut nonce, &request)?;
    assert!(
        request
            .complete((scalar(&response)? + Scalar::ONE).to_bytes().into())
            .is_err()
    );
    assert!(signing_package([42; 32], BTreeMap::new(), operator).is_err());
    assert!(
        signing_package(
            [42; 32],
            BTreeMap::from([(user_identifier()?, operator)]),
            operator
        )
        .is_err()
    );
    assert!(
        SingleUserPrecommit::new(&f.key, [3; 32])?
            .attach(&f.key, &[0; 64])
            .is_err()
    );
    Ok(())
}

#[test]
fn both_proof_plan_variants_match_bitcoin_sighashes_and_exact_outputs() -> Result<()> {
    use bitcoin::{
        Amount, ScriptBuf, Transaction, TxOut,
        consensus::deserialize,
        hashes::Hash,
        sighash::{Prevouts, SighashCache, TapSighashType},
    };
    use zark_protocol::spark_single_user::SigningPlan;
    let f = fixture()?;
    let receiver = ProjectivePoint::GENERATOR * Scalar::from(13u64);
    let user = point_bytes(
        k256::PublicKey::from_sec1_bytes(f.key.native_keys().user_key())?.to_projective(),
    )?;
    let operator = point_bytes(
        k256::PublicKey::from_sec1_bytes(f.key.native_keys().operator_key())?.to_projective(),
    )?;
    let secp = Secp256k1::verification_only();
    let combined = bitcoin::secp256k1::PublicKey::from_slice(f.key.native_keys().combined_key())?
        .x_only_public_key()
        .0;
    let receiver = bitcoin::secp256k1::PublicKey::from_slice(&compressed(receiver)?)?
        .x_only_public_key()
        .0;
    for amount in [42, 64_000] {
        for variant in 0..2 {
            let plan = SigningPlan {
                salt: [1; 32],
                anchor_txid: [2; 32],
                anchor_vout: 3,
                amount,
                native_delay: 2000,
                operator: operator.to_vec(),
                receiver: point_bytes(ProjectivePoint::GENERATOR * Scalar::from(13u64))?.to_vec(),
                variant,
            };
            let bodies = plan.bodies(user)?;
            let tx: Transaction = deserialize(&bodies.transaction)?;
            let previous = TxOut {
                value: Amount::from_sat(amount),
                script_pubkey: ScriptBuf::new_p2tr(&secp, combined, None),
            };
            let actual = SighashCache::new(&tx).taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(&[previous]),
                TapSighashType::Default,
            )?;
            assert_eq!(actual.to_byte_array(), bodies.sighash);
            assert_eq!(
                tx.output[0].script_pubkey,
                ScriptBuf::new_p2tr(&secp, receiver, None)
            );
            assert_eq!(
                tx.output[0].value.to_sat(),
                if variant == 1 && amount > 955 {
                    amount - 955
                } else {
                    amount
                }
            );
            assert_eq!(tx.output.len(), if variant == 0 { 2 } else { 1 });
            assert_eq!(
                tx.input[0].sequence.0,
                (1 << 30) | if variant == 0 { 1900 } else { 1950 }
            );
        }
    }
    Ok(())
}
