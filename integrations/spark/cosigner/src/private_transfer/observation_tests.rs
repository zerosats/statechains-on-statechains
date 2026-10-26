//! Adversarial bindings with signed synthetic backing; no chain or wallet RPC.
use crate::native_observation::{
    CompletionPermit, LeafQuery, NativeObservationSource, OriginPermit,
};
use anyhow::Result;
use bitcoin::hashes::Hash;
use serde_json::{Value, json};
use zark_protocol::{
    handoff::{OperationScope, TransferContext},
    hash,
    spark_recovery::RecoveryContext,
    spark_wire::NativeCompletion,
};

const TRANSFER: &str = "00000000-0000-4000-8000-000000000001";
const LEAF: &str = "00000000-0000-4000-8000-000000000002";
struct Source(Value);
impl NativeObservationSource for Source {
    fn completed_leaf(&mut self, _: &LeafQuery<'_>) -> Result<Value> {
        Ok(self.0.clone())
    }
}
fn context() -> (TransferContext, RecoveryContext) {
    let session: [u8; 32] = k256::schnorr::SigningKey::from_bytes(&[5; 32])
        .expect("fixed nonzero test scalar")
        .verifying_key()
        .to_bytes()
        .into();
    (
        TransferContext {
            deployment: [1; 32],
            coin: [2; 32],
            previous_state: [3; 32],
            operation: [4; 32],
            recipient_claim: [6; 32],
            session_auth: session,
            start_revision: 19,
            scope: OperationScope::Single,
        },
        RecoveryContext {
            deployment: [1; 32],
            coin: [2; 32],
            previous_state: [3; 32],
            operation: [4; 32],
            session,
            successor_state: [6; 32],
            revision: 19,
        },
    )
}
fn observed(backing: &super::PrivateBacking) -> Value {
    let anchor = backing.anchor();
    json!({"transfer_id":TRANSFER,"leaf_id":LEAF,"operators_completed":3,
        "active_block":hex::encode([9;32]),"active_confirmations":6,
        "anchor":{"txid":anchor.outpoint.txid.to_byte_array(),"vout":anchor.outpoint.vout,
            "amount_sats":anchor.output.value.to_sat(),"script":anchor.output.script_pubkey.as_bytes()},
        "root":backing.prefix().root_node,"cpfp_refund":backing.prefix().cpfp_refund,
        "intermediate_refund":backing.prefix().cpfp_refund,"intermediate_direct":backing.prefix().direct_from_cpfp_refund,
        "direct_from_cpfp_refund":backing.prefix().direct_from_cpfp_refund,
        "owner":backing.keys().user_key(),"user":backing.keys().user_key(),"combined":backing.keys().combined_key()})
}

#[test]
fn admission_recomputes_commitment_and_rejects_unrelated_native_state() -> Result<()> {
    let backing = super::received_root_tests::received(1900)?;
    let (context, recovery) = context();
    let opening = backing.encode_private()?;
    let original = observed(&backing);
    let receiver = backing.keys().user_key();
    let query = || LeafQuery {
        transfer: TRANSFER,
        leaf: LEAF,
        receiver,
    };
    let permit = OriginPermit::observe(
        &context,
        &recovery,
        &opening,
        query(),
        3,
        &mut Source(original.clone()),
    )?;
    permit.authorize(&context, &backing.observed_commitment(&recovery)?)?;
    assert!(permit.authorize(&context, &[7; 32]).is_err());
    let mut other = context.clone();
    other.operation[0] ^= 1;
    assert!(
        permit
            .authorize(&other, &backing.observed_commitment(&recovery)?)
            .is_err()
    );
    for attack in 0..8 {
        let mut value = original.clone();
        match attack {
            0 => value["transfer_id"] = LEAF.into(),
            1 => value["leaf_id"] = TRANSFER.into(),
            2 => value["active_confirmations"] = 0.into(),
            3 => value["operators_completed"] = 2.into(),
            4 => value["anchor"]["amount_sats"] = 1.into(),
            5 => value["root"][0] = 255.into(),
            6 => value["user"] = json!(vec![0u8; 33]),
            _ => value["intermediate_refund"][0] = 255.into(),
        }
        assert!(
            OriginPermit::observe(
                &context,
                &recovery,
                &opening,
                query(),
                3,
                &mut Source(value)
            )
            .is_err(),
            "attack {attack}"
        );
    }
    Ok(())
}

/// A wrong additive tweak u' moves the claimed leaf to q = P + (u - u')G. The
/// blind signer cannot see q; FreezeOrigin is admitted only through this
/// observer, which must refuse a consistent leaf on any key other than P.
#[test]
fn origin_admission_rejects_a_leaf_claimed_onto_another_user_key() -> Result<()> {
    use k256::{ProjectivePoint, elliptic_curve::sec1::ToEncodedPoint};
    let backing = super::received_root_tests::received(1900)?;
    let (context, recovery) = context();
    let shift = ProjectivePoint::GENERATOR * k256::Scalar::from(7u64);
    let moved = |key: &[u8]| -> Result<Vec<u8>> {
        let p = k256::PublicKey::from_sec1_bytes(key)?.to_projective() + shift;
        Ok(p.to_affine().to_encoded_point(true).as_bytes().to_vec())
    };
    let mut value = observed(&backing);
    let q = moved(backing.keys().user_key())?;
    value["owner"] = json!(q);
    value["user"] = json!(q);
    value["combined"] = json!(moved(backing.keys().combined_key())?);
    let query = |receiver| LeafQuery {
        transfer: TRANSFER,
        leaf: LEAF,
        receiver,
    };
    let opening = backing.encode_private()?;
    let observe = |receiver, value: &Value| {
        OriginPermit::observe(
            &context,
            &recovery,
            &opening,
            query(receiver),
            3,
            &mut Source(value.clone()),
        )
        .err()
        .expect("leaf on another USER key admitted")
        .to_string()
    };
    let error = observe(backing.keys().user_key(), &value);
    assert!(error.contains("ownership/funding observation"), "{error}");
    let error = observe(&q, &value);
    assert!(error.contains("joint USER key"), "{error}");
    value["owner"] = json!(backing.keys().user_key());
    let error = observe(backing.keys().user_key(), &value);
    assert!(
        error.contains("differs from disclosed signed backing"),
        "{error}"
    );
    Ok(())
}

#[test]
fn completion_checks_packet_scope_and_its_frozen_evidence_before_granting() -> Result<()> {
    let backing = super::received_root_tests::received(1900)?;
    let (context, _) = context();
    let received = observed(&backing);
    let user = k256::PublicKey::from_sec1_bytes(backing.keys().user_key())?.to_projective();
    let user = zark_protocol::point_bytes(user)?;
    let operator = k256::PublicKey::from_sec1_bytes(backing.keys().operator_key())?.to_projective();
    let plan = zark_protocol::spark_native::PlanOpening {
        salt: [7; 32],
        transfer_id: hex::decode(TRANSFER.replace('-', ""))?.try_into().unwrap(),
        leaf_id: hex::decode(LEAF.replace('-', ""))?.try_into().unwrap(),
        expiry: 123456,
        cluster: [8; 32],
        anchor_txid: backing.anchor().outpoint.txid.to_byte_array(),
        anchor_vout: backing.anchor().outpoint.vout,
        amount: backing.anchor().output.value.to_sat(),
        native_delay: 2000,
        operator: zark_protocol::point_bytes(operator)?,
        mask_user: user,
        receiver_identity: backing.keys().user_key().try_into().unwrap(),
        mask_cipher_sha256: [9; 32],
    };
    let bodies = plan.bodies(user)?;
    let packet = serde_json::to_vec(&json!({"transfer_id":TRANSFER,"leaf_id":LEAF,
        "receiver_identity":backing.keys().user_key(),"user_key":backing.keys().user_key(),
        "amount_sats":plan.amount,"expiry_unix_seconds":plan.expiry,
        "refunds":[{"raw_tx":bodies.new_refunds[0]},{"raw_tx":bodies.new_refunds[1]}]}))?;
    let completion = NativeCompletion {
        plan: plan.commitment(user)?,
        cluster: plan.cluster,
        packet: hash(&[&packet]),
    };
    let evidence_value = json!({"transfer_id":TRANSFER,"leaf_id":LEAF,
        "packet_sha256":hex::encode(completion.packet),"received":received});
    let evidence = serde_json::to_vec(&evidence_value)?;
    let permit = CompletionPermit::observe(
        &context,
        &completion,
        &packet,
        &evidence,
        &plan,
        &user,
        3,
        &mut Source(received.clone()),
    )?;
    permit.authorize(&context, &completion, &hash(&[&evidence]))?;
    assert!(permit.authorize(&context, &completion, &[42; 32]).is_err());
    let mut changed = completion.clone();
    changed.packet[0] ^= 1;
    assert!(
        CompletionPermit::observe(
            &context,
            &changed,
            &packet,
            &evidence,
            &plan,
            &user,
            3,
            &mut Source(received.clone())
        )
        .is_err()
    );
    let mut changed = evidence_value;
    changed["received"]["anchor"]["vout"] = 19.into();
    assert!(
        CompletionPermit::observe(
            &context,
            &completion,
            &packet,
            &serde_json::to_vec(&changed)?,
            &plan,
            &user,
            3,
            &mut Source(received.clone())
        )
        .is_err()
    );
    let mut moved = received;
    moved["owner"] = json!(vec![2u8; 33]);
    assert!(
        CompletionPermit::observe(
            &context,
            &completion,
            &packet,
            &evidence,
            &plan,
            &user,
            3,
            &mut Source(moved)
        )
        .is_err()
    );
    Ok(())
}
