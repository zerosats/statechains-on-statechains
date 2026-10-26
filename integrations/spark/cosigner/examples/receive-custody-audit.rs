//! Read-only audit of public transactions retained by the funded receive test.
use anyhow::{Context, Result, ensure};
use bitcoin::{
    ScriptBuf, Transaction,
    consensus::deserialize,
    hashes::Hash,
    secp256k1::{Message, PublicKey, Secp256k1, XOnlyPublicKey, schnorr::Signature},
    sighash::{Prevouts, SighashCache, TapSighashType},
};
use serde_json::{Value, json};
use std::{fs, path::PathBuf};

fn bytes(v: &Value, key: &str) -> Result<Vec<u8>> {
    Ok(serde_json::from_value(v[key].clone())?)
}
fn verify(tx: &Transaction, parent: &Transaction) -> Result<()> {
    ensure!(tx.input.len() == 1, "single input required");
    let input = &tx.input[0];
    ensure!(
        input.previous_output.txid == parent.compute_txid(),
        "wrong parent"
    );
    let previous = parent
        .output
        .get(input.previous_output.vout as usize)
        .context("missing prevout")?;
    ensure!(previous.script_pubkey.is_p2tr(), "P2TR prevout required");
    ensure!(
        input.witness.len() == 1,
        "complete key-spend witness required"
    );
    let sig = Signature::from_slice(input.witness.iter().next().context("missing signature")?)?;
    let digest = SighashCache::new(tx).taproot_key_spend_signature_hash(
        0,
        &Prevouts::All(&[previous]),
        TapSighashType::Default,
    )?;
    Ok(Secp256k1::verification_only().verify_schnorr(
        &sig,
        &Message::from_digest(digest.to_byte_array()),
        &XOnlyPublicKey::from_slice(&previous.script_pubkey.as_bytes()[2..])?,
    )?)
}
fn main() -> Result<()> {
    let root = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .context("provide retained fixture directory")?,
    );
    let prepared: Value =
        serde_json::from_slice(&fs::read(root.join("native-prepare.private.json"))?)?;
    let observed: Value = serde_json::from_slice(&fs::read(root.join("native-observation.json"))?)?;
    // These files also contain private wallet transport data. Only public
    // transaction facts and public keys are printed; no keys are opened.
    let leaf = &prepared["leaves"][0];
    let parent: Transaction = deserialize(&bytes(leaf, "node_raw")?)?;
    let earlier: Transaction = deserialize(&bytes(leaf, "refund_raw")?)?;
    let claimed: Transaction = deserialize(&bytes(&observed, "cpfp_refund")?)?;
    verify(&earlier, &parent)?;
    verify(&claimed, &parent)?;
    let script = |key: &[u8]| -> Result<ScriptBuf> {
        Ok(ScriptBuf::new_p2tr(
            &Secp256k1::verification_only(),
            PublicKey::from_slice(key)?.x_only_public_key().0,
            None,
        ))
    };
    use k256::{PublicKey as KPublic, elliptic_curve::sec1::ToEncodedPoint};
    use zark_spark_cosigner::{
        initial_exit::{
            DepositAnchor, InitialRootLeafExitV1, NativeLeafKeys,
            validate_received_root_claim_custody,
        },
        keys::{Purpose, Scope},
    };
    let user = bytes(&observed, "user")?;
    let combined = bytes(&observed, "combined")?;
    let operator = (KPublic::from_sec1_bytes(&combined)?.to_projective()
        - KPublic::from_sec1_bytes(&user)?.to_projective())
    .to_affine()
    .to_encoded_point(true);
    let keys = NativeLeafKeys::new(
        Scope {
            deployment: [1; 32],
            coin: [2; 32],
            purpose: Purpose::LeafSigning,
        },
        &user,
        operator.as_bytes(),
        &combined,
    )?;
    let a = &observed["anchor"];
    let anchor = DepositAnchor {
        outpoint: bitcoin::OutPoint {
            txid: bitcoin::Txid::from_slice(&bytes(a, "txid")?)?,
            vout: a["vout"].as_u64().context("anchor vout")? as u32,
        },
        output: bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(a["amount_sats"].as_u64().context("anchor amount")?),
            script_pubkey: ScriptBuf::from_bytes(bytes(a, "script")?),
        },
    };
    let mut intermediate_direct: Transaction =
        serde_json::from_value(leaf["node"]["direct_from_cpfp_refund_tx"].clone())?;
    let evidence_path = root.join("native-intermediate-observation.json");
    if evidence_path.exists() {
        let evidence: Value = serde_json::from_slice(&fs::read(evidence_path)?)?;
        ensure!(
            bytes(&evidence, "root")? == bytes(leaf, "node_raw")?
                && bytes(&evidence, "cpfp_refund")? == bytes(leaf, "refund_raw")?,
            "intermediate observer differs from retained SDK input"
        );
        let signed: Transaction = deserialize(&bytes(&evidence, "direct_from_cpfp_refund")?)?;
        let mut body = signed.clone();
        for input in &mut body.input {
            input.witness.clear();
        }
        for input in &mut intermediate_direct.input {
            input.witness.clear();
        }
        ensure!(
            body == intermediate_direct,
            "intermediate direct refund body differs"
        );
        intermediate_direct = signed;
    }
    let incoming = InitialRootLeafExitV1::new(
        bytes(leaf, "node_raw")?,
        bytes(leaf, "refund_raw")?,
        bitcoin::consensus::serialize(&intermediate_direct),
    );
    let final_prefix = InitialRootLeafExitV1::new(
        bytes(&observed, "root")?,
        bytes(&observed, "cpfp_refund")?,
        bytes(&observed, "direct_from_cpfp_refund")?,
    );
    let custody =
        validate_received_root_claim_custody(&anchor, &keys, &final_prefix, &incoming, 1900);
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "earlier_signature_valid":true,
            "claimed_signature_valid":true,
            "receive_custody_accepted":custody.is_ok(),
            "receive_custody_error":custody.err().map(|e|e.to_string()),
            "same_outpoint":earlier.input[0].previous_output == claimed.input[0].previous_output,
            "earlier_delay":earlier.input[0].sequence.0 & 0xffff,
            "claimed_delay":claimed.input[0].sequence.0 & 0xffff,
            "earlier_pays_transport_identity":earlier.output[0].script_pubkey == script(&bytes(&observed,"owner")?)?,
            "claimed_pays_joint_user":claimed.output[0].script_pubkey == script(&bytes(&observed,"user")?)?,
            "different_destinations":earlier.output[0].script_pubkey != claimed.output[0].script_pubkey,
            "earlier_txid":earlier.compute_txid().to_string(),
            "claimed_txid":claimed.compute_txid().to_string()
        }))?
    );
    Ok(())
}
