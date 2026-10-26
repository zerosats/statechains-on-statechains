//! Explicitly trusted, disclosed-backing observation for the interim prototype.
//! The source must query configured native operators and an authenticated chain
//! observer itself. A wallet response, cached report or caller-selected digest
//! is not a source. These checks bind that trust decision to exact native bytes;
//! they cannot make a dishonest source truthful or hide its backing knowledge.
use crate::private_transfer::PrivateBacking;
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::time::{Duration, Instant};
use zark_protocol::{
    handoff::TransferContext, hash, spark_recovery::RecoveryContext, spark_wire::NativeCompletion,
};

pub struct LeafQuery<'a> {
    pub transfer: &'a str,
    pub leaf: &'a str,
    pub receiver: &'a [u8],
}

pub trait NativeObservationSource {
    /// Return current, completed transfer-to-leaf membership, available leaf
    /// state and active confirmed unspent anchor after all configured operators
    /// agree. Fail closed on disagreement, reorg, missing data or unavailable
    /// chain state. The returned bytes contain no native secret shares.
    fn completed_leaf(&mut self, query: &LeafQuery<'_>) -> Result<Value>;
}

struct Scope {
    context: TransferContext,
    observed: Instant,
}
impl Scope {
    fn new(context: &TransferContext) -> Result<Self> {
        context.encode()?;
        Ok(Self {
            context: context.clone(),
            observed: Instant::now(),
        })
    }
    fn check(&self, context: &TransferContext) -> Result<()> {
        ensure!(
            &self.context == context && self.observed.elapsed() <= Duration::from_secs(30),
            "native observation expired or belongs to another operation"
        );
        Ok(())
    }
}

pub struct OriginPermit {
    scope: Scope,
    backing: [u8; 32],
}
impl OriginPermit {
    pub fn observe(
        context: &TransferContext,
        recovery: &RecoveryContext,
        opening: &[u8],
        query: LeafQuery<'_>,
        operators: usize,
        source: &mut impl NativeObservationSource,
    ) -> Result<Self> {
        let backing = PrivateBacking::decode_private(opening)?;
        ensure!(
            query.receiver == backing.keys().user_key(),
            "received identity must equal the joint USER key"
        );
        ensure!(
            context.deployment == recovery.deployment && context.coin == recovery.coin,
            "native origin observation domain"
        );
        let observed = source.completed_leaf(&query)?;
        check_current(&observed, &query, operators)?;
        let anchor = backing.anchor();
        use bitcoin::hashes::Hash;
        ensure!(
            bytes(&observed["anchor"], "txid")? == anchor.outpoint.txid.to_byte_array()
                && observed["anchor"]["vout"] == anchor.outpoint.vout
                && observed["anchor"]["amount_sats"] == anchor.output.value.to_sat()
                && bytes(&observed["anchor"], "script")? == anchor.output.script_pubkey.as_bytes()
                && bytes(&observed, "root")? == backing.prefix().root_node
                && bytes(&observed, "cpfp_refund")? == backing.prefix().cpfp_refund
                && bytes(&observed, "direct_from_cpfp_refund")?
                    == backing.prefix().direct_from_cpfp_refund
                && bytes(&observed, "user")? == backing.keys().user_key()
                && bytes(&observed, "combined")? == backing.keys().combined_key(),
            "observed native leaf differs from disclosed signed backing"
        );
        let intermediate = crate::initial_exit::InitialRootLeafExitV1::new(
            bytes(&observed, "root")?,
            bytes(&observed, "intermediate_refund")?,
            bytes(&observed, "intermediate_direct")?,
        );
        crate::initial_exit::validate_received_root_claim_custody(
            anchor,
            backing.keys(),
            backing.prefix(),
            &intermediate,
            backing.validated_exit().native_delay(),
        )?;
        Ok(Self {
            scope: Scope::new(context)?,
            backing: backing.observed_commitment(recovery)?,
        })
    }
    pub fn authorize(&self, context: &TransferContext, backing: &[u8; 32]) -> Result<()> {
        self.scope.check(context)?;
        ensure!(
            &self.backing == backing,
            "native origin backing commitment differs"
        );
        Ok(())
    }
}

pub struct CompletionPermit {
    scope: Scope,
    completion: NativeCompletion,
    evidence: [u8; 32],
}
impl CompletionPermit {
    #[allow(clippy::too_many_arguments)]
    pub fn observe(
        context: &TransferContext,
        completion: &NativeCompletion,
        packet: &[u8],
        evidence: &[u8],
        plan: &zark_protocol::spark_native::PlanOpening,
        user: &[u8; 64],
        operators: usize,
        source: &mut impl NativeObservationSource,
    ) -> Result<Self> {
        ensure!(
            !packet.is_empty()
                && packet.len() <= 128 * 1024
                && !evidence.is_empty()
                && evidence.len() <= 128 * 1024,
            "native observation size"
        );
        completion.message()?;
        ensure!(
            plan.commitment(*user)? == completion.plan && plan.cluster == completion.cluster,
            "observed completion plan opening differs"
        );
        ensure!(
            hash(&[packet]) == completion.packet,
            "observed completion packet digest differs"
        );
        let packet_value: Value = serde_json::from_slice(packet)?;
        let saved: Value = serde_json::from_slice(evidence)?;
        ensure!(
            serde_json::to_vec(&packet_value)? == packet && serde_json::to_vec(&saved)? == evidence,
            "noncanonical native completion observation"
        );
        let receiver = bytes(&packet_value, "receiver_identity")?;
        let query = LeafQuery {
            transfer: packet_value["transfer_id"]
                .as_str()
                .context("packet transfer")?,
            leaf: packet_value["leaf_id"].as_str().context("packet leaf")?,
            receiver: &receiver,
        };
        ensure!(
            hex::decode(query.transfer.replace('-', ""))? == plan.transfer_id
                && hex::decode(query.leaf.replace('-', ""))? == plan.leaf_id
                && query.receiver == plan.receiver_identity
                && packet_value["amount_sats"] == plan.amount
                && packet_value["expiry_unix_seconds"] == plan.expiry,
            "native packet differs from authorized plan metadata"
        );
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let user_key = zark_protocol::point(user)?
            .to_affine()
            .to_encoded_point(true);
        ensure!(
            bytes(&packet_value, "user_key")? == user_key.as_bytes(),
            "native packet USER differs from authorized plan"
        );
        let bodies = plan.bodies(*user)?;
        let refunds = packet_value["refunds"]
            .as_array()
            .context("native packet refunds")?;
        ensure!(refunds.len() == 2, "native packet refund coverage");
        for (refund, expected) in refunds.iter().zip(&bodies.new_refunds) {
            ensure!(
                transaction_body(&bytes(refund, "raw_tx")?)? == *expected,
                "native packet refund differs from authorized plan"
            );
        }
        let observed = source.completed_leaf(&query)?;
        check_current(&observed, &query, operators)?;
        ensure!(
            transaction_body(&bytes(&observed, "root")?)? == bodies.root,
            "settled leaf is not the authorized native backing"
        );
        for (i, key) in ["intermediate_refund", "intermediate_direct"]
            .into_iter()
            .enumerate()
        {
            ensure!(
                transaction_body(&bytes(&observed, key)?)? == bodies.new_refunds[i],
                "settled intermediate refund differs from authorized plan"
            );
        }
        ensure!(
            saved["transfer_id"] == query.transfer
                && saved["leaf_id"] == query.leaf
                && saved["packet_sha256"] == hex::encode(completion.packet),
            "completion evidence packet scope"
        );
        // Confirmations/tip can advance; the actual settled native ownership,
        // signed transactions and anchor must still match the frozen evidence.
        for key in [
            "transfer_id",
            "leaf_id",
            "anchor",
            "root",
            "cpfp_refund",
            "direct_from_cpfp_refund",
            "owner",
            "user",
            "combined",
        ] {
            ensure!(
                observed[key] == saved["received"][key],
                "completion evidence native state differs: {key}"
            );
        }
        Ok(Self {
            scope: Scope::new(context)?,
            completion: completion.clone(),
            evidence: hash(&[evidence]),
        })
    }
    pub fn authorize(
        &self,
        context: &TransferContext,
        completion: &NativeCompletion,
        evidence: &[u8; 32],
    ) -> Result<()> {
        self.scope.check(context)?;
        ensure!(
            &self.completion == completion && &self.evidence == evidence,
            "native completion permit differs"
        );
        Ok(())
    }
}

fn transaction_body(raw: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        !raw.is_empty() && raw.len() <= 4096,
        "native observation transaction size"
    );
    let mut tx: bitcoin::Transaction = bitcoin::consensus::deserialize(raw)?;
    ensure!(
        bitcoin::consensus::serialize(&tx) == raw,
        "noncanonical native observation transaction"
    );
    for input in &mut tx.input {
        input.witness.clear();
    }
    Ok(bitcoin::consensus::serialize(&tx))
}

fn bytes(value: &Value, key: &str) -> Result<Vec<u8>> {
    serde_json::from_value(value[key].clone()).with_context(|| format!("native observation {key}"))
}
fn check_current(observed: &Value, query: &LeafQuery<'_>, operators: usize) -> Result<()> {
    ensure!(
        (2..=16).contains(&operators) && serde_json::to_vec(observed)?.len() <= 128 * 1024,
        "native observation quorum/size"
    );
    for id in [query.transfer, query.leaf] {
        ensure!(
            id.len() == 36
                && id
                    .as_bytes()
                    .iter()
                    .enumerate()
                    .all(|(i, b)| if [8, 13, 18, 23].contains(&i) {
                        *b == b'-'
                    } else {
                        b.is_ascii_digit() || (b'a'..=b'f').contains(b)
                    }),
            "native observation UUID"
        );
    }
    k256::PublicKey::from_sec1_bytes(query.receiver)?;
    let tip = observed["active_block"]
        .as_str()
        .context("native observation active block")?;
    ensure!(
        query.receiver.len() == 33
            && tip.len() == 64
            && hex::decode(tip)?.iter().any(|b| *b != 0)
            && observed["active_confirmations"]
                .as_u64()
                .is_some_and(|n| n > 0)
            && observed["operators_completed"] == operators
            && observed["transfer_id"] == query.transfer
            && observed["leaf_id"] == query.leaf
            && bytes(observed, "owner")? == query.receiver,
        "native completed ownership/funding observation missing or substituted"
    );
    Ok(())
}
