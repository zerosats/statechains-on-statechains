//! Private receiver offer: current sender proof and shared native backing only.
//! Historical certificates, server points, recoveries and capabilities are absent.
use super::PrivateBacking;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zark_protocol::{
    spark_lineage::{
        Handover, PinnedSparkVerifier, bridge_commitment, draft_token_commitment,
        masked_share_commitment, recipient_claim_commitment,
    },
    spark_wire::Predecessor,
};
use zeroize::{Zeroize, Zeroizing};

const MAX_BYTES: usize = 128 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OfferRecord {
    pub schema: String,
    pub version: u32,
    pub predecessor: Predecessor,
    pub backing: Vec<u8>,
    pub handover: Vec<u8>,
    pub proof: Vec<u8>,
    pub masked: [u8; 32],
    pub masked_salt: [u8; 32],
    pub bridge_salt: [u8; 32],
    pub claim_salt: [u8; 32],
    pub token: [u8; 32],
    pub old_delay: u32,
}
impl Drop for OfferRecord {
    fn drop(&mut self) {
        self.backing.zeroize();
        self.handover.zeroize();
        self.proof.zeroize();
        self.masked.zeroize();
        self.masked_salt.zeroize();
        self.bridge_salt.zeroize();
        self.claim_salt.zeroize();
        self.token.zeroize();
    }
}
pub struct PrivateOffer {
    pub(super) record: OfferRecord,
    pub(super) backing: PrivateBacking,
    pub(super) handover: Handover,
}
impl PrivateOffer {
    pub(super) fn from_record(
        record: OfferRecord,
        verifier: &PinnedSparkVerifier,
        scratch: &Path,
    ) -> Result<Self> {
        ensure!(
            record.schema == "zark-spark-private-offer" && record.version == 1,
            "private Spark offer schema"
        );
        let handover = Handover::decode(&record.handover)?;
        verifier.verify_handover(record.predecessor, &handover, &record.proof, scratch)?;
        let backing = PrivateBacking::decode_private(&record.backing)?;
        ensure!(
            handover.intent.deployment == backing.keys().scope().deployment
                && handover.intent.coin == backing.keys().scope().coin,
            "private Spark offer backing domain"
        );
        ensure!(
            masked_share_commitment(&handover.intent, &record.masked, &record.masked_salt)?
                == handover.masked_share,
            "private Spark offer masked share"
        );
        ensure!(
            bridge_commitment(
                &handover.intent,
                &handover.backing,
                record.old_delay,
                &handover.policy,
                &record.bridge_salt
            )? == handover.bridge,
            "private Spark offer recovery bridge"
        );
        ensure!(
            draft_token_commitment(&handover.intent, &record.token)? == handover.draft_token,
            "private Spark offer draft token"
        );
        Ok(Self {
            record,
            backing,
            handover,
        })
    }
    /// This is plaintext private wallet material, not a public SSP/signer wire.
    /// A confidential authenticated wallet envelope must carry it in live use.
    pub fn encode_private(&self) -> Result<Zeroizing<Vec<u8>>> {
        let bytes = Zeroizing::new(serde_json::to_vec(&self.record)?);
        ensure!(bytes.len() <= MAX_BYTES, "private Spark offer size");
        Ok(bytes)
    }
    pub fn decode_private(
        bytes: &[u8],
        claim_key: &[u8; 32],
        verifier: &PinnedSparkVerifier,
        scratch: &Path,
    ) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_BYTES,
            "private Spark offer size"
        );
        let record: OfferRecord = serde_json::from_slice(bytes)?;
        let value = Self::from_record(record, verifier, scratch)?;
        let intent = &value.handover.intent;
        ensure!(
            recipient_claim_commitment(
                &intent.deployment,
                &intent.coin,
                &intent.operation,
                claim_key,
                &value.record.claim_salt
            )? == intent.recipient_claim,
            "private Spark offer recipient mismatch"
        );
        ensure!(
            value.encode_private()?.as_slice() == bytes,
            "noncanonical private Spark offer"
        );
        Ok(value)
    }
    pub fn backing(&self) -> &PrivateBacking {
        &self.backing
    }
    pub fn handover(&self) -> &Handover {
        &self.handover
    }
    pub fn predecessor(&self) -> Predecessor {
        self.record.predecessor
    }
    pub fn sender_proof(&self) -> &[u8] {
        &self.record.proof
    }
}
