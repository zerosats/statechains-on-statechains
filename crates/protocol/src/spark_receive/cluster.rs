//! Trusted native configuration includes BOTH FROST IDs and polynomial indices.
use crate::{hash, scalar, spark_lineage::Digest};
use anyhow::{Result, ensure};
use k256::{PublicKey, Scalar, elliptic_curve::sec1::ToEncodedPoint};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimOperator {
    pub index: u16,
    pub encryption_key: Vec<u8>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimCluster {
    pub threshold: usize,
    pub operators: BTreeMap<String, ClaimOperator>,
}
impl ClaimCluster {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.threshold == 2 && (2..=16).contains(&self.operators.len()),
            "ordinary receive supports a pinned threshold-two cluster"
        );
        let mut keys = BTreeSet::new();
        let mut indices = BTreeSet::new();
        for (id, op) in &self.operators {
            let raw: Digest = hex::decode(id)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("claim operator ID size"))?;
            ensure!(
                hex::encode(raw) == *id && scalar(&raw)? != Scalar::ZERO,
                "claim operator identifier"
            );
            let key = PublicKey::from_sec1_bytes(&op.encryption_key)?;
            ensure!(
                op.encryption_key.len() == 33
                    && key.to_encoded_point(true).as_bytes() == op.encryption_key,
                "claim operator identity encoding"
            );
            ensure!(
                op.index > 0
                    && usize::from(op.index) <= self.operators.len()
                    && indices.insert(op.index)
                    && keys.insert(&op.encryption_key),
                "claim operator coverage/indices"
            );
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<Digest> {
        self.validate()?;
        Ok(hash(&[
            b"ZARK/spark/receive/cluster/v1",
            &serde_json::to_vec(self)?,
        ]))
    }
    /// Ordinary protobuf size for one UUID leaf, one 32-byte share, threshold
    /// two proofs and the complete operator-ID/public-share map.
    pub fn template_shape(&self) -> Result<(usize, usize)> {
        self.validate()?;
        // SecretShare: scalar field (34), two point fields (35 each) = 104.
        // Each map entry is 66 bytes of key + 35 bytes of value, with a
        // two-byte field header. IDs are canonical 64-byte lowercase hex.
        let leaf = 38 + 106 + 103 * self.operators.len();
        // Outer repeated message header uses a two-byte length at these bounds.
        Ok((3 + leaf, 45))
    }
}
