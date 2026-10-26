//! Exact `spark_authn.Challenge` bytes as Spark re-marshals and verifies them.
//!
//! The relation supports one canonical shape only: version 1, a five-byte
//! timestamp varint, a 32-byte nonce and a compressed SEC1 key. Anything else
//! is rejected here rather than signed under a different interpretation.
use crate::{hash, spark_lineage::Digest};
use anyhow::{Result, ensure};

pub const ENCODED_LEN: usize = 77;
const MIN_TIMESTAMP: u64 = 1 << 28;
const MAX_TIMESTAMP: u64 = 1 << 35;

pub(super) fn check_timestamp(timestamp: u64) -> Result<()> {
    ensure!(
        (MIN_TIMESTAMP..MAX_TIMESTAMP).contains(&timestamp),
        "Spark auth timestamp outside the canonical varint width"
    );
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparkChallenge {
    pub timestamp: u64,
    pub nonce: Digest,
    pub public_key: [u8; 33],
}
impl SparkChallenge {
    pub fn encode(&self) -> Result<[u8; ENCODED_LEN]> {
        check_timestamp(self.timestamp)?;
        ensure!(
            matches!(self.public_key[0], 2 | 3),
            "Spark auth key must be compressed SEC1"
        );
        let mut out = [0; ENCODED_LEN];
        out[..3].copy_from_slice(&[8, 1, 16]);
        for i in 0..4 {
            out[3 + i] = ((self.timestamp >> (7 * i)) & 127) as u8 | 128;
        }
        out[7] = (self.timestamp >> 28) as u8;
        out[8..10].copy_from_slice(&[26, 32]);
        out[10..42].copy_from_slice(&self.nonce);
        out[42..44].copy_from_slice(&[34, 33]);
        out[44..].copy_from_slice(&self.public_key);
        Ok(out)
    }
    /// Accepts only bytes that re-encode identically from the parsed fields.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == ENCODED_LEN, "Spark auth challenge shape");
        let mut timestamp = u64::from(bytes[7]) << 28;
        for i in 0..4 {
            timestamp |= u64::from(bytes[3 + i] & 127) << (7 * i);
        }
        let value = Self {
            timestamp,
            nonce: bytes[10..42].try_into()?,
            public_key: bytes[44..].try_into()?,
        };
        ensure!(
            value.encode()? == bytes,
            "noncanonical Spark auth challenge"
        );
        Ok(value)
    }
    /// The digest Spark's verifier checks: sha256(proto.Marshal(challenge)).
    pub fn message(&self) -> Result<Digest> {
        Ok(hash(&[&self.encode()?]))
    }
}
