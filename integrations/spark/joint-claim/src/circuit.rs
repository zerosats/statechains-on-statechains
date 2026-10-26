//! Exact encrypted output only: (wallet evaluation + server evaluation) mod n
//! is inserted into the standard protobuf, then CTR-masked and GCM-authenticated.
use crate::boolean::Builder;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tandem::Circuit;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitSpec {
    pub plaintext_bytes: usize,
    pub scalar_offset: usize,
}
impl CircuitSpec {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (32..=2048).contains(&self.plaintext_bytes)
                && self
                    .scalar_offset
                    .checked_add(32)
                    .is_some_and(|n| n <= self.plaintext_bytes),
            "joint claim circuit bounds"
        );
        Ok(())
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let mut h = Sha256::new();
        h.update(b"ZARK/spark/joint-claim/boolean-encryption/v1");
        h.update((self.plaintext_bytes as u32).to_le_bytes());
        h.update((self.scalar_offset as u32).to_le_bytes());
        Ok(h.finalize().into())
    }
}
pub struct ClaimCircuit {
    pub(crate) circuit: Arc<Circuit>,
    pub(crate) spec: CircuitSpec,
}
impl ClaimCircuit {
    pub fn new(spec: CircuitSpec) -> Result<Self> {
        spec.validate()?;
        // Contributor: scalar, H=AES_K(0), zero-plaintext tag, CTR stream.
        // Evaluator: scalar and exact native protobuf template.
        let bits = spec.plaintext_bytes * 8;
        let (mut b, c, e) = Builder::inputs(256 + 128 + 128 + bits, 256 + bits);
        let (sum, valid) = b.scalar_sum(&e[..256], &c[..256]);
        let mut plaintext = e[256..].to_vec();
        plaintext[spec.scalar_offset * 8..(spec.scalar_offset + 32) * 8].copy_from_slice(&sum);
        let ciphertext = b.xor_words(&plaintext, &c[512..]);
        let h = &c[256..384];
        let zero_tag = &c[384..512];
        let mut delta = vec![b.zero; 128];
        for chunk in plaintext.chunks(128) {
            let mut block = vec![b.zero; 128];
            block[..chunk.len()].copy_from_slice(chunk);
            let x = b.xor_words(&delta, &block);
            delta = b.gcm_multiply(&x, h);
        }
        // The final GCM length block cancels against the zero-message tag;
        // its delta is zero, but the accumulated polynomial still multiplies H.
        delta = b.gcm_multiply(&delta, h);
        let tag = b.xor_words(&delta, zero_tag);
        let mut output = vec![valid];
        output.extend(tag);
        output.extend(ciphertext);
        let circuit = b.finish(output);
        circuit
            .validate()
            .map_err(|e| anyhow::anyhow!("joint claim circuit: {e}"))?;
        Ok(Self {
            circuit: Arc::new(circuit),
            spec,
        })
    }
    pub fn spec(&self) -> CircuitSpec {
        self.spec
    }
    pub fn digest(&self) -> [u8; 32] {
        self.circuit.blake3_hash()
    }
    pub fn and_gates(&self) -> usize {
        self.circuit.and_gates()
    }
}

pub(crate) fn bits(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|b| (0..8).rev().map(move |i| b & (1 << i) != 0))
        .collect()
}
pub(crate) fn bytes(bits: &[bool]) -> Result<Vec<u8>> {
    ensure!(
        bits.len().is_multiple_of(8),
        "joint claim output byte alignment"
    );
    Ok(bits
        .chunks(8)
        .map(|b| b.iter().fold(0, |v, &bit| (v << 1) | u8::from(bit)))
        .collect())
}
