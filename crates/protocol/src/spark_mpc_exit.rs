//! Cooperative exit through Spark's upstream `start_transfer_mpc`, authorized
//! by one proof-gated blind BIP-340 signature under the joint identity key.
//!
//! The signer is never a blind Schnorr oracle. A ticket exists only inside an
//! issued (permanently ownership-locked) native exit with an upstream MPC
//! contribution, and its single response is released only for a pinned proof
//! that the blinded challenge is for the exact Spark `AuthorizationPayload`
//! of that exit: the frozen plan's transfer, leaf, expiry, amount, owner key,
//! mask commitment, receiver, mask ciphertext and receiver-paying refunds, with
//! the signer's own position-two commitment vector at position two. Only the
//! wallet's position-one vector, its ECDSA leaf signature and the ciphertext
//! bytes are wallet-chosen, and they are fixed before the signer's nonce.
use crate::{application_hash, hash, point, scalar, spark_lineage::Digest};
use anyhow::{Result, ensure};
pub mod payload;
pub mod sealed;
#[cfg(test)]
mod tests;
mod verifier;
mod witness;
pub use sealed::MpcContribution;
pub use verifier::PinnedTransferAuthVerifier;
pub use witness::TransferAuthWitness;

pub const REGISTRY: &str = "zark-spark-mpc-transfer-auth-schnorr-v1";
pub const HEADER_LEN: usize = 262;
pub const ENCODED_LEN: usize = 390;
/// Spark positions for the wallet and signer sub-users.
pub const POSITIONS: [u64; 2] = [1, 2];
/// Spark ECIES of a 32-byte mask: 65-byte ephemeral, 16-byte IV, MAC and body.
pub const SECRET_CIPHER_LEN: usize = 129;
/// Strict-DER low-S ECDSA lengths the pinned circuit accepts.
pub const MIN_LEAF_SIGNATURE_LEN: usize = 68;
pub const MAX_LEAF_SIGNATURE_LEN: usize = 72;
const VERSION: [u8; 4] = [1, 0, 0, 0];

/// Everything the signer fixes from its own state before releasing a nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferAuthHeader {
    /// `spark_auth::scope_digest` of the issued native exit's frozen intent.
    pub scope: Digest,
    pub key_commitment: Digest,
    pub server: [u8; 64],
    pub plan: Digest,
    /// The UUIDs the signer sealed into its upstream sub-shares; the proof
    /// shows the plan names the same transfer and leaf.
    pub transfer_id: [u8; 16],
    pub leaf_id: [u8; 16],
    pub signer_proofs: [[u8; 33]; 2],
}
impl TransferAuthHeader {
    pub fn encode(&self) -> Result<[u8; HEADER_LEN]> {
        ensure!(
            self.scope != [0; 32] && self.key_commitment != [0; 32] && self.plan != [0; 32],
            "zero Spark transfer auth binding"
        );
        ensure!(
            self.transfer_id != [0; 16] && self.leaf_id != [0; 16],
            "Spark transfer auth UUIDs"
        );
        point(&self.server)?;
        let mut out = [0; HEADER_LEN];
        out[..4].copy_from_slice(&VERSION);
        out[4..36].copy_from_slice(&self.scope);
        out[36..68].copy_from_slice(&self.key_commitment);
        out[68..132].copy_from_slice(&self.server);
        out[132..164].copy_from_slice(&self.plan);
        out[164..180].copy_from_slice(&self.transfer_id);
        out[180..196].copy_from_slice(&self.leaf_id);
        out[196..229].copy_from_slice(&self.signer_proofs[0]);
        out[229..262].copy_from_slice(&self.signer_proofs[1]);
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferAuthStatement {
    pub header: TransferAuthHeader,
    pub commitment: Digest,
    pub nonce: [u8; 64],
    pub challenge: Digest,
}
impl TransferAuthStatement {
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure!(
            self.commitment != [0; 32],
            "zero Spark transfer auth commitment"
        );
        point(&self.nonce)?;
        scalar(&self.challenge)?;
        let out = [
            &self.header.encode()?[..],
            &self.commitment,
            &self.nonce,
            &self.challenge,
        ]
        .concat();
        ensure!(
            out.len() == ENCODED_LEN,
            "Spark transfer auth statement size"
        );
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == ENCODED_LEN && bytes[..4] == VERSION,
            "Spark transfer auth statement shape"
        );
        let value = Self {
            header: TransferAuthHeader {
                scope: bytes[4..36].try_into()?,
                key_commitment: bytes[36..68].try_into()?,
                server: bytes[68..132].try_into()?,
                plan: bytes[132..164].try_into()?,
                transfer_id: bytes[164..180].try_into()?,
                leaf_id: bytes[180..196].try_into()?,
                signer_proofs: [bytes[196..229].try_into()?, bytes[229..262].try_into()?],
            },
            commitment: bytes[262..294].try_into()?,
            nonce: bytes[294..358].try_into()?,
            challenge: bytes[358..390].try_into()?,
        };
        ensure!(
            value.encode()? == bytes,
            "noncanonical Spark transfer auth statement"
        );
        Ok(value)
    }
    pub fn digest(&self) -> Result<Digest> {
        Ok(hash(&[
            b"ZARK/spark/mpc-exit/transfer-auth-statement/v1",
            &self.encode()?,
        ]))
    }
}

/// Frozen before the signer's nonce exists; it fixes the whole Spark payload
/// (hence the wallet-chosen leaf signature and vector) and the blinding.
pub fn blinding_commitment(
    header: &TransferAuthHeader,
    message: &Digest,
    alpha: &Digest,
    beta: &Digest,
    salt: &Digest,
) -> Result<Digest> {
    for value in [alpha, beta] {
        ensure!(
            !bool::from(scalar(value)?.is_zero()),
            "zero Spark transfer auth blinding"
        );
    }
    ensure!(*salt != [0; 32], "zero Spark transfer auth salt");
    Ok(application_hash::hash(&[
        b"ZARK/spark/transfer-auth/blinding/v1",
        &header.encode()?,
        message,
        alpha,
        beta,
        salt,
    ]))
}
