//! Proof-gated blind BIP-340 signing for Spark operator authentication only.
//!
//! Spark accepts identity-key Schnorr signatures for transfer and token
//! authorization as well as session authentication, so this is never a generic
//! blind signer. Every response is bound to one frozen commitment and released
//! only for a pinned proof that the blinded challenge belongs to a canonical
//! version-1 `spark_authn.Challenge` naming the coin's committed joint identity
//! key. Claim, leaf and package digests keep the separate ECDSA identity path.
use crate::{application_hash, hash, point, scalar, spark_lineage::Digest};
use anyhow::{Result, ensure};
mod challenge;
#[cfg(test)]
mod tests;
mod verifier;
mod wallet;
pub use challenge::SparkChallenge;
pub use verifier::PinnedAuthVerifier;
pub use wallet::{AuthBlinding, AuthWitness, BlindedAuth, IdentityKey};

pub const REGISTRY: &str = "zark-spark-auth-schnorr-v1";
pub const ENCODED_LEN: usize = 268;
/// Spark rejects a challenge once `now + 1 - timestamp > 60`. The signer leaves
/// headroom for the wallet's final round trip and verify_challenge call.
pub const MAX_AGE_SECONDS: u64 = 50;
pub const MAX_FUTURE_SECONDS: u64 = 5;
const VERSION: [u8; 4] = [1, 0, 0, 0];
const HEADER_LEN: usize = 140;

/// The signer's clock is the only freshness authority. Spark's own timeout is
/// rechecked by Spark; this bound stops stale or far-future pre-signing.
pub fn check_fresh(timestamp: u64, now: u64) -> Result<()> {
    ensure!(
        timestamp <= now.saturating_add(MAX_FUTURE_SECONDS)
            && now.saturating_sub(timestamp) <= MAX_AGE_SECONDS,
        "Spark auth challenge is not fresh"
    );
    Ok(())
}

/// Every auth ticket names the exact identity scope (current owner, coin and
/// session) the existing joint identity commands authorize.
pub fn scope_digest(base: &crate::spark_lineage::Intent) -> Result<Digest> {
    Ok(hash(&[b"ZARK/spark/auth/scope/v1", &base.encode()?]))
}

/// Everything the signer fixes before releasing its nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthHeader {
    pub scope: Digest,
    pub key_commitment: Digest,
    pub server: [u8; 64],
    pub timestamp: u64,
}
impl AuthHeader {
    pub fn encode(&self) -> Result<[u8; HEADER_LEN]> {
        ensure!(
            self.scope != [0; 32] && self.key_commitment != [0; 32],
            "zero Spark auth binding"
        );
        challenge::check_timestamp(self.timestamp)?;
        point(&self.server)?;
        let mut out = [0; HEADER_LEN];
        out[..4].copy_from_slice(&VERSION);
        out[4..36].copy_from_slice(&self.scope);
        out[36..68].copy_from_slice(&self.key_commitment);
        out[68..132].copy_from_slice(&self.server);
        out[132..].copy_from_slice(&self.timestamp.to_le_bytes());
        Ok(out)
    }
}

/// Public proof statement: the header, the frozen blinding commitment, the
/// signer's nonce point and the submitted blinded challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthStatement {
    pub header: AuthHeader,
    pub commitment: Digest,
    pub nonce: [u8; 64],
    pub challenge: Digest,
}
impl AuthStatement {
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure!(self.commitment != [0; 32], "zero Spark auth commitment");
        point(&self.nonce)?;
        scalar(&self.challenge)?;
        let out = [
            &self.header.encode()?[..],
            &self.commitment,
            &self.nonce,
            &self.challenge,
        ]
        .concat();
        ensure!(out.len() == ENCODED_LEN, "Spark auth statement size");
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == ENCODED_LEN, "Spark auth statement size");
        ensure!(bytes[..4] == VERSION, "Spark auth statement version");
        let digest = |offset: usize| -> Digest {
            bytes[offset..offset + 32]
                .try_into()
                .expect("checked auth statement size")
        };
        let value = Self {
            header: AuthHeader {
                scope: digest(4),
                key_commitment: digest(36),
                server: bytes[68..132].try_into()?,
                timestamp: u64::from_le_bytes(bytes[132..140].try_into()?),
            },
            commitment: digest(140),
            nonce: bytes[172..236].try_into()?,
            challenge: digest(236),
        };
        ensure!(
            value.encode()? == bytes,
            "noncanonical Spark auth statement"
        );
        Ok(value)
    }
}

/// Wallet opening frozen before the server nonce exists. It fixes the message,
/// so the wallet can choose neither the challenge nor the blinding afterwards.
pub fn blinding_commitment(
    header: &AuthHeader,
    message: &Digest,
    alpha: &Digest,
    beta: &Digest,
    salt: &Digest,
) -> Result<Digest> {
    for value in [alpha, beta] {
        ensure!(
            !bool::from(scalar(value)?.is_zero()),
            "zero Spark auth blinding"
        );
    }
    ensure!(*salt != [0; 32], "zero Spark auth salt");
    Ok(application_hash::hash(&[
        b"ZARK/spark/auth/blinding/v1",
        &header.encode()?,
        message,
        alpha,
        beta,
        salt,
    ]))
}

/// Same commitment the garbled-circuit identity path uses for the wallet share.
pub fn key_commitment(user: &Digest, salt: &Digest) -> Result<Digest> {
    let factor = scalar(&KEY_FACTOR)?;
    Ok(hash(&[
        &(scalar(user)? * factor).to_bytes(),
        salt,
        &hash(&[b"ZARK/spark/joint-identity/key-commit/v1"]),
    ]))
}
// 2^256 mod n, matching the circuit's KEY_FACTOR and the identity GC encoding.
const KEY_FACTOR: Digest = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 69, 81, 35, 25, 80, 183, 95, 196, 64, 45, 161,
    115, 47, 201, 190, 191,
];
