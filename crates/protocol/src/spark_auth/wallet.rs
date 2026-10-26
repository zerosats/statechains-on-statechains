//! Wallet-only blinding. No routine here takes or returns the signer's share.
//!
//! BIP-340 verifies under the even-y lifts of P and R. With signs sp, sr in
//! {1, -1} making them even, the signer answers z = k + c'x_s for
//! c' = beta + sr*sp*e, and the wallet completes s = sr*(z + alpha) + e*sp*x_w,
//! which is the discrete log of even R plus e times that of even P.
use super::{AuthHeader, SparkChallenge, blinding_commitment, key_commitment};
use crate::{
    even, point, point_bytes, random_scalar, random32, reduce, scalar, spark_lineage::Digest,
    tagged_hash,
};
use anyhow::{Result, ensure};
use k256::{
    ProjectivePoint, Scalar,
    schnorr::{Signature, VerifyingKey},
};
use zeroize::{Zeroize, Zeroizing};

/// The fixed joint identity key P = x_w*G + X_s and its GC-compatible opening.
pub struct IdentityKey {
    pub(crate) user: Digest,
    pub(crate) salt: Digest,
    pub(crate) server: [u8; 64],
    pub(crate) joint: ProjectivePoint,
    commitment: Digest,
}
impl Drop for IdentityKey {
    fn drop(&mut self) {
        self.user.zeroize();
        self.salt.zeroize();
    }
}
impl IdentityKey {
    pub fn new(user: Digest, salt: Digest, server: [u8; 64]) -> Result<Self> {
        let share = Zeroizing::new(scalar(&user)?);
        ensure!(
            *share != Scalar::ZERO && salt != [0; 32],
            "zero Spark identity opening"
        );
        let joint = point(&server)? + ProjectivePoint::GENERATOR * *share;
        point_bytes(joint)?;
        Ok(Self {
            commitment: key_commitment(&user, &salt)?,
            user,
            salt,
            server,
            joint,
        })
    }
    pub fn commitment(&self) -> Digest {
        self.commitment
    }
    pub fn compressed(&self) -> Result<[u8; 33]> {
        let raw = point_bytes(self.joint)?;
        let mut out = [0; 33];
        out[0] = 2 + (raw[63] & 1);
        out[1..].copy_from_slice(&raw[..32]);
        Ok(out)
    }
    pub fn header(&self, scope: Digest, timestamp: u64) -> AuthHeader {
        AuthHeader {
            scope,
            key_commitment: self.commitment,
            server: self.server,
            timestamp,
        }
    }
    /// A challenge for another key is never blinded, even for a local retry.
    pub fn check_challenge(&self, challenge: &SparkChallenge) -> Result<()> {
        ensure!(
            challenge.public_key == self.compressed()?,
            "Spark auth challenge names another key"
        );
        challenge.encode()?;
        Ok(())
    }
}

/// Durable before the commitment leaves the wallet; reused only for the exact
/// same frozen ticket, never for a second server nonce.
#[derive(Clone)]
pub struct AuthBlinding {
    pub alpha: Digest,
    pub beta: Digest,
    pub salt: Digest,
}
impl Drop for AuthBlinding {
    fn drop(&mut self) {
        self.alpha.zeroize();
        self.beta.zeroize();
        self.salt.zeroize();
    }
}

/// Session values the wallet keeps between the challenge and the response.
pub struct BlindedAuth {
    pub challenge: Digest,
    nonce: ProjectivePoint,
    e: Scalar,
    pub(super) nonce_sign: Scalar,
    pub(super) key_sign: Scalar,
}

impl AuthBlinding {
    pub fn random() -> Self {
        Self {
            alpha: random_scalar().to_bytes().into(),
            beta: random_scalar().to_bytes().into(),
            salt: random32(),
        }
    }
    pub fn commitment(&self, header: &AuthHeader, message: &Digest) -> Result<Digest> {
        blinding_commitment(header, message, &self.alpha, &self.beta, &self.salt)
    }
    pub fn bind(
        &self,
        key: &IdentityKey,
        server_nonce: &[u8; 64],
        message: &Digest,
    ) -> Result<BlindedAuth> {
        let (joint, key_sign) = even(key.joint)?;
        let (nonce, nonce_sign) = even(
            point(server_nonce)?
                + ProjectivePoint::GENERATOR * scalar(&self.alpha)?
                + point(&key.server)? * scalar(&self.beta)?,
        )?;
        let e = reduce(tagged_hash(
            "BIP0340/challenge",
            &[
                &point_bytes(nonce)?[..32],
                &point_bytes(joint)?[..32],
                message,
            ],
        ));
        let challenge = scalar(&self.beta)? + nonce_sign * key_sign * e;
        Ok(BlindedAuth {
            challenge: challenge.to_bytes().into(),
            nonce,
            e,
            nonce_sign,
            key_sign,
        })
    }
    /// Verifies the signer's contribution and the final signature before release.
    pub fn finish(
        &self,
        key: &IdentityKey,
        bound: &BlindedAuth,
        server_nonce: &[u8; 64],
        partial: &Digest,
        message: &Digest,
    ) -> Result<[u8; 64]> {
        let z = scalar(partial)?;
        ensure!(
            ProjectivePoint::GENERATOR * z
                == point(server_nonce)? + point(&key.server)? * scalar(&bound.challenge)?,
            "invalid Spark auth server contribution"
        );
        let user = Zeroizing::new(scalar(&key.user)?);
        let s = bound.nonce_sign * (z + scalar(&self.alpha)?) + bound.e * bound.key_sign * *user;
        let mut signature = [0; 64];
        signature[..32].copy_from_slice(&point_bytes(bound.nonce)?[..32]);
        signature[32..].copy_from_slice(&s.to_bytes());
        VerifyingKey::from_bytes(&key.compressed()?[1..])?
            .verify_raw(message, &Signature::try_from(signature.as_slice())?)?;
        Ok(signature)
    }
}

/// Explicit wallet-local prover input. Never send this to a signer.
pub struct AuthWitness<'a> {
    pub key: &'a IdentityKey,
    pub challenge: &'a SparkChallenge,
    pub blinding: &'a AuthBlinding,
}
impl AuthWitness<'_> {
    pub fn prover_toml(&self, statement: &super::AuthStatement) -> Result<Zeroizing<String>> {
        self.key.check_challenge(self.challenge)?;
        ensure!(
            statement.header
                == self
                    .key
                    .header(statement.header.scope, self.challenge.timestamp),
            "Spark auth witness differs from statement header"
        );
        let bytes = statement.encode()?;
        let packed = crate::public_fields(&bytes)
            .chunks_exact(32)
            .map(|b| format!("\"0x{}\"", hex::encode(b)))
            .collect::<Vec<_>>()
            .join(",");
        let mut out = Zeroizing::new(format!(
            "packed = [{packed}]\nstatement = {}\n",
            array(&bytes)
        ));
        for (name, value) in [
            ("user", &self.key.user),
            ("key_salt", &self.key.salt),
            ("challenge_nonce", &self.challenge.nonce),
            ("alpha", &self.blinding.alpha),
            ("beta", &self.blinding.beta),
            ("salt", &self.blinding.salt),
        ] {
            out.push_str(&format!("{name} = {}\n", array(value)));
        }
        Ok(out)
    }
}

fn array(bytes: &[u8]) -> String {
    format!(
        "[{}]",
        bytes
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}
