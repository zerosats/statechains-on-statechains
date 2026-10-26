//! Client-side blinding. No routine takes the server's secret share.
use crate::{
    even, handoff::Digest, point, point_bytes, random_scalar, reduce, scalar, tagged_hash,
};
use anyhow::{Result, ensure};
use k256::{ProjectivePoint, Scalar};
use zeroize::Zeroize;

/// Checks a server partial against its public share, nonce and challenge.
pub fn verify_partial(
    server: &[u8; 64],
    nonce: &[u8; 64],
    challenge: &Digest,
    partial: &Digest,
) -> Result<()> {
    ensure!(
        k256::ProjectivePoint::GENERATOR * scalar(partial)?
            == point(nonce)? + point(server)? * scalar(challenge)?,
        "invalid signing response"
    );
    Ok(())
}

pub struct FundingKey {
    pub internal: ProjectivePoint,
    pub output: ProjectivePoint,
    pub server_coefficient: Scalar,
    user_effective: Scalar,
}

impl FundingKey {
    pub fn new(server: ProjectivePoint, owner: Scalar) -> Result<Self> {
        let (internal, p_sign) = even(server + ProjectivePoint::GENERATOR * owner)?;
        let t = scalar(&tagged_hash("TapTweak", &[&point_bytes(internal)?[..32]]))?;
        let (output, q_sign) = even(internal + ProjectivePoint::GENERATOR * t)?;
        Ok(Self {
            internal,
            output,
            server_coefficient: p_sign * q_sign,
            user_effective: q_sign * (p_sign * owner + t),
        })
    }
    pub fn xonly(&self) -> Result<[u8; 32]> {
        Ok(point_bytes(self.output)?[..32].try_into()?)
    }
}

impl Drop for FundingKey {
    fn drop(&mut self) {
        self.user_effective.zeroize();
    }
}

pub struct Blinding {
    pub alpha: Scalar,
    pub beta: Scalar,
}
impl Default for Blinding {
    fn default() -> Self {
        Self {
            alpha: random_scalar(),
            beta: random_scalar(),
        }
    }
}
impl Drop for Blinding {
    fn drop(&mut self) {
        self.alpha.zeroize();
        self.beta.zeroize();
    }
}

pub struct SigningSession {
    pub challenge: Scalar,
    pub nonce: ProjectivePoint,
    e: Scalar,
    nonce_sign: Scalar,
}

impl Blinding {
    pub fn bind(
        &self,
        key: &FundingKey,
        server: ProjectivePoint,
        server_nonce: ProjectivePoint,
        message: [u8; 32],
    ) -> Result<SigningSession> {
        let (nonce, nonce_sign) =
            even(server_nonce + ProjectivePoint::GENERATOR * self.alpha + server * self.beta)?;
        let e = reduce(tagged_hash(
            "BIP0340/challenge",
            &[&point_bytes(nonce)?[..32], &key.xonly()?, &message],
        ));
        Ok(SigningSession {
            challenge: self.beta + nonce_sign * e * key.server_coefficient,
            nonce,
            e,
            nonce_sign,
        })
    }
    pub fn finish(
        &self,
        key: &FundingKey,
        session: &SigningSession,
        server: ProjectivePoint,
        server_nonce: ProjectivePoint,
        partial: Scalar,
    ) -> Result<[u8; 64]> {
        ensure!(
            ProjectivePoint::GENERATOR * partial == server_nonce + server * session.challenge,
            "invalid server contribution"
        );
        let sig_s = session.nonce_sign * (partial + self.alpha) + session.e * key.user_effective;
        let mut sig = [0; 64];
        sig[..32].copy_from_slice(&point_bytes(session.nonce)?[..32]);
        sig[32..].copy_from_slice(&sig_s.to_bytes());
        Ok(sig)
    }
}
