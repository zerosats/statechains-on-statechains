//! One ordinary Spark USER signing job, authorized by current private ownership.
//! Separate pins and nonce purpose; existing ownership/native proof bytes stay
//! unchanged. Issuance does not prove Spark settlement or release ownership.
use crate::{
    application_hash, hash, point, scalar,
    spark_lineage::{Config, Digest},
    spark_native::ExitContext,
};
use anyhow::{Result, ensure};
use k256::schnorr::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
mod plan;
#[cfg(test)]
mod tests;
mod transcript;
mod verifier;
mod witness;
pub use plan::{SigningBodies, SigningPlan};
pub use transcript::{USER_IDENTIFIER, blinded_challenge};
pub use verifier::{PinnedSingleUserVerifier, SigningRole, VerifiedSigning};
pub use witness::SigningWitness;
pub const REGISTRY: &str = "zark-spark-single-user-initial-root-two-role-v1";
pub const ENCODED_LEN: usize = 652;
pub const PURPOSE: &str = "single-user-initial-root-refund-v1";

pub fn owner_message(context: &ExitContext, plan: &Digest, commitment: &Digest) -> Result<Digest> {
    ensure!(
        *plan != [0; 32] && *commitment != [0; 32],
        "single-USER preparation commitments"
    );
    Ok(hash(&[
        b"ZARK/spark/single-user/owner/v1",
        &context.encode()?,
        plan,
        commitment,
    ]))
}
pub fn verify_owner(
    context: &ExitContext,
    plan: &Digest,
    commitment: &Digest,
    capability: &Digest,
    public: &Digest,
    signature: &[u8],
) -> Result<()> {
    ensure!(
        *public != context.session,
        "single-USER owner/session separation"
    );
    ensure!(
        crate::spark_lineage::public_capability_commitment(
            &context.deployment,
            &context.coin,
            public
        )? == *capability,
        "single-USER current owner capability"
    );
    VerifyingKey::from_bytes(public)?.verify_raw(
        &owner_message(context, plan, commitment)?,
        &Signature::try_from(signature)?,
    )?;
    Ok(())
}

#[derive(Clone, PartialEq, Eq)]
pub struct SigningAuthorization {
    pub context: ExitContext,
    pub backing: Digest,
    pub policy: Digest,
    pub capability: Digest,
    pub plan: Digest,
    pub server: [u8; 64],
    pub config: Config,
    pub nonce: [u8; 64],
    pub challenge: Digest,
    pub blinding: Digest,
}
impl SigningAuthorization {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = self.context.encode()?;
        for value in [&self.backing, &self.policy, &self.capability, &self.plan] {
            ensure!(*value != [0; 32], "zero single-USER commitment");
            bytes.extend_from_slice(value);
        }
        point(&self.server)?;
        bytes.extend_from_slice(&self.server);
        bytes.extend_from_slice(&self.config.encode()?);
        point(&self.nonce)?;
        scalar(&self.challenge)?;
        ensure!(self.blinding != [0; 32], "zero single-USER blinding");
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.challenge);
        bytes.extend_from_slice(&self.blinding);
        ensure!(bytes.len() == ENCODED_LEN, "single-USER statement size");
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == ENCODED_LEN, "single-USER statement size");
        let d = |o: usize| -> Digest {
            bytes[o..o + 32]
                .try_into()
                .expect("checked statement length")
        };
        let value = Self {
            context: ExitContext {
                deployment: d(4),
                coin: d(36),
                current_state: d(68),
                operation: d(100),
                session: d(132),
                revision: u64::from_le_bytes(bytes[164..172].try_into()?),
            },
            backing: d(172),
            policy: d(204),
            capability: d(236),
            plan: d(268),
            server: bytes[300..364].try_into()?,
            config: Config::decode(&bytes[364..524])?,
            nonce: bytes[524..588].try_into()?,
            challenge: d(588),
            blinding: d(620),
        };
        ensure!(
            value.encode()? == bytes,
            "noncanonical single-USER statement"
        );
        Ok(value)
    }
    pub fn digest(&self) -> Result<Digest> {
        Ok(hash(&[
            b"ZARK/spark/single-user/authorization/v1",
            &self.encode()?,
        ]))
    }
}

/// Wallet-only prover opening. A typed commitment is frozen before nonce release.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Opening {
    pub alpha: Digest,
    pub beta: Digest,
    pub binding: Digest,
    pub salt: Digest,
}
impl Drop for Opening {
    fn drop(&mut self) {
        self.alpha.zeroize();
        self.beta.zeroize();
        self.binding.zeroize();
        self.salt.zeroize();
    }
}
impl Opening {
    pub fn commitment(
        &self,
        context: &ExitContext,
        plan: &Digest,
        server: &[u8; 64],
    ) -> Result<Digest> {
        ensure!(
            *plan != [0; 32] && self.salt != [0; 32],
            "single-USER opening domain"
        );
        point(server)?;
        for s in [&self.alpha, &self.beta, &self.binding] {
            ensure!(
                !bool::from(scalar(s)?.is_zero()),
                "zero single-USER blinding scalar"
            );
        }
        Ok(application_hash::hash(&[
            b"ZARK/spark/single-user/blinding/v1",
            &context.encode()?,
            plan,
            server,
            &self.alpha,
            &self.beta,
            &self.binding,
            &self.salt,
        ]))
    }
}
