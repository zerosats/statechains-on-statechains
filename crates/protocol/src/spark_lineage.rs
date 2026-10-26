//! Spark ownership-lineage statements, separate from Bitcoin protocol bytes.
//!
//! The four implemented roles cover origin and private handover, not a native
//! exit. Neither these encodings nor a recovery primitive establish ownership.
//! Trusted registry pins and the durable signer's current state are required.
use crate::{
    application_hash, handoff::validate_recursive_vk_hash, spark_recovery::RecoveryAuthorization,
};
use anyhow::{Result, ensure};
use k256::schnorr::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
mod commitments;
#[cfg(test)]
mod tests;
mod verifier;
pub use commitments::{
    bridge_commitment, capability_commitment, delta_commitment, draft_state_commitment,
    draft_token_commitment, mask_commitment, masked_share_commitment, origin_field,
    origin_previous_state, public_capability_commitment, recipient_claim_commitment,
    require_intent, server_commitment, state_commitment,
};
pub use verifier::{PinnedSparkVerifier, SparkRole, VerifiedSparkRole};

pub type Digest = [u8; 32];
pub const VERSION: u32 = 1;
/// Registry identifier for authenticated manifests. VERSION 1 here names only
/// this Spark four-role suite; it cannot be interpreted as Bitcoin's six roles.
pub const REGISTRY: &str = "zark-spark-private-ownership-four-role-v1";
pub const ROLE_COUNT: usize = 4;
pub const DEPOSIT: usize = 0;
pub const SENDER_FROM_ORIGIN: usize = 1;
pub const SENDER_FROM_TRANSFER: usize = 2;
pub const RECEIVER: usize = 3;

pub(crate) fn nonzero(value: &Digest) -> Result<()> {
    ensure!(*value != [0; 32], "zero Spark ownership field");
    Ok(())
}
pub(crate) fn part(bytes: &[u8], offset: usize) -> Digest {
    bytes[offset..offset + 32]
        .try_into()
        .expect("checked ownership statement length")
}
pub(crate) fn domain(deployment: &Digest, coin: &Digest) -> Result<Vec<u8>> {
    nonzero(deployment)?;
    nonzero(coin)?;
    Ok([VERSION.to_le_bytes().as_slice(), deployment, coin].concat())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub origin_key: Digest,
    pub role_hashes: [Digest; ROLE_COUNT],
}
impl Config {
    pub const ENCODED_LEN: usize = 160;
    pub fn encode(&self) -> Result<Vec<u8>> {
        nonzero(&self.origin_key)?;
        VerifyingKey::from_bytes(&self.origin_key)?;
        let mut out = self.origin_key.to_vec();
        for (i, role) in self.role_hashes.iter().enumerate() {
            validate_recursive_vk_hash(role)?;
            ensure!(
                !self.role_hashes[..i].contains(role),
                "duplicate Spark role hash"
            );
            out.extend_from_slice(role);
        }
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == Self::ENCODED_LEN, "Spark role config length");
        let value = Self {
            origin_key: part(bytes, 0),
            role_hashes: std::array::from_fn(|i| part(bytes, 32 + i * 32)),
        };
        ensure!(value.encode()? == bytes, "noncanonical Spark role config");
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub deployment: Digest,
    pub coin: Digest,
    pub previous_state: Digest,
    pub operation: Digest,
    pub recipient_claim: Digest,
    pub revision: u64,
}
impl Intent {
    pub const ENCODED_LEN: usize = 172;
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = domain(&self.deployment, &self.coin)?;
        for value in [&self.previous_state, &self.operation, &self.recipient_claim] {
            nonzero(value)?;
            out.extend_from_slice(value);
        }
        ensure!(self.revision > 0, "Spark handover CAS revision");
        out.extend_from_slice(&self.revision.to_le_bytes());
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == Self::ENCODED_LEN, "Spark intent length");
        let value = Self {
            deployment: part(bytes, 4),
            coin: part(bytes, 36),
            previous_state: part(bytes, 68),
            operation: part(bytes, 100),
            recipient_claim: part(bytes, 132),
            revision: u64::from_le_bytes(bytes[164..172].try_into()?),
        };
        ensure!(value.encode()? == bytes, "noncanonical Spark intent");
        Ok(value)
    }
    pub fn digest(&self) -> Result<Digest> {
        Ok(application_hash::hash(&[
            b"ZARK/spark/ownership/intent/v1",
            &self.encode()?,
        ]))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    pub deployment: Digest,
    pub coin: Digest,
    pub backing: Digest,
    pub state: Digest,
    pub policy: Digest,
    pub config: Config,
}
impl Certificate {
    pub const ENCODED_LEN: usize = 324;
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = domain(&self.deployment, &self.coin)?;
        for value in [&self.backing, &self.state, &self.policy] {
            nonzero(value)?;
            out.extend_from_slice(value);
        }
        out.extend_from_slice(&self.config.encode()?);
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == Self::ENCODED_LEN, "Spark certificate length");
        let value = Self {
            deployment: part(bytes, 4),
            coin: part(bytes, 36),
            backing: part(bytes, 68),
            state: part(bytes, 100),
            policy: part(bytes, 132),
            config: Config::decode(&bytes[164..])?,
        };
        ensure!(value.encode()? == bytes, "noncanonical Spark certificate");
        Ok(value)
    }
    pub fn origin_message(&self) -> Result<Digest> {
        Ok(application_hash::hash(&[
            b"ZARK/spark/ownership/origin/v1",
            &self.encode()?,
        ]))
    }
    pub fn verify_origin_attestation(&self, signature: &[u8; 64]) -> Result<()> {
        VerifyingKey::from_bytes(&self.config.origin_key)?.verify_raw(
            &self.origin_message()?,
            &Signature::try_from(signature.as_slice())?,
        )?;
        Ok(())
    }
    /// Reconstructs canonical state bytes, without verifying partial equations,
    /// proofs or ownership. An accepted private certificate separately requires
    /// both actual responses and its pinned deposit/receiver role verification.
    pub fn from_issuance(issuance: &Issuance, partials: &[Digest; 2]) -> Result<Self> {
        let recovery = &issuance.recovery;
        let context = &recovery.context;
        let state = state_commitment(
            &context.deployment,
            &context.coin,
            &recovery.backing,
            &issuance.next_capability,
            &recovery.recovery,
            &issuance.server_share,
            &recovery.policy,
            &issuance.issuance_commitment(partials)?,
        )?;
        let value = Self {
            deployment: context.deployment,
            coin: context.coin,
            backing: recovery.backing,
            state,
            policy: recovery.policy,
            config: issuance.config.clone(),
        };
        value.encode()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Handover {
    pub intent: Intent,
    pub backing: Digest,
    pub mask: Digest,
    pub masked_share: Digest,
    pub bridge: Digest,
    pub previous_capability: Digest,
    pub server_share: Digest,
    pub policy: Digest,
    pub draft_token: Digest,
    pub config: Config,
}
impl Handover {
    pub const ENCODED_LEN: usize = 588;
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = self.intent.encode()?;
        for value in [
            &self.backing,
            &self.mask,
            &self.masked_share,
            &self.bridge,
            &self.previous_capability,
            &self.server_share,
            &self.policy,
            &self.draft_token,
        ] {
            nonzero(value)?;
            out.extend_from_slice(value);
        }
        out.extend_from_slice(&self.config.encode()?);
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == Self::ENCODED_LEN, "Spark handover length");
        let value = Self {
            intent: Intent::decode(&bytes[..172])?,
            backing: part(bytes, 172),
            mask: part(bytes, 204),
            masked_share: part(bytes, 236),
            bridge: part(bytes, 268),
            previous_capability: part(bytes, 300),
            server_share: part(bytes, 332),
            policy: part(bytes, 364),
            draft_token: part(bytes, 396),
            config: Config::decode(&bytes[428..])?,
        };
        ensure!(value.encode()? == bytes, "noncanonical Spark handover");
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issuance {
    pub recovery: RecoveryAuthorization,
    pub recipient_claim: Digest,
    pub mask: Digest,
    pub masked_share: Digest,
    pub bridge: Digest,
    pub delta: Digest,
    pub previous_capability: Digest,
    pub next_capability: Digest,
    pub server_share: Digest,
    pub config: Config,
}
impl Issuance {
    pub const ENCODED_LEN: usize = 1036;
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = self.recovery.encode()?;
        for value in [
            &self.recipient_claim,
            &self.mask,
            &self.masked_share,
            &self.bridge,
            &self.delta,
            &self.previous_capability,
            &self.next_capability,
            &self.server_share,
        ] {
            nonzero(value)?;
            out.extend_from_slice(value);
        }
        ensure!(
            self.previous_capability != self.next_capability,
            "Spark capability rotation"
        );
        out.extend_from_slice(&self.config.encode()?);
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == Self::ENCODED_LEN, "Spark issuance length");
        let value = Self {
            recovery: RecoveryAuthorization::decode(&bytes[..620])?,
            recipient_claim: part(bytes, 620),
            mask: part(bytes, 652),
            masked_share: part(bytes, 684),
            bridge: part(bytes, 716),
            delta: part(bytes, 748),
            previous_capability: part(bytes, 780),
            next_capability: part(bytes, 812),
            server_share: part(bytes, 844),
            config: Config::decode(&bytes[876..])?,
        };
        ensure!(value.encode()? == bytes, "noncanonical Spark issuance");
        Ok(value)
    }
    pub fn digest(&self) -> Result<Digest> {
        Ok(application_hash::hash(&[
            b"ZARK/spark/ownership/authorization/v1",
            &self.encode()?,
        ]))
    }
    pub fn issuance_commitment(&self, partials: &[Digest; 2]) -> Result<Digest> {
        crate::scalar(&partials[0])?;
        crate::scalar(&partials[1])?;
        Ok(application_hash::hash(&[
            b"ZARK/spark/ownership/issuance/v1",
            &self.digest()?,
            &partials[0],
            &partials[1],
        ]))
    }
}
