//! Fresh allocation authorization for ROOT + two initial native refunds.
//! No issued ownership certificate exists yet. The real Engine must match the
//! allocated session/point/intent and retain the exact backing/capability for
//! subsequent origin issuance. This does not prove chain state or settlement.
use crate::{
    application_hash, hash, point, scalar,
    spark_lineage::{self, Config, Digest},
};
use anyhow::{Result, ensure};
use k256::schnorr::{Signature, VerifyingKey};
use zeroize::Zeroize;
mod plan;
#[cfg(test)]
mod tests;
mod verifier;
mod witness;
pub use plan::{CreationBodies, PlanOpening};
pub use verifier::{PinnedNativeBootstrapVerifier, VerifiedNativeBootstrap};
pub use witness::{BootstrapJobOpening, BootstrapWitness};

pub const VERSION: u32 = 1;
pub const JOB_COUNT: usize = 3;
pub const ENCODED_LEN: usize = 940;
pub const REGISTRY: &str = "zark-spark-native-bootstrap-initial-root-three-job-v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapContext {
    pub deployment: Digest,
    pub coin: Digest,
    pub allocation_state: Digest,
    pub operation: Digest,
    pub session: Digest,
    pub revision: u64,
}
impl BootstrapContext {
    pub const ENCODED_LEN: usize = 172;
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = VERSION.to_le_bytes().to_vec();
        for value in [
            &self.deployment,
            &self.coin,
            &self.allocation_state,
            &self.operation,
            &self.session,
        ] {
            ensure!(*value != [0; 32], "zero native bootstrap context");
            out.extend_from_slice(value);
        }
        ensure!(
            self.allocation_state
                == spark_lineage::origin_previous_state(&self.deployment, &self.coin)?,
            "bootstrap origin allocation state"
        );
        VerifyingKey::from_bytes(&self.session)?;
        ensure!(self.revision == 1, "bootstrap allocation starting revision");
        out.extend_from_slice(&self.revision.to_le_bytes());
        Ok(out)
    }
    pub fn owner_message(
        &self,
        backing: &Digest,
        capability: &Digest,
        plan: &Digest,
        server: &[u8; 64],
        commitments: &[Digest; 3],
    ) -> Result<Digest> {
        ensure!(
            *backing != [0; 32] && *capability != [0; 32] && *plan != [0; 32],
            "bootstrap owner binding"
        );
        point(server)?;
        for i in 0..3 {
            ensure!(
                commitments[i] != [0; 32],
                "zero bootstrap blinding commitment"
            );
            for j in 0..i {
                ensure!(
                    commitments[i] != commitments[j],
                    "bootstrap blinding commitment reuse"
                );
            }
        }
        Ok(hash(&[
            b"ZARK/spark/native/bootstrap-owner-prepare/v1",
            &self.encode()?,
            backing,
            capability,
            plan,
            server,
            &commitments[0],
            &commitments[1],
            &commitments[2],
        ]))
    }
    #[allow(clippy::too_many_arguments)]
    pub fn verify_owner(
        &self,
        backing: &Digest,
        capability: &Digest,
        plan: &Digest,
        server: &[u8; 64],
        commitments: &[Digest; 3],
        public: &Digest,
        signature: &[u8; 64],
    ) -> Result<()> {
        ensure!(
            *public != self.session
                && spark_lineage::public_capability_commitment(
                    &self.deployment,
                    &self.coin,
                    public
                )? == *capability,
            "bootstrap initial owner capability"
        );
        VerifyingKey::from_bytes(public)?.verify_raw(
            &self.owner_message(backing, capability, plan, server, commitments)?,
            &Signature::try_from(signature.as_slice())?,
        )?;
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapBranch {
    pub server_nonce: [u8; 64],
    pub challenge: Digest,
    pub blinding_commitment: Digest,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapAuthorization {
    pub context: BootstrapContext,
    pub backing: Digest,
    pub policy: Digest,
    pub capability: Digest,
    pub plan: Digest,
    pub cluster: Digest,
    pub server: [u8; 64],
    pub config: Config,
    pub branches: [BootstrapBranch; 3],
}
impl BootstrapAuthorization {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = self.context.encode()?;
        for value in [
            &self.backing,
            &self.policy,
            &self.capability,
            &self.plan,
            &self.cluster,
        ] {
            ensure!(*value != [0; 32], "zero bootstrap commitment");
            out.extend_from_slice(value);
        }
        point(&self.server)?;
        out.extend_from_slice(&self.server);
        out.extend_from_slice(&self.config.encode()?);
        for (i, branch) in self.branches.iter().enumerate() {
            point(&branch.server_nonce)?;
            scalar(&branch.challenge)?;
            ensure!(
                branch.blinding_commitment != [0; 32],
                "zero bootstrap blinding commitment"
            );
            for other in &self.branches[..i] {
                ensure!(
                    branch.server_nonce[..32] != other.server_nonce[..32]
                        && branch.blinding_commitment != other.blinding_commitment,
                    "bootstrap branch nonce reuse"
                );
            }
            out.extend_from_slice(&branch.server_nonce);
            out.extend_from_slice(&branch.challenge);
            out.extend_from_slice(&branch.blinding_commitment);
        }
        ensure!(out.len() == ENCODED_LEN, "bootstrap statement size");
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == ENCODED_LEN, "bootstrap statement size");
        let part = |offset: usize| -> Digest {
            bytes[offset..offset + 32]
                .try_into()
                .expect("checked bootstrap statement length")
        };
        let value = Self {
            context: BootstrapContext {
                deployment: part(4),
                coin: part(36),
                allocation_state: part(68),
                operation: part(100),
                session: part(132),
                revision: u64::from_le_bytes(bytes[164..172].try_into()?),
            },
            backing: part(172),
            policy: part(204),
            capability: part(236),
            plan: part(268),
            cluster: part(300),
            server: bytes[332..396].try_into()?,
            config: Config::decode(&bytes[396..556])?,
            branches: std::array::from_fn(|i| {
                let offset = 556 + 128 * i;
                BootstrapBranch {
                    server_nonce: bytes[offset..offset + 64]
                        .try_into()
                        .expect("checked bootstrap statement length"),
                    challenge: part(offset + 64),
                    blinding_commitment: part(offset + 96),
                }
            }),
        };
        ensure!(value.encode()? == bytes, "noncanonical bootstrap statement");
        Ok(value)
    }
    pub fn digest(&self) -> Result<Digest> {
        Ok(hash(&[
            b"ZARK/spark/native/bootstrap-authorization/v1",
            &self.encode()?,
        ]))
    }
}
pub struct WalletOpening {
    pub alpha: Digest,
    pub beta: Digest,
    pub binding: Digest,
    pub salt: Digest,
}
impl Drop for WalletOpening {
    fn drop(&mut self) {
        self.alpha.zeroize();
        self.beta.zeroize();
        self.binding.zeroize();
        self.salt.zeroize();
    }
}
impl WalletOpening {
    pub(crate) fn native(&self) -> crate::spark_native::WalletOpening {
        crate::spark_native::WalletOpening {
            alpha: self.alpha,
            beta: self.beta,
            binding: self.binding,
            salt: self.salt,
        }
    }
    pub fn commitment(
        &self,
        context: &BootstrapContext,
        backing: &Digest,
        plan: &Digest,
        server: &[u8; 64],
        index: u32,
    ) -> Result<Digest> {
        ensure!(
            index < 3 && *backing != [0; 32] && *plan != [0; 32] && self.salt != [0; 32],
            "bootstrap wallet opening domain"
        );
        point(server)?;
        for secret in [&self.alpha, &self.beta, &self.binding] {
            ensure!(
                !bool::from(scalar(secret)?.is_zero()),
                "bootstrap wallet scalar zero"
            );
        }
        Ok(application_hash::hash(&[
            b"ZARK/spark/native/bootstrap-wallet-blinding/v1",
            &context.encode()?,
            backing,
            plan,
            server,
            &index.to_le_bytes(),
            &self.alpha,
            &self.beta,
            &self.binding,
            &self.salt,
        ]))
    }
}
