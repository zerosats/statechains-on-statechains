//! Private authorization of initial-root native Spark refund signatures.
//!
//! Separate from the immutable four-role ownership suite. These records do not
//! authorize native key-share export, prove chain freshness or complete a native
//! transfer. The signer retains its ownership lock through native reconciliation.
use crate::{
    application_hash, hash, point, scalar,
    spark_lineage::{self, Config, Digest},
};
use anyhow::{Result, ensure};
use k256::schnorr::{Signature, VerifyingKey};
use zeroize::Zeroize;
mod frost;
mod plan;
#[cfg(test)]
mod tests;
mod verifier;
mod witness;
pub use frost::{JobTranscript, Participant, blinded_native_challenge, frost_h1};
pub use plan::{NativeBodies, PlanOpening};
pub(crate) use plan::{
    compressed as native_compressed, sighash_for_prevout as native_sighash,
    taproot as native_taproot, transaction as native_transaction,
};
pub use verifier::{NativeExitRole, PinnedNativeExitVerifier, VerifiedNativeExit};
pub use witness::{ExitWitness, NativeJobOpening};

pub const VERSION: u32 = 1;
pub const PROFILE_INITIAL_ROOT: u32 = 1;
pub const JOB_COUNT: usize = 2;
pub const ENCODED_LEN: usize = 812;
pub const REGISTRY: &str = "zark-spark-native-initial-root-two-role-v1";
pub const ORDINARY_REGISTRY: &str = "zark-spark-native-initial-root-ordinary-user-v1";

/// Each ordinary refund has an independent single-USER blinding domain while
/// the proof still authenticates one complete two-refund exit plan.
pub fn ordinary_branch_plan(plan: &Digest, index: usize) -> Result<Digest> {
    ensure!(
        *plan != [0; 32] && index < 2,
        "ordinary native branch domain"
    );
    Ok(hash(&[
        b"ZARK/spark/native/ordinary-branch/v1",
        plan,
        &[index as u8],
    ]))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExitContext {
    pub deployment: Digest,
    pub coin: Digest,
    pub current_state: Digest,
    pub operation: Digest,
    pub session: Digest,
    pub revision: u64,
}
impl ExitContext {
    pub const ENCODED_LEN: usize = 172;
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = VERSION.to_le_bytes().to_vec();
        for value in [
            &self.deployment,
            &self.coin,
            &self.current_state,
            &self.operation,
            &self.session,
        ] {
            ensure!(*value != [0; 32], "zero native exit context");
            out.extend_from_slice(value);
        }
        VerifyingKey::from_bytes(&self.session)?;
        ensure!(self.revision > 0, "native exit starting revision");
        out.extend_from_slice(&self.revision.to_le_bytes());
        Ok(out)
    }
    /// Independent current-owner authentication precedes releasing any nonce.
    pub fn owner_message(&self, plan: &Digest, commitments: &[Digest; 2]) -> Result<Digest> {
        ensure!(
            *plan != [0; 32]
                && commitments.iter().all(|v| *v != [0; 32])
                && commitments[0] != commitments[1],
            "native exit preparation commitments"
        );
        Ok(hash(&[
            b"ZARK/spark/native/owner-prepare/v1",
            &self.encode()?,
            plan,
            &commitments[0],
            &commitments[1],
        ]))
    }
    pub fn verify_owner(
        &self,
        plan: &Digest,
        commitments: &[Digest; 2],
        capability: &Digest,
        public: &Digest,
        signature: &[u8; 64],
    ) -> Result<()> {
        ensure!(
            *public != self.session,
            "native owner and session keys must differ"
        );
        ensure!(
            spark_lineage::public_capability_commitment(&self.deployment, &self.coin, public)?
                == *capability,
            "native current owner capability"
        );
        VerifyingKey::from_bytes(public)?.verify_raw(
            &self.owner_message(plan, commitments)?,
            &Signature::try_from(signature.as_slice())?,
        )?;
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeBranch {
    pub server_nonce: [u8; 64],
    pub challenge: Digest,
    pub blinding_commitment: Digest,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExitAuthorization {
    pub context: ExitContext,
    pub backing: Digest,
    pub policy: Digest,
    pub capability: Digest,
    pub plan: Digest,
    pub cluster: Digest,
    pub server: [u8; 64],
    pub config: Config,
    pub branches: [NativeBranch; 2],
}
impl ExitAuthorization {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = self.context.encode()?;
        for value in [
            &self.backing,
            &self.policy,
            &self.capability,
            &self.plan,
            &self.cluster,
        ] {
            ensure!(*value != [0; 32], "zero native exit commitment");
            out.extend_from_slice(value);
        }
        point(&self.server)?;
        out.extend_from_slice(&self.server);
        out.extend_from_slice(&self.config.encode()?);
        ensure!(
            self.branches[0].server_nonce[..32] != self.branches[1].server_nonce[..32],
            "native nonce reused up to sign"
        );
        ensure!(
            self.branches[0].blinding_commitment != self.branches[1].blinding_commitment,
            "native blinding commitment reused"
        );
        for branch in &self.branches {
            point(&branch.server_nonce)?;
            scalar(&branch.challenge)?;
            ensure!(
                branch.blinding_commitment != [0; 32],
                "zero native blinding commitment"
            );
            out.extend_from_slice(&branch.server_nonce);
            out.extend_from_slice(&branch.challenge);
            out.extend_from_slice(&branch.blinding_commitment);
        }
        ensure!(out.len() == ENCODED_LEN, "native exit statement size");
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == ENCODED_LEN, "native exit statement size");
        let part = |offset: usize| -> Digest {
            bytes[offset..offset + 32]
                .try_into()
                .expect("checked native statement size")
        };
        let context = ExitContext {
            deployment: part(4),
            coin: part(36),
            current_state: part(68),
            operation: part(100),
            session: part(132),
            revision: u64::from_le_bytes(bytes[164..172].try_into()?),
        };
        let value = Self {
            context,
            backing: part(172),
            policy: part(204),
            capability: part(236),
            plan: part(268),
            cluster: part(300),
            server: bytes[332..396].try_into()?,
            config: Config::decode(&bytes[396..556])?,
            branches: std::array::from_fn(|i| {
                let offset = 556 + 128 * i;
                NativeBranch {
                    server_nonce: bytes[offset..offset + 64]
                        .try_into()
                        .expect("checked native statement size"),
                    challenge: part(offset + 64),
                    blinding_commitment: part(offset + 96),
                }
            }),
        };
        ensure!(
            value.encode()? == bytes,
            "noncanonical native exit statement"
        );
        Ok(value)
    }
    pub fn digest(&self) -> Result<Digest> {
        Ok(hash(&[
            b"ZARK/spark/native/exit-authorization/v1",
            &self.encode()?,
        ]))
    }
}

/// Wallet-local opening, frozen before the original signer nonce is released.
/// This does not contain or accept the signer's secret share.
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
    pub fn commitment(
        &self,
        context: &ExitContext,
        plan: &Digest,
        server: &[u8; 64],
        index: u32,
    ) -> Result<Digest> {
        ensure!(
            index < 2 && *plan != [0; 32] && self.salt != [0; 32],
            "native wallet opening domain"
        );
        point(server)?;
        for bytes in [&self.alpha, &self.beta, &self.binding] {
            ensure!(
                !bool::from(scalar(bytes)?.is_zero()),
                "zero native wallet blinding"
            );
        }
        Ok(application_hash::hash(&[
            b"ZARK/spark/native/wallet-blinding/v1",
            &context.encode()?,
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
