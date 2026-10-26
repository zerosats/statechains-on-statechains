//! Fresh, ordinary USER claim signing before origin admission. No existing
//! ownership certificate is assumed, and no native plaintext goes to signer.
use crate::{
    application_hash, hash, point, scalar,
    spark_bootstrap::BootstrapContext,
    spark_lineage::{Config, Digest},
    spark_native::ExitContext,
    spark_single_user::Opening,
};
use anyhow::{Result, ensure};
use k256::schnorr::{Signature, VerifyingKey};
mod cluster;
mod plan;
mod verifier;
mod witness;
pub use cluster::{ClaimCluster, ClaimOperator};
pub use plan::{ReceiveBodies, ReceivePlan};
pub use verifier::PinnedReceiveVerifier;
pub use witness::{ReceiveJob, ReceiveWitness};

pub const REGISTRY: &str = "zark-spark-receive-root-ordinary-user-v1";
pub const PURPOSE: &str = "ordinary-user-root-claim-v1";
pub const ENCODED_LEN: usize = 812;

/// Every opaque MPC round has a separate replay key under the allocated intent.
pub fn frame_intent(
    intent: &crate::spark_lineage::Intent,
    operator: &str,
    step: u8,
) -> Result<crate::spark_lineage::Intent> {
    ensure!(operator.len() == 64 && step < 7, "receive frame scope");
    let mut value = intent.clone();
    value.operation = hash(&[
        b"ZARK/spark/receive/frame/v1",
        &intent.encode()?,
        operator.as_bytes(),
        &[step],
    ]);
    Ok(value)
}

pub fn exit_context(c: &BootstrapContext) -> ExitContext {
    ExitContext {
        deployment: c.deployment,
        coin: c.coin,
        current_state: c.allocation_state,
        operation: c.operation,
        session: c.session,
        revision: c.revision,
    }
}
pub fn owner_message(
    c: &BootstrapContext,
    backing: &Digest,
    capability: &Digest,
    plan: &Digest,
    cluster: &Digest,
    commitments: &[Digest; 2],
) -> Result<Digest> {
    c.encode()?;
    for v in [
        backing,
        capability,
        plan,
        cluster,
        &commitments[0],
        &commitments[1],
    ] {
        ensure!(*v != [0; 32], "zero receive preparation commitment");
    }
    ensure!(
        commitments[0] != commitments[1],
        "receive branch blinding reuse"
    );
    Ok(hash(&[
        b"ZARK/spark/receive/owner/v1",
        &c.encode()?,
        backing,
        capability,
        plan,
        cluster,
        &commitments[0],
        &commitments[1],
    ]))
}
#[allow(clippy::too_many_arguments)]
pub fn verify_owner(
    c: &BootstrapContext,
    backing: &Digest,
    capability: &Digest,
    plan: &Digest,
    cluster: &Digest,
    commitments: &[Digest; 2],
    public: &Digest,
    signature: &[u8],
) -> Result<()> {
    ensure!(
        *public != c.session
            && crate::spark_lineage::public_capability_commitment(&c.deployment, &c.coin, public)?
                == *capability,
        "receive owner/session capability"
    );
    VerifyingKey::from_bytes(public)?.verify_raw(
        &owner_message(c, backing, capability, plan, cluster, commitments)?,
        &Signature::try_from(signature)?,
    )?;
    Ok(())
}
/// Each native variant has a distinct plan-bound precommit, even when both
/// claim the same leaf and both pay the same joint USER key.
pub fn branch_plan(plan: &Digest, index: usize) -> Result<Digest> {
    ensure!(*plan != [0; 32] && index < 2, "receive branch plan");
    Ok(hash(&[
        b"ZARK/spark/receive/branch/v1",
        plan,
        &[index as u8],
    ]))
}
pub fn blinding_commitment(
    c: &BootstrapContext,
    plan: &Digest,
    server: &[u8; 64],
    index: usize,
    opening: &Opening,
) -> Result<Digest> {
    opening.commitment(&exit_context(c), &branch_plan(plan, index)?, server)
}
#[derive(Clone, PartialEq, Eq)]
pub struct ReceiveBranch {
    pub nonce: [u8; 64],
    pub challenge: Digest,
    pub blinding: Digest,
}
#[derive(Clone, PartialEq, Eq)]
pub struct ReceiveAuthorization {
    pub context: BootstrapContext,
    pub backing: Digest,
    pub policy: Digest,
    pub capability: Digest,
    pub plan: Digest,
    pub cluster: Digest,
    pub server: [u8; 64],
    pub config: Config,
    pub branches: [ReceiveBranch; 2],
}
impl ReceiveAuthorization {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = self.context.encode()?;
        for v in [
            &self.backing,
            &self.policy,
            &self.capability,
            &self.plan,
            &self.cluster,
        ] {
            ensure!(*v != [0; 32], "zero receive statement commitment");
            out.extend_from_slice(v);
        }
        point(&self.server)?;
        out.extend_from_slice(&self.server);
        out.extend_from_slice(&self.config.encode()?);
        ensure!(
            self.branches[0].nonce[..32] != self.branches[1].nonce[..32]
                && self.branches[0].blinding != self.branches[1].blinding,
            "receive branch nonce reuse"
        );
        for b in &self.branches {
            point(&b.nonce)?;
            scalar(&b.challenge)?;
            ensure!(b.blinding != [0; 32], "zero receive blinding");
            out.extend_from_slice(&b.nonce);
            out.extend_from_slice(&b.challenge);
            out.extend_from_slice(&b.blinding);
        }
        ensure!(out.len() == ENCODED_LEN, "receive statement size");
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == ENCODED_LEN, "receive statement size");
        let d = |o: usize| -> Digest {
            bytes[o..o + 32]
                .try_into()
                .expect("checked receive statement")
        };
        let v = Self {
            context: BootstrapContext {
                deployment: d(4),
                coin: d(36),
                allocation_state: d(68),
                operation: d(100),
                session: d(132),
                revision: u64::from_le_bytes(bytes[164..172].try_into()?),
            },
            backing: d(172),
            policy: d(204),
            capability: d(236),
            plan: d(268),
            cluster: d(300),
            server: bytes[332..396].try_into()?,
            config: Config::decode(&bytes[396..556])?,
            branches: std::array::from_fn(|i| {
                let o = 556 + i * 128;
                ReceiveBranch {
                    nonce: bytes[o..o + 64]
                        .try_into()
                        .expect("checked receive statement"),
                    challenge: d(o + 64),
                    blinding: d(o + 96),
                }
            }),
        };
        ensure!(v.encode()? == bytes, "noncanonical receive statement");
        Ok(v)
    }
    pub fn digest(&self) -> Result<Digest> {
        Ok(application_hash::hash(&[
            b"ZARK/spark/receive/authorization/v1",
            &self.encode()?,
        ]))
    }
}
