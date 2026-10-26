use super::{Digest, ReceiveAuthorization, ReceiveBranch, ReceivePlan, blinding_commitment};
use crate::{
    point, point_bytes, scalar,
    spark_bootstrap::BootstrapContext,
    spark_lineage::{Config, capability_commitment},
    spark_native::Participant,
    spark_recovery::RecoveryContext,
    spark_single_user::{Opening, blinded_challenge},
};
use anyhow::{Result, ensure};
use k256::{ProjectivePoint, Scalar};
use zeroize::{Zeroize, Zeroizing};
pub struct ReceiveJob {
    pub opening: Opening,
    pub operators: [Participant; 2],
}
pub struct ReceiveWitness {
    pub user: Digest,
    pub owner: Digest,
    pub backing_salt: Digest,
    pub session_point: [u8; 64],
    pub plan: ReceivePlan,
    pub jobs: [ReceiveJob; 2],
}
impl Drop for ReceiveWitness {
    fn drop(&mut self) {
        self.user.zeroize();
        self.owner.zeroize();
        self.backing_salt.zeroize();
    }
}
impl ReceiveWitness {
    pub fn raw_user(&self, server: &[u8; 64]) -> Result<[u8; 64]> {
        let user = Zeroizing::new(scalar(&self.user)?);
        ensure!(*user != Scalar::ZERO, "receive zero wallet share");
        point_bytes(point(server)? + ProjectivePoint::GENERATOR * *user)
    }
    pub fn backing(&self, c: &BootstrapContext, server: &[u8; 64]) -> Result<Digest> {
        ensure!(
            self.backing_salt != self.plan.salt,
            "receive commitment salts must differ"
        );
        self.plan.backing(
            &RecoveryContext {
                deployment: c.deployment,
                coin: c.coin,
                previous_state: c.allocation_state,
                operation: c.operation,
                session: c.session,
                successor_state: [1; 32],
                revision: c.revision,
            },
            self.raw_user(server)?,
            self.backing_salt,
        )
    }
    pub fn commitments(&self, c: &BootstrapContext, server: &[u8; 64]) -> Result<[Digest; 2]> {
        let plan = self.plan.commitment(self.raw_user(server)?)?;
        Ok([
            blinding_commitment(c, &plan, server, 0, &self.jobs[0].opening)?,
            blinding_commitment(c, &plan, server, 1, &self.jobs[1].opening)?,
        ])
    }
    pub fn authorize(
        &self,
        c: BootstrapContext,
        policy: Digest,
        config: Config,
        server: [u8; 64],
        nonces: [[u8; 64]; 2],
    ) -> Result<ReceiveAuthorization> {
        let session = point_bytes(point(&self.session_point)?)?;
        ensure!(
            session[..32] == c.session && session[63] & 1 == 0,
            "receive session opening"
        );
        let raw = self.raw_user(&server)?;
        let bodies = self.plan.bodies(raw)?;
        let plan = self.plan.commitment(raw)?;
        let commitments = self.commitments(&c, &server)?;
        let a = ReceiveAuthorization {
            backing: self.backing(&c, &server)?,
            capability: capability_commitment(&c.deployment, &c.coin, &self.owner)?,
            policy,
            plan,
            cluster: self.plan.cluster,
            server,
            config,
            branches: std::array::from_fn(|i| ReceiveBranch {
                nonce: nonces[i],
                challenge: [0; 32],
                blinding: commitments[i],
            }),
            context: c,
        };
        let mut a = a;
        for (i, (branch, job)) in a.branches.iter_mut().zip(&self.jobs).enumerate() {
            branch.challenge = blinded_challenge(
                server,
                nonces[i],
                bodies.combined,
                bodies.sighashes[i],
                &job.opening,
                &job.operators,
            )?;
        }
        a.encode()?;
        Ok(a)
    }
    pub fn append_prover_fields(&self, out: &mut String) -> Result<()> {
        let arr = |b: &[u8]| serde_json::to_string(b);
        for (name, bytes) in [
            ("user", self.user.as_slice()),
            ("owner_secret", self.owner.as_slice()),
            ("backing_salt", self.backing_salt.as_slice()),
            ("session_point", self.session_point.as_slice()),
            ("plan_salt", self.plan.salt.as_slice()),
            ("anchor_txid", self.plan.anchor_txid.as_slice()),
            ("operator", self.plan.operator.as_slice()),
        ] {
            out.push_str(&format!("{name} = {}\n", arr(bytes)?));
        }
        for (name, value) in [
            ("anchor_vout", u64::from(self.plan.anchor_vout)),
            ("amount", self.plan.amount),
            ("native_delay", u64::from(self.plan.native_delay)),
        ] {
            out.push_str(&format!("{name} = {value}\n"));
        }
        let mut jobs = Vec::new();
        for job in &self.jobs {
            let b = &job.opening;
            jobs.push(format!("{{alpha={},beta={},tau={},salt={},operator_ids={},operator_hiding={},operator_binding={}}}",
            arr(&b.alpha)?,arr(&b.beta)?,arr(&b.binding)?,arr(&b.salt)?,
            serde_json::to_string(&job.operators.iter().map(|p|p.identifier.to_vec()).collect::<Vec<_>>())?,
            serde_json::to_string(&job.operators.iter().map(|p|p.hiding.to_vec()).collect::<Vec<_>>())?,
            serde_json::to_string(&job.operators.iter().map(|p|p.binding.to_vec()).collect::<Vec<_>>())?));
        }
        out.push_str(&format!("jobs = [{}]\n", jobs.join(",")));
        Ok(())
    }
}
