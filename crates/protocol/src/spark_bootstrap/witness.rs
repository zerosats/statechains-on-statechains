//! Private creation witness. The server scalar is never accepted or exported.
use super::{
    BootstrapAuthorization, BootstrapBranch, BootstrapContext, Digest, PlanOpening, WalletOpening,
};
use crate::{
    blind_signing::FundingKey,
    point, point_bytes, scalar,
    spark_lineage::{Config, capability_commitment},
    spark_native::{JobTranscript, blinded_native_challenge},
    spark_recovery::{BackingOpening, RecoveryContext, RefundOpening},
};
use anyhow::{Result, ensure};
use k256::{ProjectivePoint, Scalar};
use zeroize::{Zeroize, Zeroizing};
pub struct BootstrapJobOpening {
    pub blinding: WalletOpening,
    pub transcript: JobTranscript,
    pub wallet_hiding: Digest,
    pub wallet_binding: Digest,
}
impl Drop for BootstrapJobOpening {
    fn drop(&mut self) {
        self.wallet_hiding.zeroize();
        self.wallet_binding.zeroize();
    }
}
pub struct BootstrapWitness {
    pub user: Digest,
    pub owner_secret: Digest,
    pub backing_salt: Digest,
    pub session_point: [u8; 64],
    pub plan: PlanOpening,
    pub jobs: [BootstrapJobOpening; 3],
}
impl Drop for BootstrapWitness {
    fn drop(&mut self) {
        self.user.zeroize();
        self.owner_secret.zeroize();
        self.backing_salt.zeroize();
        self.plan.salt.zeroize();
    }
}
impl BootstrapWitness {
    fn raw_user(&self, server: &[u8; 64]) -> Result<[u8; 64]> {
        let user = Zeroizing::new(scalar(&self.user)?);
        ensure!(*user != Scalar::ZERO, "bootstrap zero wallet share");
        point_bytes(point(server)? + ProjectivePoint::GENERATOR * *user)
    }
    pub fn capability(&self, context: &BootstrapContext) -> Result<Digest> {
        context.encode()?;
        capability_commitment(&context.deployment, &context.coin, &self.owner_secret)
    }
    pub fn backing(&self, context: &BootstrapContext, server: &[u8; 64]) -> Result<Digest> {
        context.encode()?;
        ensure!(
            self.backing_salt != [0; 32] && self.backing_salt != self.plan.salt,
            "bootstrap independent backing salt"
        );
        let bodies = self.plan.bodies(self.raw_user(server)?)?;
        let opening = BackingOpening {
            salt: self.backing_salt,
            refunds: std::array::from_fn(|i| RefundOpening {
                txid: crate::hash(&[&crate::hash(&[&bodies.refunds[i]])]),
                amount: if i == 0 || self.plan.amount <= 955 {
                    self.plan.amount
                } else {
                    self.plan.amount - 955
                },
            }),
        };
        let user = Zeroizing::new(scalar(&self.user)?);
        let key = FundingKey::new(point(server)?, *user)?;
        let scope = RecoveryContext {
            deployment: context.deployment,
            coin: context.coin,
            previous_state: context.allocation_state,
            operation: context.operation,
            session: context.session,
            successor_state: [1; 32],
            revision: context.revision,
        };
        opening.commitment(&scope, &key)
    }
    pub fn plan_commitment(&self, server: &[u8; 64]) -> Result<Digest> {
        self.plan.commitment(self.raw_user(server)?)
    }
    pub fn commitments(
        &self,
        context: &BootstrapContext,
        server: &[u8; 64],
    ) -> Result<[Digest; 3]> {
        let backing = self.backing(context, server)?;
        let plan = self.plan_commitment(server)?;
        let mut commitments = Vec::new();
        for (i, job) in self.jobs.iter().enumerate() {
            commitments.push(
                job.blinding
                    .commitment(context, &backing, &plan, server, i as u32)?,
            );
        }
        commitments
            .try_into()
            .map_err(|_| anyhow::anyhow!("bootstrap job count"))
    }
    pub fn authorize(
        &self,
        context: BootstrapContext,
        policy: Digest,
        config: Config,
        server: [u8; 64],
        nonces: [[u8; 64]; 3],
    ) -> Result<BootstrapAuthorization> {
        let session = point_bytes(point(&self.session_point)?)?;
        ensure!(
            session[..32] == context.session && session[63] & 1 == 0,
            "bootstrap session opening"
        );
        let backing = self.backing(&context, &server)?;
        let capability = self.capability(&context)?;
        let plan = self.plan_commitment(&server)?;
        let raw_user = self.raw_user(&server)?;
        let bodies = self.plan.bodies(raw_user)?;
        let combined = point_bytes(point(&raw_user)? + point(&self.plan.operator)?)?;
        let commitments = self.commitments(&context, &server)?;
        let mut branches = Vec::new();
        for (i, job) in self.jobs.iter().enumerate() {
            for (secret, advertised) in [
                (&job.wallet_hiding, &job.transcript.wallet.hiding),
                (&job.wallet_binding, &job.transcript.wallet.binding),
            ] {
                let secret = Zeroizing::new(scalar(secret)?);
                ensure!(
                    *secret != Scalar::ZERO
                        && point_bytes(ProjectivePoint::GENERATOR * *secret)? == *advertised,
                    "bootstrap native wallet nonce opening"
                );
            }
            for other in &self.jobs[..i] {
                ensure!(
                    job.blinding.alpha != other.blinding.alpha
                        && job.blinding.beta != other.blinding.beta
                        && job.blinding.binding != other.blinding.binding
                        && job.blinding.salt != other.blinding.salt,
                    "bootstrap branch randomness reuse"
                );
            }
            branches.push(BootstrapBranch {
                server_nonce: nonces[i],
                challenge: blinded_native_challenge(
                    server,
                    nonces[i],
                    combined,
                    bodies.sighashes[i],
                    &job.blinding.native(),
                    &job.transcript,
                )?,
                blinding_commitment: commitments[i],
            });
        }
        let value = BootstrapAuthorization {
            context,
            backing,
            policy,
            capability,
            plan,
            cluster: self.plan.cluster,
            server,
            config,
            branches: branches
                .try_into()
                .map_err(|_| anyhow::anyhow!("bootstrap job count"))?,
        };
        value.encode()?;
        Ok(value)
    }
    pub fn append_prover_fields(&self, out: &mut String) -> Result<()> {
        let array = |bytes: &[u8]| {
            format!(
                "[{}]",
                bytes
                    .iter()
                    .map(u8::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        for (name, bytes) in [
            ("user", self.user.as_slice()),
            ("owner_secret", self.owner_secret.as_slice()),
            ("backing_salt", self.backing_salt.as_slice()),
            ("session_point", self.session_point.as_slice()),
            ("plan_salt", self.plan.salt.as_slice()),
            (
                "signing_keyshare_id",
                self.plan.signing_keyshare_id.as_slice(),
            ),
            ("anchor_txid", self.plan.anchor_txid.as_slice()),
            ("operator", self.plan.operator.as_slice()),
        ] {
            out.push_str(&format!("{name} = {}\n", array(bytes)));
        }
        out.push_str(&format!(
            "anchor_vout = {}\namount = {}\n",
            self.plan.anchor_vout, self.plan.amount
        ));
        let mut jobs = Vec::new();
        for job in &self.jobs {
            let b = &job.blinding;
            let ids = job
                .transcript
                .operators
                .iter()
                .map(|p| array(&p.identifier))
                .collect::<Vec<_>>()
                .join(",");
            let hiding = job
                .transcript
                .operators
                .iter()
                .map(|p| array(&p.hiding))
                .collect::<Vec<_>>()
                .join(",");
            let binding = job
                .transcript
                .operators
                .iter()
                .map(|p| array(&p.binding))
                .collect::<Vec<_>>()
                .join(",");
            jobs.push(format!("{{alpha={},beta={},tau={},salt={},operator_ids=[{}],operator_hiding=[{}],operator_binding=[{}],wallet_hiding={},wallet_binding={}}}",
                array(&b.alpha),array(&b.beta),array(&b.binding),array(&b.salt),ids,hiding,binding,array(&job.wallet_hiding),array(&job.wallet_binding)));
        }
        out.push_str(&format!("jobs = [{}]\n", jobs.join(",")));
        Ok(())
    }
}
