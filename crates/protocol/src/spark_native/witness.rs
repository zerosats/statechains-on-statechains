//! Wallet-local native proof inputs. Never serialize these onto signer wire.
use super::{
    Digest, ExitAuthorization, ExitContext, JobTranscript, NativeBranch, PlanOpening,
    WalletOpening, blinded_native_challenge,
};
use crate::{
    blind_signing::FundingKey,
    point, point_bytes, scalar,
    spark_lineage::{Config, capability_commitment},
    spark_recovery::{BackingOpening, RecoveryContext, RefundOpening},
};
use anyhow::{Result, ensure};
use k256::{ProjectivePoint, Scalar, elliptic_curve::sec1::ToEncodedPoint};
use zeroize::{Zeroize, Zeroizing};

pub struct NativeJobOpening {
    pub blinding: WalletOpening,
    pub transcript: JobTranscript,
    pub wallet_hiding: Digest,
    pub wallet_binding: Digest,
}
impl Drop for NativeJobOpening {
    fn drop(&mut self) {
        self.wallet_hiding.zeroize();
        self.wallet_binding.zeroize();
    }
}
pub struct ExitWitness {
    pub user: Digest,
    pub owner_secret: Digest,
    pub backing_salt: Digest,
    pub session_point: [u8; 64],
    pub plan: PlanOpening,
    pub jobs: [NativeJobOpening; 2],
}
impl Drop for ExitWitness {
    fn drop(&mut self) {
        self.user.zeroize();
        self.owner_secret.zeroize();
        self.backing_salt.zeroize();
        self.plan.salt.zeroize();
    }
}
impl ExitWitness {
    /// Arithmetic/encoding only. Authority additionally requires the pinned
    /// native role, authenticated current certificate and frozen signer state.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize(
        &self,
        context: ExitContext,
        backing: Digest,
        policy: Digest,
        capability: Digest,
        config: Config,
        server: [u8; 64],
        nonces: [[u8; 64]; 2],
    ) -> Result<ExitAuthorization> {
        self.authorize_profile(
            context, backing, policy, capability, config, server, nonces, false,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_ordinary(
        &self,
        context: ExitContext,
        backing: Digest,
        policy: Digest,
        capability: Digest,
        config: Config,
        server: [u8; 64],
        nonces: [[u8; 64]; 2],
    ) -> Result<ExitAuthorization> {
        self.authorize_profile(
            context, backing, policy, capability, config, server, nonces, true,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn authorize_profile(
        &self,
        context: ExitContext,
        backing: Digest,
        policy: Digest,
        capability: Digest,
        config: Config,
        server: [u8; 64],
        nonces: [[u8; 64]; 2],
        ordinary: bool,
    ) -> Result<ExitAuthorization> {
        context.encode()?;
        ensure!(
            capability_commitment(&context.deployment, &context.coin, &self.owner_secret)?
                == capability,
            "native owner capability opening"
        );
        let session = point_bytes(point(&self.session_point)?)?;
        ensure!(
            session[..32] == context.session && session[63] & 1 == 0,
            "native session point opening"
        );
        let owner = Zeroizing::new(scalar(&self.user)?);
        ensure!(*owner != Scalar::ZERO, "native wallet share zero");
        let server_point = point(&server)?;
        let raw_user = server_point + ProjectivePoint::GENERATOR * *owner;
        let raw_user_bytes = point_bytes(raw_user)?;
        let bodies = self.plan.bodies(raw_user_bytes)?;
        let opening = BackingOpening {
            salt: self.backing_salt,
            refunds: std::array::from_fn(|i| RefundOpening {
                txid: crate::hash(&[&crate::hash(&[&bodies.old_refunds[i]])]),
                amount: if i == 0 || self.plan.amount <= 955 {
                    self.plan.amount
                } else {
                    self.plan.amount - 955
                },
            }),
        };
        let key = FundingKey::new(server_point, *owner)?;
        let scope = RecoveryContext {
            deployment: context.deployment,
            coin: context.coin,
            previous_state: context.current_state,
            operation: context.operation,
            session: context.session,
            successor_state: [1; 32],
            revision: context.revision,
        };
        ensure!(
            opening.commitment(&scope, &key)? == backing,
            "native exit backing opening"
        );
        let plan = self.plan.commitment(raw_user_bytes)?;
        let combined = point_bytes(raw_user + point(&self.plan.operator)?)?;
        let mut branches = Vec::new();
        for (i, (job, nonce)) in self.jobs.iter().zip(nonces).enumerate() {
            let (challenge, blinding_commitment) = if ordinary {
                let opening = crate::spark_single_user::Opening {
                    alpha: job.blinding.alpha,
                    beta: job.blinding.beta,
                    binding: job.blinding.binding,
                    salt: job.blinding.salt,
                };
                (
                    crate::spark_single_user::blinded_challenge(
                        server,
                        nonce,
                        combined,
                        bodies.sighashes[i],
                        &opening,
                        &job.transcript.operators,
                    )?,
                    opening.commitment(
                        &context,
                        &super::ordinary_branch_plan(&plan, i)?,
                        &server,
                    )?,
                )
            } else {
                for (secret, advertised) in [
                    (&job.wallet_hiding, &job.transcript.wallet.hiding),
                    (&job.wallet_binding, &job.transcript.wallet.binding),
                ] {
                    let secret = Zeroizing::new(scalar(secret)?);
                    ensure!(*secret != Scalar::ZERO, "native wallet nonce zero");
                    ensure!(
                        point_bytes(ProjectivePoint::GENERATOR * *secret)? == *advertised,
                        "native wallet nonce opening"
                    );
                }
                (
                    blinded_native_challenge(
                        server,
                        nonce,
                        combined,
                        bodies.sighashes[i],
                        &job.blinding,
                        &job.transcript,
                    )?,
                    job.blinding
                        .commitment(&context, &plan, &server, i as u32)?,
                )
            };
            branches.push(NativeBranch {
                server_nonce: nonce,
                challenge,
                blinding_commitment,
            });
        }
        let a = &self.jobs[0].blinding;
        let b = &self.jobs[1].blinding;
        ensure!(
            a.alpha != b.alpha && a.beta != b.beta && a.binding != b.binding && a.salt != b.salt,
            "native branch blinding reused"
        );
        let value = ExitAuthorization {
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
                .map_err(|_| anyhow::anyhow!("native job count"))?,
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
        let identity =
            k256::PublicKey::from_sec1_bytes(&self.plan.receiver_identity)?.to_encoded_point(false);
        for (name, bytes) in [
            ("user", self.user.as_slice()),
            ("owner_secret", self.owner_secret.as_slice()),
            ("backing_salt", self.backing_salt.as_slice()),
            ("session_point", self.session_point.as_slice()),
            ("plan_salt", self.plan.salt.as_slice()),
            ("transfer_id", self.plan.transfer_id.as_slice()),
            ("leaf_id", self.plan.leaf_id.as_slice()),
            ("anchor_txid", self.plan.anchor_txid.as_slice()),
            ("operator", self.plan.operator.as_slice()),
            ("mask_user", self.plan.mask_user.as_slice()),
            ("receiver_identity", &identity.as_bytes()[1..]),
            (
                "mask_cipher_sha256",
                self.plan.mask_cipher_sha256.as_slice(),
            ),
        ] {
            out.push_str(&format!("{name} = {}\n", array(bytes)));
        }
        for (name, value) in [
            ("expiry", self.plan.expiry),
            ("anchor_vout", u64::from(self.plan.anchor_vout)),
            ("amount", self.plan.amount),
            ("native_delay", u64::from(self.plan.native_delay)),
        ] {
            out.push_str(&format!("{name} = {value}\n"));
        }
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
            jobs.push(format!("{{alpha={}, beta={}, tau={}, salt={}, operator_ids=[{}], operator_hiding=[{}], operator_binding=[{}], wallet_hiding={}, wallet_binding={}}}",
                array(&b.alpha),array(&b.beta),array(&b.binding),array(&b.salt),ids,hiding,binding,array(&job.wallet_hiding),array(&job.wallet_binding)));
        }
        out.push_str(&format!("jobs = [{}]\n", jobs.join(",")));
        Ok(())
    }
}
