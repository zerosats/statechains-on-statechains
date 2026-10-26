//! These openings remain in the wallet's private journal/prover input.
use super::{Opening, SigningAuthorization, SigningPlan, blinded_challenge};
use crate::{
    blind_signing::FundingKey,
    hash, point, point_bytes, scalar,
    spark_lineage::{Config, Digest, capability_commitment},
    spark_native::{ExitContext, Participant},
    spark_recovery::{BackingOpening, RecoveryContext, RefundOpening},
};
use anyhow::{Result, ensure};
use k256::{ProjectivePoint, Scalar};
use zeroize::{Zeroize, Zeroizing};
pub struct SigningWitness {
    pub user: Digest,
    pub owner: Digest,
    pub backing_salt: Digest,
    pub session_point: [u8; 64],
    pub plan: SigningPlan,
    pub opening: Opening,
    pub operators: [Participant; 2],
}
impl Drop for SigningWitness {
    fn drop(&mut self) {
        self.user.zeroize();
        self.owner.zeroize();
        self.backing_salt.zeroize();
    }
}
impl SigningWitness {
    #[allow(clippy::too_many_arguments)]
    pub fn authorize(
        &self,
        context: ExitContext,
        backing: Digest,
        policy: Digest,
        capability: Digest,
        config: Config,
        server: [u8; 64],
        nonce: [u8; 64],
    ) -> Result<SigningAuthorization> {
        ensure!(
            capability_commitment(&context.deployment, &context.coin, &self.owner)? == capability,
            "single-USER owner opening"
        );
        let session = point_bytes(point(&self.session_point)?)?;
        ensure!(
            session[..32] == context.session && session[63] & 1 == 0,
            "single-USER session opening"
        );
        let user = Zeroizing::new(scalar(&self.user)?);
        ensure!(*user != Scalar::ZERO, "zero single-USER wallet share");
        let raw = point(&server)? + ProjectivePoint::GENERATOR * *user;
        let raw = point_bytes(raw)?;
        let bodies = self.plan.bodies(raw)?;
        let opening = BackingOpening {
            salt: self.backing_salt,
            refunds: std::array::from_fn(|i| RefundOpening {
                txid: hash(&[&hash(&[&bodies.old_refunds[i]])]),
                amount: if i == 0 || self.plan.amount <= 955 {
                    self.plan.amount
                } else {
                    self.plan.amount - 955
                },
            }),
        };
        let key = FundingKey::new(point(&server)?, *user)?;
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
            "single-USER authenticated backing differs"
        );
        let plan = self.plan.commitment(raw)?;
        let authorization = SigningAuthorization {
            blinding: self.opening.commitment(&context, &plan, &server)?,
            challenge: blinded_challenge(
                server,
                nonce,
                bodies.combined,
                bodies.sighash,
                &self.opening,
                &self.operators,
            )?,
            context,
            backing,
            policy,
            capability,
            plan,
            server,
            config,
            nonce,
        };
        authorization.encode()?;
        Ok(authorization)
    }
    pub fn append_prover_fields(&self, out: &mut String) -> Result<()> {
        let array = |b: &[u8]| serde_json::to_string(b);
        for (name, value) in [
            ("user", self.user.as_slice()),
            ("owner_secret", self.owner.as_slice()),
            ("backing_salt", self.backing_salt.as_slice()),
            ("session_point", self.session_point.as_slice()),
            ("plan_salt", self.plan.salt.as_slice()),
            ("anchor_txid", self.plan.anchor_txid.as_slice()),
            ("operator", self.plan.operator.as_slice()),
            ("receiver", self.plan.receiver.as_slice()),
            ("alpha", self.opening.alpha.as_slice()),
            ("beta", self.opening.beta.as_slice()),
            ("tau", self.opening.binding.as_slice()),
            ("salt", self.opening.salt.as_slice()),
        ] {
            out.push_str(&format!("{name} = {}\n", array(value)?));
        }
        for (name, value) in [
            ("anchor_vout", u64::from(self.plan.anchor_vout)),
            ("amount", self.plan.amount),
            ("native_delay", u64::from(self.plan.native_delay)),
            ("variant", u64::from(self.plan.variant)),
        ] {
            out.push_str(&format!("{name} = {value}\n"));
        }
        for (name, values) in [
            (
                "operator_ids",
                self.operators
                    .iter()
                    .map(|p| p.identifier.to_vec())
                    .collect::<Vec<_>>(),
            ),
            (
                "operator_hiding",
                self.operators.iter().map(|p| p.hiding.to_vec()).collect(),
            ),
            (
                "operator_binding",
                self.operators.iter().map(|p| p.binding.to_vec()).collect(),
            ),
        ] {
            out.push_str(&format!("{name} = {}\n", serde_json::to_string(&values)?));
        }
        Ok(())
    }
}
