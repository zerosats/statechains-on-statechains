//! Purpose-specific durable issuance. A response keeps ownership locked until a
//! future, separately verified reconciliation protocol establishes settlement.
use super::{
    Command, Engine, Policy, ProofRole, ProofSpec, Request,
    blind_issuance::{self, FrozenResponse},
    state::{Branch, Coin, Phase},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zark_protocol::{
    hash, point, point_bytes, random_scalar, scalar,
    spark_lineage::{Digest, Intent},
    spark_native::ExitContext,
    spark_single_user::{PURPOSE, SigningAuthorization, verify_owner},
};
#[cfg(test)]
mod tests;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Workflow {
    purpose: String,
    registry: Digest,
    intent: Intent,
    session: Digest,
    plan: Digest,
    branch: Branch,
    statement: Option<Vec<u8>>,
    partial: Option<Digest>,
}
pub(super) fn is_command(command: &Command) -> bool {
    matches!(
        command,
        Command::SingleUserPrepare { .. }
            | Command::SingleUserIssue { .. }
            | Command::SingleUserCancel {}
    )
}
fn context(intent: &Intent, session: Digest) -> ExitContext {
    ExitContext {
        deployment: intent.deployment,
        coin: intent.coin,
        current_state: intent.previous_state,
        operation: intent.operation,
        session,
        revision: intent.revision,
    }
}
fn nonce_id(w: &Workflow) -> Result<Digest> {
    Ok(hash(&[
        b"ZARK/spark/signer/single-user-nonce/v1",
        PURPOSE.as_bytes(),
        &w.registry,
        &context(&w.intent, w.session).encode()?,
        &w.plan,
        &w.branch.point,
        &w.branch.commitment,
    ]))
}
impl Workflow {
    pub(super) fn operation(&self) -> Digest {
        self.intent.operation
    }
    pub(super) fn validate_revision(&self, revision: u64) -> Result<()> {
        ensure!(
            self.intent
                .revision
                .checked_add(if self.partial.is_some() { 2 } else { 1 })
                == Some(revision),
            "single-USER phase revision"
        );
        Ok(())
    }
    pub(super) fn validate(&self, coin: &Coin, policy: &Policy) -> Result<()> {
        self.intent.encode()?;
        context(&self.intent, self.session).encode()?;
        ensure!(
            coin.phase == Phase::Accepted && coin.pending.is_none() && coin.native.is_none(),
            "single-USER ownership phase"
        );
        ensure!(
            self.purpose == PURPOSE
                && self.registry != [0; 32]
                && policy.single_user == Some(self.registry),
            "single-USER pinned registry differs"
        );
        ensure!(
            self.intent.deployment == coin.deployment
                && self.intent.coin == coin.coin
                && self.intent.previous_state == coin.state
                && self.intent.recipient_claim == self.plan
                && self.plan != [0; 32],
            "single-USER frozen intent differs"
        );
        ensure!(
            self.branch.index == 0
                && self.branch.commitment != [0; 32]
                && self.branch.id == nonce_id(self)?,
            "single-USER nonce purpose differs"
        );
        point(&self.branch.point)?;
        ensure!(
            self.statement.is_some() == self.partial.is_some()
                && self.branch.secret.is_some() == self.partial.is_none(),
            "single-USER nonce lifecycle"
        );
        if let Some(secret) = self.branch.secret {
            ensure!(
                scalar(&secret)? != k256::Scalar::ZERO
                    && point_bytes(k256::ProjectivePoint::GENERATOR * scalar(&secret)?)?[..]
                        == self.branch.point,
                "single-USER nonce changed"
            );
        }
        if let Some(bytes) = &self.statement {
            let statement = SigningAuthorization::decode(bytes)?;
            self.match_statement(coin, policy, &statement)?;
            ensure!(
                k256::ProjectivePoint::GENERATOR
                    * scalar(&self.partial.context("single-USER retained partial")?)?
                    == point(&statement.nonce)?
                        + point(&statement.server)? * scalar(&statement.challenge)?,
                "single-USER retained response changed"
            );
        }
        Ok(())
    }
    fn match_statement(
        &self,
        coin: &Coin,
        policy: &Policy,
        a: &SigningAuthorization,
    ) -> Result<()> {
        ensure!(
            a.context == context(&self.intent, self.session)
                && a.backing == coin.backing
                && a.policy == policy.policy
                && a.capability == coin.capability
                && a.plan == self.plan
                && a.server == coin.server()?
                && a.config == policy.config,
            "single-USER statement differs from frozen ownership"
        );
        ensure!(
            a.nonce[..] == self.branch.point && a.blinding == self.branch.commitment,
            "single-USER frozen nonce/opening differs"
        );
        Ok(())
    }
}
impl Engine {
    pub(super) fn plan_single_user(
        &self,
        coin: &Coin,
        request: &Request,
    ) -> Result<Option<ProofSpec>> {
        ensure!(
            self.single_user_verifier.is_some(),
            "single-USER proof suite is not deployed"
        );
        ensure!(
            request.intent.deployment == coin.deployment && request.intent.coin == coin.coin,
            "single-USER request coin differs"
        );
        if let Command::SingleUserPrepare {
            plan,
            nonce_commitment,
            owner,
        } = &request.command
        {
            ensure!(
                coin.phase == Phase::Accepted
                    && coin.pending.is_none()
                    && coin.native.is_none()
                    && coin.single_user.is_none()
                    && request.intent.previous_state == coin.state
                    && request.intent.recipient_claim == *plan,
                "single-USER preparation phase"
            );
            verify_owner(
                &context(&request.intent, request.session),
                plan,
                nonce_commitment,
                &coin.capability,
                &owner.public_key,
                &owner.signature,
            )?;
            return Ok(None);
        }
        let w = coin
            .single_user
            .as_ref()
            .context("single-USER workflow absent")?;
        ensure!(
            w.intent == request.intent && w.session == request.session,
            "single-USER frozen session/intent differs"
        );
        ensure!(
            w.statement.is_none(),
            "single-USER response already issued; ownership stays locked"
        );
        match &request.command {
            Command::SingleUserIssue { statement, .. } => {
                let statement = SigningAuthorization::decode(statement)?;
                w.match_statement(coin, &self.policy, &statement)?;
                Ok(Some(ProofSpec {
                    role: ProofRole::SingleUser(
                        coin.owner.context("single-USER predecessor absent")?,
                    ),
                    statement: statement.encode()?,
                }))
            }
            Command::SingleUserCancel {} => Ok(None),
            _ => anyhow::bail!("not a single-USER command"),
        }
    }
    pub(super) fn apply_single_user(
        &self,
        mut coin: Coin,
        request: &Request,
    ) -> Result<(Coin, Value, bool)> {
        let response = match &request.command {
            Command::SingleUserPrepare {
                plan,
                nonce_commitment,
                ..
            } => {
                // Fresh allocation, never an existing recovery/native nonce.
                let secret: Digest = random_scalar().to_bytes().into();
                let point =
                    point_bytes(k256::ProjectivePoint::GENERATOR * scalar(&secret)?)?.to_vec();
                let mut w = Workflow {
                    purpose: PURPOSE.into(),
                    registry: self
                        .policy
                        .single_user
                        .context("single-USER registry absent")?,
                    intent: request.intent.clone(),
                    session: request.session,
                    plan: *plan,
                    branch: Branch {
                        index: 0,
                        id: [0; 32],
                        point,
                        commitment: *nonce_commitment,
                        secret: Some(secret),
                    },
                    statement: None,
                    partial: None,
                };
                w.branch.id = nonce_id(&w)?;
                let result = json!({"purpose":PURPOSE,"registry":w.registry,"nonce_id":w.branch.id,"nonce":w.branch.point});
                coin.single_user = Some(w);
                result
            }
            Command::SingleUserIssue { statement, .. } => {
                let a = SigningAuthorization::decode(statement)?;
                let w = coin
                    .single_user
                    .as_mut()
                    .context("single-USER workflow absent")?;
                let [partial] = blind_issuance::issue(
                    &coin.secret,
                    [&mut w.branch.secret],
                    [FrozenResponse {
                        nonce_point: &a.nonce,
                        nonce_commitment: &a.blinding,
                        blinded_challenge: &a.challenge,
                    }],
                )?;
                w.statement = Some(statement.clone());
                w.partial = Some(partial);
                // The outer Engine atomically commits this response, burned
                // nonce and ownership lock, then publishes the checkpoint.
                json!({"partial":partial,"authorization":a.digest()?,"signing_pending":true})
            }
            Command::SingleUserCancel {} => {
                coin.single_user = None;
                json!({"cancelled":true})
            }
            _ => anyhow::bail!("not a single-USER command"),
        };
        Ok((coin, response, false))
    }
}
