//! Native nonces have their own durable purpose and never reuse recovery slots.
//! Signature issuance keeps ownership locked: it does not prove Spark settlement
//! or authorize exporting the retained server share.
use super::{
    Command, Engine, Policy, ProofRole, ProofSpec, Request,
    blind_issuance::{self, FrozenResponse},
    state::{Branch, Coin, Phase},
};
use anyhow::{Context, Result, ensure};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zark_protocol::{
    hash, point, point_bytes, random_scalar, scalar,
    spark_lineage::{Digest, Intent},
    spark_native::{ExitAuthorization, ExitContext},
    spark_native_vss::{self, OpaqueContribution},
    spark_wire::{NativeCompletion, NativeExitReceipt},
};
use zeroize::Zeroizing;

const PURPOSE: &str = "native-initial-root-exit-v1";
#[cfg(test)]
pub(super) mod tests;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Workflow {
    purpose: String,
    registry: Digest,
    cluster: Digest,
    pub(super) intent: Intent,
    pub(super) session: Digest,
    plan: Digest,
    branches: [Branch; 2],
    pub(super) statement: Option<Vec<u8>>,
    partials: Option<[Digest; 2]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) contribution: Option<OpaqueContribution>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) tweaks: Option<super::native_tweaks::Workflow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) mpc: Option<super::mpc_exit::MpcExit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completion: Option<NativeExitReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    observed_completion: Option<ObservedCompletion>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedCompletion {
    completion: NativeCompletion,
    evidence: Digest,
}

pub(super) fn is_command(command: &Command) -> bool {
    matches!(
        command,
        Command::NativeExitPrepare { .. }
            | Command::NativeExitIssue { .. }
            | Command::NativeExitCancel { .. }
            | Command::NativeExitContribution { .. }
            | Command::NativeExitComplete { .. }
            | Command::NativeExitObservedComplete { .. }
    ) || super::mpc_exit::is_command(command)
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

fn nonce_id(workflow: &Workflow, branch: &Branch) -> Result<Digest> {
    Ok(hash(&[
        b"ZARK/spark/signer/native-nonce/v1",
        PURPOSE.as_bytes(),
        &workflow.registry,
        &workflow.cluster,
        &context(&workflow.intent, workflow.session).encode()?,
        &workflow.plan,
        &[branch.index],
        &branch.point,
        &branch.commitment,
    ]))
}

impl Workflow {
    pub(super) fn operation(&self) -> Digest {
        self.intent.operation
    }
    pub(super) fn plan(&self) -> Digest {
        self.plan
    }
    pub(super) fn cluster(&self) -> Digest {
        self.cluster
    }
    pub(super) fn completed(&self) -> bool {
        self.completion.is_some() || self.observed_completion.is_some()
    }
    pub(super) fn identity_scope(&self) -> Option<(&Intent, Digest)> {
        (!self.completed()).then_some((&self.intent, self.session))
    }

    fn check_completion(&self, coin: &Coin, completion: &NativeCompletion) -> Result<()> {
        let mpc = match &self.mpc {
            Some(mpc) => mpc
                .issued_statement(self, coin)?
                .map(|s| s.digest())
                .transpose()?,
            None => None,
        };
        ensure!(
            (self.contribution.is_some()
                || self.tweaks.as_ref().and_then(|t| t.sealed_packet()) == Some(completion.packet)
                || mpc == Some(completion.packet))
                && completion.plan == self.plan
                && completion.cluster == self.cluster,
            "native completion lifecycle or context"
        );
        completion.message()?;
        Ok(())
    }

    pub(super) fn validate_revision(&self, revision: u64) -> Result<()> {
        // No other mutation is allowed while native ownership is locked. The
        // operation's starting CAS revision therefore fixes every durable step.
        let steps = if self.completed() {
            4
        } else if self.contribution.is_some()
            || self.mpc.is_some()
            || self
                .tweaks
                .as_ref()
                .and_then(|t| t.sealed_packet())
                .is_some()
        {
            3
        } else if self.statement.is_some() {
            2
        } else {
            1
        };
        ensure!(
            self.intent.revision.checked_add(steps) == Some(revision),
            "native phase revision changed"
        );
        Ok(())
    }

    pub(super) fn validate(&self, coin: &Coin, policy: &Policy) -> Result<()> {
        self.intent.encode()?;
        ensure!(
            coin.phase == Phase::Accepted && coin.pending.is_none(),
            "native ownership phase"
        );
        ensure!(
            self.purpose == PURPOSE
                && self.registry != [0; 32]
                && self.cluster != [0; 32]
                && policy.native == Some((self.registry, self.cluster)),
            "native registry changed or missing"
        );
        ensure!(
            self.intent.deployment == coin.deployment
                && self.intent.coin == coin.coin
                && self.intent.previous_state == coin.state
                && self.intent.recipient_claim == self.plan
                && self.plan != [0; 32],
            "native frozen intent changed"
        );
        context(&self.intent, self.session).encode()?;
        ensure!(
            self.statement.is_some() == self.partials.is_some(),
            "native response lifecycle"
        );
        if let Some(tweaks) = &self.tweaks {
            ensure!(
                self.statement.is_some() && self.contribution.is_none(),
                "native tweak authorization/lifecycle"
            );
            tweaks.validate(coin, policy, &self.intent, self.session)?;
        }
        if let Some(mpc) = &self.mpc {
            ensure!(
                self.statement.is_some() && self.contribution.is_none() && self.tweaks.is_none(),
                "native MPC exit lifecycle"
            );
            let cluster = policy
                .native_cluster
                .as_ref()
                .context("native MPC cluster missing")?;
            ensure!(
                cluster.digest()? == self.cluster,
                "native MPC cluster changed"
            );
            mpc.validate(self, coin, cluster)?;
        }
        if let Some(contribution) = &self.contribution {
            ensure!(
                self.statement.is_some() && contribution.position == 2,
                "native VSS precedes authorization"
            );
            let cluster = policy
                .native_cluster
                .as_ref()
                .context("native ciphertext cluster missing")?;
            ensure!(
                cluster.digest()? == self.cluster,
                "native ciphertext cluster changed"
            );
            contribution.validate(
                cluster,
                &self.plan,
                (-point(&coin.server()?)?)
                    .to_affine()
                    .to_encoded_point(true)
                    .as_bytes(),
            )?;
        }
        if let Some(receipt) = &self.completion {
            ensure!(
                self.observed_completion.is_none(),
                "native completion authorities mixed"
            );
            self.check_completion(coin, &receipt.completion)?;
            receipt.verify(
                policy
                    .native_cluster
                    .as_ref()
                    .context("native completion cluster missing")?,
            )?;
        }
        if let Some(observed) = &self.observed_completion {
            self.check_completion(coin, &observed.completion)?;
            ensure!(
                observed.evidence != [0; 32],
                "zero native completion evidence"
            );
        }
        for (index, branch) in self.branches.iter().enumerate() {
            ensure!(
                branch.index as usize == index
                    && branch.id == nonce_id(self, branch)?
                    && branch.commitment != [0; 32],
                "native nonce purpose or branch changed"
            );
            point(&branch.point)?;
            ensure!(
                branch.secret.is_some() == self.statement.is_none(),
                "native nonce lifecycle"
            );
            if let Some(secret) = branch.secret {
                ensure!(
                    point_bytes(k256::ProjectivePoint::GENERATOR * scalar(&secret)?)?[..]
                        == branch.point,
                    "native nonce point changed"
                );
            }
        }
        ensure!(
            self.branches[0].point[..32] != self.branches[1].point[..32]
                && self.branches[0].commitment != self.branches[1].commitment,
            "native nonce reuse"
        );
        if let Some(raw) = &self.statement {
            let statement = ExitAuthorization::decode(raw)?;
            self.match_statement(coin, policy, &statement)?;
            for (branch, partial) in statement
                .branches
                .iter()
                .zip(self.partials.as_ref().context("native partials")?)
            {
                ensure!(
                    k256::ProjectivePoint::GENERATOR * scalar(partial)?
                        == point(&branch.server_nonce)?
                            + point(&statement.server)? * scalar(&branch.challenge)?,
                    "native retained response changed"
                );
            }
        }
        Ok(())
    }

    fn match_statement(
        &self,
        coin: &Coin,
        policy: &Policy,
        statement: &ExitAuthorization,
    ) -> Result<()> {
        ensure!(
            statement.context == context(&self.intent, self.session)
                && statement.backing == coin.backing
                && statement.policy == policy.policy
                && statement.capability == coin.capability
                && statement.plan == self.plan
                && statement.cluster == self.cluster
                && statement.server == coin.server()?
                && statement.config == policy.config,
            "native authorization differs from frozen ownership"
        );
        for (branch, frozen) in statement.branches.iter().zip(&self.branches) {
            ensure!(
                branch.server_nonce[..] == frozen.point
                    && branch.blinding_commitment == frozen.commitment,
                "native authorization nonce or commitment changed"
            );
        }
        Ok(())
    }
}

impl Engine {
    pub(super) fn plan_native(&self, coin: &Coin, request: &Request) -> Result<Option<ProofSpec>> {
        ensure!(
            self.native_verifier.is_some(),
            "native exit proof suite is not deployed"
        );
        ensure!(
            request.intent.deployment == coin.deployment && request.intent.coin == coin.coin,
            "native request coin changed"
        );
        if let Command::NativeExitPrepare {
            plan,
            nonce_commitments,
            owner,
        } = &request.command
        {
            ensure!(
                coin.phase == Phase::Accepted
                    && coin.native.is_none()
                    && request.intent.previous_state == coin.state
                    && request.intent.recipient_claim == *plan,
                "native prepare phase or current state"
            );
            context(&request.intent, request.session).verify_owner(
                plan,
                nonce_commitments,
                &coin.capability,
                &owner.public_key,
                &owner.signature.as_slice().try_into()?,
            )?;
            return Ok(None);
        }
        let workflow = coin.native.as_ref().context("native workflow missing")?;
        ensure!(
            workflow.intent == request.intent && workflow.session == request.session,
            "native frozen session or intent changed"
        );
        match &request.command {
            Command::NativeExitIssue { statement, .. } => {
                ensure!(
                    workflow.statement.is_none(),
                    "native pair already issued; ownership remains locked"
                );
                let statement = ExitAuthorization::decode(statement)?;
                workflow.match_statement(coin, &self.policy, &statement)?;
                Ok(Some(ProofSpec {
                    role: ProofRole::Native(coin.owner.context("native owner kind")?),
                    statement: statement.encode()?,
                }))
            }
            Command::NativeExitCancel {} => {
                ensure!(
                    workflow.statement.is_none(),
                    "cannot cancel an issued native pair"
                );
                Ok(None)
            }
            Command::NativeExitContribution {} => {
                ensure!(
                    workflow.statement.is_some()
                        && workflow.contribution.is_none()
                        && workflow.tweaks.is_none()
                        && workflow.mpc.is_none(),
                    "native contribution phase"
                );
                let cluster = self
                    .policy
                    .native_cluster
                    .as_ref()
                    .context("native VSS cluster is not configured")?;
                ensure!(
                    cluster.digest()? == workflow.cluster,
                    "native VSS cluster changed"
                );
                Ok(None)
            }
            Command::NativeExitComplete { receipt } => {
                ensure!(!workflow.completed(), "native completion phase");
                workflow.check_completion(coin, &receipt.completion)?;
                receipt.verify(
                    self.policy
                        .native_cluster
                        .as_ref()
                        .context("native completion cluster missing")?,
                )?;
                Ok(None)
            }
            Command::NativeExitObservedComplete {
                completion,
                evidence,
            } => {
                ensure!(!workflow.completed(), "native completion phase");
                workflow.check_completion(coin, completion)?;
                authorize_observed(self.admission.as_ref(), request, completion, evidence)?;
                Ok(None)
            }
            command if super::mpc_exit::is_command(command) => {
                self.plan_mpc_exit(coin, workflow, request)
            }
            _ => anyhow::bail!("not a native command"),
        }
    }

    pub(super) fn apply_native(
        &self,
        mut coin: Coin,
        request: &Request,
    ) -> Result<(Coin, Value, bool)> {
        let response = match &request.command {
            Command::NativeExitPrepare {
                plan,
                nonce_commitments,
                ..
            } => {
                // Preparation is authenticated by the current owner capability.
                // Retired tickets from an earlier private owner cannot be used
                // for this operation's identity signing scope, and an earlier
                // owner's Schnorr login key cannot pin this owner's key.
                coin.identities = None;
                coin.auth = None;
                let (registry, cluster) = self.policy.native.context("native verifier missing")?;
                let mut workflow = Workflow {
                    purpose: PURPOSE.into(),
                    registry,
                    cluster,
                    intent: request.intent.clone(),
                    session: request.session,
                    plan: *plan,
                    branches: std::array::from_fn(|index| Branch {
                        index: index as u8,
                        id: [0; 32],
                        point: Vec::new(),
                        commitment: nonce_commitments[index],
                        secret: None,
                    }),
                    statement: None,
                    partials: None,
                    contribution: None,
                    tweaks: None,
                    mpc: None,
                    completion: None,
                    observed_completion: None,
                };
                for index in 0..2 {
                    let (secret, point) = loop {
                        let secret: Digest = random_scalar().to_bytes().into();
                        let point =
                            point_bytes(k256::ProjectivePoint::GENERATOR * scalar(&secret)?)?
                                .to_vec();
                        if index == 0 || workflow.branches[0].point[..32] != point[..32] {
                            break (secret, point);
                        }
                    };
                    workflow.branches[index].point = point;
                    workflow.branches[index].secret = Some(secret);
                    workflow.branches[index].id = nonce_id(&workflow, &workflow.branches[index])?;
                }
                let response = json!({"purpose":PURPOSE,"registry":registry,"cluster":cluster,
                    "nonces":workflow.branches.iter().map(|b| json!({"index":b.index,"id":b.id,"point":b.point})).collect::<Vec<_>>()});
                coin.native = Some(workflow);
                response
            }
            Command::NativeExitIssue { statement, .. } => {
                let authorization = ExitAuthorization::decode(statement)?;
                let workflow = coin.native.as_mut().context("native workflow missing")?;
                let [first, second] = &mut workflow.branches;
                let partials = blind_issuance::issue(
                    &coin.secret,
                    [&mut first.secret, &mut second.secret],
                    std::array::from_fn(|i| FrozenResponse {
                        nonce_point: &authorization.branches[i].server_nonce,
                        nonce_commitment: &authorization.branches[i].blinding_commitment,
                        blinded_challenge: &authorization.branches[i].challenge,
                    }),
                )?;
                workflow.statement = Some(statement.clone());
                workflow.partials = Some(partials);
                // Commit the pair and retained lock before either response escapes.
                json!({"partials":partials,"authorization":authorization.digest()?,"native_pending":true})
            }
            Command::NativeExitCancel {} => {
                if let Some(identities) = &mut coin.identities {
                    identities.retire_unused();
                }
                coin.native = None;
                json!({"cancelled":true})
            }
            Command::NativeExitContribution {} => {
                let constant: Zeroizing<Digest> =
                    Zeroizing::new((-scalar(&coin.secret)?).to_bytes().into());
                let cluster = self
                    .policy
                    .native_cluster
                    .as_ref()
                    .context("native VSS cluster missing")?;
                let workflow = coin.native.as_mut().context("native workflow missing")?;
                let contribution = spark_native_vss::prepare(2, *constant, workflow.plan, cluster)?;
                contribution.validate(
                    cluster,
                    &workflow.plan,
                    (k256::ProjectivePoint::GENERATOR * scalar(&constant[..])?)
                        .to_affine()
                        .to_encoded_point(true)
                        .as_bytes(),
                )?;
                workflow.contribution = Some(contribution.clone());
                // The enclosing commit saves ciphertexts and floor before release.
                json!({"contribution":contribution,"native_pending":true})
            }
            Command::NativeExitComplete { receipt } => {
                if let Some(identities) = &mut coin.identities {
                    identities.retire_unused();
                }
                let workflow = coin.native.as_mut().context("native workflow missing")?;
                workflow.completion = Some(receipt.clone());
                // This receipt and terminal head are one checkpointed mutation.
                // Retain the native addon permanently: private Reserve stays closed.
                json!({"native_completed":true,"receipt":receipt.digest()?,"state":coin.state})
            }
            Command::NativeExitObservedComplete {
                completion,
                evidence,
            } => {
                if let Some(identities) = &mut coin.identities {
                    identities.retire_unused();
                }
                let workflow = coin.native.as_mut().context("native workflow missing")?;
                workflow.observed_completion = Some(ObservedCompletion {
                    completion: completion.clone(),
                    evidence: *evidence,
                });
                // Admission was established against the external observer before
                // this atomic checkpoint. Replays return the retained decision;
                // they never accept replacement wallet evidence.
                json!({"native_completed":true,"observation":evidence,"state":coin.state})
            }
            command if super::mpc_exit::is_command(command) => {
                self.apply_mpc_exit(&mut coin, request)?
            }
            _ => anyhow::bail!("not a native command"),
        };
        Ok((coin, response, false))
    }
}

fn authorize_observed(
    admission: &dyn crate::engine::Admission,
    request: &Request,
    completion: &NativeCompletion,
    evidence: &Digest,
) -> Result<()> {
    completion.message()?;
    ensure!(*evidence != [0; 32], "zero native completion evidence");
    admission.authorize_spark_native_completion(
        &super::admission_context(request),
        completion,
        evidence,
    )
}
