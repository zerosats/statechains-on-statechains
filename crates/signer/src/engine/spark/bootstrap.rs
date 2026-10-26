//! A fresh allocation may sign only its proof-bound initial native tree. The
//! three responses are not admission of a native deposit or prefix completion.
#[cfg(test)]
mod tests;
mod validation;
use super::{
    Command, Engine, Policy, ProofRole, ProofSpec, Request,
    blind_issuance::{self, FrozenResponse},
    state::{Branch, Coin, Phase},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zark_protocol::{
    hash, point_bytes, random_scalar, scalar,
    spark_bootstrap::{BootstrapAuthorization, BootstrapContext},
    spark_lineage::{Digest, Intent},
};

const PURPOSE: &str = "native-initial-root-bootstrap-v1";

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Stage {
    Prepared,
    Issued,
    Frozen,
    Cancelled,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Workflow {
    purpose: String,
    registry: Digest,
    cluster: Digest,
    intent: Intent,
    session: Digest,
    server: Vec<u8>,
    backing: Digest,
    capability: Digest,
    plan: Digest,
    branches: [Branch; 3],
    statement: Option<Vec<u8>>,
    partials: Option<[Digest; 3]>,
    stage: Stage,
}

pub(super) fn is_command(command: &Command) -> bool {
    matches!(
        command,
        Command::NativeBootstrapPrepare { .. }
            | Command::NativeBootstrapIssue { .. }
            | Command::NativeBootstrapCancel { .. }
    )
}
fn context(intent: &Intent, session: Digest) -> BootstrapContext {
    BootstrapContext {
        deployment: intent.deployment,
        coin: intent.coin,
        allocation_state: intent.previous_state,
        operation: intent.operation,
        session,
        revision: intent.revision,
    }
}
fn nonce_id(workflow: &Workflow, branch: &Branch) -> Result<Digest> {
    Ok(hash(&[
        b"ZARK/spark/signer/bootstrap-nonce/v1",
        PURPOSE.as_bytes(),
        &workflow.registry,
        &workflow.cluster,
        &context(&workflow.intent, workflow.session).encode()?,
        &workflow.backing,
        &workflow.capability,
        &workflow.plan,
        &workflow.server,
        &[branch.index],
        &branch.point,
        &branch.commitment,
    ]))
}

impl Engine {
    pub(super) fn bootstrap_gate(&self, coin: &Coin, request: &Request) -> Result<()> {
        if let Command::FreezeOrigin {
            backing,
            capability,
        } = &request.command
        {
            if self.policy.bootstrap.is_some() {
                ensure!(
                    coin.bootstrap.is_some(),
                    "native bootstrap required before origin freeze"
                );
            }
            if let Some(bootstrap) = &coin.bootstrap {
                ensure!(
                    bootstrap.stage == Stage::Issued
                        && bootstrap.backing == *backing
                        && bootstrap.capability == *capability,
                    "origin freeze differs from issued native bootstrap"
                );
            }
        }
        if let Some(bootstrap) = &coin.bootstrap {
            ensure!(
                bootstrap.stage == Stage::Frozen
                    || (bootstrap.stage == Stage::Issued
                        && matches!(request.command, Command::FreezeOrigin { .. })),
                "native bootstrap locks allocation"
            );
        }
        Ok(())
    }

    pub(super) fn plan_bootstrap(
        &self,
        coin: &Coin,
        request: &Request,
    ) -> Result<Option<ProofSpec>> {
        ensure!(
            self.bootstrap_verifier.is_some(),
            "bootstrap proof suite is not deployed"
        );
        ensure!(
            coin.phase == Phase::Allocated
                && coin.native.is_none()
                && coin.session == request.session
                && coin
                    .pending
                    .as_ref()
                    .is_some_and(|p| p.origin && p.intent == request.intent),
            "bootstrap allocated session or intent changed"
        );
        if let Command::NativeBootstrapPrepare {
            backing,
            capability,
            plan,
            nonce_commitments,
            owner,
        } = &request.command
        {
            ensure!(
                coin.bootstrap.is_none(),
                "allocation already used native bootstrap"
            );
            context(&request.intent, request.session).verify_owner(
                backing,
                capability,
                plan,
                &coin.server()?,
                nonce_commitments,
                &owner.public_key,
                &owner.signature.as_slice().try_into()?,
            )?;
            return Ok(None);
        }
        let bootstrap = coin
            .bootstrap
            .as_ref()
            .context("native bootstrap missing")?;
        ensure!(
            bootstrap.stage == Stage::Prepared
                && bootstrap.intent == request.intent
                && bootstrap.session == request.session,
            "native bootstrap phase or session changed"
        );
        match &request.command {
            Command::NativeBootstrapIssue { statement, .. } => {
                let statement = BootstrapAuthorization::decode(statement)?;
                bootstrap.match_statement(&self.policy, &statement)?;
                Ok(Some(ProofSpec {
                    role: ProofRole::Bootstrap,
                    statement: statement.encode()?,
                }))
            }
            Command::NativeBootstrapCancel {} => Ok(None),
            _ => anyhow::bail!("not a bootstrap command"),
        }
    }

    pub(super) fn apply_bootstrap(
        &self,
        mut coin: Coin,
        request: &Request,
    ) -> Result<(Coin, Value, bool)> {
        let response = match &request.command {
            Command::NativeBootstrapPrepare {
                backing,
                capability,
                plan,
                nonce_commitments,
                ..
            } => {
                let (registry, cluster) = self
                    .policy
                    .bootstrap
                    .context("bootstrap registry missing")?;
                let mut bootstrap = Workflow {
                    purpose: PURPOSE.into(),
                    registry,
                    cluster,
                    intent: request.intent.clone(),
                    session: request.session,
                    server: coin.server()?.to_vec(),
                    backing: *backing,
                    capability: *capability,
                    plan: *plan,
                    branches: std::array::from_fn(|i| Branch {
                        index: i as u8,
                        id: [0; 32],
                        point: Vec::new(),
                        commitment: nonce_commitments[i],
                        secret: None,
                    }),
                    statement: None,
                    partials: None,
                    stage: Stage::Prepared,
                };
                for i in 0..3 {
                    let (secret, point) = loop {
                        let secret: Digest = random_scalar().to_bytes().into();
                        let point =
                            point_bytes(k256::ProjectivePoint::GENERATOR * scalar(&secret)?)?
                                .to_vec();
                        if bootstrap.branches[..i]
                            .iter()
                            .all(|b| b.point[..32] != point[..32])
                        {
                            break (secret, point);
                        }
                    };
                    bootstrap.branches[i].point = point;
                    bootstrap.branches[i].secret = Some(secret);
                    bootstrap.branches[i].id = nonce_id(&bootstrap, &bootstrap.branches[i])?;
                }
                let response = json!({"purpose":PURPOSE,"registry":registry,"cluster":cluster,"nonces":bootstrap.branches.iter()
                    .map(|b|json!({"index":b.index,"id":b.id,"point":b.point})).collect::<Vec<_>>()});
                coin.bootstrap = Some(bootstrap);
                response
            }
            Command::NativeBootstrapIssue { statement, .. } => {
                let authorization = BootstrapAuthorization::decode(statement)?;
                let bootstrap = coin.bootstrap.as_mut().context("bootstrap missing")?;
                let [first, second, third] = &mut bootstrap.branches;
                let partials = blind_issuance::issue(
                    &coin.secret,
                    [&mut first.secret, &mut second.secret, &mut third.secret],
                    std::array::from_fn(|i| FrozenResponse {
                        nonce_point: &authorization.branches[i].server_nonce,
                        nonce_commitment: &authorization.branches[i].blinding_commitment,
                        blinded_challenge: &authorization.branches[i].challenge,
                    }),
                )?;
                bootstrap.statement = Some(statement.clone());
                bootstrap.partials = Some(partials);
                bootstrap.stage = Stage::Issued;
                json!({"partials":partials,"authorization":authorization.digest()?,"native_prefix_pending":true})
            }
            Command::NativeBootstrapCancel {} => {
                let bootstrap = coin.bootstrap.as_mut().context("bootstrap missing")?;
                for branch in &mut bootstrap.branches {
                    if let Some(secret) = &mut branch.secret {
                        zeroize::Zeroize::zeroize(secret);
                    }
                    branch.secret = None;
                }
                bootstrap.stage = Stage::Cancelled;
                json!({"cancelled":true,"allocation_retired":true})
            }
            _ => anyhow::bail!("not a bootstrap command"),
        };
        Ok((coin, response, false))
    }
}
