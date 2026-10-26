//! Ordinary native claim preparation is a locked fresh-allocation workflow.
//! Opaque MPC outputs are released only after the transcript/checkpoint commit.
mod additive;
mod frames;
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
use std::collections::BTreeMap;
use zark_protocol::{
    hash, point_bytes, random_scalar, random32, scalar,
    spark_bootstrap::BootstrapContext,
    spark_lineage::{Digest, Intent},
    spark_receive::{PURPOSE, ReceiveAuthorization, frame_intent, verify_owner},
};
use zeroize::Zeroize;
pub(super) struct ContributorCache {
    prefix: Digest,
    contributor: zark_spark_claim_mpc::ClaimContributor,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Stage {
    Prepared,
    TweaksReady,
    Issued,
    Frozen,
    Aborted,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Secrets {
    slope: Digest,
    seed: Digest,
}
impl Drop for Secrets {
    fn drop(&mut self) {
        self.slope.zeroize();
        self.seed.zeroize();
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transcript {
    initial: Digest,
    rounds: Vec<(Digest, Digest)>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Workflow {
    purpose: String,
    registry: Digest,
    cluster: Digest,
    circuit: Digest,
    intent: Intent,
    session: Digest,
    server: Vec<u8>,
    backing: Digest,
    capability: Digest,
    plan: Digest,
    branches: [Branch; 2],
    secrets: Option<Secrets>,
    transcripts: BTreeMap<String, Transcript>,
    statement: Option<Vec<u8>>,
    partials: Option<[Digest; 2]>,
    stage: Stage,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    additive: bool,
}
pub(super) fn is_command(command: &Command) -> bool {
    matches!(
        command,
        Command::ReceivePrepare { .. }
            | Command::ReceiveFrame { .. }
            | Command::ReceiveTweak { .. }
            | Command::ReceiveIssue { .. }
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
fn nonce_id(w: &Workflow, b: &Branch) -> Result<Digest> {
    Ok(hash(&[
        b"ZARK/spark/signer/receive-nonce/v1",
        PURPOSE.as_bytes(),
        &w.registry,
        &w.cluster,
        &w.circuit,
        &context(&w.intent, w.session).encode()?,
        &w.backing,
        &w.capability,
        &w.plan,
        &w.server,
        &[b.index],
        &b.point,
        &b.commitment,
    ]))
}
impl Engine {
    pub(super) fn receive_gate(&self, coin: &Coin, request: &Request) -> Result<()> {
        if let Command::FreezeOrigin {
            backing,
            capability,
        } = &request.command
        {
            if self.policy.receive.is_some() {
                ensure!(
                    coin.receive.is_some(),
                    "ordinary receive required before origin freeze"
                );
            }
            if let Some(w) = &coin.receive {
                ensure!(
                    w.stage == Stage::Issued
                        && w.backing == *backing
                        && w.capability == *capability,
                    "origin freeze differs from issued ordinary receive"
                );
            }
            if self.policy.receive.is_some() {
                self.admission
                    .authorize_spark_received_origin(&super::admission_context(request), backing)?;
            }
        }
        if let Some(w) = &coin.receive {
            ensure!(
                w.stage == Stage::Frozen
                    || (w.stage == Stage::Issued
                        && matches!(request.command, Command::FreezeOrigin { .. })),
                "ordinary receive locks allocation"
            );
        }
        Ok(())
    }
    pub(super) fn plan_receive(&self, coin: &Coin, request: &Request) -> Result<Option<ProofSpec>> {
        let runtime = self
            .receive
            .as_ref()
            .context("ordinary receive is not deployed")?;
        ensure!(
            coin.phase == Phase::Allocated
                && coin.native.is_none()
                && coin.bootstrap.is_none()
                && coin.single_user.is_none()
                && coin.session == request.session,
            "ordinary receive allocation/session"
        );
        let pending = coin
            .pending
            .as_ref()
            .context("receive allocation pending")?;
        ensure!(pending.origin, "receive requires origin allocation");
        if let Command::ReceivePrepare {
            backing,
            capability,
            plan,
            nonce_commitments,
            owner,
        } = &request.command
        {
            ensure!(
                coin.receive.is_none() && pending.intent == request.intent,
                "receive allocation already used"
            );
            verify_owner(
                &context(&request.intent, request.session),
                backing,
                capability,
                plan,
                &runtime.cluster.digest()?,
                nonce_commitments,
                &owner.public_key,
                &owner.signature,
            )?;
            return Ok(None);
        }
        let w = coin
            .receive
            .as_ref()
            .context("receive preparation missing")?;
        ensure!(
            pending.intent == w.intent && request.session == w.session,
            "receive frozen allocation differs"
        );
        match &request.command {
            Command::ReceiveTweak { tweak } => {
                ensure!(request.intent == w.intent, "receive tweak context");
                Self::check_receive_tweak(w, tweak)?;
                Ok(None)
            }
            Command::ReceiveFrame {
                operator,
                step,
                frame,
            } => {
                ensure!(!w.additive, "additive receive has no MPC frames");
                let t = w
                    .transcripts
                    .get(operator)
                    .context("unconfigured receive operator")?;
                ensure!(
                    w.stage == Stage::Prepared
                        && usize::from(*step) == t.rounds.len()
                        && *step < 7
                        && *frame != [0; 32]
                        && frame_intent(&w.intent, operator, *step)? == request.intent,
                    "receive frame order/context"
                );
                self.check_receive_request_slot(request)?;
                self.read_receive_blob(frame)?;
                Ok(None)
            }
            Command::ReceiveIssue { statement, .. } => {
                ensure!(
                    w.stage == Stage::TweaksReady && request.intent == w.intent,
                    "receive tweaks are incomplete or signing already issued"
                );
                let a = ReceiveAuthorization::decode(statement)?;
                w.match_statement(&self.policy, &a)?;
                Ok(Some(ProofSpec {
                    role: ProofRole::Receive,
                    statement: a.encode()?,
                }))
            }
            _ => anyhow::bail!("not a receive command"),
        }
    }
    pub(super) fn apply_receive(
        &self,
        mut coin: Coin,
        request: &Request,
    ) -> Result<(Coin, Value, bool)> {
        let response = match &request.command {
            Command::ReceivePrepare {
                backing,
                capability,
                plan,
                nonce_commitments,
                ..
            } => {
                let runtime = self.receive.as_ref().context("receive runtime missing")?;
                let (registry, cluster, circuit) =
                    self.policy.receive.context("receive policy missing")?;
                let additive = self.policy.additive_receive;
                let secrets = (!additive).then(|| Secrets {
                    slope: loop {
                        let slope: Digest = random_scalar().to_bytes().into();
                        if runtime.cluster.operators.values().all(|op| {
                            -scalar(&coin.secret).expect("validated secret")
                                + scalar(&slope).expect("fresh scalar")
                                    * k256::Scalar::from(u64::from(op.index))
                                != k256::Scalar::ZERO
                        }) {
                            break slope;
                        }
                    },
                    seed: random32(),
                });
                let mut w = Workflow {
                    purpose: PURPOSE.into(),
                    registry,
                    cluster,
                    circuit,
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
                    secrets,
                    transcripts: BTreeMap::new(),
                    statement: None,
                    partials: None,
                    stage: Stage::Prepared,
                    additive,
                };
                for i in 0..2 {
                    let (secret, point) = loop {
                        let secret: Digest = random_scalar().to_bytes().into();
                        let point =
                            point_bytes(k256::ProjectivePoint::GENERATOR * scalar(&secret)?)?
                                .to_vec();
                        if w.branches[..i].iter().all(|b| b.point[..32] != point[..32]) {
                            break (secret, point);
                        }
                    };
                    w.branches[i].point = point;
                    w.branches[i].secret = Some(secret);
                    w.branches[i].id = nonce_id(&w, &w.branches[i])?;
                }
                let nonces = w
                    .branches
                    .iter()
                    .map(|b| json!({"index":b.index,"id":b.id,"point":b.point}))
                    .collect::<Vec<_>>();
                if additive {
                    coin.receive = Some(w);
                    return Ok((
                        coin,
                        json!({"purpose":PURPOSE,"registry":registry,"cluster":cluster,"circuit":circuit,"additive":true,"nonces":nonces}),
                        false,
                    ));
                }
                let slope = w
                    .secrets
                    .as_ref()
                    .context("receive MPC secrets missing")?
                    .slope;
                let mut operators = BTreeMap::new();
                for id in runtime.cluster.operators.keys() {
                    let (mask, _, message) = self.receive_contributor(&w, &coin.secret, id)?;
                    let initial = self.write_receive_blob(&message)?;
                    operators.insert(
                        id.clone(),
                        json!({"header":mask.header(),"initial":initial}),
                    );
                    w.transcripts.insert(
                        id.clone(),
                        Transcript {
                            initial,
                            rounds: Vec::new(),
                        },
                    );
                }
                let coefficients = [
                    point_bytes(-zark_protocol::point(&w.server)?)?.to_vec(),
                    point_bytes(k256::ProjectivePoint::GENERATOR * scalar(&slope)?)?.to_vec(),
                ];
                let response = json!({"purpose":PURPOSE,"registry":registry,"cluster":cluster,"circuit":circuit,"coefficients":coefficients,"operators":operators,
                    "nonces":nonces});
                coin.receive = Some(w);
                response
            }
            Command::ReceiveTweak { tweak } => self.release_receive_tweak(&mut coin, tweak)?,
            Command::ReceiveFrame {
                operator, frame, ..
            } => {
                let w = coin
                    .receive
                    .as_ref()
                    .context("receive preparation missing")?;
                let result = self.advance_receive(w, &coin.secret, operator, frame);
                let w = coin
                    .receive
                    .as_mut()
                    .context("receive preparation missing")?;
                match result {
                    Ok(reply) => {
                        let t = w
                            .transcripts
                            .get_mut(operator)
                            .context("receive operator missing")?;
                        t.rounds.push((*frame, reply));
                        if w.transcripts.values().all(|t| t.rounds.len() == 7) {
                            w.secrets = None;
                            w.stage = Stage::TweaksReady;
                        }
                        json!({"reply":reply,"tweaks_ready":w.stage==Stage::TweaksReady})
                    }
                    Err(_) => {
                        // Any uncertain protocol failure retires all inputs and OT
                        // randomness. An alternate frame must never reuse them.
                        w.secrets = None;
                        w.stage = Stage::Aborted;
                        self.clear_receive_cache(w)?;
                        for b in &mut w.branches {
                            if let Some(s) = &mut b.secret {
                                s.zeroize();
                            }
                            b.secret = None;
                        }
                        json!({"aborted":true,"allocation_retired":true})
                    }
                }
            }
            Command::ReceiveIssue { statement, .. } => {
                let a = ReceiveAuthorization::decode(statement)?;
                let w = coin
                    .receive
                    .as_mut()
                    .context("receive preparation missing")?;
                let [first, second] = &mut w.branches;
                let partials = blind_issuance::issue(
                    &coin.secret,
                    [&mut first.secret, &mut second.secret],
                    std::array::from_fn(|i| FrozenResponse {
                        nonce_point: &a.branches[i].nonce,
                        nonce_commitment: &a.branches[i].blinding,
                        blinded_challenge: &a.branches[i].challenge,
                    }),
                )?;
                w.statement = Some(statement.clone());
                w.partials = Some(partials);
                w.stage = Stage::Issued;
                json!({"partials":partials,"authorization":a.digest()?,"native_claim_pending":true})
            }
            _ => anyhow::bail!("not a receive command"),
        };
        Ok((coin, response, false))
    }
}
