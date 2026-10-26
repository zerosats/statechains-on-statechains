//! Historical receive records retain public points, never historical shares.
use super::*;
use zark_protocol::{point, spark_lineage};
impl Workflow {
    pub(in crate::engine::spark) fn validate_frames(&self, engine: &Engine) -> Result<()> {
        for (id, t) in &self.transcripts {
            engine.read_receive_blob(&t.initial)?;
            for (step, (input, output)) in t.rounds.iter().enumerate() {
                engine.read_receive_blob(input)?;
                engine.read_receive_blob(output)?;
                let request = Request {
                    intent: frame_intent(&self.intent, id, step as u8)?,
                    session: self.session,
                    command: Command::ReceiveFrame {
                        operator: id.clone(),
                        step: step as u8,
                        frame: *input,
                    },
                    signature: Vec::new(),
                };
                engine.check_receive_request_slot(&request)?;
            }
        }
        Ok(())
    }
    pub(in crate::engine::spark) fn freeze(&mut self) -> Result<()> {
        ensure!(self.stage == Stage::Issued, "receive responses not issued");
        self.stage = Stage::Frozen;
        Ok(())
    }
    pub(in crate::engine::spark) fn validate_revision(&self, revision: u64) -> Result<()> {
        let rounds = if self.additive {
            u64::from(matches!(
                self.stage,
                Stage::TweaksReady | Stage::Issued | Stage::Frozen
            ))
        } else {
            self.transcripts
                .values()
                .map(|t| t.rounds.len() as u64)
                .sum::<u64>()
        };
        let base = 2
            + rounds
            + u64::from(matches!(
                self.stage,
                Stage::Issued | Stage::Frozen | Stage::Aborted
            ));
        ensure!(
            if self.stage == Stage::Frozen {
                revision > base
            } else {
                revision == base
            },
            "receive transcript revision differs"
        );
        Ok(())
    }
    pub(in crate::engine::spark) fn validate(&self, coin: &Coin, policy: &Policy) -> Result<()> {
        self.intent.encode()?;
        context(&self.intent, self.session).encode()?;
        ensure!(
            self.purpose == PURPOSE
                && policy.receive == Some((self.registry, self.cluster, self.circuit)),
            "receive pinned registry/cluster/circuit changed"
        );
        ensure!(
            self.intent.deployment == coin.deployment
                && self.intent.coin == coin.coin
                && self.intent.recipient_claim
                    == spark_lineage::origin_field(&coin.deployment, &coin.coin, 0)?
                && self.backing != [0; 32]
                && self.capability != [0; 32]
                && self.plan != [0; 32],
            "receive allocation scope"
        );
        point(&self.server)?;
        if self.stage == Stage::Frozen {
            ensure!(
                coin.phase != Phase::Allocated && coin.backing == self.backing,
                "receive frozen backing changed"
            );
        } else {
            ensure!(
                coin.phase == Phase::Allocated
                    && coin.session == self.session
                    && coin.native.is_none()
                    && coin.bootstrap.is_none()
                    && coin
                        .pending
                        .as_ref()
                        .is_some_and(|p| p.origin && p.intent == self.intent),
                "receive allocation phase changed"
            );
        }
        if coin.owner != Some(super::super::Predecessor::Transfer) {
            ensure!(
                coin.server()?.as_slice() == self.server,
                "receive allocated point changed"
            );
        }
        let cluster = policy
            .receive_cluster
            .as_ref()
            .context("receive cluster missing")?;
        ensure!(
            self.additive == policy.additive_receive,
            "receive tweak mode differs from deployment"
        );
        if self.additive {
            ensure!(
                self.transcripts.is_empty()
                    && self.secrets.is_none()
                    && self.stage != Stage::Aborted,
                "additive receive retains MPC state"
            );
        } else {
            ensure!(
                self.transcripts.keys().eq(cluster.operators.keys())
                    && self.transcripts.values().all(|t| t.initial != [0; 32]
                        && t.rounds.len() <= 7
                        && t.rounds.iter().all(|(a, b)| *a != [0; 32] && *b != [0; 32])),
                "receive transcript coverage/shape"
            );
            let ready = self.transcripts.values().all(|t| t.rounds.len() == 7);
            ensure!(
                self.secrets.is_some() == (self.stage == Stage::Prepared)
                    && (matches!(
                        self.stage,
                        Stage::TweaksReady | Stage::Issued | Stage::Frozen
                    ) == ready
                        || self.stage == Stage::Aborted),
                "receive MPC secret lifecycle"
            );
        }
        if let Some(s) = &self.secrets {
            ensure!(
                scalar(&s.slope)? != k256::Scalar::ZERO && s.seed != [0; 32],
                "receive zero MPC randomness"
            );
        }
        let issued = matches!(self.stage, Stage::Issued | Stage::Frozen);
        ensure!(
            self.statement.is_some() == issued && self.partials.is_some() == issued,
            "receive issuance lifecycle"
        );
        for (i, b) in self.branches.iter().enumerate() {
            ensure!(
                usize::from(b.index) == i && b.commitment != [0; 32] && b.id == nonce_id(self, b)?,
                "receive nonce purpose changed"
            );
            point(&b.point)?;
            ensure!(
                b.secret.is_some() == matches!(self.stage, Stage::Prepared | Stage::TweaksReady),
                "receive nonce lifecycle"
            );
            if let Some(s) = b.secret {
                ensure!(
                    point_bytes(k256::ProjectivePoint::GENERATOR * scalar(&s)?)?.as_slice()
                        == b.point,
                    "receive nonce point changed"
                );
            }
        }
        ensure!(
            self.branches[0].point[..32] != self.branches[1].point[..32]
                && self.branches[0].commitment != self.branches[1].commitment,
            "receive nonce reuse"
        );
        if let Some(bytes) = &self.statement {
            let a = ReceiveAuthorization::decode(bytes)?;
            self.match_statement(policy, &a)?;
            for (b, p) in a
                .branches
                .iter()
                .zip(self.partials.as_ref().context("receive partials missing")?)
            {
                ensure!(
                    k256::ProjectivePoint::GENERATOR * scalar(p)?
                        == point(&b.nonce)? + point(&a.server)? * scalar(&b.challenge)?,
                    "receive retained partial changed"
                );
            }
        }
        Ok(())
    }
    pub(super) fn match_statement(&self, policy: &Policy, a: &ReceiveAuthorization) -> Result<()> {
        ensure!(
            a.context == context(&self.intent, self.session)
                && a.backing == self.backing
                && a.capability == self.capability
                && a.plan == self.plan
                && a.cluster == self.cluster
                && a.server.as_slice() == self.server
                && a.policy == policy.policy
                && a.config == policy.config,
            "receive statement differs from frozen allocation"
        );
        for (b, f) in a.branches.iter().zip(&self.branches) {
            ensure!(
                b.nonce.as_slice() == f.point && b.blinding == f.commitment,
                "receive branch changed"
            );
        }
        Ok(())
    }
}
