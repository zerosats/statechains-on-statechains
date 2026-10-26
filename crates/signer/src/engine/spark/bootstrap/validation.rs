//! Bootstrap history keeps only the old public point after share refresh. It
//! never stores an extra historical secret or exposes this record to a receiver.
use super::*;
use zark_protocol::{point, spark_lineage};

impl Workflow {
    pub(in crate::engine::spark) fn freeze(&mut self) -> Result<()> {
        ensure!(
            self.stage == Stage::Issued,
            "bootstrap responses not issued"
        );
        self.stage = Stage::Frozen;
        Ok(())
    }
    pub(in crate::engine::spark) fn validate_revision(&self, revision: u64) -> Result<()> {
        let expected = match self.stage {
            Stage::Prepared => Some(2),
            Stage::Issued | Stage::Cancelled => Some(3),
            Stage::Frozen => None,
        };
        ensure!(
            expected.is_none_or(|value| value == revision),
            "bootstrap phase revision changed"
        );
        if self.stage == Stage::Frozen {
            ensure!(revision >= 4, "bootstrap origin freeze revision missing");
        }
        Ok(())
    }
    pub(in crate::engine::spark) fn validate(&self, coin: &Coin, policy: &Policy) -> Result<()> {
        self.intent.encode()?;
        context(&self.intent, self.session).encode()?;
        ensure!(
            self.purpose == PURPOSE && policy.bootstrap == Some((self.registry, self.cluster)),
            "bootstrap registry changed or missing"
        );
        ensure!(
            self.intent.deployment == coin.deployment
                && self.intent.coin == coin.coin
                && self.intent.recipient_claim
                    == spark_lineage::origin_field(&coin.deployment, &coin.coin, 0)?
                && self.backing != [0; 32]
                && self.capability != [0; 32]
                && self.plan != [0; 32],
            "bootstrap allocation scope"
        );
        point(&self.server)?;
        if self.stage == Stage::Frozen {
            ensure!(
                coin.phase != Phase::Allocated && coin.backing == self.backing,
                "bootstrap frozen backing changed"
            );
        } else {
            ensure!(
                coin.phase == Phase::Allocated
                    && coin.native.is_none()
                    && coin.session == self.session
                    && coin
                        .pending
                        .as_ref()
                        .is_some_and(|p| p.origin && p.intent == self.intent),
                "bootstrap allocation phase changed"
            );
        }
        if coin.owner != Some(super::super::Predecessor::Transfer) {
            ensure!(
                coin.server()?.as_slice() == self.server,
                "bootstrap allocated point changed"
            );
            if self.stage == Stage::Frozen {
                ensure!(
                    coin.capability == self.capability,
                    "bootstrap initial owner changed"
                );
            }
        }
        let issued = matches!(self.stage, Stage::Issued | Stage::Frozen);
        ensure!(
            self.statement.is_some() == issued && self.partials.is_some() == issued,
            "bootstrap issuance lifecycle"
        );
        for (i, branch) in self.branches.iter().enumerate() {
            ensure!(
                branch.index as usize == i
                    && branch.commitment != [0; 32]
                    && branch.id == nonce_id(self, branch)?,
                "bootstrap nonce purpose changed"
            );
            point(&branch.point)?;
            ensure!(
                branch.secret.is_some() == (self.stage == Stage::Prepared),
                "bootstrap nonce lifecycle"
            );
            if let Some(secret) = branch.secret {
                ensure!(
                    point_bytes(k256::ProjectivePoint::GENERATOR * scalar(&secret)?)?.as_slice()
                        == branch.point,
                    "bootstrap nonce point changed"
                );
            }
            for prior in &self.branches[..i] {
                ensure!(
                    branch.point[..32] != prior.point[..32]
                        && branch.commitment != prior.commitment,
                    "bootstrap nonce reuse"
                );
            }
        }
        if let Some(raw) = &self.statement {
            let statement = BootstrapAuthorization::decode(raw)?;
            self.match_statement(policy, &statement)?;
            for (branch, partial) in statement.branches.iter().zip(
                self.partials
                    .as_ref()
                    .context("bootstrap partials missing")?,
            ) {
                ensure!(
                    k256::ProjectivePoint::GENERATOR * scalar(partial)?
                        == point(&branch.server_nonce)?
                            + point(&statement.server)? * scalar(&branch.challenge)?,
                    "bootstrap retained partial changed"
                );
            }
        }
        Ok(())
    }
    pub(super) fn match_statement(
        &self,
        policy: &Policy,
        statement: &BootstrapAuthorization,
    ) -> Result<()> {
        ensure!(
            statement.context == context(&self.intent, self.session)
                && statement.backing == self.backing
                && statement.capability == self.capability
                && statement.plan == self.plan
                && statement.cluster == self.cluster
                && statement.policy == policy.policy
                && statement.config == policy.config
                && statement.server.as_slice() == self.server,
            "bootstrap statement differs from frozen allocation"
        );
        for (branch, frozen) in statement.branches.iter().zip(&self.branches) {
            ensure!(
                branch.server_nonce.as_slice() == frozen.point
                    && branch.blinding_commitment == frozen.commitment,
                "bootstrap branch changed"
            );
        }
        Ok(())
    }
}
