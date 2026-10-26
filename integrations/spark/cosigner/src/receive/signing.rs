//! Two native claim refunds, constrained by the separately pinned receive VK.
use super::*;
use crate::{
    leaf_signing::OperatorCommitments,
    native_bridge::{SingleUserContribution, SingleUserPrecommit, SingleUserRequest},
};
use zark_protocol::{
    spark_receive::{ReceiveAuthorization, branch_plan, exit_context},
    spark_wire::Command,
};
impl ReceiveJournal {
    fn nonce(&self, index: usize) -> Result<[u8; 64]> {
        ensure!(index < 2, "receive native variant");
        let bytes: Vec<u8> = serde_json::from_value(
            self.record
                .prepared
                .as_ref()
                .context("receive nonces absent")?["nonces"][index]["point"]
                .clone(),
        )?;
        Ok(bytes.as_slice().try_into()?)
    }
    fn precommit(&self, index: usize) -> Result<SingleUserPrecommit> {
        ensure!(index < 2, "receive native variant");
        SingleUserPrecommit::from_opening(
            &self.key,
            &exit_context(&self.context()?),
            &branch_plan(&self.record.plan.commitment(self.raw_user()?)?, index)?,
            &self.record.openings[index],
        )
    }
    fn operators(&self, index: usize) -> Result<OperatorCommitments> {
        ensure!(index < 2, "receive native variant");
        let rows = &self
            .record
            .operators
            .as_ref()
            .context("receive operator commitments absent")?[index];
        let mut out = OperatorCommitments::new();
        for r in rows {
            let id = frost_secp256k1_tr::Identifier::deserialize(&r.id)?;
            let c = frost_secp256k1_tr::round1::SigningCommitments::deserialize(&r.commitment)?;
            ensure!(
                id.serialize() == r.id
                    && c.serialize()? == r.commitment
                    && self
                        .record
                        .cluster
                        .operators
                        .contains_key(&hex::encode(&r.id))
                    && out.insert(id, c).is_none(),
                "receive native operator transcript encoding/coverage"
            );
        }
        ensure!(out.len() == 2, "receive native signing quorum");
        Ok(out)
    }
    pub(super) fn signing_request(&self, index: usize) -> Result<SingleUserRequest> {
        self.precommit(index)?
            .attach(&self.key, &self.nonce(index)?)?
            .bind(
                &self.key,
                self.record.plan.bodies(self.raw_user()?)?.sighashes[index],
                self.operators(index)?,
            )
    }
    pub fn user_commitment(
        &self,
        index: usize,
    ) -> Result<frost_secp256k1_tr::round1::SigningCommitments> {
        self.persist()?;
        Ok(self
            .precommit(index)?
            .attach(&self.key, &self.nonce(index)?)?
            .commitment())
    }
    pub fn bind_operators(&mut self, operators: [OperatorCommitments; 2]) -> Result<()> {
        ensure!(
            !self.record.requests.contains_key(&25),
            "receive signing transcript already frozen"
        );
        self.packages()?;
        let mut lists = Vec::new();
        for list in operators {
            lists.push(
                list.into_iter()
                    .map(|(id, c)| {
                        Ok(Operator {
                            id: id.serialize(),
                            commitment: c.serialize()?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
            );
        }
        let rows: [Vec<Operator>; 2] = lists
            .try_into()
            .map_err(|_| anyhow::anyhow!("receive job count"))?;
        if let Some(saved) = &self.record.operators {
            ensure!(
                serde_json::to_vec(saved)? == serde_json::to_vec(&rows)?,
                "receive operator transcript retry differs"
            );
        } else {
            self.record.operators = Some(rows);
        }
        self.authorization()?;
        self.persist()
    }
    pub fn authorization(&self) -> Result<ReceiveAuthorization> {
        let a = self.witness()?.authorize(
            self.context()?,
            self.record.policy,
            self.record.config.clone(),
            self.record.server.as_slice().try_into()?,
            [self.nonce(0)?, self.nonce(1)?],
        )?;
        for i in 0..2 {
            let r = self.signing_request(i)?;
            ensure!(
                r.blinded_challenge() == a.branches[i].challenge
                    && r.blinding_commitment() == a.branches[i].blinding,
                "receive proof/FROST arithmetic differs"
            );
        }
        Ok(a)
    }
    pub fn prover_toml(&self) -> Result<Zeroizing<String>> {
        self.persist()?;
        let a = self.authorization()?;
        let mut out = crate::private_transfer::witness::statement(&a.encode()?)?;
        self.witness()?.append_prover_fields(&mut out)?;
        Ok(out)
    }
    pub fn issue_request(
        &mut self,
        proof: Vec<u8>,
        verifier: &PinnedReceiveVerifier,
        scratch: &Path,
    ) -> Result<Request> {
        ensure!(
            verifier.registry_fingerprint() == self.record.registry,
            "receive proof registry differs"
        );
        let a = self.authorization()?;
        verifier.verify(&a, &proof, scratch)?;
        if let Some(r) = self.frozen(25)? {
            let Command::ReceiveIssue {
                statement,
                proof: old,
            } = &r.command
            else {
                anyhow::bail!("invalid saved receive issue");
            };
            ensure!(
                *statement == a.encode()? && *old == proof,
                "receive issue retry changed"
            );
            return Ok(r);
        }
        self.freeze(Command::ReceiveIssue {
            statement: a.encode()?,
            proof,
        })
    }
    pub fn bind_partials(&mut self, response: &Value) -> Result<()> {
        ensure!(
            self.record.requests.contains_key(&25),
            "receive issuance not frozen"
        );
        let a = self.authorization()?;
        ensure!(
            serde_json::from_value::<Digest>(response["authorization"].clone())? == a.digest()?,
            "receive response authorization differs"
        );
        let partials: [Digest; 2] = serde_json::from_value(response["partials"].clone())?;
        for (i, p) in partials.into_iter().enumerate() {
            self.signing_request(i)?.complete(p)?;
        }
        ensure!(
            self.record.partials.is_none_or(|old| old == partials),
            "receive response retry changed"
        );
        self.record.partials = Some(partials);
        self.persist()
    }
    pub fn contribution(&self, index: usize) -> Result<SingleUserContribution> {
        ensure!(index < 2, "receive native variant");
        self.persist()?;
        self.signing_request(index)?.complete(
            self.record
                .partials
                .context("receive partial responses absent")?[index],
        )
    }
    pub fn expected_refunds(&self) -> Result<([Vec<u8>; 2], [Digest; 2])> {
        let b = self.record.plan.bodies(self.raw_user()?)?;
        Ok((b.refunds, b.sighashes))
    }
}
