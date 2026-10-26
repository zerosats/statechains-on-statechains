//! Enter the ordinary Zark origin workflow only after receiving the exact
//! signed native prefix. Engine's independent native observer gates freezing.
use super::*;
use crate::private_transfer::{
    PrivateBacking, PrivateRecovery, RecoveryJournal, RecoveryParameters, origin_prover_toml,
};
use zark_protocol::{
    handoff::RecoverySchedule,
    spark_lineage::{PinnedSparkVerifier, capability_commitment},
    spark_wire::Predecessor,
};
impl ReceiveJournal {
    /// Begin the first blinded handover from a completed native receive.
    /// The capability stays inside this journal; callers cannot export it.
    #[allow(clippy::too_many_arguments)]
    pub fn start_sender(
        &self,
        directory: &Path,
        next: crate::private_transfer::NextRecipient,
        backing: &PrivateBacking,
        recovery: &PrivateRecovery,
        certificate: &crate::private_transfer::PrivateCertificate,
        verifier: &PinnedSparkVerifier,
        scratch: &Path,
    ) -> Result<crate::private_transfer::PrivateSender> {
        ensure!(
            self.record.partials.is_some()
                && recovery.frozen().backing == self.backing_commitment()?
                && recovery.witness().user == self.record.user
                && certificate.authorization().next_capability
                    == capability_commitment(
                        &self.record.intent.deployment,
                        &self.record.intent.coin,
                        &self.record.owner
                    )?,
            "received origin current owner differs"
        );
        self.persist()?;
        crate::private_transfer::PrivateSender::create(
            directory,
            crate::private_transfer::SenderParameters {
                intent: next.intent.clone(),
                session_secret: zark_protocol::owner_auth::generate_secret(),
                owner_secret: self.record.owner,
                claim_key: next.claim_key,
                claim_salt: next.claim_salt,
            },
            backing,
            recovery,
            certificate,
            verifier,
            scratch,
        )
    }
    pub fn received_backing(
        &self,
        anchor: crate::initial_exit::DepositAnchor,
        prefix: crate::initial_exit::InitialRootLeafExitV1,
        incoming: &crate::initial_exit::InitialRootLeafExitV1,
    ) -> Result<PrivateBacking> {
        self.persist()?;
        // Checking only the final prefix would admit an independently spendable
        // same-window refund retained from the sender's transfer package.
        crate::initial_exit::validate_received_root_claim_custody(
            &anchor,
            self.key.native_keys(),
            &prefix,
            incoming,
            self.record.plan.native_delay,
        )?;
        let backing = PrivateBacking::new_received_root(
            anchor,
            self.key.native_keys().clone(),
            prefix,
            self.record.plan.native_delay,
            self.record.backing_salt,
        )?;
        let c = self.context()?;
        let context = zark_protocol::spark_recovery::RecoveryContext {
            deployment: c.deployment,
            coin: c.coin,
            previous_state: c.allocation_state,
            operation: c.operation,
            session: c.session,
            successor_state: [1; 32],
            revision: c.revision,
        };
        ensure!(
            backing.commitment(
                &context,
                &backing.owner_key(
                    &self.record.server.as_slice().try_into()?,
                    scalar(&self.record.user)?
                )?
            )? == self.backing_commitment()?,
            "native received backing differs from proof-bound claim"
        );
        Ok(backing)
    }
    pub fn create_origin_recovery(
        &self,
        directory: &Path,
        backing: &PrivateBacking,
        payout_secret: Digest,
        fee: u64,
        schedule: RecoverySchedule,
    ) -> Result<RecoveryJournal> {
        ensure!(
            self.record.partials.is_some(),
            "receive claim signatures not completed"
        );
        self.persist()?;
        let recovery = PrivateRecovery::prepare(
            backing,
            RecoveryParameters {
                intent: self.record.intent.clone(),
                session: self.context()?.session,
                server: self.record.server.as_slice().try_into()?,
                server_salt: self.record.server_salt,
                user: self.record.user,
                next_capability: capability_commitment(
                    &self.record.intent.deployment,
                    &self.record.intent.coin,
                    &self.record.owner,
                )?,
                payout_secret,
                fee,
                owner_index: 1,
                schedule,
            },
        )?;
        ensure!(
            recovery.frozen().backing == self.backing_commitment()?,
            "origin recovery backing differs from native claim"
        );
        RecoveryJournal::create(
            directory,
            Predecessor::Origin,
            backing,
            recovery,
            self.record.session,
        )
    }
    pub fn freeze_origin_request(&mut self, recovery: &RecoveryJournal) -> Result<Request> {
        ensure!(
            self.record.partials.is_some()
                && recovery.recovery().frozen().backing == self.backing_commitment()?
                && recovery.recovery().next_capability()
                    == capability_commitment(
                        &self.record.intent.deployment,
                        &self.record.intent.coin,
                        &self.record.owner
                    )?,
            "receive origin freeze differs"
        );
        if let Some(request) = self.frozen(2)? {
            return Ok(request);
        }
        self.freeze(Command::FreezeOrigin {
            backing: recovery.recovery().frozen().backing,
            capability: recovery.recovery().next_capability(),
        })
    }
    pub fn origin_prover_toml(
        &self,
        recovery: &RecoveryJournal,
        ownership: &PinnedSparkVerifier,
    ) -> Result<Zeroizing<String>> {
        self.persist()?;
        ensure!(
            recovery.recovery().frozen().backing == self.backing_commitment()?,
            "receive origin witness backing differs"
        );
        origin_prover_toml(recovery.recovery(), &self.record.owner, ownership)
    }
}
