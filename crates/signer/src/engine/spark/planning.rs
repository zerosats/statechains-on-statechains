//! Match canonical ownership statements against the actual frozen signer state.
use super::{
    Command, Engine, Predecessor, ProofRole, ProofSpec, Request,
    state::{Coin, Phase},
};
use anyhow::{Context, Result, ensure};
use zark_protocol::{
    point_bytes, scalar,
    spark_lineage::{self as lineage, Handover, Issuance, SparkRole},
};

impl Engine {
    pub(super) fn plan(&self, coin: &Coin, request: &Request) -> Result<Option<ProofSpec>> {
        coin.validate(&self.policy)?;
        super::share_release::terminal_gate(coin)?;
        if super::ecdsa_2p::is_command(&request.command) {
            return self.plan_ecdsa(coin, request);
        }
        self.ecdsa_gate(coin, request)?;
        if super::identity::is_command(&request.command) {
            return self.plan_identity(coin, request);
        }
        if super::auth::is_command(&request.command) {
            return self.plan_auth(coin, request);
        }
        ensure!(
            !coin.identities.as_ref().is_some_and(|s| s.active()),
            "unfinished identity signing locks the receive allocation"
        );
        if super::native_tweaks::is_command(&request.command) {
            return self.plan_native_tweaks(coin, request);
        }
        if super::receive::is_command(&request.command) {
            return self.plan_receive(coin, request);
        }
        self.receive_gate(coin, request)?;
        if super::single_user::is_command(&request.command) {
            return self.plan_single_user(coin, request);
        }
        ensure!(
            coin.single_user.is_none(),
            "Spark single-USER signing locks private ownership"
        );
        if super::bootstrap::is_command(&request.command) {
            return self.plan_bootstrap(coin, request);
        }
        self.bootstrap_gate(coin, request)?;
        if super::native::is_command(&request.command) {
            return self.plan_native(coin, request);
        }
        ensure!(
            coin.native.is_none(),
            "Spark native workflow locks private ownership"
        );
        if super::share_release::is_command(&request.command) {
            self.plan_share_release(coin, request)?;
            return Ok(None);
        }
        ensure!(
            request.intent.coin == coin.coin && request.intent.deployment == coin.deployment,
            "Spark request coin changed"
        );
        if !matches!(request.command, Command::Reserve { .. }) {
            let pending = coin
                .pending
                .as_ref()
                .context("Spark pending operation missing")?;
            ensure!(
                pending.intent == request.intent,
                "Spark frozen intent changed"
            );
        }
        let spec = match &request.command {
            Command::FreezeOrigin {
                backing,
                capability,
            } => {
                ensure!(
                    coin.phase == Phase::Allocated && request.session == coin.session,
                    "Spark origin freeze session or phase"
                );
                ensure!(
                    *backing != [0; 32]
                        && *capability != [0; 32]
                        && *capability != lineage::origin_field(&coin.deployment, &coin.coin, 5)?,
                    "Spark origin commitments"
                );
                None
            }
            Command::Reserve { owner } => {
                ensure!(
                    coin.phase == Phase::Accepted && request.intent.previous_state == coin.state,
                    "Spark reservation phase or state"
                );
                owner.verify(&request.intent, &request.session, &coin.capability)?;
                None
            }
            Command::Handover {
                predecessor,
                statement,
                ..
            } => {
                let pending = coin.pending.as_ref().context("Spark handover pending")?;
                ensure!(
                    coin.phase == Phase::Reserved
                        && pending.sender == Some(request.session)
                        && Some(*predecessor) == coin.owner,
                    "Spark sender session, phase or predecessor"
                );
                let handover = Handover::decode(statement)?;
                ensure!(
                    handover.intent == pending.intent
                        && handover.config == self.policy.config
                        && handover.backing == coin.backing
                        && handover.policy == self.policy.policy
                        && handover.previous_capability == coin.capability
                        && handover.server_share == coin.server_commitment()?
                        && Some(handover.mask) == pending.mask_commitment,
                    "Spark sender statement differs from frozen reservation"
                );
                Some(ProofSpec {
                    role: ProofRole::Ownership(if *predecessor == Predecessor::Origin {
                        SparkRole::SenderFromOrigin
                    } else {
                        SparkRole::SenderFromTransfer
                    }),
                    statement: handover.encode()?,
                })
            }
            Command::ProposeRecipient {
                token,
                delta,
                delta_salt,
                next_capability,
            } => {
                let pending = coin.pending.as_ref().context("Spark recipient pending")?;
                ensure!(
                    coin.phase == Phase::Handover,
                    "Spark recipient proposal phase"
                );
                let handover = Handover::decode(
                    pending
                        .handover
                        .as_ref()
                        .context("Spark authenticated handover missing")?,
                )?;
                ensure!(
                    lineage::draft_token_commitment(&pending.intent, token)?
                        == handover.draft_token,
                    "Spark confidential draft token"
                );
                scalar(delta)?;
                ensure!(
                    *delta_salt != [0; 32]
                        && *next_capability != [0; 32]
                        && *next_capability != coin.capability,
                    "Spark recipient commitments"
                );
                let draft = scalar(&coin.secret)? + scalar(delta)?
                    - scalar(pending.mask.as_ref().context("Spark frozen mask")?)?;
                point_bytes(k256::ProjectivePoint::GENERATOR * draft)?;
                None
            }
            Command::Prepare {
                successor_state,
                recovery,
                nonce_commitments,
            } => {
                let pending = coin.pending.as_ref().context("Spark recovery pending")?;
                ensure!(
                    matches!(coin.phase, Phase::Origin | Phase::Proposed)
                        && pending.recipient == Some(request.session),
                    "Spark recovery session or phase"
                );
                ensure!(
                    *successor_state != [0; 32]
                        && *recovery != [0; 32]
                        && nonce_commitments.iter().all(|value| *value != [0; 32])
                        && nonce_commitments[0] != nonce_commitments[1],
                    "Spark recovery preparation commitments"
                );
                None
            }
            Command::Issue { statement, .. } => {
                let pending = coin.pending.as_ref().context("Spark issuance pending")?;
                ensure!(
                    coin.phase == Phase::Prepared && pending.recipient == Some(request.session),
                    "Spark issuance phase or session"
                );
                let issuance = Issuance::decode(statement)?;
                lineage::require_intent(&issuance, &pending.intent)?;
                let authorization = &issuance.recovery;
                let preparation = pending
                    .preparation
                    .as_ref()
                    .context("Spark frozen recovery missing")?;
                let secret = if pending.origin {
                    coin.secret
                } else {
                    pending.draft_secret.context("Spark draft authority")?
                };
                let salt = if pending.origin {
                    coin.salt
                } else {
                    pending.draft_salt.context("Spark draft salt")?
                };
                let server = point_bytes(k256::ProjectivePoint::GENERATOR * scalar(&secret)?)?;
                ensure!(
                    issuance.config == self.policy.config
                        && authorization.context.session == request.session
                        && authorization.backing == coin.backing
                        && authorization.policy == self.policy.policy
                        && authorization.context.successor_state == preparation.successor_state
                        && authorization.recovery == preparation.recovery
                        && authorization.server == server
                        && Some(issuance.next_capability) == pending.next_capability
                        && issuance.server_share
                            == lineage::server_commitment(
                                &coin.deployment,
                                &coin.coin,
                                &server,
                                &salt
                            )?,
                    "Spark issuance differs from frozen recipient or authority"
                );
                for (branch, frozen) in authorization.branches.iter().zip(&preparation.branches) {
                    ensure!(
                        branch.server_nonce.as_slice() == frozen.point
                            && branch.nonce_commitment == frozen.commitment,
                        "Spark issuance nonce purpose or branch changed"
                    );
                }
                if pending.origin {
                    let fields = [
                        issuance.recipient_claim,
                        issuance.mask,
                        issuance.masked_share,
                        issuance.bridge,
                        issuance.delta,
                        issuance.previous_capability,
                    ];
                    for (index, field) in fields.iter().enumerate() {
                        ensure!(
                            *field
                                == lineage::origin_field(
                                    &coin.deployment,
                                    &coin.coin,
                                    index as u32
                                )?,
                            "Spark origin sentinel changed"
                        );
                    }
                } else {
                    let handover = Handover::decode(
                        pending.handover.as_ref().context("Spark proved handover")?,
                    )?;
                    ensure!(
                        issuance.mask == handover.mask
                            && issuance.masked_share == handover.masked_share
                            && issuance.bridge == handover.bridge
                            && issuance.previous_capability == handover.previous_capability
                            && issuance.previous_capability == coin.capability
                            && issuance.delta
                                == lineage::delta_commitment(
                                    &authorization.context,
                                    pending.delta.as_ref().context("Spark receiver delta")?,
                                    pending
                                        .delta_salt
                                        .as_ref()
                                        .context("Spark receiver delta salt")?
                                )?,
                        "Spark issuance differs from authenticated share refresh"
                    );
                }
                Some(ProofSpec {
                    role: ProofRole::Ownership(if pending.origin {
                        SparkRole::Deposit
                    } else {
                        SparkRole::Receiver
                    }),
                    statement: issuance.encode()?,
                })
            }
            Command::Acknowledge { state, certificate } => {
                let pending = coin
                    .pending
                    .as_ref()
                    .context("Spark acknowledgement pending")?;
                ensure!(
                    coin.phase == Phase::Issued
                        && pending.recipient == Some(request.session)
                        && *state == coin.state
                        && *certificate == coin.certificate_id()?,
                    "Spark acknowledgement differs from issued recovery"
                );
                None
            }
            Command::Cancel { .. } => {
                let pending = coin
                    .pending
                    .as_ref()
                    .context("Spark cancellation pending")?;
                ensure!(
                    !pending.origin
                        && pending.sender == Some(request.session)
                        && matches!(
                            coin.phase,
                            Phase::Reserved | Phase::Handover | Phase::Proposed | Phase::Prepared
                        ),
                    "Spark cancellation is not a pre-issuance sender operation"
                );
                None
            }
            Command::Allocate { .. } => anyhow::bail!("Spark allocation reached existing coin"),
            Command::Exit { .. } => {
                anyhow::bail!("Spark native exit authorization is not deployed")
            }
            Command::Head { .. } => anyhow::bail!("Spark head query reached mutation planner"),
            Command::NativeExitPrepare { .. }
            | Command::NativeExitIssue { .. }
            | Command::NativeExitCancel { .. }
            | Command::NativeExitContribution { .. }
            | Command::NativeExitComplete { .. }
            | Command::NativeExitObservedComplete { .. } => unreachable!("native dispatched above"),
            Command::NativeBootstrapPrepare { .. }
            | Command::NativeBootstrapIssue { .. }
            | Command::NativeBootstrapCancel { .. } => unreachable!("bootstrap dispatched above"),
            Command::SingleUserPrepare { .. }
            | Command::SingleUserIssue { .. }
            | Command::SingleUserCancel {} => unreachable!("single-USER dispatched above"),
            Command::ReceivePrepare { .. }
            | Command::ReceiveFrame { .. }
            | Command::ReceiveTweak { .. }
            | Command::ReceiveIssue { .. } => unreachable!("receive dispatched above"),
            Command::IdentityPrepare { .. }
            | Command::IdentityFrame { .. }
            | Command::IdentityDecrypt { .. }
            | Command::IdentitySign { .. } => unreachable!("identity dispatched above"),
            Command::NativeTweakPrepare { .. }
            | Command::NativeTweakFrame { .. }
            | Command::NativeTweakSeal { .. } => unreachable!("native tweaks dispatched above"),
            Command::AuthPrepare { .. } | Command::AuthIssue { .. } => {
                unreachable!("Spark auth dispatched above")
            }
            Command::NativeMpcContribution { .. }
            | Command::NativeTransferAuthPrepare { .. }
            | Command::NativeTransferAuthIssue { .. } => {
                unreachable!("Spark MPC exit dispatched above")
            }
            Command::EcdsaKeygen { .. }
            | Command::EcdsaKeygenFinish { .. }
            | Command::EcdsaSign { .. }
            | Command::EcdsaSignFinish { .. } => unreachable!("ECDSA-2P dispatched above"),
            Command::ShareRelease { .. } => unreachable!("share release dispatched above"),
        };
        Ok(spec)
    }
}
