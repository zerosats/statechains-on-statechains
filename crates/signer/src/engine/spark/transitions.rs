//! Apply only a revalidated, real-proof-authorized mutation to the local copy.
use super::{
    Command, Engine, Predecessor, Request,
    blind_issuance::{self, FrozenResponse},
    state::{Branch, Coin, Pending, Phase, Preparation},
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use zark_protocol::{
    hash, point_bytes, random_scalar, random32, scalar,
    spark_lineage::{self as lineage, Certificate, Issuance},
};
use zeroize::{Zeroize, Zeroizing};

impl Engine {
    pub(super) fn allocate(&self, request: &Request) -> Result<Coin> {
        let intent = &request.intent;
        ensure!(
            intent.revision == 1
                && intent.previous_state
                    == lineage::origin_previous_state(&intent.deployment, &intent.coin)?
                && intent.recipient_claim
                    == lineage::origin_field(&intent.deployment, &intent.coin, 0)?,
            "Spark allocation requires a fresh origin"
        );
        Ok(Coin {
            deployment: intent.deployment,
            coin: intent.coin,
            backing: [0; 32],
            state: intent.previous_state,
            capability: [0; 32],
            secret: random_scalar().to_bytes().into(),
            salt: nonzero_random(),
            session: request.session,
            owner: None,
            phase: Phase::Allocated,
            pending: Some(Pending::new(request, true)),
            issuance: None,
            partials: None,
            origin_signature: None,
            native: None,
            bootstrap: None,
            single_user: None,
            receive: None,
            identities: None,
            auth: None,
            ecdsa: None,
            exit: None,
        })
    }

    pub(super) fn apply(&self, mut coin: Coin, request: &Request) -> Result<(Coin, Value, bool)> {
        if super::share_release::is_command(&request.command) {
            return self.apply_share_release(coin, request);
        }
        if super::ecdsa_2p::is_command(&request.command) {
            return self.apply_ecdsa(coin, request);
        }
        if super::identity::is_command(&request.command) {
            return self.apply_identity(coin, request);
        }
        if super::auth::is_command(&request.command) {
            return self.apply_auth(coin, request);
        }
        if super::native_tweaks::is_command(&request.command) {
            return self.apply_native_tweaks(coin, request);
        }
        if super::receive::is_command(&request.command) {
            return self.apply_receive(coin, request);
        }
        if super::single_user::is_command(&request.command) {
            return self.apply_single_user(coin, request);
        }
        if super::bootstrap::is_command(&request.command) {
            return self.apply_bootstrap(coin, request);
        }
        if super::native::is_command(&request.command) {
            return self.apply_native(coin, request);
        }
        let mut purge_mask = false;
        let response = match &request.command {
            Command::FreezeOrigin {
                backing,
                capability,
            } => {
                coin.backing = *backing;
                coin.capability = *capability;
                coin.pending
                    .as_mut()
                    .context("Spark origin pending")?
                    .next_capability = Some(*capability);
                coin.phase = Phase::Origin;
                if let Some(bootstrap) = &mut coin.bootstrap {
                    bootstrap.freeze()?;
                }
                if let Some(receive) = &mut coin.receive {
                    receive.freeze()?;
                }
                retire_for_freeze(&mut coin);
                json!({"frozen":true,"backing":backing,"capability":capability})
            }
            Command::Reserve { .. } => {
                let mask = random_scalar().to_bytes().into();
                let salt = nonzero_random();
                let commitment = lineage::mask_commitment(&request.intent, &mask, &salt)?;
                let mut pending = Pending::new(request, false);
                pending.mask = Some(mask);
                pending.mask_salt = Some(salt);
                pending.mask_commitment = Some(commitment);
                coin.pending = Some(pending);
                coin.phase = Phase::Reserved;
                json!({"mask":mask,"mask_salt":salt,"mask_commitment":commitment,"server":coin.server()?.to_vec(),"server_salt":coin.salt})
            }
            Command::Handover { statement, .. } => {
                coin.pending
                    .as_mut()
                    .context("Spark proved handover")?
                    .handover = Some(statement.clone());
                coin.phase = Phase::Handover;
                json!({"authorized":true})
            }
            Command::ProposeRecipient {
                delta,
                delta_salt,
                next_capability,
                ..
            } => {
                let pending = coin.pending.as_mut().context("Spark receiver pending")?;
                let draft = Zeroizing::new(
                    scalar(&coin.secret)? + scalar(delta)?
                        - scalar(pending.mask.as_ref().context("Spark mask")?)?,
                );
                let secret: [u8; 32] = draft.to_bytes().into();
                let salt = nonzero_random();
                pending.recipient = Some(request.session);
                pending.draft_secret = Some(secret);
                pending.draft_salt = Some(salt);
                pending.delta = Some(*delta);
                pending.delta_salt = Some(*delta_salt);
                pending.next_capability = Some(*next_capability);
                erase(&mut pending.mask);
                erase(&mut pending.mask_salt);
                coin.phase = Phase::Proposed;
                purge_mask = true;
                json!({"draft_server":point_bytes(k256::ProjectivePoint::GENERATOR * *draft)?.to_vec(),"server_salt":salt})
            }
            Command::Prepare {
                successor_state,
                recovery,
                nonce_commitments,
            } => {
                let pending = coin.pending.as_mut().context("Spark preparation pending")?;
                let mut branches = Vec::new();
                for (index, commitment) in nonce_commitments.iter().enumerate() {
                    let (secret, point) = loop {
                        let secret: [u8; 32] = random_scalar().to_bytes().into();
                        let point =
                            point_bytes(k256::ProjectivePoint::GENERATOR * scalar(&secret)?)?
                                .to_vec();
                        if branches
                            .first()
                            .is_none_or(|prior: &Branch| prior.point[..32] != point[..32])
                        {
                            break (secret, point);
                        }
                    };
                    let id = super::state::nonce_id(
                        &pending.intent,
                        &request.session,
                        successor_state,
                        recovery,
                        index as u8,
                        &point,
                        commitment,
                    )?;
                    branches.push(Branch {
                        index: index as u8,
                        id,
                        point,
                        commitment: *commitment,
                        secret: Some(secret),
                    });
                }
                let branches: [Branch; 2] = branches
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Spark branch count"))?;
                let public = branches.each_ref().map(|branch| json!({"index":branch.index,"id":branch.id,"point":branch.point,"commitment":branch.commitment}));
                pending.preparation = Some(Preparation {
                    purpose: "wrapped-recovery-v1".into(),
                    successor_state: *successor_state,
                    recovery: *recovery,
                    branches,
                });
                coin.phase = Phase::Prepared;
                json!({"server_nonces":public})
            }
            Command::Issue { statement, .. } => {
                let issuance = Issuance::decode(statement)?;
                let pending = coin.pending.as_mut().context("Spark issuance pending")?;
                let secret = Zeroizing::new(if pending.origin {
                    coin.secret
                } else {
                    pending.draft_secret.context("Spark draft share")?
                });
                let salt = if pending.origin {
                    coin.salt
                } else {
                    pending.draft_salt.context("Spark draft salt")?
                };
                let preparation = pending
                    .preparation
                    .as_mut()
                    .context("Spark frozen nonce set")?;
                let [first, second] = &mut preparation.branches;
                // BOTH branches are checked/computed before either nonce slot is
                // erased; the caller atomically persists this set and new head.
                let partials = blind_issuance::issue(
                    &secret,
                    [&mut first.secret, &mut second.secret],
                    issuance
                        .recovery
                        .branches
                        .each_ref()
                        .map(|branch| FrozenResponse {
                            nonce_point: &branch.server_nonce,
                            nonce_commitment: &branch.nonce_commitment,
                            blinded_challenge: &branch.challenge,
                        }),
                )?;
                let certificate = Certificate::from_issuance(&issuance, &partials)?;
                let certificate_bytes = certificate.encode()?;
                let certificate_id = hash(&[&certificate_bytes]);
                let signature = if pending.origin {
                    Some(
                        self.origin
                            .sign_raw(&certificate.origin_message()?, &random32())?
                            .to_bytes()
                            .to_vec(),
                    )
                } else {
                    None
                };
                let origin = pending.origin;
                coin.state = certificate.state;
                coin.capability = issuance.next_capability;
                coin.session = request.session;
                coin.owner = Some(if pending.origin {
                    Predecessor::Origin
                } else {
                    Predecessor::Transfer
                });
                coin.issuance = Some(statement.clone());
                coin.partials = Some(partials);
                coin.origin_signature = signature.clone();
                for value in [
                    &mut pending.mask,
                    &mut pending.mask_salt,
                    &mut pending.draft_secret,
                    &mut pending.delta,
                    &mut pending.delta_salt,
                ] {
                    erase(value);
                }
                pending.draft_salt = None;
                install_share(&mut coin, &secret, salt, origin);
                coin.phase = Phase::Issued;
                purge_mask = true;
                json!({"issued":true,"partials":partials,"authorization_digest":issuance.digest()?,"certificate":certificate_bytes,"certificate_id":certificate_id,"state":coin.state,"capability":coin.capability,"origin_signature":signature})
            }
            Command::Acknowledge { .. } => {
                // Acknowledgement is accepted only from the issued recipient.
                // Its wallet must verify and durably save both complete signed
                // recoveries and the certificate BEFORE sending this command.
                coin.pending = None;
                coin.phase = Phase::Accepted;
                json!({"accepted":true,"state":coin.state,"capability":coin.capability,"certificate_id":coin.certificate_id()?})
            }
            Command::Cancel { .. } => {
                // No challenge response has been released in these phases. The
                // old share/head remain authoritative; dropping Pending retires
                // all unused mask, draft and nonce bytes before persistence.
                coin.pending = None;
                coin.phase = Phase::Accepted;
                json!({"cancelled":true,"state":coin.state,"capability":coin.capability,"certificate_id":coin.certificate_id()?})
            }
            Command::Allocate { .. } => anyhow::bail!("Spark allocation reached mutation path"),
            Command::Exit { .. } => {
                anyhow::bail!("Spark native exit authorization is not deployed")
            }
            Command::Head { .. } => anyhow::bail!("Spark head query reached mutation path"),
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
        Ok((coin, response, purge_mask))
    }
}

/// Allocation-scoped identity work cannot continue once the origin is frozen,
/// so no live nonce for it may outlive the freeze.
pub(super) fn retire_for_freeze(coin: &mut Coin) {
    if let Some(identities) = &mut coin.identities {
        identities.retire_unused();
    }
    if let Some(auth) = &mut coin.auth {
        auth.retire_live();
    }
    if let Some(ecdsa) = &mut coin.ecdsa {
        ecdsa.retire();
    }
}

/// Auth tickets are bound to the share they were prepared with and belong to
/// the earlier owner's scope, as at native preparation. A transfer issue drops
/// them with that share, so validation of the new share stays exact.
pub(super) fn install_share(coin: &mut Coin, secret: &[u8; 32], salt: [u8; 32], origin: bool) {
    if !origin {
        coin.auth = None;
    }
    coin.secret.zeroize();
    coin.secret = *secret;
    coin.salt = salt;
}

fn nonzero_random() -> [u8; 32] {
    loop {
        let value = random32();
        if value != [0; 32] {
            return value;
        }
    }
}
fn erase(value: &mut Option<[u8; 32]>) {
    if let Some(secret) = value.as_mut() {
        secret.zeroize();
    }
    *value = None;
}
