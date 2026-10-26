//! Spark-only persisted records. No Bitcoin record is reinterpreted or migrated.
use super::{Policy, Request};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use zark_protocol::{
    hash, point, point_bytes, scalar,
    spark_lineage::{self as lineage, Certificate, Digest, Intent, Issuance},
};
use zeroize::Zeroize;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    Allocated,
    Origin,
    Reserved,
    Handover,
    Proposed,
    Prepared,
    Issued,
    Accepted,
    /// Absorbing: the share was erased and released to the current owner.
    Exited,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Branch {
    pub index: u8,
    pub id: Digest,
    pub point: Vec<u8>,
    pub commitment: Digest,
    pub secret: Option<Digest>,
}
impl Drop for Branch {
    fn drop(&mut self) {
        if let Some(secret) = &mut self.secret {
            secret.zeroize();
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Preparation {
    /// Purpose is fixed by this record version, never selected by a client.
    pub purpose: String,
    pub successor_state: Digest,
    pub recovery: Digest,
    pub branches: [Branch; 2],
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pending {
    pub origin: bool,
    pub intent: Intent,
    pub sender: Option<Digest>,
    pub recipient: Option<Digest>,
    pub mask: Option<Digest>,
    pub mask_salt: Option<Digest>,
    pub mask_commitment: Option<Digest>,
    pub handover: Option<Vec<u8>>,
    pub draft_secret: Option<Digest>,
    pub draft_salt: Option<Digest>,
    pub delta: Option<Digest>,
    pub delta_salt: Option<Digest>,
    pub next_capability: Option<Digest>,
    pub preparation: Option<Preparation>,
}

impl Pending {
    pub fn new(request: &Request, origin: bool) -> Self {
        Self {
            origin,
            intent: request.intent.clone(),
            sender: (!origin).then_some(request.session),
            recipient: origin.then_some(request.session),
            mask: None,
            mask_salt: None,
            mask_commitment: None,
            handover: None,
            draft_secret: None,
            draft_salt: None,
            delta: None,
            delta_salt: None,
            next_capability: None,
            preparation: None,
        }
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        for secret in [
            &mut self.mask,
            &mut self.mask_salt,
            &mut self.draft_secret,
            &mut self.delta,
            &mut self.delta_salt,
        ]
        .into_iter()
        .flatten()
        {
            secret.zeroize();
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Coin {
    pub deployment: Digest,
    pub coin: Digest,
    pub backing: Digest,
    pub state: Digest,
    pub capability: Digest,
    pub secret: Digest,
    pub salt: Digest,
    pub session: Digest,
    pub owner: Option<super::Predecessor>,
    pub phase: Phase,
    pub pending: Option<Pending>,
    pub issuance: Option<Vec<u8>>,
    pub partials: Option<[Digest; 2]>,
    pub origin_signature: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native: Option<super::native::Workflow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap: Option<super::bootstrap::Workflow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub single_user: Option<super::single_user::Workflow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receive: Option<super::receive::Workflow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identities: Option<super::identity::Sessions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<super::auth::Tickets>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecdsa: Option<super::ecdsa_2p::State>,
    /// Absent on every coin that has not exited, so existing rows keep their bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<super::share_release::Released>,
}

impl Drop for Coin {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl Coin {
    pub fn server(&self) -> Result<[u8; 64]> {
        // The share itself is erased once released; its certified point remains.
        if let Some(exit) = &self.exit {
            return exit.server();
        }
        point_bytes(k256::ProjectivePoint::GENERATOR * scalar(&self.secret)?)
    }
    pub fn server_commitment(&self) -> Result<Digest> {
        lineage::server_commitment(&self.deployment, &self.coin, &self.server()?, &self.salt)
    }
    pub fn certificate(&self) -> Result<Certificate> {
        Certificate::from_issuance(
            &Issuance::decode(
                self.issuance
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("missing Spark issuance"))?,
            )?,
            self.partials
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing Spark partials"))?,
        )
    }
    pub fn certificate_id(&self) -> Result<Digest> {
        Ok(hash(&[&self.certificate()?.encode()?]))
    }

    pub fn validate(&self, policy: &Policy) -> Result<()> {
        ensure!(
            self.deployment == policy.deployment && self.coin != [0; 32],
            "Spark coin deployment"
        );
        self.server()?;
        ensure!(self.salt != [0; 32], "zero Spark server salt");
        k256::schnorr::VerifyingKey::from_bytes(&self.session)?;
        if let Some(native) = &self.native {
            native.validate(self, policy)?;
        }
        if let Some(bootstrap) = &self.bootstrap {
            bootstrap.validate(self, policy)?;
        }
        if let Some(single) = &self.single_user {
            single.validate(self, policy)?;
        }
        if let Some(receive) = &self.receive {
            receive.validate(self, policy)?;
        }
        if let Some(identities) = &self.identities {
            identities.validate(self, policy)?;
        }
        if let Some(auth) = &self.auth {
            auth.validate(self, policy)?;
        }
        if let Some(ecdsa) = &self.ecdsa {
            ecdsa.validate(self, policy)?;
        }
        ensure!(
            self.exit.is_some() == (self.phase == Phase::Exited),
            "Spark exit record lifecycle"
        );
        if let Some(exit) = &self.exit {
            exit.validate(self)?;
        }
        if self.phase == Phase::Allocated {
            ensure!(
                self.backing == [0; 32]
                    && self.capability == [0; 32]
                    && self.owner.is_none()
                    && self.issuance.is_none(),
                "Spark allocation shape"
            );
        } else {
            ensure!(
                self.backing != [0; 32] && self.capability != [0; 32],
                "Spark coin commitments"
            );
        }
        ensure!(
            self.pending.is_some() == !matches!(self.phase, Phase::Accepted | Phase::Exited),
            "Spark pending lifecycle"
        );
        let must_be_issued = matches!(
            self.phase,
            Phase::Reserved
                | Phase::Handover
                | Phase::Proposed
                | Phase::Issued
                | Phase::Accepted
                | Phase::Exited
        ) || (self.phase == Phase::Prepared
            && self.pending.as_ref().is_some_and(|pending| !pending.origin));
        ensure!(
            self.issuance.is_some() == must_be_issued,
            "Spark phase does not match issued ownership"
        );
        if let Some(raw) = &self.issuance {
            let issuance = Issuance::decode(raw)?;
            let certificate = self.certificate()?;
            ensure!(
                issuance.config == policy.config
                    && certificate.deployment == self.deployment
                    && certificate.coin == self.coin
                    && certificate.backing == self.backing
                    && certificate.state == self.state
                    && certificate.policy == policy.policy
                    && issuance.next_capability == self.capability
                    && issuance.recovery.server == self.server()?
                    && issuance.server_share == self.server_commitment()?,
                "Spark issued state changed"
            );
            for (branch, partial) in issuance
                .recovery
                .branches
                .iter()
                .zip(self.partials.as_ref().expect("certificate validated"))
            {
                ensure!(
                    k256::ProjectivePoint::GENERATOR * scalar(partial)?
                        == point(&branch.server_nonce)?
                            + point(&issuance.recovery.server)? * scalar(&branch.challenge)?,
                    "Spark retained partial changed"
                );
            }
            ensure!(self.owner.is_some(), "Spark issuance owner kind missing");
            if self.owner == Some(super::Predecessor::Origin) {
                certificate.verify_origin_attestation(
                    &self
                        .origin_signature
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("missing Spark origin attestation"))?
                        .as_slice()
                        .try_into()?,
                )?;
            }
        } else {
            ensure!(
                self.owner.is_none()
                    && self.partials.is_none()
                    && self.origin_signature.is_none()
                    && self.state == lineage::origin_previous_state(&self.deployment, &self.coin)?,
                "Spark unissued origin shape"
            );
        }
        if let Some(pending) = &self.pending {
            pending.intent.encode()?;
            ensure!(
                pending.intent.deployment == self.deployment && pending.intent.coin == self.coin,
                "Spark pending scope"
            );
            for session in [pending.sender, pending.recipient].into_iter().flatten() {
                k256::schnorr::VerifyingKey::from_bytes(&session)?;
            }
            if self.phase != Phase::Issued {
                ensure!(
                    pending.intent.previous_state == self.state,
                    "Spark predecessor changed"
                );
            }
            if pending.origin {
                ensure!(
                    pending.sender.is_none()
                        && pending.recipient == Some(self.session)
                        && pending.intent.revision == 1
                        && pending.intent.recipient_claim
                            == lineage::origin_field(&self.deployment, &self.coin, 0)?
                        && pending.intent.previous_state
                            == lineage::origin_previous_state(&self.deployment, &self.coin)?
                        && pending.mask.is_none()
                        && pending.mask_salt.is_none()
                        && pending.mask_commitment.is_none()
                        && pending.handover.is_none()
                        && pending.draft_secret.is_none()
                        && pending.draft_salt.is_none()
                        && pending.delta.is_none()
                        && pending.delta_salt.is_none(),
                    "Spark origin pending shape"
                );
                ensure!(
                    matches!(
                        self.phase,
                        Phase::Allocated | Phase::Origin | Phase::Prepared | Phase::Issued
                    ),
                    "Spark origin phase"
                );
                ensure!(
                    if self.phase == Phase::Allocated {
                        pending.next_capability.is_none()
                    } else {
                        pending.next_capability == Some(self.capability)
                    },
                    "Spark frozen origin capability changed"
                );
            } else {
                ensure!(
                    pending.sender.is_some()
                        && pending.mask_commitment.is_some()
                        && matches!(
                            self.phase,
                            Phase::Reserved
                                | Phase::Handover
                                | Phase::Proposed
                                | Phase::Prepared
                                | Phase::Issued
                        ),
                    "Spark transfer pending shape"
                );
                let before_recipient = matches!(self.phase, Phase::Reserved | Phase::Handover);
                ensure!(
                    pending.mask.is_some() == before_recipient
                        && pending.mask_salt.is_some() == before_recipient
                        && pending.recipient.is_some() != before_recipient
                        && pending.next_capability.is_some() != before_recipient,
                    "Spark recipient admission shape"
                );
                let draft = matches!(self.phase, Phase::Proposed | Phase::Prepared);
                ensure!(
                    pending.draft_secret.is_some() == draft
                        && pending.draft_salt.is_some() == draft
                        && pending.delta.is_some() == draft
                        && pending.delta_salt.is_some() == draft,
                    "Spark confidential refresh shape"
                );
                ensure!(
                    pending.handover.is_some() == (self.phase != Phase::Reserved),
                    "Spark authenticated handover shape"
                );
                if let Some(raw) = &pending.handover {
                    let handover = lineage::Handover::decode(raw)?;
                    ensure!(
                        handover.intent == pending.intent
                            && handover.config == policy.config
                            && handover.backing == self.backing
                            && handover.policy == policy.policy
                            && Some(handover.mask) == pending.mask_commitment,
                        "Spark retained handover changed"
                    );
                    if self.phase != Phase::Issued {
                        ensure!(
                            handover.previous_capability == self.capability
                                && handover.server_share == self.server_commitment()?,
                            "Spark frozen predecessor changed"
                        );
                    }
                }
                if let Some(secret) = pending.draft_secret {
                    point_bytes(k256::ProjectivePoint::GENERATOR * scalar(&secret)?)?;
                }
                if let Some(capability) = pending.next_capability {
                    ensure!(capability != [0; 32], "zero Spark successor capability");
                    if self.phase == Phase::Issued {
                        ensure!(
                            capability == self.capability,
                            "Spark issued successor capability changed"
                        );
                    } else {
                        ensure!(
                            capability != self.capability,
                            "Spark ownership capability did not rotate"
                        );
                    }
                }
            }
            ensure!(
                pending.preparation.is_some()
                    == matches!(self.phase, Phase::Prepared | Phase::Issued),
                "Spark preparation lifecycle"
            );
            if let Some(mask) = &pending.mask {
                ensure!(
                    pending.mask_commitment
                        == Some(lineage::mask_commitment(
                            &pending.intent,
                            mask,
                            pending
                                .mask_salt
                                .as_ref()
                                .ok_or_else(|| anyhow::anyhow!("missing Spark mask salt"))?
                        )?),
                    "Spark frozen mask changed"
                );
            }
            if let Some(preparation) = &pending.preparation {
                ensure!(
                    preparation.purpose == "wrapped-recovery-v1"
                        && preparation.successor_state != [0; 32]
                        && preparation.recovery != [0; 32],
                    "Spark preparation purpose"
                );
                for (index, branch) in preparation.branches.iter().enumerate() {
                    ensure!(
                        usize::from(branch.index) == index
                            && branch.id != [0; 32]
                            && branch.commitment != [0; 32],
                        "Spark nonce branch scope"
                    );
                    point(&branch.point)?;
                    ensure!(
                        branch.id
                            == nonce_id(
                                &pending.intent,
                                &pending.recipient.context("Spark nonce recipient missing")?,
                                &preparation.successor_state,
                                &preparation.recovery,
                                branch.index,
                                &branch.point,
                                &branch.commitment
                            )?,
                        "Spark nonce purpose or context changed"
                    );
                    ensure!(
                        branch.secret.is_some() == (self.phase == Phase::Prepared),
                        "Spark nonce lifecycle"
                    );
                    if let Some(secret) = branch.secret {
                        ensure!(
                            point_bytes(k256::ProjectivePoint::GENERATOR * scalar(&secret)?)?
                                .as_slice()
                                == branch.point,
                            "Spark nonce point changed"
                        );
                    }
                }
                ensure!(
                    preparation.branches[0].point[..32] != preparation.branches[1].point[..32]
                        && preparation.branches[0].commitment != preparation.branches[1].commitment,
                    "Spark nonce variants collide"
                );
            }
        }
        Ok(())
    }
}

pub(super) fn nonce_id(
    intent: &Intent,
    session: &Digest,
    successor_state: &Digest,
    recovery: &Digest,
    index: u8,
    point: &[u8],
    commitment: &Digest,
) -> Result<Digest> {
    ensure!(index < 2, "Spark nonce branch index");
    zark_protocol::point(point)?;
    Ok(hash(&[
        b"ZARK/spark/signer/wrapped-recovery-nonce/v1",
        &intent.encode()?,
        session,
        successor_state,
        recovery,
        &[index],
        point,
        commitment,
    ]))
}
