//! Durable recipient-local independent keys and confidential share refresh.
//! The sender sees neither delta nor the recipient's user/capability secrets.
use super::{
    PrivateCertificate, PrivateOffer, PrivateRecovery, PrivateSender, RecoveryJournal,
    RecoveryParameters, SenderParameters, persistence::OperationFile, witness,
};
use anyhow::{Result, ensure};
use k256::ProjectivePoint;
use serde::{Deserialize, Serialize};
use std::path::Path;
use zark_protocol::{
    handoff::RecoverySchedule,
    owner_auth::{generate_secret, normalized_key},
    point_bytes, random_scalar, random32, scalar,
    spark_lineage::{
        Intent, Issuance, PinnedSparkVerifier, SparkRole, capability_commitment, delta_commitment,
        server_commitment,
    },
    spark_wire::{Command, Predecessor, Request},
};
use zeroize::{Zeroize, Zeroizing};

mod share_exit;

const FILE: &str = "private-recipient.json";
const MAX_BYTES: usize = 256 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    version: u32,
    offer: Vec<u8>,
    claim: [u8; 32],
    session: [u8; 32],
    owner: [u8; 32],
    user: [u8; 32],
    delta: [u8; 32],
    delta_salt: [u8; 32],
    proposal: Option<Vec<u8>>,
}
impl Drop for Record {
    fn drop(&mut self) {
        self.offer.zeroize();
        self.claim.zeroize();
        self.session.zeroize();
        self.owner.zeroize();
        self.user.zeroize();
        self.delta.zeroize();
        self.delta_salt.zeroize();
        if let Some(v) = &mut self.proposal {
            v.zeroize();
        }
    }
}
pub struct PrivateReceiver {
    file: OperationFile,
    record: Record,
    offer: PrivateOffer,
}
pub struct NextRecipient {
    pub intent: Intent,
    pub claim_key: [u8; 32],
    pub claim_salt: [u8; 32],
}
impl Drop for NextRecipient {
    fn drop(&mut self) {
        self.claim_salt.zeroize();
    }
}
impl PrivateReceiver {
    pub fn create(
        directory: &Path,
        offer: &[u8],
        claim: [u8; 32],
        verifier: &PinnedSparkVerifier,
        scratch: &Path,
    ) -> Result<Self> {
        let claim = Zeroizing::new(claim);
        let key = normalized_key(&claim)?;
        let native = PrivateOffer::decode_private(
            offer,
            &key.verifying_key().to_bytes().into(),
            verifier,
            scratch,
        )?;
        let user = Zeroizing::new(random_scalar());
        let masked = Zeroizing::new(scalar(&native.record.masked)?);
        let delta = Zeroizing::new(*masked - *user);
        let record = Record {
            schema: "zark-spark-private-recipient".into(),
            version: 1,
            offer: offer.to_vec(),
            claim: *claim,
            session: generate_secret(),
            owner: generate_secret(),
            user: user.to_bytes().into(),
            delta: delta.to_bytes().into(),
            delta_salt: random32(),
            proposal: None,
        };
        let file = OperationFile::create(directory, FILE)?;
        let value = Self {
            file,
            record,
            offer: native,
        };
        value.persist()?;
        Ok(value)
    }
    pub fn open(directory: &Path, verifier: &PinnedSparkVerifier, scratch: &Path) -> Result<Self> {
        let (file, bytes) = OperationFile::open(directory, FILE, MAX_BYTES)?;
        let record: Record = serde_json::from_slice(&bytes)?;
        ensure!(
            record.schema == "zark-spark-private-recipient" && record.version == 1,
            "private recipient schema"
        );
        let canonical = Zeroizing::new(serde_json::to_vec(&record)?);
        ensure!(
            canonical.as_slice() == bytes.as_slice(),
            "noncanonical private recipient record"
        );
        let key = normalized_key(&record.claim)?;
        let offer = PrivateOffer::decode_private(
            &record.offer,
            &key.verifying_key().to_bytes().into(),
            verifier,
            scratch,
        )?;
        normalized_key(&record.owner)?;
        normalized_key(&record.session)?;
        ensure!(
            scalar(&offer.record.masked)? == scalar(&record.user)? + scalar(&record.delta)?,
            "private recipient saved delta changed"
        );
        ensure!(
            scalar(&record.user)? != k256::Scalar::ZERO && record.delta_salt != [0; 32],
            "private recipient zero opening"
        );
        let value = Self {
            file,
            record,
            offer,
        };
        if let Some(saved) = &value.record.proposal {
            let request = Request::decode(saved)?;
            ensure!(
                request.intent == value.offer.handover.intent
                    && request.session == value.session_public()?,
                "private recipient saved proposal context changed"
            );
            ensure!(
                serde_json::to_vec(&request.command)?
                    == serde_json::to_vec(&value.proposal_command()?)?,
                "private recipient saved proposal command changed"
            );
        }
        Ok(value)
    }
    fn persist(&self) -> Result<()> {
        self.file.save(
            &Zeroizing::new(serde_json::to_vec(&self.record)?),
            MAX_BYTES,
        )
    }
    fn session_public(&self) -> Result<[u8; 32]> {
        Ok(normalized_key(&self.record.session)?
            .verifying_key()
            .to_bytes()
            .into())
    }
    fn next_capability(&self) -> Result<[u8; 32]> {
        let i = &self.offer.handover.intent;
        capability_commitment(&i.deployment, &i.coin, &self.record.owner)
    }
    fn proposal_command(&self) -> Result<Command> {
        Ok(Command::ProposeRecipient {
            token: self.offer.record.token,
            delta: self.record.delta,
            delta_salt: self.record.delta_salt,
            next_capability: self.next_capability()?,
        })
    }
    /// Contains a confidential delta. Send only directly to the authenticated
    /// signer, never through the sender or a public relay transcript.
    pub fn proposal_request(&mut self) -> Result<Request> {
        if let Some(saved) = &self.record.proposal {
            let request = Request::decode(saved)?;
            self.persist()?;
            return Ok(request);
        }
        let request = Request::sign(
            self.offer.handover.intent.clone(),
            self.proposal_command()?,
            &normalized_key(&self.record.session)?,
        )?;
        self.record.proposal = Some(request.encode()?);
        self.persist()?;
        Ok(request)
    }
    pub fn recovery(
        &self,
        server: [u8; 64],
        server_salt: [u8; 32],
        payout_secret: [u8; 32],
        fee: u64,
        schedule: RecoverySchedule,
    ) -> Result<PrivateRecovery> {
        ensure!(
            self.record.proposal.is_some(),
            "private recipient draft before frozen proposal"
        );
        schedule.validate()?;
        let consumed = schedule
            .initial
            .checked_sub(self.offer.record.old_delay)
            .ok_or_else(|| anyhow::anyhow!("private recipient predecessor delay exceeds policy"))?;
        ensure!(
            consumed % schedule.gap == 0,
            "private recipient predecessor schedule mismatch"
        );
        let owner_index = consumed / schedule.gap + 2;
        let draft = PrivateRecovery::prepare(
            self.offer.backing(),
            RecoveryParameters {
                intent: self.offer.handover.intent.clone(),
                session: self.session_public()?,
                server,
                server_salt,
                user: self.record.user,
                next_capability: self.next_capability()?,
                payout_secret,
                fee,
                owner_index,
                schedule,
            },
        )?;
        ensure!(
            draft.frozen().backing == self.offer.handover.backing
                && draft.frozen().policy == self.offer.handover.policy,
            "private recipient draft changed backing or policy"
        );
        Ok(draft)
    }
    pub fn issuance(
        &self,
        recovery: &PrivateRecovery,
        verifier: &PinnedSparkVerifier,
    ) -> Result<Issuance> {
        ensure!(
            recovery.intent() == &self.offer.handover.intent
                && recovery.frozen().context.session == self.session_public()?,
            "private recipient issuance context changed"
        );
        ensure!(
            recovery.witness().user == self.record.user,
            "private recipient recovery user changed"
        );
        let h = &self.offer.handover;
        let r = recovery.authorization()?.clone();
        ensure!(
            r.backing == h.backing
                && r.policy == h.policy
                && recovery.next_capability() == self.next_capability()?,
            "private recipient issuance backing or owner changed"
        );
        let value = Issuance {
            recipient_claim: h.intent.recipient_claim,
            mask: h.mask,
            masked_share: h.masked_share,
            bridge: h.bridge,
            delta: delta_commitment(&r.context, &self.record.delta, &self.record.delta_salt)?,
            previous_capability: h.previous_capability,
            next_capability: self.next_capability()?,
            server_share: server_commitment(
                &r.context.deployment,
                &r.context.coin,
                &r.server,
                recovery.server_salt(),
            )?,
            recovery: r,
            config: verifier.config().clone(),
        };
        value.encode()?;
        Ok(value)
    }
    pub fn prover_toml(
        &self,
        recovery: &PrivateRecovery,
        verifier: &PinnedSparkVerifier,
        scratch: &Path,
    ) -> Result<Zeroizing<String>> {
        verifier.verify_handover(
            self.offer.predecessor(),
            self.offer.handover(),
            self.offer.sender_proof(),
            scratch,
        )?;
        let issuance = self.issuance(recovery, verifier)?;
        let mut out = witness::statement(&issuance.encode()?)?;
        recovery.witness().append_prover_fields(&mut out)?;
        witness::bytes(&mut out, "handover", &self.offer.handover.encode()?)?;
        let role = if self.offer.predecessor() == Predecessor::Origin {
            SparkRole::SenderFromOrigin
        } else {
            SparkRole::SenderFromTransfer
        };
        witness::fields(
            &mut out,
            "handover_vk",
            &verifier.recursive_key_bytes(role)?,
            115,
        )?;
        witness::fields(&mut out, "handover_proof", self.offer.sender_proof(), 458)?;
        let session = Zeroizing::new(scalar(&self.record.session)?);
        let session_point = point_bytes(ProjectivePoint::GENERATOR * *session)?;
        for (name, value) in [
            ("claim_secret", self.record.claim.as_slice()),
            ("claim_salt", self.offer.record.claim_salt.as_slice()),
            ("session_point", session_point.as_slice()),
            ("next_owner_secret", self.record.owner.as_slice()),
            ("masked", self.offer.record.masked.as_slice()),
            ("masked_salt", self.offer.record.masked_salt.as_slice()),
            ("delta", self.record.delta.as_slice()),
            ("delta_salt", self.record.delta_salt.as_slice()),
            ("server_salt", recovery.server_salt().as_slice()),
            ("bridge_salt", self.offer.record.bridge_salt.as_slice()),
        ] {
            witness::bytes(&mut out, name, value)?;
        }
        out.push_str(&format!("old_delay = {}\n", self.offer.record.old_delay));
        Ok(out)
    }
    pub fn create_recovery_journal(
        &self,
        directory: &Path,
        recovery: PrivateRecovery,
    ) -> Result<RecoveryJournal> {
        ensure!(
            recovery.intent() == &self.offer.handover.intent
                && recovery.next_capability() == self.next_capability()?,
            "private recipient recovery journal owner changed"
        );
        RecoveryJournal::create(
            directory,
            Predecessor::Transfer,
            self.offer.backing(),
            recovery,
            self.record.session,
        )
    }
    pub fn start_sender(
        &self,
        directory: &Path,
        next: NextRecipient,
        recovery: &PrivateRecovery,
        certificate: &PrivateCertificate,
        verifier: &PinnedSparkVerifier,
        scratch: &Path,
    ) -> Result<PrivateSender> {
        PrivateSender::create(
            directory,
            SenderParameters {
                intent: next.intent.clone(),
                session_secret: generate_secret(),
                owner_secret: self.record.owner,
                claim_key: next.claim_key,
                claim_salt: next.claim_salt,
            },
            self.offer.backing(),
            recovery,
            certificate,
            verifier,
            scratch,
        )
    }
    pub fn offer(&self) -> &PrivateOffer {
        &self.offer
    }
}
