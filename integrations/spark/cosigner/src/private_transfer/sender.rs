//! Durable sender-local reservation and proof witness. Old recovery witnesses
//! stay in this journal; only the newly authenticated private offer is exported.
use super::{
    PrivateBacking, PrivateCertificate, PrivateOffer, PrivateRecovery, offer::OfferRecord,
    persistence::OperationFile,
};
use anyhow::{Result, ensure};
use k256::schnorr::SigningKey;
use serde::{Deserialize, Serialize};
use std::path::Path;
use zark_protocol::{
    owner_auth::normalized_key,
    random32, scalar,
    spark_lineage::{
        Handover, Intent, PinnedSparkVerifier, bridge_commitment, capability_commitment,
        draft_token_commitment, mask_commitment, masked_share_commitment,
        recipient_claim_commitment,
    },
    spark_wire::{Command, OwnerAuthorization, Request},
};
use zeroize::{Zeroize, Zeroizing};

#[path = "sender_witness.rs"]
mod prover_witness;

const FILE: &str = "private-sender.json";
const MAX_BYTES: usize = 1024 * 1024;
pub struct SenderParameters {
    pub intent: Intent,
    pub session_secret: [u8; 32],
    pub owner_secret: [u8; 32],
    pub claim_key: [u8; 32],
    pub claim_salt: [u8; 32],
}
impl Drop for SenderParameters {
    fn drop(&mut self) {
        self.session_secret.zeroize();
        self.owner_secret.zeroize();
        self.claim_salt.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Mask {
    value: [u8; 32],
    salt: [u8; 32],
    masked: [u8; 32],
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    version: u32,
    intent: Intent,
    session: [u8; 32],
    owner: [u8; 32],
    claim_key: [u8; 32],
    claim_salt: [u8; 32],
    token: [u8; 32],
    masked_salt: [u8; 32],
    bridge_salt: [u8; 32],
    backing: Vec<u8>,
    recovery: Vec<u8>,
    certificate: Vec<u8>,
    mask: Option<Mask>,
    reservation: Option<Vec<u8>>,
    handover: Option<Vec<u8>>,
    offer: Option<Vec<u8>>,
}
impl Drop for Record {
    fn drop(&mut self) {
        self.session.zeroize();
        self.owner.zeroize();
        self.claim_salt.zeroize();
        self.token.zeroize();
        self.masked_salt.zeroize();
        self.bridge_salt.zeroize();
        self.backing.zeroize();
        self.recovery.zeroize();
        self.certificate.zeroize();
        if let Some(m) = &mut self.mask {
            m.value.zeroize();
            m.salt.zeroize();
            m.masked.zeroize();
        }
        if let Some(v) = &mut self.reservation {
            v.zeroize();
        }
        if let Some(v) = &mut self.handover {
            v.zeroize();
        }
        if let Some(v) = &mut self.offer {
            v.zeroize();
        }
    }
}
pub struct PrivateSender {
    file: OperationFile,
    record: Record,
    backing: PrivateBacking,
    recovery: PrivateRecovery,
    certificate: PrivateCertificate,
}
impl PrivateSender {
    pub fn create(
        directory: &Path,
        p: SenderParameters,
        backing: &PrivateBacking,
        recovery: &PrivateRecovery,
        certificate: &PrivateCertificate,
        verifier: &PinnedSparkVerifier,
        scratch: &Path,
    ) -> Result<Self> {
        let record = Record {
            schema: "zark-spark-private-sender".into(),
            version: 1,
            intent: p.intent.clone(),
            session: p.session_secret,
            owner: p.owner_secret,
            claim_key: p.claim_key,
            claim_salt: p.claim_salt,
            token: random32(),
            masked_salt: random32(),
            bridge_salt: random32(),
            backing: backing.encode_private()?.to_vec(),
            recovery: recovery.encode_private()?.to_vec(),
            certificate: certificate.encode_private()?.to_vec(),
            mask: None,
            reservation: None,
            handover: None,
            offer: None,
        };
        let file = OperationFile::create(directory, FILE)?;
        let value = Self::restore(file, record, verifier, scratch)?;
        value.persist()?;
        Ok(value)
    }
    pub fn open(directory: &Path, verifier: &PinnedSparkVerifier, scratch: &Path) -> Result<Self> {
        let (file, bytes) = OperationFile::open(directory, FILE, MAX_BYTES)?;
        let record: Record = serde_json::from_slice(&bytes)?;
        let canonical = Zeroizing::new(serde_json::to_vec(&record)?);
        ensure!(
            canonical.as_slice() == bytes.as_slice(),
            "noncanonical private sender journal"
        );
        Self::restore(file, record, verifier, scratch)
    }
    fn restore(
        file: OperationFile,
        record: Record,
        verifier: &PinnedSparkVerifier,
        scratch: &Path,
    ) -> Result<Self> {
        ensure!(
            record.schema == "zark-spark-private-sender" && record.version == 1,
            "private sender journal schema"
        );
        let backing = PrivateBacking::decode_private(&record.backing)?;
        let recovery = PrivateRecovery::decode_private(&backing, &record.recovery)?;
        let certificate = PrivateCertificate::decode_private(&record.certificate)?;
        let value = Self {
            file,
            record,
            backing,
            recovery,
            certificate,
        };
        value.verify_current(verifier, scratch)?;
        Ok(value)
    }
    fn verify_current(&self, verifier: &PinnedSparkVerifier, scratch: &Path) -> Result<()> {
        self.record.intent.encode()?;
        let cert = self.certificate.verify(verifier, scratch)?;
        ensure!(
            cert.deployment == self.record.intent.deployment
                && cert.coin == self.record.intent.coin
                && cert.state == self.record.intent.previous_state,
            "private sender predecessor context"
        );
        let auth = self.certificate.authorization();
        ensure!(
            self.recovery.authorization()?.encode()? == auth.recovery.encode()?,
            "private sender certificate recovery differs"
        );
        self.recovery.completed()?;
        ensure!(
            self.recovery.server_salt() == self.certificate.server_salt(),
            "private sender server opening differs"
        );
        ensure!(
            capability_commitment(&cert.deployment, &cert.coin, &self.record.owner)?
                == auth.next_capability,
            "private sender current capability"
        );
        ensure!(
            self.recovery.witness().target.owner_index < 8,
            "final private Spark owner cannot transfer"
        );
        ensure!(
            recipient_claim_commitment(
                &cert.deployment,
                &cert.coin,
                &self.record.intent.operation,
                &self.record.claim_key,
                &self.record.claim_salt
            )? == self.record.intent.recipient_claim,
            "private sender intended recipient"
        );
        let session = normalized_key(&self.record.session)?;
        ensure!(
            session.verifying_key().to_bytes()[..]
                != normalized_key(&self.record.owner)?
                    .verifying_key()
                    .to_bytes()[..],
            "private sender owner and session must differ"
        );
        let key = self.backing.owner_key(
            &auth.recovery.server,
            scalar(&self.recovery.witness().user)?,
        )?;
        ensure!(
            self.backing.commitment(&auth.recovery.context, &key)? == cert.backing,
            "private sender native backing differs from certificate"
        );
        if let Some(mask) = &self.record.mask {
            ensure!(
                scalar(&mask.masked)?
                    == scalar(&self.recovery.witness().user)? + scalar(&mask.value)?,
                "private sender saved masked share changed"
            );
            mask_commitment(&self.record.intent, &mask.value, &mask.salt)?;
        }
        let session_public: [u8; 32] = session.verifying_key().to_bytes().into();
        if let Some(saved) = &self.record.reservation {
            let request = Request::decode(saved)?;
            ensure!(
                request.intent == self.record.intent && request.session == session_public,
                "saved private sender reservation context"
            );
            let Command::Reserve { owner } = &request.command else {
                anyhow::bail!("saved private sender reservation command")
            };
            owner.verify(&self.record.intent, &session_public, &auth.next_capability)?;
        }
        if let Some(saved) = &self.record.handover {
            ensure!(
                self.record.reservation.is_some(),
                "saved private sender handover before reservation"
            );
            let request = Request::decode(saved)?;
            ensure!(
                request.intent == self.record.intent && request.session == session_public,
                "saved private sender handover context"
            );
            let Command::Handover {
                predecessor,
                statement,
                proof,
            } = &request.command
            else {
                anyhow::bail!("saved private sender handover command")
            };
            let handover = self.handover()?;
            ensure!(
                *predecessor == self.certificate.kind() && *statement == handover.encode()?,
                "saved private sender handover changed"
            );
            verifier.verify_handover(*predecessor, &handover, proof, scratch)?;
        }
        if let Some(saved) = &self.record.offer {
            ensure!(
                self.record.handover.is_some(),
                "saved private sender offer before handover"
            );
            let offer =
                PrivateOffer::decode_private(saved, &self.record.claim_key, verifier, scratch)?;
            ensure!(
                offer.handover().encode()? == self.handover()?.encode()?
                    && offer.backing().encode_private()?.as_slice()
                        == self.record.backing.as_slice(),
                "saved private sender offer changed"
            );
        }
        Ok(())
    }
    fn persist(&self) -> Result<()> {
        self.file.save(
            &Zeroizing::new(serde_json::to_vec(&self.record)?),
            MAX_BYTES,
        )
    }

    pub fn reservation_request(&mut self) -> Result<Request> {
        if let Some(saved) = &self.record.reservation {
            let request = Request::decode(saved)?;
            self.persist()?;
            return Ok(request);
        }
        let session = normalized_key(&self.record.session)?;
        let owner = OwnerAuthorization::sign(
            &self.record.intent,
            &session.verifying_key().to_bytes().into(),
            &normalized_key(&self.record.owner)?,
        )?;
        let request = Request::sign(
            self.record.intent.clone(),
            Command::Reserve { owner },
            &session,
        )?;
        self.record.reservation = Some(request.encode()?);
        self.persist()?;
        Ok(request)
    }
    pub fn save_mask(
        &mut self,
        value: [u8; 32],
        salt: [u8; 32],
        commitment: [u8; 32],
    ) -> Result<()> {
        ensure!(
            self.record.reservation.is_some(),
            "private sender mask before reservation"
        );
        ensure!(
            mask_commitment(&self.record.intent, &value, &salt)? == commitment,
            "private sender mask response commitment"
        );
        let user = Zeroizing::new(scalar(&self.recovery.witness().user)?);
        let masked = Zeroizing::new(*user + scalar(&value)?);
        ensure!(
            *masked != k256::Scalar::ZERO,
            "zero masked private sender share"
        );
        let masked: [u8; 32] = masked.to_bytes().into();
        if let Some(saved) = &self.record.mask {
            ensure!(
                saved.value == value && saved.salt == salt && saved.masked == masked,
                "private sender mask retry changed"
            );
            self.persist()?;
            return Ok(());
        }
        self.record.mask = Some(Mask {
            value,
            salt,
            masked,
        });
        self.persist()
    }
    pub fn handover(&self) -> Result<Handover> {
        let mask = self
            .record
            .mask
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("private sender mask missing"))?;
        let cert = self.certificate.native_lineage()?;
        let a = self.certificate.authorization();
        let value = Handover {
            intent: self.record.intent.clone(),
            backing: cert.backing,
            mask: mask_commitment(&self.record.intent, &mask.value, &mask.salt)?,
            masked_share: masked_share_commitment(
                &self.record.intent,
                &mask.masked,
                &self.record.masked_salt,
            )?,
            bridge: bridge_commitment(
                &self.record.intent,
                &cert.backing,
                self.recovery.witness().target.delay,
                &cert.policy,
                &self.record.bridge_salt,
            )?,
            previous_capability: a.next_capability,
            server_share: a.server_share,
            policy: cert.policy,
            draft_token: draft_token_commitment(&self.record.intent, &self.record.token)?,
            config: cert.config,
        };
        value.encode()?;
        Ok(value)
    }
    pub fn handover_request(
        &mut self,
        proof: &[u8],
        verifier: &PinnedSparkVerifier,
        scratch: &Path,
    ) -> Result<Request> {
        self.verify_current(verifier, scratch)?;
        let statement = self.handover()?.encode()?;
        verifier.verify_handover(self.certificate.kind(), &self.handover()?, proof, scratch)?;
        if let Some(saved) = &self.record.handover {
            let request = Request::decode(saved)?;
            let Command::Handover {
                predecessor,
                statement: old,
                proof: oldproof,
            } = &request.command
            else {
                anyhow::bail!("saved private sender command")
            };
            ensure!(
                *predecessor == self.certificate.kind() && *old == statement && oldproof == proof,
                "private sender handover retry changed"
            );
            self.persist()?;
            return Ok(request);
        }
        let request = Request::sign(
            self.record.intent.clone(),
            Command::Handover {
                predecessor: self.certificate.kind(),
                statement,
                proof: proof.to_vec(),
            },
            &SigningKey::from_bytes(&self.record.session)?,
        )?;
        self.record.handover = Some(request.encode()?);
        self.persist()?;
        Ok(request)
    }
    pub fn saved_handover_request(
        &self,
        verifier: &PinnedSparkVerifier,
        scratch: &Path,
    ) -> Result<Option<Request>> {
        self.verify_current(verifier, scratch)?;
        let Some(saved) = &self.record.handover else {
            return Ok(None);
        };
        let request = Request::decode(saved)?;
        self.persist()?;
        Ok(Some(request))
    }
    /// Call only after the actual signer acknowledges the frozen Handover. The
    /// receiver still independently verifies its pinned sender proof.
    pub fn private_offer(
        &mut self,
        verifier: &PinnedSparkVerifier,
        scratch: &Path,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.verify_current(verifier, scratch)?;
        if let Some(saved) = &self.record.offer {
            self.persist()?;
            return Ok(Zeroizing::new(saved.clone()));
        }
        let request = Request::decode(
            self.record
                .handover
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("private sender handover not frozen"))?,
        )?;
        let Command::Handover {
            predecessor,
            statement,
            proof,
        } = &request.command
        else {
            anyhow::bail!("private sender handover command")
        };
        let mask = self
            .record
            .mask
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("private sender mask missing"))?;
        let offer = PrivateOffer::from_record(
            OfferRecord {
                schema: "zark-spark-private-offer".into(),
                version: 1,
                predecessor: *predecessor,
                backing: self.record.backing.clone(),
                handover: statement.clone(),
                proof: proof.clone(),
                masked: mask.masked,
                masked_salt: self.record.masked_salt,
                bridge_salt: self.record.bridge_salt,
                claim_salt: self.record.claim_salt,
                token: self.record.token,
                old_delay: self.recovery.witness().target.delay,
            },
            verifier,
            scratch,
        )?;
        let encoded = offer.encode_private()?;
        self.record.offer = Some(encoded.to_vec());
        self.persist()?;
        Ok(encoded)
    }
}
