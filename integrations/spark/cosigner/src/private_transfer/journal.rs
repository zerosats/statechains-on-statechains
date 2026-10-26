//! Recipient recovery journal: exact authenticated requests and recovery-before-
//! acknowledgement. This does not replace fresh signer-head or chain checks.
use super::{PrivateBacking, PrivateCertificate, PrivateRecovery};
use anyhow::{Result, ensure};
use k256::schnorr::SigningKey;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use zark_protocol::{
    hash,
    local::ProcessLock,
    spark_lineage::{Certificate, Issuance, PinnedSparkVerifier, require_intent},
    spark_wire::{Command, Predecessor, Request},
    storage::{atomic_write, sync_observed},
};
use zeroize::{Zeroize, Zeroizing};

const FILE: &str = "private-receiver.json";
const MAX_BYTES: u64 = 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    version: u32,
    kind: Predecessor,
    session: [u8; 32],
    backing: Vec<u8>,
    recovery: Vec<u8>,
    requests: BTreeMap<u8, Vec<u8>>,
    certificate: Option<Vec<u8>>,
}
impl Drop for Record {
    fn drop(&mut self) {
        self.session.zeroize();
        self.backing.zeroize();
        self.recovery.zeroize();
        for value in self.requests.values_mut() {
            value.zeroize();
        }
        if let Some(value) = &mut self.certificate {
            value.zeroize();
        }
    }
}

pub struct IssuedRecovery {
    pub partials: [[u8; 32]; 2],
    pub certificate: Vec<u8>,
    pub certificate_id: [u8; 32],
    pub state: [u8; 32],
    pub capability: [u8; 32],
    pub origin_signature: Option<Vec<u8>>,
}

pub struct RecoveryJournal {
    directory: PathBuf,
    record: Record,
    backing: PrivateBacking,
    recovery: PrivateRecovery,
    _lock: ProcessLock,
}

impl RecoveryJournal {
    pub fn create(
        directory: &Path,
        kind: Predecessor,
        backing: &PrivateBacking,
        recovery: PrivateRecovery,
        session: [u8; 32],
    ) -> Result<Self> {
        let session = Zeroizing::new(session);
        ensure!(
            SigningKey::from_bytes(&session[..])?
                .verifying_key()
                .to_bytes()[..]
                == recovery.frozen().context.session,
            "recovery journal session differs"
        );
        let backing_bytes = backing.encode_private()?;
        let record = Record {
            schema: "zark-spark-private-receiver".into(),
            version: 1,
            kind,
            session: *session,
            backing: backing_bytes.to_vec(),
            recovery: recovery.encode_private()?.to_vec(),
            requests: BTreeMap::new(),
            certificate: None,
        };
        fs::DirBuilder::new().mode(0o700).create(directory)?;
        check_directory(directory)?;
        let lock = ProcessLock::acquire(&directory.join("operation.lock"))?;
        let value = Self {
            directory: directory.into(),
            record,
            backing: PrivateBacking::decode_private(&backing_bytes)?,
            recovery,
            _lock: lock,
        };
        value.validate()?;
        value.persist()?;
        Ok(value)
    }

    pub fn open(directory: &Path) -> Result<Self> {
        check_directory(directory)?;
        let lock_path = directory.join("operation.lock");
        check_file(&fs::symlink_metadata(&lock_path)?)?;
        let lock = ProcessLock::acquire(&lock_path)?;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(directory.join(FILE))?;
        check_file(&file.metadata()?)?;
        let mut bytes = Zeroizing::new(Vec::new());
        (&mut file).take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_BYTES,
            "private receiver journal size"
        );
        let record: Record = serde_json::from_slice(&bytes)?;
        let canonical = Zeroizing::new(serde_json::to_vec(&record)?);
        ensure!(
            canonical.as_slice() == bytes.as_slice(),
            "noncanonical private receiver journal"
        );
        let backing = PrivateBacking::decode_private(&record.backing)?;
        let recovery = PrivateRecovery::decode_private(&backing, &record.recovery)?;
        let value = Self {
            directory: directory.into(),
            record,
            backing,
            recovery,
            _lock: lock,
        };
        value.validate()?;
        sync_observed(&file, directory)?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.record.schema == "zark-spark-private-receiver" && self.record.version == 1,
            "private receiver journal schema"
        );
        let session = SigningKey::from_bytes(&self.record.session)?;
        ensure!(
            session.verifying_key().to_bytes()[..] == self.recovery.frozen().context.session,
            "private receiver session changed"
        );
        ensure!(
            self.record.requests.len() <= 3,
            "private receiver request count"
        );
        for (purpose, wire) in &self.record.requests {
            ensure!(
                (6..=8).contains(purpose),
                "unexpected private receiver command"
            );
            let request = Request::decode(wire)?;
            ensure!(
                request.command.purpose() == *purpose
                    && request.session == self.recovery.frozen().context.session
                    && request.intent == *self.recovery.intent(),
                "private receiver request context changed"
            );
            match &request.command {
                Command::Prepare {
                    successor_state,
                    recovery,
                    nonce_commitments,
                } => {
                    let frozen = self.recovery.frozen();
                    ensure!(
                        *successor_state == frozen.context.successor_state
                            && *recovery == frozen.recovery
                            && *nonce_commitments == frozen.nonce_commitments,
                        "saved private recovery preparation changed"
                    );
                }
                Command::Issue { statement, .. } => {
                    let issuance = Issuance::decode(statement)?;
                    require_intent(&issuance, self.recovery.intent())?;
                    ensure!(
                        issuance.recovery.encode()? == self.recovery.authorization()?.encode()?
                            && issuance.next_capability == self.recovery.next_capability(),
                        "saved private recovery issuance changed"
                    );
                }
                Command::Acknowledge { .. } => (),
                _ => anyhow::bail!("unexpected private receiver saved command"),
            }
        }
        if let Some(cert) = &self.record.certificate {
            let cert = PrivateCertificate::decode_private(cert)?;
            ensure!(
                cert.kind() == self.record.kind
                    && cert.authorization().recovery.encode()?
                        == self.recovery.authorization()?.encode()?,
                "private receiver certificate context changed"
            );
            let issued =
                Request::decode(self.record.requests.get(&7).ok_or_else(|| {
                    anyhow::anyhow!("private receiver certificate before issuance")
                })?)?;
            let Command::Issue { statement, proof } = &issued.command else {
                anyhow::bail!("private receiver issued command changed")
            };
            ensure!(
                *statement == cert.authorization().encode()? && proof == cert.proof(),
                "private receiver certificate differs from exact issuance"
            );
            self.recovery.completed()?;
            if let Some(ack) = self.record.requests.get(&8) {
                let ack = Request::decode(ack)?;
                let Command::Acknowledge { state, certificate } = &ack.command else {
                    anyhow::bail!("private receiver acknowledgement command changed")
                };
                ensure!(
                    *state == cert.native_lineage()?.state && *certificate == cert.identity()?,
                    "private receiver saved acknowledgement changed"
                );
            }
        }
        ensure!(
            !self.record.requests.contains_key(&8) || self.record.certificate.is_some(),
            "private receiver acknowledgement before recovery certificate"
        );
        Ok(())
    }

    fn persist(&self) -> Result<()> {
        self.validate()?;
        let bytes = Zeroizing::new(serde_json::to_vec(&self.record)?);
        ensure!(
            bytes.len() as u64 <= MAX_BYTES,
            "private receiver journal size"
        );
        atomic_write(&self.directory.join(FILE), &bytes)
    }

    fn save_recovery(&mut self) -> Result<()> {
        self.record.recovery = self.recovery.encode_private()?.to_vec();
        self.persist()
    }

    fn freeze(&mut self, command: Command) -> Result<Request> {
        let purpose = command.purpose();
        if let Some(saved) = self.record.requests.get(&purpose) {
            let request = Request::decode(saved)?;
            ensure!(
                serde_json::to_vec(&request.command)? == serde_json::to_vec(&command)?,
                "private receiver exact request changed"
            );
            // A prior write/fsync may have failed after populating this cache.
            // Never release even identical bytes until this complete snapshot
            // is durably written, including recovery and certificate for Ack.
            self.save_recovery()?;
            return Ok(request);
        }
        let request = Request::sign(
            self.recovery.intent().clone(),
            command,
            &SigningKey::from_bytes(&self.record.session)?,
        )?;
        self.record.requests.insert(purpose, request.encode()?);
        self.save_recovery()?;
        Ok(request)
    }

    pub fn prepare_request(&mut self) -> Result<Request> {
        let frozen = self.recovery.frozen();
        self.freeze(Command::Prepare {
            successor_state: frozen.context.successor_state,
            recovery: frozen.recovery,
            nonce_commitments: frozen.nonce_commitments,
        })
    }

    /// Persist exact signer nonces before a prover sees the bound challenges.
    pub fn bind_nonces(&mut self, nonces: [[u8; 64]; 2]) -> Result<()> {
        ensure!(
            self.record.requests.contains_key(&6),
            "private receiver nonce before preparation"
        );
        self.recovery.bind_nonces(nonces)?;
        self.save_recovery()
    }

    pub fn issue_request(
        &mut self,
        issuance: &Issuance,
        proof: &[u8],
        verifier: &PinnedSparkVerifier,
        scratch: &Path,
    ) -> Result<Request> {
        require_intent(issuance, self.recovery.intent())?;
        ensure!(
            issuance.recovery.encode()? == self.recovery.authorization()?.encode()?
                && issuance.next_capability == self.recovery.next_capability(),
            "private receiver issuance differs from saved recovery"
        );
        verifier.verify_issuance(
            self.record.kind == Predecessor::Origin,
            issuance,
            proof,
            scratch,
        )?;
        self.freeze(Command::Issue {
            statement: issuance.encode()?,
            proof: proof.to_vec(),
        })
    }

    pub fn saved_issue_request(
        &mut self,
        verifier: &PinnedSparkVerifier,
        scratch: &Path,
    ) -> Result<Option<Request>> {
        let Some(saved) = self.record.requests.get(&7) else {
            return Ok(None);
        };
        let request = Request::decode(saved)?;
        let Command::Issue { statement, proof } = &request.command else {
            anyhow::bail!("saved private receiver issuance command")
        };
        let issuance = Issuance::decode(statement)?;
        require_intent(&issuance, self.recovery.intent())?;
        ensure!(
            issuance.recovery.encode()? == self.recovery.authorization()?.encode()?,
            "saved private receiver issuance changed"
        );
        verifier.verify_issuance(
            self.record.kind == Predecessor::Origin,
            &issuance,
            proof,
            scratch,
        )?;
        self.save_recovery()?;
        Ok(Some(request))
    }

    pub fn complete_issuance(
        &mut self,
        response: IssuedRecovery,
        verifier: &PinnedSparkVerifier,
        scratch: &Path,
    ) -> Result<Certificate> {
        let request = Request::decode(
            self.record
                .requests
                .get(&7)
                .ok_or_else(|| anyhow::anyhow!("private receiver issuance request missing"))?,
        )?;
        let Command::Issue { statement, proof } = &request.command else {
            anyhow::bail!("private receiver command is not issuance")
        };
        let issuance = Issuance::decode(statement)?;
        ensure!(
            issuance.recovery.encode()? == self.recovery.authorization()?.encode()?,
            "private receiver completed another issuance"
        );
        let own = PrivateCertificate::from_issued(
            self.record.kind,
            issuance,
            proof.clone(),
            response.partials,
            *self.recovery.server_salt(),
            response.origin_signature,
        )?;
        let lineage = own.verify(verifier, scratch)?;
        ensure!(
            lineage.encode()? == response.certificate
                && own.identity()? == response.certificate_id
                && lineage.state == response.state
                && own.authorization().next_capability == response.capability,
            "private receiver signer certificate differs"
        );
        self.recovery.finish(response.partials)?;
        let encoded = own.encode_private()?;
        if let Some(saved) = &self.record.certificate {
            ensure!(
                *saved == *encoded,
                "private receiver issued certificate retry changed"
            );
        }
        self.record.certificate = Some(encoded.to_vec());
        // The one durable record contains BOTH complete native recoveries and
        // the actually proof-verified private certificate before ack can exist.
        self.save_recovery()?;
        Ok(lineage)
    }

    /// Freeze only, without sending. The native bridge must additionally check
    /// a fresh signer head and every live recovery window before transmitting.
    pub fn saved_recovery_acknowledgement(
        &mut self,
        verifier: &PinnedSparkVerifier,
        scratch: &Path,
    ) -> Result<Request> {
        let own =
            PrivateCertificate::decode_private(self.record.certificate.as_ref().ok_or_else(
                || anyhow::anyhow!("private receiver recovery certificate not durable"),
            )?)?;
        let lineage = own.verify(verifier, scratch)?;
        self.recovery.finish(own.partials())?;
        self.freeze(Command::Acknowledge {
            state: lineage.state,
            certificate: hash(&[&lineage.encode()?]),
        })
    }

    pub fn backing(&self) -> &PrivateBacking {
        &self.backing
    }
    pub fn recovery(&self) -> &PrivateRecovery {
        &self.recovery
    }
    pub fn certificate(
        &self,
        verifier: &PinnedSparkVerifier,
        scratch: &Path,
    ) -> Result<PrivateCertificate> {
        let own = PrivateCertificate::decode_private(
            self.record
                .certificate
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("private receiver certificate missing"))?,
        )?;
        own.verify(verifier, scratch)?;
        self.persist()?;
        Ok(own)
    }
}

fn check_directory(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.mode() & 0o777 == 0o700 && m.uid() == unsafe { libc::geteuid() },
        "private receiver directory permissions or owner"
    );
    Ok(())
}
fn check_file(m: &fs::Metadata) -> Result<()> {
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.mode() & 0o777 == 0o600
            && m.uid() == unsafe { libc::geteuid() },
        "private receiver file permissions or owner"
    );
    Ok(())
}
