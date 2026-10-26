//! Wallet journal for proof-gated blind Schnorr Spark operator authentication.
//!
//! One ticket per raw Spark challenge. The blinding is durable before its
//! commitment reaches the signer, each signed request is durable before it is
//! sent and is resent byte-for-byte after an uncertain response, and a
//! blinding is only ever bound to the first server nonce this journal stored:
//! binding it to a second nonce would hand the signer two blinded challenges
//! for one message. The final signature is durable before it is returned.
use crate::private_transfer::persistence::OperationFile;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};
use zark_protocol::{
    hash,
    owner_auth::normalized_key,
    point,
    spark_auth::{self, AuthBlinding, AuthStatement, AuthWitness, IdentityKey, SparkChallenge},
    spark_lineage::{Digest, Intent},
    spark_wire::{Command, Request, auth_issue_intent, auth_prepare_intent},
};
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
#[path = "blind_auth_tests.rs"]
mod tests;

const FILE: &str = "private-auth.json";
const MAX: usize = 512 * 1024;
const MAX_TICKETS: usize = 8;
/// Spark refuses a challenge after 60 s, so older tickets are unusable.
const RETAIN_SECONDS: u64 = 120;

/// The joint identity opening and its signer scope (current owner and session).
pub struct AuthParameters {
    pub intent: Intent,
    pub session: Digest,
    pub user: Digest,
    pub key_salt: Digest,
    pub server: [u8; 64],
}
impl Drop for AuthParameters {
    fn drop(&mut self) {
        self.session.zeroize();
        self.user.zeroize();
        self.key_salt.zeroize();
    }
}
impl AuthParameters {
    fn key(&self) -> Result<IdentityKey> {
        IdentityKey::new(self.user, self.key_salt, self.server)
    }
}

/// Unsigned: blinding and prepare, then nonce, then issue. Signed: signature only.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ticket {
    challenge: String,
    blinding: Option<[Digest; 3]>,
    prepare: Option<String>,
    nonce: Option<String>,
    issue: Option<String>,
    signature: Option<String>,
}
impl Drop for Ticket {
    fn drop(&mut self) {
        if let Some(b) = &mut self.blinding {
            b.zeroize();
        }
    }
}
impl Ticket {
    fn challenge(&self) -> Result<SparkChallenge> {
        SparkChallenge::decode(&hex::decode(&self.challenge)?)
    }
    fn blinding(&self) -> Result<AuthBlinding> {
        let [alpha, beta, salt] = self.blinding.context("Spark auth blinding missing")?;
        Ok(AuthBlinding { alpha, beta, salt })
    }
    fn nonce(&self) -> Result<[u8; 64]> {
        Ok(
            hex::decode(self.nonce.as_ref().context("Spark auth nonce missing")?)?
                .as_slice()
                .try_into()?,
        )
    }
}
fn request(encoded: &Option<String>) -> Result<Request> {
    Request::decode(&hex::decode(
        encoded.as_ref().context("Spark auth request missing")?,
    )?)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    base: Intent,
    server: Vec<u8>,
    key_commitment: Digest,
    tickets: BTreeMap<String, Ticket>,
}

pub struct BlindAuthJournal {
    file: OperationFile,
    record: Record,
}
impl BlindAuthJournal {
    pub fn create(directory: &Path, p: &AuthParameters) -> Result<Self> {
        let record = Record {
            version: 1,
            base: p.intent.clone(),
            server: p.server.to_vec(),
            key_commitment: p.key()?.commitment(),
            tickets: BTreeMap::new(),
        };
        let out = Self {
            file: OperationFile::create(directory, FILE)?,
            record,
        };
        out.persist()?;
        Ok(out)
    }
    pub fn open(directory: &Path) -> Result<Self> {
        let (file, bytes) = OperationFile::open(directory, FILE, MAX)?;
        let record: Record = serde_json::from_slice(&bytes)?;
        ensure!(
            serde_json::to_vec(&record)? == *bytes && record.version == 1,
            "Spark auth journal encoding/version"
        );
        let out = Self { file, record };
        out.validate()?;
        Ok(out)
    }
    fn persist(&self) -> Result<()> {
        self.file
            .save(&Zeroizing::new(serde_json::to_vec(&self.record)?), MAX)
    }

    /// Signs one raw Spark `Challenge`, resuming its interrupted ticket if any.
    /// `signer` delivers a request to the Zark signer; `prover` returns the
    /// pinned auth proof for a wallet-local input and public statement.
    pub fn sign(
        &mut self,
        p: &AuthParameters,
        raw: &[u8],
        mut signer: impl FnMut(&Request) -> Result<Value>,
        prover: impl FnOnce(&str, &[u8]) -> Result<Vec<u8>>,
    ) -> Result<[u8; 64]> {
        let key = p.key()?;
        ensure!(
            p.intent == self.record.base
                && p.server[..] == self.record.server[..]
                && key.commitment() == self.record.key_commitment,
            "Spark auth journal belongs to another identity scope"
        );
        let challenge = SparkChallenge::decode(raw)?;
        key.check_challenge(&challenge)?;
        let id = hex::encode(hash(&[raw]));
        if !self.record.tickets.contains_key(&id) {
            self.begin(p, &key, &challenge, raw)?;
        }
        let t = &self.record.tickets[&id];
        if let Some(signature) = &t.signature {
            return Ok(hex::decode(signature)?.as_slice().try_into()?);
        }
        let prepare = request(&t.prepare)?;
        if t.nonce.is_none() {
            let nonce = prepared_nonce(&prepare, &signer(&prepare)?)?;
            self.ticket(&id)?.nonce = Some(hex::encode(nonce));
            self.persist()?;
        }
        let t = &self.record.tickets[&id];
        let (blinding, nonce, message) = (t.blinding()?, t.nonce()?, challenge.message()?);
        let bound = blinding.bind(&key, &nonce, &message)?;
        if t.issue.is_none() {
            let Command::AuthPrepare { commitment, .. } = prepare.command else {
                anyhow::bail!("Spark auth prepare command")
            };
            let statement = AuthStatement {
                header: key.header(spark_auth::scope_digest(&p.intent)?, challenge.timestamp),
                commitment,
                nonce,
                challenge: bound.challenge,
            };
            let input = AuthWitness {
                key: &key,
                challenge: &challenge,
                blinding: &blinding,
            }
            .prover_toml(&statement)?;
            let proof = prover(&input, &statement.encode()?)?;
            let issue = Request::sign(
                auth_issue_intent(&prepare.intent, &bound.challenge)?,
                Command::AuthIssue {
                    ticket: prepare.intent.operation,
                    challenge: bound.challenge,
                    proof,
                },
                &normalized_key(&p.session)?,
            )?;
            self.ticket(&id)?.issue = Some(hex::encode(issue.encode()?));
            self.persist()?;
        }
        let issue = request(&self.record.tickets[&id].issue)?;
        ensure!(
            matches!(issue.command, Command::AuthIssue { challenge, .. } if challenge == bound.challenge),
            "Spark auth issue differs from its frozen blinding"
        );
        let response = signer(&issue)?;
        let partial: Digest = serde_json::from_value(response["partial"].clone())?;
        // finish() checks G*z = R_s + c'X_s and the final BIP-340 equation.
        let signature = blinding.finish(&key, &bound, &nonce, &partial, &message)?;
        let t = self.ticket(&id)?;
        if let Some(b) = &mut t.blinding {
            b.zeroize();
        }
        (t.blinding, t.prepare, t.nonce, t.issue) = (None, None, None, None);
        t.signature = Some(hex::encode(signature));
        self.persist()?;
        Ok(signature)
    }

    fn begin(
        &mut self,
        p: &AuthParameters,
        key: &IdentityKey,
        challenge: &SparkChallenge,
        raw: &[u8],
    ) -> Result<()> {
        // The signer's clock is authoritative; this only avoids wasting a ticket.
        let now = now()?;
        spark_auth::check_fresh(challenge.timestamp, now)?;
        self.prune(now)?;
        ensure!(
            self.record.tickets.len() < MAX_TICKETS,
            "too many Spark auth tickets"
        );
        let blinding = AuthBlinding::random();
        let header = key.header(spark_auth::scope_digest(&p.intent)?, challenge.timestamp);
        let commitment = blinding.commitment(&header, &challenge.message()?)?;
        let key_commitment = key.commitment();
        let prepare = Request::sign(
            auth_prepare_intent(&p.intent, &key_commitment, challenge.timestamp, &commitment)?,
            Command::AuthPrepare {
                key_commitment,
                timestamp: challenge.timestamp,
                commitment,
            },
            &normalized_key(&p.session)?,
        )?;
        self.record.tickets.insert(
            hex::encode(hash(&[raw])),
            Ticket {
                challenge: hex::encode(raw),
                blinding: Some([blinding.alpha, blinding.beta, blinding.salt]),
                prepare: Some(hex::encode(prepare.encode()?)),
                nonce: None,
                issue: None,
                signature: None,
            },
        );
        self.validate()?;
        self.persist()
    }
    fn prune(&mut self, now: u64) -> Result<()> {
        let mut expired = Vec::new();
        for (id, t) in &self.record.tickets {
            if now.saturating_sub(t.challenge()?.timestamp) > RETAIN_SECONDS {
                expired.push(id.clone());
            }
        }
        for id in expired {
            self.record.tickets.remove(&id);
        }
        Ok(())
    }
    fn ticket(&mut self, id: &str) -> Result<&mut Ticket> {
        self.record
            .tickets
            .get_mut(id)
            .context("Spark auth ticket missing")
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.record.tickets.len() <= MAX_TICKETS && self.record.key_commitment != [0; 32],
            "Spark auth journal coverage"
        );
        let server: [u8; 64] = self.record.server.as_slice().try_into()?;
        point(&server)?;
        let scope = spark_auth::scope_digest(&self.record.base)?;
        for (id, t) in &self.record.tickets {
            let challenge = t.challenge()?;
            ensure!(
                *id == hex::encode(hash(&[&challenge.encode()?])),
                "Spark auth ticket id"
            );
            if t.signature.is_some() {
                ensure!(
                    t.blinding.is_none()
                        && t.prepare.is_none()
                        && t.nonce.is_none()
                        && t.issue.is_none(),
                    "signed Spark auth ticket retains secrets"
                );
                continue;
            }
            let prepare = request(&t.prepare)?;
            let Command::AuthPrepare {
                key_commitment,
                timestamp,
                commitment,
            } = &prepare.command
            else {
                anyhow::bail!("Spark auth prepare command")
            };
            let header = spark_auth::AuthHeader {
                scope,
                key_commitment: self.record.key_commitment,
                server,
                timestamp: challenge.timestamp,
            };
            ensure!(
                *key_commitment == self.record.key_commitment
                    && *timestamp == challenge.timestamp
                    && *commitment == t.blinding()?.commitment(&header, &challenge.message()?)?
                    && prepare.intent
                        == auth_prepare_intent(
                            &self.record.base,
                            key_commitment,
                            *timestamp,
                            commitment
                        )?,
                "Spark auth prepare context"
            );
            if t.nonce.is_some() {
                point(&t.nonce()?)?;
            }
            if t.issue.is_some() {
                let issue = request(&t.issue)?;
                let Command::AuthIssue {
                    ticket, challenge, ..
                } = &issue.command
                else {
                    anyhow::bail!("Spark auth issue command")
                };
                ensure!(
                    t.nonce.is_some()
                        && *ticket == prepare.intent.operation
                        && issue.session == prepare.session
                        && issue.intent == auth_issue_intent(&prepare.intent, challenge)?,
                    "Spark auth issue context"
                );
            }
        }
        Ok(())
    }
}

fn prepared_nonce(prepare: &Request, response: &Value) -> Result<[u8; 64]> {
    let nonce: Vec<u8> = serde_json::from_value(response["nonce"].clone())?;
    let nonce: [u8; 64] = nonce.as_slice().try_into()?;
    point(&nonce)?;
    ensure!(
        response["ticket"] == json!(prepare.intent.operation),
        "Spark auth prepare response"
    );
    Ok(nonce)
}

fn now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}
