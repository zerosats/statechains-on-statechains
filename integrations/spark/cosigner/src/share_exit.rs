//! Wallet journal for a terminal exit by share release.
//!
//! The signer marks the coin exited and returns x_s encrypted to a fresh key;
//! the wallet completes p = x_w + x_s and spends the leaf with a stock
//! single-key Spark send. Ordering rules this journal enforces:
//!
//! - every request and its recipient secret is durable before it is sent, and
//!   the exact bytes are resent until a response is stored;
//! - the decrypted share is checked against the certified X_s and the coin's
//!   joint key P before p is stored, and only then are recipient secrets erased;
//! - the root and both refund transactions must be absent from the mempool and
//!   chain immediately before any Spark call;
//! - the Spark transfer ID is fixed and durable before the first send, so a
//!   retry resumes that transfer instead of starting a second one.
//!
//! The caller holds this journal (and its operation lock) from the first
//! request until the send completes. It never makes the coin available again.
use crate::private_transfer::persistence::OperationFile;
use anyhow::{Context, Result, bail, ensure};
use k256::{Scalar, elliptic_curve::sec1::ToEncodedPoint, schnorr::SigningKey};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
use zark_protocol::{
    random_scalar, scalar,
    spark_lineage::{Digest, Intent},
    spark_share_release::{self as release, Binding},
    spark_wire::{Command, Request},
};
use zeroize::{Zeroize, Zeroizing};

const FILE: &str = "share-exit.json";
const SCHEMA: &str = "zark-spark-share-exit";
const MAX_BYTES: usize = 256 * 1024;
const MAX_ATTEMPTS: usize = 16;

/// Certified facts the wallet already holds for the coin. `server` comes from
/// the wallet's own certificate, never from a signer response.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExitCoin {
    pub deployment: Digest,
    pub coin: Digest,
    pub state: Digest,
    pub capability: Digest,
    pub server: Vec<u8>,
    pub joint: Vec<u8>,
    /// Bitcoin txids of the leaf's root and both P-refunds.
    pub root: Digest,
    pub refunds: [Digest; 2],
    /// Compressed Spark identity key of the receiving third party.
    pub receiver: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxStatus {
    Absent,
    Mempool,
    Confirmed,
}

/// An authenticated Bitcoin node view. Errors must be returned, never mapped
/// to `Absent`.
pub trait ChainView {
    fn status(&self, txid: &Digest) -> Result<TxStatus>;
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attempt {
    request: Vec<u8>,
    recipient: Option<Digest>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    version: u32,
    coin: ExitCoin,
    attempts: Vec<Attempt>,
    /// Index of the attempt whose committed response produced `secret`.
    released: Option<u32>,
    secret: Option<Digest>,
    /// Seeds the driver's inner SDK signer so a resumed transfer derives the
    /// same new-leaf keys.
    driver_seed: Digest,
    transfer_id: Option<[u8; 16]>,
    completed: bool,
}

impl Drop for Record {
    fn drop(&mut self) {
        self.driver_seed.zeroize();
        for attempt in &mut self.attempts {
            if let Some(secret) = &mut attempt.recipient {
                secret.zeroize();
            }
        }
        if let Some(secret) = &mut self.secret {
            secret.zeroize();
        }
    }
}

/// What the SDK driver (`integrations/spark/sdk/send.rs`) needs for one stock
/// single-key send.
pub struct SendPlan {
    pub secret: Zeroizing<Digest>,
    pub driver_seed: Zeroizing<Digest>,
    pub transfer_id: [u8; 16],
    pub receiver: Vec<u8>,
}

impl SendPlan {
    pub fn transfer_uuid(&self) -> String {
        let h = hex::encode(self.transfer_id);
        format!(
            "{}-{}-{}-{}-{}",
            &h[..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..]
        )
    }

    /// Answers one driver port request. `leaf` is the SDK `TreeNode` JSON the
    /// wallet retained when it received the coin.
    pub fn answer(&self, request: &Value, leaf: &Value) -> Result<Value> {
        match request.get("op").and_then(Value::as_str) {
            Some("exit_send") => Ok(serde_json::json!({
                "secret": self.secret.to_vec(),
                "seed": self.driver_seed.to_vec(),
                "transfer_id": self.transfer_uuid(),
                "receiver": self.receiver,
                "leaf": leaf,
            })),
            Some("seal_leaf_key") => {
                let public: Vec<u8> = serde_json::from_value(
                    request.get("public").context("inner identity")?.clone(),
                )?;
                release::compressed_point(&public)?;
                Ok(serde_json::to_value(zark_protocol::spark_ecies::encrypt(
                    &public,
                    &*self.secret,
                )?)?)
            }
            _ => bail!("unsupported exit send driver request"),
        }
    }
}

pub struct ShareExit {
    file: OperationFile,
    record: Record,
}

impl ShareExit {
    pub fn create(directory: &Path, coin: ExitCoin) -> Result<Self> {
        zark_protocol::point(&coin.server)?;
        zark_protocol::point(&coin.joint)?;
        release::compressed_point(&coin.receiver)?;
        ensure!(
            coin.root != coin.refunds[0]
                && coin.root != coin.refunds[1]
                && coin.refunds[0] != coin.refunds[1],
            "share exit chain watch list"
        );
        let file = OperationFile::create(directory, FILE)?;
        let value = Self {
            file,
            record: Record {
                schema: SCHEMA.into(),
                version: 1,
                coin,
                attempts: Vec::new(),
                released: None,
                secret: None,
                driver_seed: random_scalar().to_bytes().into(),
                transfer_id: None,
                completed: false,
            },
        };
        value.persist()?;
        Ok(value)
    }

    pub fn open(directory: &Path) -> Result<Self> {
        let (file, bytes) = OperationFile::open(directory, FILE, MAX_BYTES)?;
        let record: Record = serde_json::from_slice(&bytes)?;
        ensure!(
            record.schema == SCHEMA && record.version == 1,
            "share exit journal schema"
        );
        ensure!(
            Zeroizing::new(serde_json::to_vec(&record)?).as_slice() == bytes.as_slice(),
            "noncanonical share exit journal"
        );
        Ok(Self { file, record })
    }

    fn persist(&self) -> Result<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(&self.record)?);
        self.file.save(&bytes, MAX_BYTES)
    }

    /// The exact bytes to (re)send. A new attempt is allowed only after the
    /// caller saw the exact retry of every earlier attempt refused without a
    /// stored response; the CAS and the absorbing exit make a second commit
    /// impossible either way, and every recipient secret is kept.
    pub fn pending(&self) -> Result<Option<Request>> {
        if self.record.released.is_some() {
            return Ok(None);
        }
        self.record
            .attempts
            .last()
            .map(|a| Ok(serde_json::from_slice(&a.request)?))
            .transpose()
    }

    pub fn new_attempt(
        &mut self,
        owner: &SigningKey,
        operation: Digest,
        revision: u64,
    ) -> Result<Request> {
        ensure!(self.record.released.is_none(), "share already released");
        ensure!(
            self.record.attempts.len() < MAX_ATTEMPTS,
            "share exit attempts exhausted"
        );
        let coin = &self.record.coin;
        let recipient = Zeroizing::new(random_scalar());
        let point = compressed(&recipient);
        let session = SigningKey::from_bytes(&random_scalar().to_bytes())?;
        let intent = Intent {
            deployment: coin.deployment,
            coin: coin.coin,
            previous_state: coin.state,
            operation,
            recipient_claim: release::recipient_claim(&coin.deployment, &coin.coin, &point)?,
            revision,
        };
        let server: [u8; 64] = coin.server.as_slice().try_into()?;
        let session_public: Digest = session.verifying_key().to_bytes().into();
        let owner = release::sign_owner(
            &release::context(&intent, session_public),
            &point,
            &server,
            owner,
        )?;
        let request = Request::sign(
            intent,
            Command::ShareRelease {
                recipient: point.to_vec(),
                owner,
            },
            &session,
        )?;
        self.record.attempts.push(Attempt {
            request: serde_json::to_vec(&request)?,
            recipient: Some(recipient.to_bytes().into()),
        });
        self.persist()?;
        Ok(request)
    }

    /// Verifies a committed release response against this journal's own
    /// certified values and stores p only if it completes the joint key.
    pub fn accept(&mut self, response: &Value, wallet: &Digest) -> Result<()> {
        ensure!(self.record.released.is_none(), "share already released");
        let wire: Vec<u8> = serde_json::from_value(
            response
                .get("ciphertext")
                .context("release ciphertext")?
                .clone(),
        )?;
        let revision = response
            .get("revision")
            .and_then(Value::as_u64)
            .context("release revision")?;
        let coin = &self.record.coin;
        let server: [u8; 64] = coin.server.as_slice().try_into()?;
        let joint: [u8; 64] = coin.joint.as_slice().try_into()?;
        let mut accepted = None;
        for (index, attempt) in self.record.attempts.iter().enumerate() {
            let request: Request = serde_json::from_slice(&attempt.request)?;
            let Command::ShareRelease { recipient, .. } = &request.command else {
                bail!("journal holds another command")
            };
            let Some(secret) = &attempt.recipient else {
                continue;
            };
            if request.intent.revision.checked_add(1) != Some(revision) {
                continue;
            }
            let binding = Binding {
                deployment: coin.deployment,
                coin: coin.coin,
                intent: release::intent_digest(&request.intent)?,
                request: request.digest()?,
                session: request.session,
                recipient: recipient.as_slice().try_into()?,
                server,
                state: coin.state,
                capability: coin.capability,
                revision: request.intent.revision,
                committed_revision: revision,
            };
            if let Ok(share) = release::open(&binding, &scalar(secret)?, &wire) {
                accepted = Some((index, release::joint_secret(wallet, &share, &joint)?));
                break;
            }
        }
        let (index, secret) = accepted.context("release response matches no journaled request")?;
        self.record.released = Some(index as u32);
        self.record.secret = Some(*secret);
        for attempt in &mut self.record.attempts {
            if let Some(secret) = &mut attempt.recipient {
                secret.zeroize();
            }
            attempt.recipient = None;
        }
        self.persist()
    }

    /// Run immediately before every Spark call. Fixes the transfer ID durably
    /// on first use and refuses if any watched transaction is visible.
    pub fn prepare_send(&mut self, chain: &dyn ChainView) -> Result<SendPlan> {
        ensure!(!self.record.completed, "share exit already completed");
        let secret = self
            .record
            .secret
            .context("share not yet released and verified")?;
        let coin = &self.record.coin;
        for txid in [&coin.root, &coin.refunds[0], &coin.refunds[1]] {
            let status = chain.status(txid)?;
            ensure!(
                status == TxStatus::Absent,
                "leaf transaction {} is {status:?}; only an L1 path with p is safe",
                hex::encode(txid)
            );
        }
        let transfer_id = match self.record.transfer_id {
            Some(id) => id,
            None => {
                let mut id = [0u8; 16];
                OsRng.fill_bytes(&mut id);
                id[6] = (id[6] & 0x0f) | 0x40;
                id[8] = (id[8] & 0x3f) | 0x80;
                self.record.transfer_id = Some(id);
                self.persist()?;
                id
            }
        };
        Ok(SendPlan {
            secret: Zeroizing::new(secret),
            driver_seed: Zeroizing::new(self.record.driver_seed),
            transfer_id,
            receiver: self.record.coin.receiver.clone(),
        })
    }

    /// Only after the receiver's claim is observed; erases p.
    pub fn complete(&mut self, transfer_id: &[u8; 16]) -> Result<()> {
        ensure!(
            self.record.transfer_id == Some(*transfer_id),
            "completed another transfer"
        );
        if let Some(secret) = &mut self.record.secret {
            secret.zeroize();
        }
        self.record.secret = None;
        self.record.completed = true;
        self.persist()
    }

    pub fn transfer_id(&self) -> Option<[u8; 16]> {
        self.record.transfer_id
    }
    pub fn completed(&self) -> bool {
        self.record.completed
    }
}

fn compressed(secret: &Scalar) -> [u8; 33] {
    (k256::ProjectivePoint::GENERATOR * secret)
        .to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed point")
}

#[cfg(test)]
#[path = "share_exit_tests.rs"]
mod tests;
