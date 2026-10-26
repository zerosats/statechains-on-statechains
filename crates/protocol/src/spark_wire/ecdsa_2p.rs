//! Wire domain for cb-mpc two-party ECDSA on the fresh entry identity. Each
//! command relays one opaque protocol message; operations are domain-separated
//! from the garbled-circuit identity and Schnorr auth tickets.
use crate::{
    hash,
    spark_lineage::{Digest, Intent},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const MAX_FRAME: usize = 64 * 1024;

/// One cb-mpc protocol message, hex encoded so the 36 KiB key generation
/// message stays well inside `MAX_WIRE`.
#[derive(Clone, PartialEq, Eq)]
pub struct Frame(Vec<u8>);

impl Frame {
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_FRAME,
            "ECDSA-2P frame size"
        );
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn digest(&self) -> Digest {
        hash(&[b"ZARK/spark/ecdsa-2p/frame/v1", &self.0])
    }
}

impl Serialize for Frame {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Frame {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = hex::decode(&text).map_err(serde::de::Error::custom)?;
        Self::new(bytes).map_err(serde::de::Error::custom)
    }
}

pub fn keygen_intent(base: &Intent, frame: &Frame) -> Result<Intent> {
    let mut intent = base.clone();
    intent.operation = hash(&[
        b"ZARK/spark/ecdsa-2p/keygen/v1",
        &base.encode()?,
        &frame.digest(),
    ]);
    Ok(intent)
}

pub fn keygen_finish_intent(started: &Intent, frame: &Frame) -> Result<Intent> {
    let mut intent = started.clone();
    intent.operation = hash(&[
        b"ZARK/spark/ecdsa-2p/keygen-finish/v1",
        &started.encode()?,
        &frame.digest(),
    ]);
    Ok(intent)
}

/// A blind ticket binds no message: the signer only ever sees m''.
pub fn sign_intent(base: &Intent, nonce: &Digest) -> Result<Intent> {
    let mut intent = base.clone();
    intent.operation = hash(&[b"ZARK/spark/ecdsa-2p/blind-sign/v1", &base.encode()?, nonce]);
    Ok(intent)
}

pub fn sign_finish_intent(ticket: &Intent, frame: &Frame) -> Result<Intent> {
    let mut intent = ticket.clone();
    intent.operation = hash(&[
        b"ZARK/spark/ecdsa-2p/sign-finish/v1",
        &ticket.encode()?,
        &frame.digest(),
    ]);
    Ok(intent)
}

/// The cb-mpc session id both parties pass for one signing ticket.
pub fn session_id(ticket: &Intent) -> Result<Digest> {
    Ok(hash(&[
        b"ZARK/spark/ecdsa-2p/blind-sid/v1",
        &ticket.encode()?,
    ]))
}
