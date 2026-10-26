//! Private nonce codecs for exact-session wallet signing journals.
//!
//! A codec does not authorize signing or permit replay with another request.
//! The engine must freeze the canonical job before signing and durably replace
//! the nonce with its exact response before replying. Keep these hooks private
//! to this crate; exporting/reopening a nonce outside that lifecycle is unsafe.
#[cfg(test)]
use crate::keys::Authority;
use anyhow::{Result, ensure};
use frost_secp256k1_tr as frost;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub(crate) const MAX_PRIVATE_NONCE_BYTES: usize = 16 * 1024;

#[derive(Serialize)]
struct Encoded<'a> {
    schema: &'a str,
    version: u32,
    kind: &'a str,
    position: u16,
    authority_binding: [u8; 32],
    nonce: &'a [u8],
    public: &'a [u8],
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Decoded {
    schema: String,
    version: u32,
    kind: String,
    position: u16,
    authority_binding: [u8; 32],
    nonce: Vec<u8>,
    public: Vec<u8>,
}

#[cfg(test)]
pub(crate) fn identity_binding(authority: &Authority) -> Result<[u8; 32]> {
    authority.public_package()?;
    let mut hash = Sha256::new();
    hash.update(b"ZARK/spark/regtest/identity-nonce-authority/v1");
    hash.update(serde_json::to_vec(authority)?);
    Ok(hash.finalize().into())
}

pub(crate) fn encode(
    kind: &str,
    position: u16,
    authority_binding: [u8; 32],
    nonce: &frost::round1::SigningNonces,
    public: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let secret = Zeroizing::new(nonce.serialize()?);
    let record = Encoded {
        schema: "zark-spark-private-nonce",
        version: 1,
        kind,
        position,
        authority_binding,
        nonce: &secret,
        public,
    };
    let mut bytes = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *bytes, &record)?;
    ensure!(
        bytes.len() <= MAX_PRIVATE_NONCE_BYTES,
        "private nonce record too large"
    );
    Ok(bytes)
}

pub(crate) fn decode(
    bytes: &[u8],
    kind: &str,
    position: u16,
    authority_binding: [u8; 32],
) -> Result<(frost::round1::SigningNonces, Vec<u8>)> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_PRIVATE_NONCE_BYTES,
        "invalid private nonce record size"
    );
    let mut record: Decoded = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("invalid private nonce record"))?;
    ensure!(
        record.schema == "zark-spark-private-nonce"
            && record.version == 1
            && record.kind == kind
            && record.position == position
            && record.authority_binding == authority_binding,
        "private nonce kind, participant or authority mismatch"
    );
    let encoded = Encoded {
        schema: &record.schema,
        version: record.version,
        kind: &record.kind,
        position: record.position,
        authority_binding: record.authority_binding,
        nonce: &record.nonce,
        public: &record.public,
    };
    let mut canonical = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *canonical, &encoded)?;
    ensure!(
        canonical.as_slice() == bytes,
        "noncanonical private nonce record"
    );
    let decoded = frost::round1::SigningNonces::deserialize(&record.nonce)
        .map_err(|_| anyhow::anyhow!("invalid private FROST nonce"))?;
    // SigningNonces carries cached public commitments. Recompute them from
    // BOTH secret scalars before trusting any persisted commitment or header.
    let rebuilt = frost::round1::SigningNonces::from_nonces(*decoded.hiding(), *decoded.binding());
    let rebuilt_bytes = Zeroizing::new(rebuilt.serialize()?);
    ensure!(
        *rebuilt_bytes == record.nonce,
        "private nonce secret/commitment mismatch"
    );
    Ok((rebuilt, std::mem::take(&mut record.public)))
}

pub(crate) fn check_public(
    nonce: &frost::round1::SigningNonces,
    bytes: &[u8],
) -> Result<frost::round1::SigningCommitments> {
    let public = frost::round1::SigningCommitments::deserialize(bytes)?;
    ensure!(
        public.serialize()? == bytes && public == frost::round1::SigningCommitments::from(nonce),
        "private nonce public commitment mismatch"
    );
    Ok(public)
}

#[cfg(test)]
#[path = "signing_session_tests.rs"]
mod tests;
