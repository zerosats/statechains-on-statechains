//! Per-profile inbox. A sender seals each offer to the recipient profile's
//! inbox key; other local profiles see only ciphertext and a random name.
//!
//! The sealed payload carries no authority: a private offer is accepted only
//! after the recipient verifies its pinned sender proof against its own claim
//! key, and a public transfer only after the native claim observes it.
use super::store::{Profile, PublicProfile};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use anyhow::{Context, Result, ensure};
use hkdf::Hkdf;
use k256::{PublicKey, SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use std::{collections::BTreeMap, fs, path::Path};
use zark_protocol::{random32, storage::atomic_write};
use zeroize::Zeroizing;

const INFO: &[u8] = b"ZARK/desktop/inbox/v1";
const MAX_SEALED: u64 = 1024 * 1024;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub(super) enum Kind {
    /// A Zark private handover offer.
    Private,
    /// An ordinary Spark transfer to the Public wallet.
    Public,
}

/// Private offers and single-leaf Public transfers.
pub(super) const ENVELOPE_V1: &str = "zark-blinded-desktop-envelope-v1";
/// Public transfers of any number of leaves, listed in `leaves`.
pub(super) const ENVELOPE_V2: &str = "zark-blinded-desktop-envelope-v2";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Envelope {
    pub schema: String,
    pub kind: Kind,
    pub id: String,
    pub from: String,
    pub amount_sat: u64,
    /// Private: the exact offer bytes the sender's journal produced.
    pub offer: Option<Vec<u8>>,
    /// Native leaf behind the coin, and the SDK `TreeNode` an exit needs.
    /// Public v2: the first of `leaves`.
    pub leaf: String,
    pub leaf_node: Option<Value>,
    /// Public: the ordinary Spark transfer to claim.
    pub transfer: Option<String>,
    /// Public v2: every leaf of the transfer and its value in sats.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leaves: Option<BTreeMap<String, u64>>,
}

impl Envelope {
    /// v1 is unchanged; v2 is a Public transfer whose leaves add up to its amount.
    fn readable(&self) -> bool {
        match (self.schema.as_str(), &self.leaves) {
            (ENVELOPE_V1, None) => true,
            (ENVELOPE_V2, Some(leaves)) => {
                self.kind == Kind::Public
                    && leaves.contains_key(&self.leaf)
                    && leaves
                        .values()
                        .try_fold(0u64, |sum, sats| sum.checked_add(*sats))
                        == Some(self.amount_sat)
            }
            _ => false,
        }
    }
}
impl Drop for Envelope {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(offer) = &mut self.offer {
            offer.zeroize();
        }
    }
}

fn key(shared: &[u8], ephemeral: &[u8], recipient: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut salt = ephemeral.to_vec();
    salt.extend_from_slice(recipient);
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&salt), shared)
        .expand(INFO, &mut *key)
        .map_err(|_| anyhow::anyhow!("inbox key derivation"))?;
    Ok(key)
}

/// `ephemeral (33) || nonce (12) || AES-256-GCM(ciphertext || tag)`, with the
/// recipient key bound into the KDF salt and the associated data.
pub(super) fn seal(recipient: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let recipient_key = PublicKey::from_sec1_bytes(recipient)?;
    let ephemeral = SecretKey::random(&mut OsRng);
    let ephemeral_public = ephemeral.public_key().to_encoded_point(true);
    let shared =
        k256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), recipient_key.as_affine());
    let key = key(
        shared.raw_secret_bytes(),
        ephemeral_public.as_bytes(),
        recipient,
    )?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| anyhow::anyhow!("inbox key"))?;
    let sealed = cipher
        .encrypt(
            &Nonce::from(nonce),
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: recipient,
            },
        )
        .map_err(|_| anyhow::anyhow!("inbox encryption"))?;
    let mut wire = ephemeral_public.as_bytes().to_vec();
    wire.extend_from_slice(&nonce);
    wire.extend_from_slice(&sealed);
    Ok(wire)
}

pub(super) fn open(secret: &[u8; 32], wire: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(wire.len() > 33 + 12 + 16, "sealed inbox entry too short");
    let secret = SecretKey::from_slice(secret)?;
    let recipient = secret.public_key().to_encoded_point(true);
    let ephemeral = PublicKey::from_sec1_bytes(&wire[..33])?;
    let shared = k256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), ephemeral.as_affine());
    let key = key(shared.raw_secret_bytes(), &wire[..33], recipient.as_bytes())?;
    let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| anyhow::anyhow!("inbox key"))?;
    Ok(Zeroizing::new(
        cipher
            .decrypt(
                &Nonce::from(<[u8; 12]>::try_from(&wire[33..45])?),
                aes_gcm::aead::Payload {
                    msg: &wire[45..],
                    aad: recipient.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("inbox entry authentication failed"))?,
    ))
}

/// Writes one sealed entry into the recipient profile's inbox. The name is
/// fixed by the caller so a resumed delivery replaces, never duplicates.
pub(super) fn deliver(
    profiles: &Path,
    to: &PublicProfile,
    name: &str,
    envelope: &Envelope,
) -> Result<()> {
    ensure!(
        name.len() == 64 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "inbox entry name"
    );
    let directory = profiles.join(&to.profile).join("inbox");
    ensure!(directory.is_dir(), "recipient inbox missing");
    let plaintext = Zeroizing::new(serde_json::to_vec(envelope)?);
    let wire = seal(&hex::decode(&to.inbox_key)?, &plaintext)?;
    atomic_write(&directory.join(format!("{name}.sealed")), &wire)
}

/// A random, unlinkable inbox entry name for a new delivery.
pub(super) fn entry_name() -> String {
    hex::encode(random32())
}

pub(super) struct Entry {
    pub name: String,
    pub envelope: Envelope,
}

/// Every readable entry. Unreadable entries are reported, never deleted.
pub(super) fn entries(profile: &Profile) -> Result<(Vec<Entry>, usize)> {
    let mut out = Vec::new();
    let mut unreadable = 0;
    for item in fs::read_dir(profile.home.join("inbox"))? {
        let path = item?.path();
        let Some(name) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".sealed"))
        else {
            continue;
        };
        let read = || -> Result<Envelope> {
            let meta = fs::symlink_metadata(&path)?;
            ensure!(
                meta.is_file() && meta.len() <= MAX_SEALED,
                "inbox entry shape"
            );
            let plain = open(&profile.inbox_secret(), &fs::read(&path)?)?;
            let envelope: Envelope = serde_json::from_slice(&plain)?;
            ensure!(envelope.readable(), "inbox envelope schema");
            Ok(envelope)
        };
        match read() {
            Ok(envelope) => out.push(Entry {
                name: name.into(),
                envelope,
            }),
            Err(_) => unreadable += 1,
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok((out, unreadable))
}

pub(super) fn remove(profile: &Profile, name: &str) -> Result<()> {
    let path = profile.home.join("inbox").join(format!("{name}.sealed"));
    fs::remove_file(&path).with_context(|| format!("remove inbox entry {name}"))?;
    fs::File::open(profile.home.join("inbox"))?.sync_all()?;
    Ok(())
}
