//! Terminal Spark exit by releasing the signer's share to its current owner.
//!
//! After the signer durably marks a coin exited it encrypts its share x_s to a
//! fresh wallet key, so only the current owner learns p = x_w + x_s and can spend
//! the leaf with an unchanged Spark SDK. Nothing here proves ownership, chain
//! state or Spark settlement: the signer's current capability, CAS revision and
//! absorbing Exited phase are the authority, and the wallet must check the
//! decrypted share against its own certificate before any Spark call.
use crate::{
    hash, point, point_bytes, random_scalar, random32, scalar,
    spark_lineage::{self as lineage, Digest, Intent},
    spark_native::ExitContext,
    spark_wire::OwnerAuthorization,
};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::AeadInPlace};
use anyhow::{Result, ensure};
use hkdf::Hkdf;
use k256::{
    AffinePoint, EncodedPoint, ProjectivePoint, Scalar,
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    schnorr::{Signature, SigningKey, VerifyingKey},
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

pub const VERSION: u8 = 1;
/// Fixed by this record version; persisted in the signer's exit record.
pub const PURPOSE: &str = "share-release-v1";
pub const RECIPIENT_LEN: usize = 33;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
pub const CIPHERTEXT_LEN: usize = 1 + RECIPIENT_LEN + NONCE_LEN + 32 + TAG_LEN;
const DOMAIN: &[u8] = b"ZARK/spark/share-release/aead/v1";
const KEY_DOMAIN: &[u8] = b"ZARK/spark/share-release/aes-256-gcm-key/v1";

/// Canonical compressed, non-identity secp256k1 point.
pub fn compressed_point(bytes: &[u8]) -> Result<ProjectivePoint> {
    ensure!(bytes.len() == RECIPIENT_LEN, "share release point length");
    let encoded = EncodedPoint::from_bytes(bytes)?;
    let affine: AffinePoint = Option::from(AffinePoint::from_encoded_point(&encoded))
        .ok_or_else(|| anyhow::anyhow!("invalid share release point"))?;
    ensure!(
        affine.to_encoded_point(true).as_bytes() == bytes,
        "noncanonical share release point"
    );
    Ok(ProjectivePoint::from(affine))
}

/// The current-owner context; `revision` is the CAS revision the release consumes.
pub fn context(intent: &Intent, session: Digest) -> ExitContext {
    ExitContext {
        deployment: intent.deployment,
        coin: intent.coin,
        current_state: intent.previous_state,
        operation: intent.operation,
        session,
        revision: intent.revision,
    }
}

pub fn intent_digest(intent: &Intent) -> Result<Digest> {
    Ok(hash(&[
        b"ZARK/spark/share-release/intent/v1",
        &intent.encode()?,
    ]))
}

/// Intent field naming the only key the share may be encrypted to.
pub fn recipient_claim(deployment: &Digest, coin: &Digest, recipient: &[u8]) -> Result<Digest> {
    compressed_point(recipient)?;
    Ok(hash(&[
        b"ZARK/spark/share-release/recipient/v1",
        deployment,
        coin,
        recipient,
    ]))
}

/// Current-owner authorization. Its own domain keeps `Reserve`, head, native
/// and single-USER owner signatures from authorizing a release.
pub fn owner_message(context: &ExitContext, recipient: &[u8], server: &[u8; 64]) -> Result<Digest> {
    compressed_point(recipient)?;
    point(server)?;
    Ok(hash(&[
        b"ZARK/spark/share-release/owner/v1",
        &context.encode()?,
        recipient,
        server,
    ]))
}

pub fn sign_owner(
    context: &ExitContext,
    recipient: &[u8],
    server: &[u8; 64],
    key: &SigningKey,
) -> Result<OwnerAuthorization> {
    let public_key: Digest = key.verifying_key().to_bytes().into();
    ensure!(
        public_key != context.session,
        "share release owner/session separation"
    );
    Ok(OwnerAuthorization {
        public_key,
        signature: key
            .sign_raw(&owner_message(context, recipient, server)?, &random32())?
            .to_bytes()
            .to_vec(),
    })
}

pub fn verify_owner(
    owner: &OwnerAuthorization,
    context: &ExitContext,
    recipient: &[u8],
    server: &[u8; 64],
    capability: &Digest,
) -> Result<()> {
    ensure!(
        owner.public_key != context.session,
        "share release owner/session separation"
    );
    ensure!(
        lineage::public_capability_commitment(
            &context.deployment,
            &context.coin,
            &owner.public_key
        )? == *capability,
        "share release current owner capability"
    );
    VerifyingKey::from_bytes(&owner.public_key)?.verify_raw(
        &owner_message(context, recipient, server)?,
        &Signature::try_from(owner.signature.as_slice())?,
    )?;
    Ok(())
}

/// Everything the ciphertext is bound to. `revision` is the pre-release CAS
/// revision named by the request; `committed_revision` is the Exited row's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    pub deployment: Digest,
    pub coin: Digest,
    pub intent: Digest,
    pub request: Digest,
    pub session: Digest,
    pub recipient: [u8; RECIPIENT_LEN],
    pub server: [u8; 64],
    pub state: Digest,
    pub capability: Digest,
    pub revision: u64,
    pub committed_revision: u64,
}

impl Binding {
    fn validate(&self) -> Result<()> {
        for value in [
            &self.deployment,
            &self.coin,
            &self.intent,
            &self.request,
            &self.session,
            &self.state,
            &self.capability,
        ] {
            ensure!(*value != [0; 32], "zero share release binding");
        }
        compressed_point(&self.recipient)?;
        point(&self.server)?;
        ensure!(
            self.revision > 0 && self.revision.checked_add(1) == Some(self.committed_revision),
            "share release revision binding"
        );
        Ok(())
    }

    fn aad(&self, ephemeral: &[u8], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(DOMAIN.len() + 1 + 7 * 32 + 2 * 33 + 64 + 12 + 16);
        aad.extend_from_slice(DOMAIN);
        aad.push(VERSION);
        for value in [
            &self.deployment,
            &self.coin,
            &self.intent,
            &self.request,
            &self.session,
        ] {
            aad.extend_from_slice(value);
        }
        aad.extend_from_slice(&self.recipient);
        aad.extend_from_slice(ephemeral);
        aad.extend_from_slice(nonce);
        aad.extend_from_slice(&self.server);
        aad.extend_from_slice(&self.state);
        aad.extend_from_slice(&self.capability);
        aad.extend_from_slice(&self.revision.to_le_bytes());
        aad.extend_from_slice(&self.committed_revision.to_le_bytes());
        aad
    }
}

fn derive_key(shared: ProjectivePoint, aad: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let encoded = Zeroizing::new(
        shared
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
    );
    ensure!(encoded.len() == 33, "share release ECDH at infinity");
    let salt = Sha256::digest(aad);
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&salt), &encoded[1..])
        .expand(KEY_DOMAIN, &mut *key)
        .map_err(|_| anyhow::anyhow!("share release key derivation"))?;
    Ok(key)
}

/// Wire: version || compressed ephemeral || nonce || ciphertext || tag.
pub fn seal(binding: &Binding, secret: &[u8; 32]) -> Result<Vec<u8>> {
    binding.validate()?;
    let share = Zeroizing::new(scalar(secret)?);
    ensure!(
        point_bytes(ProjectivePoint::GENERATOR * *share)? == binding.server,
        "released share differs from bound server point"
    );
    let ephemeral_secret = Zeroizing::new(random_scalar());
    let ephemeral = (ProjectivePoint::GENERATOR * *ephemeral_secret)
        .to_affine()
        .to_encoded_point(true);
    let nonce: [u8; NONCE_LEN] = random32()[..NONCE_LEN].try_into()?;
    let aad = binding.aad(ephemeral.as_bytes(), &nonce);
    let key = derive_key(
        compressed_point(&binding.recipient)? * *ephemeral_secret,
        &aad,
    )?;
    let mut buffer = Zeroizing::new(secret.to_vec());
    Aes256Gcm::new_from_slice(&*key)
        .map_err(|_| anyhow::anyhow!("share release cipher key"))?
        .encrypt_in_place(&Nonce::from(nonce), &aad, &mut *buffer)
        .map_err(|_| anyhow::anyhow!("share release encryption"))?;
    let mut wire = Vec::with_capacity(CIPHERTEXT_LEN);
    wire.push(VERSION);
    wire.extend_from_slice(ephemeral.as_bytes());
    wire.extend_from_slice(&nonce);
    wire.extend_from_slice(&buffer);
    ensure!(wire.len() == CIPHERTEXT_LEN, "share release wire length");
    Ok(wire)
}

/// Returns x_s only if it decrypts under the full binding and matches X_s.
pub fn open(binding: &Binding, recipient: &Scalar, wire: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    binding.validate()?;
    ensure!(
        (ProjectivePoint::GENERATOR * recipient)
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            == binding.recipient,
        "wrong share release recipient key"
    );
    ensure!(
        wire.len() == CIPHERTEXT_LEN && wire[0] == VERSION,
        "share release ciphertext shape"
    );
    let ephemeral = &wire[1..1 + RECIPIENT_LEN];
    let nonce: [u8; NONCE_LEN] =
        wire[1 + RECIPIENT_LEN..1 + RECIPIENT_LEN + NONCE_LEN].try_into()?;
    let aad = binding.aad(ephemeral, &nonce);
    let key = derive_key(compressed_point(ephemeral)? * recipient, &aad)?;
    let mut buffer = Zeroizing::new(wire[1 + RECIPIENT_LEN + NONCE_LEN..].to_vec());
    Aes256Gcm::new_from_slice(&*key)
        .map_err(|_| anyhow::anyhow!("share release cipher key"))?
        .decrypt_in_place(&Nonce::from(nonce), &aad, &mut *buffer)
        .map_err(|_| anyhow::anyhow!("share release authentication failed"))?;
    let secret: Zeroizing<[u8; 32]> = Zeroizing::new(buffer.as_slice().try_into()?);
    ensure!(
        point_bytes(ProjectivePoint::GENERATOR * scalar(&*secret)?)? == binding.server,
        "released share differs from the certified server point"
    );
    Ok(secret)
}

/// Combines the shares only if they produce the coin's joint Spark key P.
/// `joint` is the uncompressed 64-byte affine encoding used by recovery records.
pub fn joint_secret(
    wallet: &[u8; 32],
    server: &[u8; 32],
    joint: &[u8; 64],
) -> Result<Zeroizing<[u8; 32]>> {
    let sum = Zeroizing::new(scalar(wallet)? + scalar(server)?);
    ensure!(!bool::from(sum.is_zero()), "zero joint Spark key");
    ensure!(
        point_bytes(ProjectivePoint::GENERATOR * *sum)? == *joint,
        "released share does not complete the coin's joint key"
    );
    Ok(Zeroizing::new(sum.to_bytes().into()))
}

#[cfg(test)]
#[path = "spark_share_release_tests.rs"]
mod tests;
