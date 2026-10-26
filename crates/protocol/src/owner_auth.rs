//! Normalized owner keys and their public capability commitments.
use crate::handoff::{Digest, PROTOCOL_VERSION};
use anyhow::{Result, ensure};
use k256::schnorr::{SigningKey, VerifyingKey};

/// Reject the negated scalar even when it has the same x-only public key.
pub fn normalized_key(secret: &Digest) -> Result<SigningKey> {
    let key = SigningKey::from_bytes(secret)?;
    ensure!(
        &key.to_bytes()[..] == secret,
        "owner secret is not normalized"
    );
    Ok(key)
}

pub fn generate_secret() -> Digest {
    SigningKey::from_bytes(&crate::random_scalar().to_bytes())
        .expect("nonzero scalar")
        .to_bytes()
        .into()
}

pub fn public_capability_commitment(
    deployment: &Digest,
    coin: &Digest,
    public_key: &Digest,
) -> Result<Digest> {
    ensure!(
        *deployment != [0; 32] && *coin != [0; 32],
        "owner capability domain"
    );
    VerifyingKey::from_bytes(public_key)?;
    Ok(crate::application_hash::hash(&[
        b"ZARK/private-handoff/owner-capability/v1",
        &PROTOCOL_VERSION.to_le_bytes(),
        deployment,
        coin,
        public_key,
    ]))
}
