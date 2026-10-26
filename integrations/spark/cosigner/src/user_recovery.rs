//! Two-party BIP341 signing above a Spark refund's shared USER output.
//!
//! Spark operators are absent from this round. Both USER holders must first
//! authorize the exact recovery transaction and its fixed recovery schedule.
//! This primitive checks signatures and domains, not ownership or chain state.
use crate::{
    keys::{Authority, Purpose, Share},
    signing_session,
};
use anyhow::{Result, ensure};
use frost_secp256k1_tr::{self as frost, keys::Tweak};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

pub struct Nonce {
    position: u16,
    authority_binding: [u8; 32],
    inner: frost::round1::SigningNonces,
    commitments: frost::round1::SigningCommitments,
}

fn binding(authority: &Authority) -> Result<[u8; 32]> {
    authority.public_package()?;
    ensure!(
        authority.members()[0].scope.purpose == Purpose::LeafSigning,
        "USER recovery requires leaf shares"
    );
    let mut hash = Sha256::new();
    hash.update(b"ZARK/spark/user-recovery/nonce-authority/v1");
    hash.update(serde_json::to_vec(authority)?);
    Ok(hash.finalize().into())
}

impl Nonce {
    pub fn prepare(share: &Share, authority: &Authority) -> Result<Self> {
        let authority_binding = binding(authority)?;
        let key = share.package(authority)?;
        let (inner, commitments) = frost::round1::commit(key.signing_share(), &mut OsRng);
        Ok(Self {
            position: share.public().position,
            authority_binding,
            inner,
            commitments,
        })
    }

    pub fn commitment(&self) -> Result<Vec<u8>> {
        Ok(self.commitments.serialize()?)
    }

    pub(crate) fn encode_private(&self) -> Result<Zeroizing<Vec<u8>>> {
        signing_session::encode(
            "user-recovery",
            self.position,
            self.authority_binding,
            &self.inner,
            &self.commitment()?,
        )
    }

    pub(crate) fn decode_private(
        bytes: &[u8],
        share: &Share,
        authority: &Authority,
    ) -> Result<Self> {
        let authority_binding = binding(authority)?;
        share.package(authority)?;
        let (inner, public) = signing_session::decode(
            bytes,
            "user-recovery",
            share.public().position,
            authority_binding,
        )?;
        let commitments = signing_session::check_public(&inner, &public)?;
        Ok(Self {
            position: share.public().position,
            authority_binding,
            inner,
            commitments,
        })
    }

    /// Consumes the nonce even on failure. No aggregate private key is formed.
    pub fn sign(
        self,
        share: &Share,
        authority: &Authority,
        sighash: [u8; 32],
        commitments: [&[u8]; 2],
    ) -> Result<Vec<u8>> {
        ensure!(
            self.position == share.public().position
                && self.authority_binding == binding(authority)?,
            "USER recovery nonce authority differs"
        );
        let package = package(sighash, commitments)?;
        ensure!(
            package
                .signing_commitments()
                .get(&frost::Identifier::try_from(self.position)?)
                == Some(&self.commitments),
            "USER recovery own nonce replaced"
        );
        // USER refunds are P2TR outputs, so plain identity Schnorr signing is
        // insufficient. The fork normalizes the internal key, distributes the
        // TapTweak through Shamir shares and handles output-key/nonce parity.
        Ok(
            frost::round2::sign_with_tweak(
                &package,
                &self.inner,
                &share.package(authority)?,
                None,
            )?
            .serialize(),
        )
    }
}

fn package(sighash: [u8; 32], commitments: [&[u8]; 2]) -> Result<frost::SigningPackage> {
    let mut values = BTreeMap::new();
    for (position, bytes) in (1u16..=2).zip(commitments) {
        let commitment = frost::round1::SigningCommitments::deserialize(bytes)?;
        ensure!(
            commitment.serialize()? == bytes,
            "noncanonical USER recovery commitment"
        );
        values.insert(frost::Identifier::try_from(position)?, commitment);
    }
    Ok(frost::SigningPackage::new(values, &sighash))
}

pub fn aggregate(
    authority: &Authority,
    sighash: [u8; 32],
    commitments: [&[u8]; 2],
    contributions: [&[u8]; 2],
) -> Result<Vec<u8>> {
    binding(authority)?;
    let package = package(sighash, commitments)?;
    let mut shares = BTreeMap::new();
    for (position, bytes) in (1u16..=2).zip(contributions) {
        shares.insert(
            frost::Identifier::try_from(position)?,
            frost::round2::SignatureShare::deserialize(bytes)?,
        );
    }
    let public = authority.public_package()?;
    let tweaked = public.clone().tweak(None::<&[u8]>);
    // A valid final sum alone does not authenticate participant attribution:
    // swapped contributions have the same sum. Verify each role explicitly.
    for (identifier, share) in &shares {
        frost::verify_signature_share(
            *identifier,
            tweaked
                .verifying_shares()
                .get(identifier)
                .ok_or_else(|| anyhow::anyhow!("USER recovery verifying share missing"))?,
            share,
            &package,
            tweaked.verifying_key(),
        )?;
    }
    let signature = frost::aggregate_with_tweak(&package, &shares, &public, None)?;
    tweaked.verifying_key().verify(&sighash, &signature)?;
    Ok(signature.serialize()?)
}

#[cfg(test)]
#[path = "user_recovery_tests.rs"]
mod tests;
