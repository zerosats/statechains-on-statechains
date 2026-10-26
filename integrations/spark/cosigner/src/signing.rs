//! One-use FROST nonces for cooperative Spark identity signing.
use crate::keys::{Authority, Share};
use crate::signing_session;
use anyhow::{Result, ensure};
use frost_secp256k1_tr as frost;
use rand::rngs::OsRng;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

pub struct Nonce {
    position: u16,
    authority_binding: [u8; 32],
    inner: frost::round1::SigningNonces,
    commitments: frost::round1::SigningCommitments,
}

impl Nonce {
    pub fn prepare(share: &Share, authority: &Authority) -> Result<Self> {
        let key = share.package(authority)?;
        let (inner, commitments) = frost::round1::commit(key.signing_share(), &mut OsRng);
        Ok(Self {
            position: share.public().position,
            authority_binding: signing_session::identity_binding(authority)?,
            inner,
            commitments,
        })
    }

    pub fn commitment(&self) -> Result<Vec<u8>> {
        Ok(self.commitments.serialize()?)
    }

    pub(crate) fn encode_private(&self) -> Result<Zeroizing<Vec<u8>>> {
        signing_session::encode(
            "identity",
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
        share.package(authority)?;
        let authority_binding = signing_session::identity_binding(authority)?;
        let (inner, public) = signing_session::decode(
            bytes,
            "identity",
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

    /// Consuming self prevents a second response, including after validation
    /// failure. Private journal codecs are restricted to the application engine.
    pub fn sign(
        self,
        share: &Share,
        authority: &Authority,
        message: [u8; 32],
        commitments: [&[u8]; 2],
    ) -> Result<Vec<u8>> {
        ensure!(
            self.position == share.public().position
                && self.authority_binding == signing_session::identity_binding(authority)?,
            "nonce participant mismatch"
        );
        let package = package(message, commitments)?;
        ensure!(
            package
                .signing_commitments()
                .get(&frost::Identifier::try_from(self.position)?)
                == Some(&self.commitments),
            "coordinator replaced our nonce commitment"
        );
        Ok(frost::round2::sign(&package, &self.inner, &share.package(authority)?)?.serialize())
    }
}

fn package(message: [u8; 32], commitments: [&[u8]; 2]) -> Result<frost::SigningPackage> {
    let mut values = BTreeMap::new();
    for (position, bytes) in (1u16..=2).zip(commitments) {
        values.insert(
            frost::Identifier::try_from(position)?,
            frost::round1::SigningCommitments::deserialize(bytes)?,
        );
    }
    Ok(frost::SigningPackage::new(values, &message))
}

/// Coordinator sees only public keys, commitments and signature contributions.
pub fn aggregate(
    authority: &Authority,
    message: [u8; 32],
    commitments: [&[u8]; 2],
    contributions: [&[u8]; 2],
) -> Result<Vec<u8>> {
    let package = package(message, commitments)?;
    let mut shares = BTreeMap::new();
    for (position, bytes) in (1u16..=2).zip(contributions) {
        shares.insert(
            frost::Identifier::try_from(position)?,
            frost::round2::SignatureShare::deserialize(bytes)?,
        );
    }
    let public = authority.public_package()?;
    let signature = frost::aggregate(&package, &shares, &public)?;
    public.verifying_key().verify(&message, &signature)?;
    Ok(signature.serialize()?)
}
