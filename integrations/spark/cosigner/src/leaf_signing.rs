//! Independent USER-group signing for Spark's pinned MPC refund scheme.
//!
//! Spark operators are the primary FROST group; wallet and Zark co-signer are
//! the secondary group. This module matches `SIGNING_SCHEME_MPC_USER_GROUP`
//! in the pinned Spark signer, including combined-key parity and TapTweak.
//! It is not a Spark RPC adapter, transaction validator or recovery mechanism.
//! Callers must verify the authenticated leaf, refund destination/transaction,
//! sighash and Zark authorization before approving a signing transcript.
use crate::keys::{Authority, Purpose, Share};
#[cfg(test)]
use crate::signing_session;
use anyhow::{Result, ensure};
use frost_core::Ciphersuite;
use frost_core::two_group::{self, SignerGroup, TwoGroupSigningPackage};
use frost_secp256k1_tr::{
    self as frost,
    keys::{EvenY, Tweak},
};
use k256::{
    ProjectivePoint, Scalar,
    elliptic_curve::{PrimeField, sec1::ToEncodedPoint},
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zeroize::Zeroize;
#[cfg(test)]
use zeroize::Zeroizing;

pub type OperatorCommitments = BTreeMap<frost::Identifier, frost::round1::SigningCommitments>;

/// Authenticated Spark leaf keys must be checked before constructing this.
#[derive(Clone)]
pub struct LeafAuthority {
    user: Authority,
    operator_key: Vec<u8>,
    combined: frost::VerifyingKey,
    output: frost::VerifyingKey,
}

impl LeafAuthority {
    pub fn new(
        user: Authority,
        operator_key: &[u8],
        advertised_combined_key: &[u8],
    ) -> Result<Self> {
        user.public_package()?;
        ensure!(
            user.members()[0].scope.purpose == Purpose::LeafSigning,
            "leaf signing requires leaf authority"
        );
        let operator = canonical_point(operator_key)?;
        let user_point = canonical_point(&user.public_key()?)?;
        let combined = operator + user_point;
        ensure!(
            combined != ProjectivePoint::IDENTITY,
            "combined key at infinity"
        );
        let encoded = combined.to_affine().to_encoded_point(true);
        // Do not infer parity from the user key alone or normalize the wire key
        // before comparison: Spark signs under the user+operator combined key.
        ensure!(
            encoded.as_bytes() == advertised_combined_key,
            "Spark leaf combined key mismatch"
        );
        let combined = frost::VerifyingKey::deserialize(encoded.as_bytes())?;
        let output = *frost::keys::PublicKeyPackage::new(BTreeMap::new(), combined, None)
            .tweak(Some(&[] as &[u8]))
            .verifying_key();
        Ok(Self {
            user,
            operator_key: operator_key.to_vec(),
            combined,
            output,
        })
    }

    /// Original SEC1 parity, before the BIP341 key-path tweak.
    pub fn combined_key(&self) -> Result<Vec<u8>> {
        Ok(self.combined.serialize()?)
    }

    pub fn output_key(&self) -> Result<Vec<u8>> {
        Ok(self.output.serialize()?)
    }

    pub(crate) fn user_authority(&self) -> &Authority {
        &self.user
    }

    pub(crate) fn operator_key(&self) -> &[u8] {
        &self.operator_key
    }

    pub(crate) fn binding(&self) -> Result<[u8; 32]> {
        let scope = &self.user.members()[0].scope;
        let mut hash = Sha256::new();
        hash.update(b"ZARK/spark/regtest/leaf-signing/nonce-domain/v1");
        hash.update(scope.deployment);
        hash.update(scope.coin);
        hash.update([scope.purpose as u8]);
        for member in self.user.members() {
            hash.update(member.position.to_be_bytes());
            hash.update(hex::decode(&member.public_key)?);
        }
        hash.update(&self.operator_key);
        hash.update(self.combined_key()?);
        Ok(hash.finalize().into())
    }

    pub(crate) fn participant_package(&self, share: &Share) -> Result<frost::keys::KeyPackage> {
        let position = share.public().position;
        let mut scalar = share.additive_scalar(&self.user)?;
        // Lagrange coefficients at positions 1,2 are 2,-1: the local Shamir
        // encodings are a/2,-b, reconstructing a+b only in public group terms.
        scalar *= match position {
            1 => Scalar::from(2u64).invert().unwrap(),
            2 => -Scalar::ONE,
            _ => unreachable!("validated shared-key position"),
        };
        let signing_share = frost::keys::SigningShare::deserialize(&scalar.to_bytes());
        scalar.zeroize();
        let signing_share = signing_share?;
        let verifying_share = frost::keys::VerifyingShare::from(signing_share);
        let raw = frost::keys::KeyPackage::new(
            frost::Identifier::try_from(position)?,
            signing_share,
            verifying_share,
            self.combined,
            2,
        );
        // This is exactly Spark USER proto parsing: normalize secrets using
        // UNTWEAKED combined parity, then install the TWEAKED combined key.
        // The primary operator group carries the tweak scalar; users do not.
        let even = raw.into_even_y(Some(self.combined.has_even_y()));
        Ok(frost::keys::KeyPackage::new(
            *even.identifier(),
            *even.signing_share(),
            *even.verifying_share(),
            self.output,
            2,
        ))
    }
}

fn canonical_point(bytes: &[u8]) -> Result<ProjectivePoint> {
    ensure!(bytes.len() == 33, "invalid Spark key length");
    let point = k256::PublicKey::from_sec1_bytes(bytes)?.to_projective();
    ensure!(
        point.to_affine().to_encoded_point(true).as_bytes() == bytes,
        "noncanonical Spark key"
    );
    Ok(point)
}

/// Non-serializable, non-cloneable nonce; consumed on success AND every error.
pub struct Nonce {
    position: u16,
    authority_binding: [u8; 32],
    inner: frost::round1::SigningNonces,
    commitments: frost::round1::SigningCommitments,
}

impl Nonce {
    pub fn prepare(share: &Share, authority: &LeafAuthority) -> Result<Self> {
        let key = authority.participant_package(share)?;
        let (inner, commitments) = frost::round1::commit(key.signing_share(), &mut OsRng);
        Ok(Self {
            position: share.public().position,
            authority_binding: authority.binding()?,
            inner,
            commitments,
        })
    }

    pub fn commitment(&self) -> Result<Vec<u8>> {
        Ok(self.commitments.serialize()?)
    }

    #[cfg(test)]
    pub(crate) fn encode_private(&self) -> Result<Zeroizing<Vec<u8>>> {
        signing_session::encode(
            "nested-leaf",
            self.position,
            self.authority_binding,
            &self.inner,
            &self.commitment()?,
        )
    }

    #[cfg(test)]
    pub(crate) fn decode_private(
        bytes: &[u8],
        share: &Share,
        authority: &LeafAuthority,
    ) -> Result<Self> {
        authority.participant_package(share)?;
        let authority_binding = authority.binding()?;
        let (inner, public) = signing_session::decode(
            bytes,
            "nested-leaf",
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

    pub fn sign(
        self,
        share: &Share,
        authority: &LeafAuthority,
        sighash: [u8; 32],
        operators: OperatorCommitments,
        users: [&[u8]; 2],
    ) -> Result<Vec<u8>> {
        ensure!(
            self.position == share.public().position
                && self.authority_binding == authority.binding()?,
            "leaf signing nonce authority mismatch"
        );
        let package = package(sighash, operators, users)?;
        ensure!(
            package
                .signing_commitments(SignerGroup::Secondary)
                .get(&frost::Identifier::try_from(self.position)?)
                == Some(&self.commitments),
            "coordinator replaced our leaf nonce commitment"
        );
        Ok(two_group::sign(
            &package,
            &self.inner,
            &authority.participant_package(share)?,
            SignerGroup::Secondary,
        )?
        .serialize())
    }
}

fn package(
    sighash: [u8; 32],
    operators: OperatorCommitments,
    users: [&[u8]; 2],
) -> Result<TwoGroupSigningPackage<frost::Secp256K1Sha256TR>> {
    let mut secondary = BTreeMap::new();
    for (position, bytes) in (1u16..=2).zip(users) {
        secondary.insert(
            frost::Identifier::try_from(position)?,
            frost::round1::SigningCommitments::deserialize(bytes)?,
        );
    }
    Ok(TwoGroupSigningPackage::new(operators, secondary, &sighash)?)
}

/// Verify both USER shares without needing any operator signature shares.
/// The two-group binding preimages come from the pinned FROST implementation.
/// Each USER's Lagrange factor cancels its additive-to-Shamir encoding; neither
/// USER carries the TapTweak scalar. Both combined-key and output-key parity,
/// and the nonce parity over BOTH groups, still apply to its public equation.
pub fn verify_user_partials(
    authority: &LeafAuthority,
    sighash: [u8; 32],
    operators: OperatorCommitments,
    users: [&[u8]; 2],
    partials: [&[u8]; 2],
) -> Result<()> {
    let members = authority.user.members();
    verify_additive_user_partials(
        authority.combined,
        authority.output,
        [
            canonical_point(&hex::decode(&members[0].public_key)?)?,
            canonical_point(&hex::decode(&members[1].public_key)?)?,
        ],
        sighash,
        operators,
        users,
        partials,
    )
}

/// Shared pinned equation for already checked additive USER decompositions.
/// The caller validates the raw public sum before any parity normalization.
pub(crate) fn verify_additive_user_partials(
    combined: frost::VerifyingKey,
    native_output: frost::VerifyingKey,
    members: [ProjectivePoint; 2],
    sighash: [u8; 32],
    operators: OperatorCommitments,
    users: [&[u8]; 2],
    partials: [&[u8]; 2],
) -> Result<()> {
    type Suite = frost::Secp256K1Sha256TR;
    let transcript = package(sighash, operators, users)?;
    let output = native_output.into_even_y(None);
    let mut total = ProjectivePoint::IDENTITY;
    let mut user_nonces = BTreeMap::new();
    for ((group, id), preimage) in transcript.binding_factor_preimages(&output)? {
        let commitment = &transcript.signing_commitments(group)[&id];
        let hiding = canonical_point(&commitment.hiding().serialize()?)?;
        let binding = canonical_point(&commitment.binding().serialize()?)?;
        let nonce = hiding + binding * Suite::H1(&preimage);
        total += nonce;
        if group == SignerGroup::Secondary {
            user_nonces.insert(id, nonce);
        }
    }
    ensure!(
        total != ProjectivePoint::IDENTITY,
        "native group nonce is identity"
    );
    let encoded = total.to_affine().to_encoded_point(true);
    let nonce_odd = encoded.as_bytes()[0] == 3;
    let mut challenge = Vec::with_capacity(96);
    challenge.extend_from_slice(&encoded.as_bytes()[1..]);
    challenge.extend_from_slice(&output.serialize()?[1..]);
    challenge.extend_from_slice(&sighash);
    let challenge = Suite::H2(&challenge);
    for ((position, mut public), bytes) in (1u16..=2).zip(members).zip(partials) {
        let raw: [u8; 32] = bytes.try_into()?;
        let scalar = Option::<Scalar>::from(Scalar::from_repr(raw.into()))
            .ok_or_else(|| anyhow::anyhow!("noncanonical USER signature share"))?;
        if !combined.has_even_y() {
            public = -public;
        }
        if !native_output.has_even_y() {
            public = -public;
        }
        let mut nonce = user_nonces[&frost::Identifier::try_from(position)?];
        if nonce_odd {
            nonce = -nonce;
        }
        ensure!(
            ProjectivePoint::GENERATOR * scalar == nonce + public * challenge,
            "invalid native USER signature contribution at position {position}"
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "leaf_signing_tests.rs"]
mod tests;
