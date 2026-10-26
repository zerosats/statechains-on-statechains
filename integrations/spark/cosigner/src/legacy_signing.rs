//! Collapse independent additive signers into Spark's legacy singleton USER.
//!
//! The legacy claim RPC accepts one user nonce pair and one signature share.
//! Both parties commit to their nonce pairs before either reveals. Their public
//! commitments are summed, and both use the SAME legacy binding factor and
//! challenge. This differs from Spark's tagged nested MPC scheme.
//!
//! These ephemeral primitives have no RPC endpoints or nonce persistence. The
//! caller must authorize each exact refund transaction and sighash. One session
//! is one refund variant; never reuse it for a second transaction or variant.
use crate::{
    keys::Share,
    leaf_signing::{LeafAuthority, OperatorCommitments},
};
use anyhow::{Context, Result, ensure};
use frost_core::Ciphersuite;
use frost_secp256k1_tr::{self as frost, keys::EvenY};
use k256::{
    ProjectivePoint, Scalar,
    elliptic_curve::{PrimeField, sec1::ToEncodedPoint},
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;
type Suite = frost::Secp256K1Sha256TR;

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub operation: [u8; 32],
    pub sighash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commitment {
    pub position: u16,
    pub digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reveal {
    pub position: u16,
    pub salt: [u8; 32],
    pub nonce_commitment: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contribution {
    pub position: u16,
    pub transcript: [u8; 32],
    pub response: [u8; 32],
}

/// Public wire artifacts for the ordinary USER fields in Spark's claim path.
pub struct UserContribution {
    pub nonce_commitment: Vec<u8>,
    pub signature_share: Vec<u8>,
}

pub struct Nonce {
    authority_binding: [u8; 32],
    session_binding: [u8; 32],
    inner: frost::round1::SigningNonces,
    reveal: Reveal,
    commitment: Commitment,
}

impl Nonce {
    pub fn prepare(share: &Share, authority: &LeafAuthority, session: Session) -> Result<Self> {
        let binding = session_binding(authority, session)?;
        let key = authority.participant_package(share)?;
        let (inner, nonce_commitment) = frost::round1::commit(key.signing_share(), &mut OsRng);
        let mut salt = [0; 32];
        OsRng.fill_bytes(&mut salt);
        let reveal = Reveal {
            position: share.public().position,
            salt,
            nonce_commitment: nonce_commitment.serialize()?,
        };
        let commitment = Commitment {
            position: reveal.position,
            digest: reveal_hash(binding, &reveal),
        };
        Ok(Self {
            authority_binding: authority.binding()?,
            session_binding: binding,
            inner,
            reveal,
            commitment,
        })
    }

    pub fn commitment(&self) -> &Commitment {
        &self.commitment
    }

    /// Consume before validation so any failed reveal permanently burns nonce.
    pub fn reveal(self, commitments: [Commitment; 2]) -> Result<RevealedNonce> {
        check_roles(&commitments)?;
        ensure!(
            commitments[usize::from(self.reveal.position - 1)] == self.commitment,
            "coordinator replaced our legacy nonce hash"
        );
        Ok(RevealedNonce {
            nonce: self,
            commitments,
        })
    }
}

pub struct RevealedNonce {
    nonce: Nonce,
    commitments: [Commitment; 2],
}

impl RevealedNonce {
    pub fn public(&self) -> &Reveal {
        &self.nonce.reveal
    }

    /// Consuming self also burns nonces when any transcript validation fails.
    pub fn sign(
        self,
        share: &Share,
        authority: &LeafAuthority,
        transcript: &Transcript,
    ) -> Result<Contribution> {
        ensure!(
            self.nonce.authority_binding == authority.binding()?
                && self.nonce.session_binding == transcript.session_binding
                && self.commitments == transcript.commitments,
            "legacy nonce authority/session mismatch"
        );
        let position = share.public().position;
        ensure!(
            position == self.nonce.reveal.position
                && transcript.reveals[usize::from(position - 1)] == self.nonce.reveal,
            "coordinator replaced our legacy nonce reveal"
        );
        let secret = Zeroizing::new(share.additive_scalar(authority.user_authority())?);
        let hiding = Zeroizing::new(self.nonce.inner.hiding().serialize());
        let binding = Zeroizing::new(self.nonce.inner.binding().serialize());
        let mut nonce_scalar =
            Zeroizing::new(scalar(&hiding)? + transcript.user_factor * scalar(&binding)?);
        if transcript.negate_nonce {
            *nonce_scalar = -*nonce_scalar;
        }
        let effective_secret = Zeroizing::new(if transcript.negate_key {
            -*secret
        } else {
            *secret
        });
        let response = Zeroizing::new(*nonce_scalar + transcript.challenge * *effective_secret);
        let contribution = Contribution {
            position,
            transcript: transcript.digest,
            response: response.to_bytes().into(),
        };
        transcript.verify_contribution(authority, &contribution)?;
        Ok(contribution)
    }
}

/// Immutable exact legacy transcript plus the individual nonce decompositions.
pub struct Transcript {
    authority_binding: [u8; 32],
    session_binding: [u8; 32],
    commitments: [Commitment; 2],
    reveals: [Reveal; 2],
    digest: [u8; 32],
    aggregate: frost::round1::SigningCommitments,
    package: frost::SigningPackage,
    user_factor: Scalar,
    challenge: Scalar,
    negate_nonce: bool,
    negate_key: bool,
}

impl Transcript {
    pub fn new(
        authority: &LeafAuthority,
        session: Session,
        commitments: [Commitment; 2],
        reveals: [Reveal; 2],
        mut operators: OperatorCommitments,
    ) -> Result<Self> {
        let binding = session_binding(authority, session)?;
        let aggregate = aggregate_nonce(binding, &commitments, &reveals)?;
        ensure!(!operators.is_empty(), "empty legacy operator group");
        let user_id = frost::Identifier::derive(b"user")?;
        ensure!(
            !operators.contains_key(&user_id),
            "operator collides with legacy user identifier"
        );
        let groups = vec![
            operators.keys().copied().collect::<BTreeSet<_>>(),
            BTreeSet::from([user_id]),
        ];
        operators.insert(user_id, aggregate);
        let package = frost::SigningPackage::new_with_participants_groups(
            operators,
            Some(groups),
            &session.sighash,
        );
        let output = frost::VerifyingKey::deserialize(&authority.output_key()?)?.into_even_y(None);
        let mut factors = BTreeMap::new();
        let mut group_nonce = ProjectivePoint::IDENTITY;
        for (id, preimage) in package.binding_factor_preimages(&output, &[])? {
            let factor = Suite::H1(&preimage);
            let commitment = package
                .signing_commitments()
                .get(&id)
                .context("missing legacy commitment")?;
            let (hiding, binding) = commitment_points(commitment)?;
            group_nonce += hiding + binding * factor;
            factors.insert(id, factor);
        }
        ensure!(
            group_nonce != ProjectivePoint::IDENTITY,
            "legacy group nonce at infinity"
        );
        let encoded_nonce = group_nonce.to_affine().to_encoded_point(true);
        let mut challenge_bytes = Vec::with_capacity(96);
        challenge_bytes.extend_from_slice(&encoded_nonce.as_bytes()[1..]);
        challenge_bytes.extend_from_slice(&output.serialize()?[1..]);
        challenge_bytes.extend_from_slice(&session.sighash);
        let challenge = Suite::H2(&challenge_bytes);
        let mut digest = Sha256::new();
        digest.update(b"ZARK/spark/regtest/legacy-user/transcript/v1");
        digest.update(binding);
        digest.update(package.serialize()?);
        for reveal in &reveals {
            digest.update(reveal_hash(binding, reveal));
        }
        Ok(Self {
            authority_binding: authority.binding()?,
            session_binding: binding,
            commitments,
            reveals,
            digest: digest.finalize().into(),
            aggregate,
            package,
            user_factor: factors[&user_id],
            challenge,
            negate_nonce: encoded_nonce.as_bytes()[0] == 3,
            negate_key: (authority.combined_key()?[0] == 3) != (authority.output_key()?[0] == 3),
        })
    }

    fn verify_contribution(
        &self,
        authority: &LeafAuthority,
        contribution: &Contribution,
    ) -> Result<()> {
        ensure!(
            self.authority_binding == authority.binding()?
                && (1..=2).contains(&contribution.position)
                && contribution.transcript == self.digest,
            "legacy contribution participant/transcript mismatch"
        );
        let index = usize::from(contribution.position - 1);
        let member = &authority.user_authority().members()[index];
        let mut public = point(&hex::decode(&member.public_key)?)?;
        if self.negate_key {
            public = -public;
        }
        let commitment =
            frost::round1::SigningCommitments::deserialize(&self.reveals[index].nonce_commitment)?;
        let (hiding, binding) = commitment_points(&commitment)?;
        let mut nonce_point = hiding + binding * self.user_factor;
        if self.negate_nonce {
            nonce_point = -nonce_point;
        }
        ensure!(
            ProjectivePoint::GENERATOR * scalar(&contribution.response)?
                == nonce_point + public * self.challenge,
            "invalid additive legacy USER contribution"
        );
        Ok(())
    }

    /// Exact ordinary Spark package for combining with operator contributions.
    pub fn signing_package(&self) -> &frost::SigningPackage {
        &self.package
    }

    pub fn aggregate(
        &self,
        authority: &LeafAuthority,
        contributions: [&Contribution; 2],
    ) -> Result<UserContribution> {
        ensure!(
            contributions[0].position == 1 && contributions[1].position == 2,
            "legacy contribution role order"
        );
        for contribution in contributions {
            self.verify_contribution(authority, contribution)?;
        }
        let response = scalar(&contributions[0].response)? + scalar(&contributions[1].response)?;
        Ok(UserContribution {
            nonce_commitment: self.aggregate.serialize()?,
            signature_share: response.to_bytes().to_vec(),
        })
    }
}

/// Call after both reveals are checked, before sending the legacy claim job.
pub fn aggregate_commitment(
    authority: &LeafAuthority,
    session: Session,
    commitments: &[Commitment; 2],
    reveals: &[Reveal; 2],
) -> Result<Vec<u8>> {
    Ok(aggregate_nonce(session_binding(authority, session)?, commitments, reveals)?.serialize()?)
}

fn session_binding(authority: &LeafAuthority, session: Session) -> Result<[u8; 32]> {
    ensure!(
        session.operation != [0; 32],
        "empty legacy signing operation"
    );
    let mut hash = Sha256::new();
    hash.update(b"ZARK/spark/regtest/legacy-user/session/v1");
    hash.update(authority.binding()?);
    hash.update(session.operation);
    hash.update(session.sighash);
    Ok(hash.finalize().into())
}

fn reveal_hash(binding: [u8; 32], reveal: &Reveal) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"ZARK/spark/regtest/legacy-user/nonce-commit/v1");
    hash.update(binding);
    hash.update(reveal.position.to_be_bytes());
    hash.update(reveal.salt);
    hash.update((reveal.nonce_commitment.len() as u64).to_be_bytes());
    hash.update(&reveal.nonce_commitment);
    hash.finalize().into()
}

fn check_roles(commitments: &[Commitment; 2]) -> Result<()> {
    ensure!(
        commitments[0].position == 1
            && commitments[1].position == 2
            && commitments
                .iter()
                .all(|commitment| commitment.digest != [0; 32]),
        "legacy nonce commitment role order"
    );
    Ok(())
}

fn aggregate_nonce(
    binding: [u8; 32],
    commitments: &[Commitment; 2],
    reveals: &[Reveal; 2],
) -> Result<frost::round1::SigningCommitments> {
    check_roles(commitments)?;
    let mut hiding = ProjectivePoint::IDENTITY;
    let mut binding_point = ProjectivePoint::IDENTITY;
    for (position, (commitment, reveal)) in (1u16..=2).zip(commitments.iter().zip(reveals)) {
        ensure!(
            reveal.position == position && commitment.digest == reveal_hash(binding, reveal),
            "legacy nonce reveal mismatch"
        );
        let parsed = frost::round1::SigningCommitments::deserialize(&reveal.nonce_commitment)?;
        ensure!(
            parsed.serialize()? == reveal.nonce_commitment,
            "noncanonical legacy nonce commitment"
        );
        let (d, e) = commitment_points(&parsed)?;
        hiding += d;
        binding_point += e;
    }
    ensure!(
        hiding != ProjectivePoint::IDENTITY && binding_point != ProjectivePoint::IDENTITY,
        "aggregate legacy nonce cancellation"
    );
    Ok(frost::round1::SigningCommitments::new(
        frost_core::round1::NonceCommitment::deserialize(
            hiding.to_affine().to_encoded_point(true).as_bytes(),
        )?,
        frost_core::round1::NonceCommitment::deserialize(
            binding_point.to_affine().to_encoded_point(true).as_bytes(),
        )?,
    ))
}

fn commitment_points(
    commitment: &frost::round1::SigningCommitments,
) -> Result<(ProjectivePoint, ProjectivePoint)> {
    Ok((
        point(&commitment.hiding().serialize()?)?,
        point(&commitment.binding().serialize()?)?,
    ))
}

fn point(bytes: &[u8]) -> Result<ProjectivePoint> {
    ensure!(bytes.len() == 33, "invalid legacy commitment point");
    Ok(k256::PublicKey::from_sec1_bytes(bytes)?.to_projective())
}

fn scalar(bytes: &[u8]) -> Result<Scalar> {
    let bytes: [u8; 32] = bytes.try_into().context("invalid legacy scalar length")?;
    Option::<Scalar>::from(Scalar::from_repr(bytes.into())).context("noncanonical legacy scalar")
}

#[cfg(test)]
#[path = "legacy_signing_tests.rs"]
pub(crate) mod tests;

#[path = "legacy_signing_codec.rs"]
mod private_codec;
