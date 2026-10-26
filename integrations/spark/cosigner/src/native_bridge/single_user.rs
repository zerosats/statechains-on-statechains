//! Wallet-side composition of user + blind Zark into Spark's ordinary USER.
//!
//! Spark receives one commitment pair and one partial, with its usual `user`
//! identifier and binding factors. No MPC-user-group fields are involved.
//! This arithmetic adapter is deliberately not an issuance endpoint: the
//! existing two-subparticipant native proofs do NOT authorize this transcript.
//! `SingleUserJournal` (or `ReceiveJournal` for a fresh ordinary claim) binds
//! the appropriate separate proof relation and durably freezes
//! the opening before nonce release. No old native/recovery slot is repurposed.
use super::CurrentUserKey;
use crate::leaf_signing::OperatorCommitments;
use anyhow::{Result, ensure};
use frost_core::Ciphersuite;
use frost_secp256k1_tr::{self as frost, keys::EvenY};
use k256::{ProjectivePoint, Scalar};
use std::collections::BTreeSet;
use zark_protocol::{
    handoff::Digest, hash, point, point_bytes, random_scalar, random32, reduce, scalar, tagged_hash,
};
use zeroize::Zeroizing;

type Suite = frost::Secp256K1Sha256TR;

/// Private blinding opening, frozen before receiving the original signer nonce.
/// Non-cloneable and non-serializable; this chunk provides no durable journal.
pub struct SingleUserPrecommit {
    key: Digest,
    commitment: Digest,
    alpha: Zeroizing<Scalar>,
    beta: Zeroizing<Scalar>,
    binding: Zeroizing<Scalar>,
}

impl SingleUserPrecommit {
    pub(crate) fn from_opening(
        key: &CurrentUserKey,
        context: &zark_protocol::spark_native::ExitContext,
        plan: &Digest,
        opening: &zark_protocol::spark_single_user::Opening,
    ) -> Result<Self> {
        ensure!(
            context.deployment == key.native_keys().scope().deployment
                && context.coin == key.native_keys().scope().coin,
            "single-USER opening key scope differs"
        );
        Ok(Self {
            key: key.binding(),
            commitment: opening.commitment(context, plan, &key.server_point()?)?,
            alpha: Zeroizing::new(scalar(&opening.alpha)?),
            beta: Zeroizing::new(scalar(&opening.beta)?),
            binding: Zeroizing::new(scalar(&opening.binding)?),
        })
    }
    pub fn new(key: &CurrentUserKey, context: Digest) -> Result<Self> {
        ensure!(context != [0; 32], "empty single-USER context");
        let alpha = Zeroizing::new(random_scalar());
        let beta = Zeroizing::new(random_scalar());
        let binding = Zeroizing::new(random_scalar());
        let salt = Zeroizing::new(random32());
        let commitment = hash(&[
            b"ZARK/spark/single-user-wallet/v1",
            &key.binding(),
            &context,
            &alpha.to_bytes(),
            &beta.to_bytes(),
            &binding.to_bytes(),
            &*salt,
        ]);
        Ok(Self {
            key: key.binding(),
            commitment,
            alpha,
            beta,
            binding,
        })
    }

    pub fn commitment(&self) -> Digest {
        self.commitment
    }

    pub fn attach(self, key: &CurrentUserKey, server_nonce: &[u8; 64]) -> Result<SingleUserNonce> {
        ensure!(
            self.key == key.binding(),
            "single-USER key changed before nonce attachment"
        );
        let original = point(server_nonce)?;
        let hiding = original
            + ProjectivePoint::GENERATOR * *self.alpha
            + point(&key.server_point()?)? * *self.beta;
        let public = frost::round1::SigningCommitments::new(
            frost::round1::NonceCommitment::deserialize(&compressed(hiding)?)?,
            frost::round1::NonceCommitment::deserialize(&compressed(
                ProjectivePoint::GENERATOR * *self.binding,
            )?)?,
        );
        Ok(SingleUserNonce {
            opening: self,
            original,
            public,
        })
    }
}

pub struct SingleUserNonce {
    opening: SingleUserPrecommit,
    original: ProjectivePoint,
    public: frost::round1::SigningCommitments,
}

impl SingleUserNonce {
    /// The sole USER commitment pair sent to ordinary Spark signing.
    pub fn commitment(&self) -> frost::round1::SigningCommitments {
        self.public
    }

    /// Consumes the nonce even on error. The full native transcript stays here;
    /// only the opaque precommit and blinded challenge belong at the signer.
    pub fn bind(
        self,
        key: &CurrentUserKey,
        sighash: Digest,
        operators: OperatorCommitments,
    ) -> Result<SingleUserRequest> {
        ensure!(
            self.opening.key == key.binding(),
            "single-USER nonce key changed"
        );
        let package = signing_package(sighash, operators, self.public)?;
        // Match ordinary Spark pre_sign: first normalize the untweaked combined
        // key, then normalize its TapTweaked output. The operators carry the
        // tweak scalar; USER contributes only its parity-adjusted original key.
        let combined = frost::VerifyingKey::deserialize(key.native_keys().combined_key())?;
        let output = frost::VerifyingKey::deserialize(&key.output_key()?)?;
        let coefficient = sign(combined.has_even_y()) * sign(output.has_even_y());
        let output = output.into_even_y(None);
        let user = user_identifier()?;
        let mut total = ProjectivePoint::IDENTITY;
        let mut user_rho = None;
        let mut user_nonce = ProjectivePoint::IDENTITY;
        for (id, preimage) in package.binding_factor_preimages(&output, &[])? {
            let rho = Suite::H1(&preimage);
            let commitment = &package.signing_commitments()[&id];
            let nonce = k256::PublicKey::from_sec1_bytes(&commitment.hiding().serialize()?)?
                .to_projective()
                + k256::PublicKey::from_sec1_bytes(&commitment.binding().serialize()?)?
                    .to_projective()
                    * rho;
            if id == user {
                user_rho = Some(rho);
                user_nonce = nonce;
            }
            total += nonce;
        }
        let (even_nonce, nonce_sign) = zark_protocol::even(total)?;
        let challenge = reduce(tagged_hash(
            "BIP0340/challenge",
            &[
                &point_bytes(even_nonce)?[..32],
                &output.serialize()?[1..],
                &sighash,
            ],
        ));
        let rho = user_rho.ok_or_else(|| anyhow::anyhow!("single-USER binding factor missing"))?;
        let server = point(&key.server_point()?)?;
        let expected = user_nonce * nonce_sign
            + k256::PublicKey::from_sec1_bytes(key.native_keys().user_key())?.to_projective()
                * (challenge * coefficient);
        let blinded = *self.opening.beta + nonce_sign * challenge * coefficient;
        let wallet_term = Zeroizing::new(
            nonce_sign * (*self.opening.alpha + rho * *self.opening.binding)
                + challenge * coefficient * key.wallet_scalar(),
        );
        Ok(SingleUserRequest {
            commitment: self.public,
            precommit: self.opening.commitment,
            original: self.original,
            server,
            blinded: blinded.to_bytes().into(),
            nonce_sign,
            wallet_term,
            expected,
        })
    }
}

/// Private wallet completion state. The signer receives neither this object
/// nor the aggregate USER/leaf keys, operator commitments, or sighash.
pub struct SingleUserRequest {
    commitment: frost::round1::SigningCommitments,
    precommit: Digest,
    original: ProjectivePoint,
    server: ProjectivePoint,
    blinded: Digest,
    nonce_sign: Scalar,
    wallet_term: Zeroizing<Scalar>,
    expected: ProjectivePoint,
}

impl SingleUserRequest {
    pub fn blinding_commitment(&self) -> Digest {
        self.precommit
    }
    pub fn blinded_challenge(&self) -> Digest {
        self.blinded
    }

    pub fn complete(self, original_response: Digest) -> Result<SingleUserContribution> {
        let response = Zeroizing::new(scalar(&original_response)?);
        ensure!(
            ProjectivePoint::GENERATOR * *response
                == self.original + self.server * scalar(&self.blinded)?,
            "invalid original single-USER blind response"
        );
        let partial = Zeroizing::new(self.nonce_sign * *response + *self.wallet_term);
        ensure!(
            ProjectivePoint::GENERATOR * *partial == self.expected,
            "invalid composed single-USER partial"
        );
        Ok(SingleUserContribution {
            commitment: self.commitment,
            signature_share: frost::round2::SignatureShare::deserialize(&partial.to_bytes())?,
        })
    }
}

/// Exactly the public USER fields expected by Spark's normal signing path.
pub struct SingleUserContribution {
    pub commitment: frost::round1::SigningCommitments,
    pub signature_share: frost::round2::SignatureShare,
}

fn user_identifier() -> Result<frost::Identifier> {
    Ok(frost::Identifier::derive(b"user")?)
}

fn signing_package(
    sighash: Digest,
    mut operators: OperatorCommitments,
    user: frost::round1::SigningCommitments,
) -> Result<frost::SigningPackage> {
    let id = user_identifier()?;
    ensure!(
        !operators.is_empty(),
        "single-USER requires operator commitments"
    );
    ensure!(
        !operators.contains_key(&id),
        "operator identifier collides with USER"
    );
    let groups = vec![operators.keys().copied().collect(), BTreeSet::from([id])];
    operators.insert(id, user);
    Ok(frost::SigningPackage::new_with_participants_groups(
        operators,
        Some(groups),
        &sighash,
    ))
}

fn sign(even: bool) -> Scalar {
    if even { Scalar::ONE } else { -Scalar::ONE }
}

fn compressed(point: ProjectivePoint) -> Result<Vec<u8>> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    point_bytes(point)?; // Reject infinity before encoding a native commitment.
    Ok(point.to_affine().to_encoded_point(true).as_bytes().to_vec())
}

#[cfg(test)]
mod tests;
