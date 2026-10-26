//! Independent additive shares, authenticated before forming a Spark authority.
use anyhow::{Context, Result, ensure};
use frost_secp256k1_tr::{self as frost, keys::EvenY};
use k256::{
    ProjectivePoint, Scalar,
    elliptic_curve::{PrimeField, sec1::ToEncodedPoint},
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum Purpose {
    Identity = 0,
    LeafSigning = 1,
    Recovery = 2,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub deployment: [u8; 32],
    pub coin: [u8; 32],
    pub purpose: Purpose,
}

impl Scope {
    fn check(&self) -> Result<()> {
        ensure!(
            self.deployment != [0; 32] && self.coin != [0; 32],
            "empty shared-key domain"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicShare {
    pub scope: Scope,
    /// Fixed identities: wallet = 1, Zark signer = 2. Neither is an operator ID.
    pub position: u16,
    pub public_key: String,
    pub proof_of_possession: String,
}

impl PublicShare {
    fn possession_message(&self) -> Result<[u8; 32]> {
        self.scope.check()?;
        ensure!(
            (1..=2).contains(&self.position),
            "invalid shared-key participant"
        );
        let key = hex::decode(&self.public_key)?;
        ensure!(
            key.len() == 33 && hex::encode(&key) == self.public_key,
            "noncanonical shared public key"
        );
        let mut hash = Sha256::new();
        hash.update(b"ZARK/spark/regtest/key-possession/v1");
        hash.update(self.scope.deployment);
        hash.update(self.scope.coin);
        hash.update([self.scope.purpose as u8]);
        hash.update(self.position.to_be_bytes());
        hash.update(key);
        Ok(hash.finalize().into())
    }

    pub fn verify(&self) -> Result<()> {
        let message = self.possession_message()?;
        let key = frost::VerifyingKey::deserialize(&hex::decode(&self.public_key)?)?;
        let bytes = hex::decode(&self.proof_of_possession)?;
        ensure!(
            hex::encode(&bytes) == self.proof_of_possession,
            "noncanonical possession proof"
        );
        let proof = frost::Signature::deserialize(&bytes)?;
        key.verify(&message, &proof)
            .context("shared-key possession proof")
    }

    fn point(&self) -> Result<ProjectivePoint> {
        Ok(k256::PublicKey::from_sec1_bytes(&hex::decode(&self.public_key)?)?.to_projective())
    }
}

/// Holds only this participant's additive scalar. No Debug/Clone/Serialize.
pub struct Share {
    secret: Zeroizing<[u8; 32]>,
    public: PublicShare,
}

impl Share {
    pub fn generate(scope: Scope, position: u16) -> Result<Self> {
        scope.check()?;
        ensure!(
            (1..=2).contains(&position),
            "invalid shared-key participant"
        );
        let key = frost::SigningKey::new(&mut OsRng);
        let encoded = Zeroizing::new(key.serialize());
        let secret = Zeroizing::new(
            encoded
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("FROST scalar length"))?,
        );
        let mut public = PublicShare {
            scope,
            position,
            public_key: hex::encode(frost::VerifyingKey::from(&key).serialize()?),
            proof_of_possession: String::new(),
        };
        public.proof_of_possession =
            hex::encode(key.sign(OsRng, &public.possession_message()?).serialize()?);
        public.verify()?;
        Ok(Self { secret, public })
    }

    pub fn public(&self) -> &PublicShare {
        &self.public
    }

    /// Builds a share from a known scalar for synthetic test signatures.
    #[cfg(test)]
    pub(crate) fn from_scalar(scope: Scope, position: u16, secret: &[u8; 32]) -> Result<Self> {
        scope.check()?;
        ensure!(
            (1..=2).contains(&position),
            "invalid shared-key participant"
        );
        let scalar = Zeroizing::new(
            Option::<Scalar>::from(Scalar::from_repr((*secret).into()))
                .context("noncanonical private share scalar")?,
        );
        ensure!(*scalar != Scalar::ZERO, "zero private share scalar");
        let key = frost::SigningKey::from_scalar(*scalar)?;
        let mut public = PublicShare {
            scope,
            position,
            public_key: hex::encode(frost::VerifyingKey::from(&key).serialize()?),
            proof_of_possession: String::new(),
        };
        public.proof_of_possession =
            hex::encode(key.sign(OsRng, &public.possession_message()?).serialize()?);
        public.verify()?;
        Ok(Self {
            secret: Zeroizing::new(*secret),
            public,
        })
    }

    pub(crate) fn additive_scalar(&self, authority: &Authority) -> Result<Scalar> {
        authority.public_package()?;
        ensure!(
            authority.members[usize::from(self.public.position - 1)] == self.public,
            "share does not belong to this Spark authority"
        );
        Option::<Scalar>::from(Scalar::from_repr((*self.secret).into()))
            .context("invalid private share")
    }

    #[cfg(test)]
    pub(crate) fn package(&self, authority: &Authority) -> Result<frost::keys::KeyPackage> {
        ensure!(
            authority.members[usize::from(self.public.position - 1)] == self.public,
            "share does not belong to this Spark authority"
        );
        // Spark's MPC endpoint expects Shamir shares. At positions 1 and 2 the
        // Lagrange coefficients are 2 and -1, so encode additive shares as a/2
        // and -b. Each party does this locally; nobody reconstructs a+b.
        let mut scalar = Option::<Scalar>::from(Scalar::from_repr((*self.secret).into()))
            .context("invalid private share")?;
        scalar *= weight(self.public.position);
        let signing = frost::keys::SigningShare::deserialize(&scalar.to_bytes())?;
        zeroize::Zeroize::zeroize(&mut scalar);
        let public = authority.public_package()?;
        let identifier = frost::Identifier::try_from(self.public.position)?;
        let verifying = *public
            .verifying_shares()
            .get(&identifier)
            .context("missing public share")?;
        // PublicKeyPackage is normalized; apply the same sign to the secret.
        let raw_group = authority.group_point()?;
        let even = raw_group.to_affine().to_encoded_point(true).as_bytes()[0] == 2;
        let signing = if even {
            signing
        } else {
            frost::keys::SigningShare::new(-signing.to_scalar())
        };
        Ok(frost::keys::KeyPackage::new(
            identifier,
            signing,
            verifying,
            *public.verifying_key(),
            2,
        ))
    }
}

fn weight(position: u16) -> Scalar {
    match position {
        1 => Scalar::from(2u64).invert().unwrap(),
        2 => -Scalar::ONE,
        _ => unreachable!("participant position validated before conversion"),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    members: [PublicShare; 2],
}

impl Authority {
    pub(crate) fn members(&self) -> &[PublicShare; 2] {
        &self.members
    }

    pub fn new(wallet: PublicShare, signer: PublicShare) -> Result<Self> {
        ensure!(
            wallet.position == 1 && signer.position == 2,
            "shared-key role order"
        );
        wallet.verify()?;
        signer.verify()?;
        ensure!(wallet.scope == signer.scope, "shared-key domains differ");
        let authority = Self {
            members: [wallet, signer],
        };
        authority.public_package()?;
        Ok(authority)
    }

    pub fn public_key(&self) -> Result<Vec<u8>> {
        // Keep the original SEC1 parity for Spark identity/ECIES compatibility.
        Ok(self
            .group_point()?
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec())
    }

    fn group_point(&self) -> Result<ProjectivePoint> {
        let point = self.members[0].point()? + self.members[1].point()?;
        ensure!(
            point != ProjectivePoint::IDENTITY,
            "shared authority at infinity"
        );
        Ok(point)
    }

    pub(crate) fn public_package(&self) -> Result<frost::keys::PublicKeyPackage> {
        // Revalidate after deserialization instead of trusting constructor use.
        ensure!(
            self.members[0].position == 1 && self.members[1].position == 2,
            "shared-key role order"
        );
        ensure!(
            self.members[0].scope == self.members[1].scope,
            "shared-key domains differ"
        );
        let mut shares = BTreeMap::new();
        for member in &self.members {
            member.verify()?;
            let point = member.point()? * weight(member.position);
            shares.insert(
                frost::Identifier::try_from(member.position)?,
                frost::keys::VerifyingShare::deserialize(
                    point.to_affine().to_encoded_point(true).as_bytes(),
                )?,
            );
        }
        let key = frost::VerifyingKey::deserialize(&self.public_key()?)?;
        Ok(frost::keys::PublicKeyPackage::new(shares, key, Some(2)).into_even_y(None))
    }
}
