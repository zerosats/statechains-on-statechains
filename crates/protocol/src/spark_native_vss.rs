//! Opaque, purpose-specific native resharing material. No UUID, amount, native
//! outpoint, recipient or unsalted plan hash is an input to share generation.
//!
//! This primitive is not an ownership/proof gate. A signer must verify the real
//! native authorization first, generate role two internally from its current
//! share, and durably save the exact ciphertext response before releasing it.
//! A threshold coalition decrypting its separate server evaluations can recover
//! that polynomial's constant; this construction does not hide it from them.
use crate::{hash, random_scalar, scalar, spark_ecies};
use anyhow::{Result, ensure};
use k256::{ProjectivePoint, Scalar, elliptic_curve::sec1::ToEncodedPoint};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

pub type Digest = [u8; 32];
pub const PAYLOAD_MAGIC: &[u8] = b"ZARK-NATIVE-VSS-v1\0";
pub const PAYLOAD_BYTES: usize = PAYLOAD_MAGIC.len() + 130;
pub const CIPHER_BYTES: usize = 97 + PAYLOAD_BYTES;

mod packet;
pub use packet::{OpaqueVssPacket, PACKET_MAGIC};

/// Load only from trusted deployment configuration. Neither a wallet request
/// nor a native packet may select alternate share recipients or a threshold.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cluster {
    pub threshold: usize,
    pub operators: BTreeMap<String, Vec<u8>>,
}

impl Cluster {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.threshold == 2 && (2..=16).contains(&self.operators.len()),
            "native root profile requires a pinned threshold-two cluster"
        );
        let mut seen = BTreeSet::new();
        for (id, key) in &self.operators {
            operator_identifier(id)?;
            canonical_point(key)?;
            ensure!(
                seen.insert(key),
                "duplicate native operator encryption identity"
            );
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<Digest> {
        self.validate()?;
        let mut bytes = b"ZARK/spark/native/cluster/v1".to_vec();
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&(self.operators.len() as u16).to_le_bytes());
        for (id, key) in &self.operators {
            bytes.extend_from_slice(&operator_identifier(id)?);
            bytes.extend_from_slice(key);
        }
        Ok(hash(&[&bytes]))
    }
}

/// Confidential holder-to-wallet response. Individual coefficient vectors
/// must be combined before constructing an operator packet; publishing role
/// two's constant commitment discloses the current server public point.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpaqueContribution {
    pub position: u16,
    pub plan: Digest,
    pub cluster: Digest,
    pub coefficient_commitments: Vec<Vec<u8>>,
    pub sealed_shares: BTreeMap<String, Vec<u8>>,
}

impl OpaqueContribution {
    pub fn validate(
        &self,
        cluster: &Cluster,
        plan: &Digest,
        expected_constant: &[u8],
    ) -> Result<()> {
        ensure!(
            (1..=2).contains(&self.position)
                && *plan != [0; 32]
                && self.plan == *plan
                && self.cluster == cluster.digest()?,
            "opaque native VSS domain differs"
        );
        ensure!(
            self.coefficient_commitments.len() == 2
                && self.sealed_shares.keys().eq(cluster.operators.keys()),
            "opaque native VSS coverage differs"
        );
        ensure!(
            canonical_point(&self.coefficient_commitments[0])?
                == canonical_point(expected_constant)?,
            "opaque native VSS constant differs"
        );
        for point in &self.coefficient_commitments {
            canonical_point(point)?;
        }
        for cipher in self.sealed_shares.values() {
            validate_cipher(cipher)?;
        }
        Ok(())
    }
}

/// Role one uses `(wallet_u - temporary_mask)/2`; role two uses `-server_s`.
/// The native operator combines evaluations with Lagrange weights 2 and -1.
/// Only the holder invokes this function; there is no scalar import endpoint.
pub fn prepare(
    position: u16,
    constant: Digest,
    plan: Digest,
    cluster: &Cluster,
) -> Result<OpaqueContribution> {
    ensure!(
        (1..=2).contains(&position) && plan != [0; 32],
        "opaque native VSS purpose"
    );
    let constant = Zeroizing::new(constant);
    let constant = Zeroizing::new(scalar(&constant[..])?);
    ensure!(*constant != Scalar::ZERO, "degenerate native VSS constant");
    let digest = cluster.digest()?;
    let slope = Zeroizing::new(loop {
        let slope = random_scalar();
        if cluster.operators.keys().all(|id| {
            let x = scalar(&operator_identifier(id).expect("validated native cluster"))
                .expect("validated native identifier");
            *constant + slope * x != Scalar::ZERO
        }) {
            break slope;
        }
    });
    let coefficient_commitments = [*constant, *slope]
        .into_iter()
        .map(|value| compressed(ProjectivePoint::GENERATOR * value))
        .collect::<Result<Vec<_>>>()?;
    let mut sealed_shares = BTreeMap::new();
    for (id, key) in &cluster.operators {
        let id_bytes = operator_identifier(id)?;
        let value = Zeroizing::new(*constant + *slope * scalar(&id_bytes)?);
        let payload = sealed_payload(plan, digest, id_bytes, position, &value);
        sealed_shares.insert(id.clone(), spark_ecies::encrypt(key, &payload)?);
    }
    Ok(OpaqueContribution {
        position,
        plan,
        cluster: digest,
        coefficient_commitments,
        sealed_shares,
    })
}

fn sealed_payload(
    plan: Digest,
    cluster: Digest,
    operator: Digest,
    position: u16,
    value: &Scalar,
) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(PAYLOAD_BYTES));
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&plan);
    out.extend_from_slice(&cluster);
    out.extend_from_slice(&operator);
    out.extend_from_slice(&position.to_le_bytes());
    out.extend_from_slice(&value.to_bytes());
    out
}

pub(crate) fn validate_cipher(cipher: &[u8]) -> Result<()> {
    ensure!(
        cipher.len() == CIPHER_BYTES && cipher[0] == 4,
        "opaque native ciphertext size"
    );
    let ephemeral = k256::PublicKey::from_sec1_bytes(&cipher[..65])?;
    ensure!(
        ephemeral.to_encoded_point(false).as_bytes() == &cipher[..65],
        "noncanonical native ECIES ephemeral"
    );
    Ok(())
}
pub(crate) fn canonical_point(bytes: &[u8]) -> Result<ProjectivePoint> {
    ensure!(bytes.len() == 33, "native VSS point length");
    let point = k256::PublicKey::from_sec1_bytes(bytes)?.to_projective();
    ensure!(
        compressed(point)?.as_slice() == bytes,
        "noncanonical native VSS point"
    );
    Ok(point)
}
pub(crate) fn compressed(point: ProjectivePoint) -> Result<Vec<u8>> {
    ensure!(
        point != ProjectivePoint::IDENTITY,
        "degenerate native VSS point"
    );
    Ok(point.to_affine().to_encoded_point(true).as_bytes().to_vec())
}
pub(crate) fn operator_identifier(id: &str) -> Result<Digest> {
    let bytes: Digest = hex::decode(id)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("native operator identifier length"))?;
    ensure!(
        hex::encode(bytes) == id && scalar(&bytes)? != Scalar::ZERO,
        "noncanonical native operator identifier"
    );
    Ok(bytes)
}
