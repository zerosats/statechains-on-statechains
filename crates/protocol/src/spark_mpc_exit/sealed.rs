//! Upstream Spark MPC key-tweak sub-shares for one leaf at position two.
//!
//! Each sealed share is Spark ECIES to an operator identity key taken only from
//! trusted deployment configuration: a wallet-chosen recipient could decrypt
//! the server's evaluations and recover its share. A threshold coalition of
//! operators can still recover the constant, as in the native VSS profile.
//! Unlike that profile, upstream payloads name the transfer and leaf UUIDs, so
//! the signer learns them; the interim entry/exit disclosure model allows it.
use super::payload::uuid_string;
use crate::{
    random_scalar, scalar, spark_ecies,
    spark_native_vss::{Cluster, Digest},
};
use anyhow::{Result, ensure};
use k256::{ProjectivePoint, Scalar, elliptic_curve::sec1::ToEncodedPoint};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Lagrange weight -1 at position two; the wallet's position one carries
/// `(x_w - mask)/2`, so operators combine to `x_w + x_s - mask`.
pub const SERVER_POSITION: u64 = 2;
const PAYLOAD_BYTES: usize = 112;
const CIPHER_BYTES: usize = 97 + PAYLOAD_BYTES;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MpcContribution {
    pub transfer_id: [u8; 16],
    pub leaf_id: [u8; 16],
    pub cluster: Digest,
    /// Constant then slope commitments: Spark's `proofs` for this position.
    pub proofs: [Vec<u8>; 2],
    pub sealed_shares: BTreeMap<String, Vec<u8>>,
}

impl MpcContribution {
    pub fn prepare(
        constant: &Digest,
        transfer_id: [u8; 16],
        leaf_id: [u8; 16],
        cluster: &Cluster,
    ) -> Result<Self> {
        ensure!(
            transfer_id != [0; 16] && leaf_id != [0; 16],
            "Spark MPC transfer or leaf missing"
        );
        let constant = Zeroizing::new(scalar(constant)?);
        ensure!(*constant != Scalar::ZERO, "degenerate Spark MPC constant");
        let slope = Zeroizing::new(loop {
            let slope = random_scalar();
            if cluster
                .operators
                .keys()
                .all(|id| identifier(id).is_ok_and(|x| *constant + slope * x != Scalar::ZERO))
            {
                break slope;
            }
        });
        let mut sealed_shares = BTreeMap::new();
        for (id, key) in &cluster.operators {
            let value = Zeroizing::new(*constant + *slope * identifier(id)?);
            let payload = sealed_payload(&transfer_id, &leaf_id, &value);
            sealed_shares.insert(id.clone(), spark_ecies::encrypt(key, &payload)?);
        }
        Ok(Self {
            transfer_id,
            leaf_id,
            cluster: cluster.digest()?,
            proofs: [
                compressed(ProjectivePoint::GENERATOR * *constant)?,
                compressed(ProjectivePoint::GENERATOR * *slope)?,
            ],
            sealed_shares,
        })
    }

    /// Public shape only: the evaluations stay sealed to the pinned operators.
    pub fn validate(&self, cluster: &Cluster, expected_constant: &ProjectivePoint) -> Result<()> {
        ensure!(
            self.transfer_id != [0; 16]
                && self.leaf_id != [0; 16]
                && self.cluster == cluster.digest()?,
            "Spark MPC contribution domain"
        );
        ensure!(
            self.sealed_shares.keys().eq(cluster.operators.keys()),
            "Spark MPC contribution operator coverage"
        );
        ensure!(
            self.proofs[0] == compressed(*expected_constant)?,
            "Spark MPC contribution constant differs"
        );
        for proof in &self.proofs {
            ensure!(proof.len() == 33, "Spark MPC commitment length");
            let point = k256::PublicKey::from_sec1_bytes(proof)?.to_projective();
            ensure!(
                compressed(point)? == *proof,
                "noncanonical Spark MPC commitment"
            );
        }
        for cipher in self.sealed_shares.values() {
            ensure!(
                cipher.len() == CIPHER_BYTES && cipher[0] == 4,
                "Spark MPC sealed share size"
            );
            let ephemeral = k256::PublicKey::from_sec1_bytes(&cipher[..65])?;
            ensure!(
                ephemeral.to_encoded_point(false).as_bytes() == &cipher[..65],
                "noncanonical Spark MPC ECIES ephemeral"
            );
        }
        Ok(())
    }

    pub fn proof_points(&self) -> Result<[[u8; 33]; 2]> {
        Ok([
            self.proofs[0].as_slice().try_into()?,
            self.proofs[1].as_slice().try_into()?,
        ])
    }
}

/// Spark Go `operator identifier` hex: a nonzero big-endian scalar.
fn identifier(id: &str) -> Result<Scalar> {
    let bytes: Digest = hex::decode(id)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Spark operator identifier length"))?;
    ensure!(
        hex::encode(bytes) == id,
        "noncanonical Spark operator identifier"
    );
    let x = scalar(&bytes)?;
    ensure!(x != Scalar::ZERO, "zero Spark operator identifier");
    Ok(x)
}

/// Canonical protobuf `MpcSealedSharePayload{transfer_id, leaf_shares:[{leaf_id, secret_share}]}`.
pub fn sealed_payload(
    transfer_id: &[u8; 16],
    leaf_id: &[u8; 16],
    value: &Scalar,
) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(PAYLOAD_BYTES));
    out.extend_from_slice(&[0x0a, 36]);
    out.extend_from_slice(uuid_string(transfer_id).as_bytes());
    out.extend_from_slice(&[0x12, 72, 0x0a, 36]);
    out.extend_from_slice(uuid_string(leaf_id).as_bytes());
    out.extend_from_slice(&[0x12, 32]);
    out.extend_from_slice(&Zeroizing::new(<[u8; 32]>::from(value.to_bytes()))[..]);
    out
}

fn compressed(point: ProjectivePoint) -> Result<Vec<u8>> {
    ensure!(
        point != ProjectivePoint::IDENTITY,
        "degenerate Spark MPC point"
    );
    Ok(point.to_affine().to_encoded_point(true).as_bytes().to_vec())
}
