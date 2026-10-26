//! Ordinary Spark claim-key-tweak packaging, with no operator extensions.
//!
//! This is a wire/encryption primitive, not joint tweak generation or admission.
//! Its input is ONE already-combined operator evaluation. Never obtain these
//! inputs by exporting the blind signer's evaluations to the wallet: enough
//! evaluations reveal its share. Ordinary ingress uses `receive::ReceiveJournal`
//! and its private MPC output instead; this module supplies its native template.
//!
//! Native leaf identifiers, keys, proofs and ciphertexts stay on the native
//! side of the boundary; none belongs on the blind signer's transport.
use anyhow::{Context, Result, ensure};
use k256::{ProjectivePoint, Scalar, elliptic_curve::sec1::ToEncodedPoint};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

mod journal;
mod wire;
pub use journal::{OperatorClaimJournal, collect_packages};

#[cfg(test)]
mod tests;

/// Trusted native configuration. The VSS evaluation index is NOT the FROST ID.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operator {
    /// One-based index: Spark's configured zero-based Index plus one.
    pub share_index: u16,
    pub encryption_key: Vec<u8>,
}

/// Wallet/native-side binding; it establishes no ownership or chain facts.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimPlan {
    pub deployment: [u8; 32],
    pub operation: [u8; 32],
    pub transfer_id: String,
    pub leaf_id: String,
    pub incoming_user_key: Vec<u8>,
    pub joint_user_key: Vec<u8>,
    pub threshold: usize,
    /// Canonical Spark operator identifier -> pinned recipient/index.
    pub operators: BTreeMap<String, Operator>,
}

impl ClaimPlan {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.deployment != [0; 32] && self.operation != [0; 32],
            "empty standard claim domain"
        );
        uuid(&self.transfer_id)?;
        uuid(&self.leaf_id)?;
        ensure!(
            (2..=16).contains(&self.operators.len())
                && (2..=self.operators.len()).contains(&self.threshold),
            "standard claim cluster bounds"
        );
        ensure!(
            point(&self.incoming_user_key)? != point(&self.joint_user_key)?,
            "zero standard claim key tweak"
        );
        let mut indices = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for (id, operator) in &self.operators {
            let raw: [u8; 32] = hex::decode(id)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("operator ID length"))?;
            ensure!(
                hex::encode(raw) == *id && zark_protocol::scalar(&raw)? != Scalar::ZERO,
                "noncanonical operator ID"
            );
            point(&operator.encryption_key)?;
            ensure!(
                operator.share_index > 0
                    && usize::from(operator.share_index) <= self.operators.len()
                    && indices.insert(operator.share_index)
                    && keys.insert(&operator.encryption_key),
                "duplicate or invalid standard claim recipient"
            );
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32]> {
        self.validate()?;
        Ok(zark_protocol::hash(&[
            b"ZARK/spark/standard-claim/plan/v1",
            &serde_json::to_vec(self)?,
        ]))
    }
}

/// Combined Feldman coefficients, held only on the native side. The constant
/// must equal incoming USER minus the new joint USER, preserving the backing
/// output key when Spark adds the tweak to its operator key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TweakProofs {
    pub coefficients: Vec<Vec<u8>>,
}

impl TweakProofs {
    /// Native-side protobuf template for private joint evaluation. The zero
    /// scalar slot is replaced INSIDE the MPC; it is never submitted as a share.
    pub(crate) fn joint_template(&self, plan: &ClaimPlan) -> Result<Zeroizing<Vec<u8>>> {
        self.validate(plan)?;
        Ok(wire::encode(
            &plan.leaf_id,
            &[0; 32],
            &self.coefficients,
            &self.public_shares(plan)?,
        ))
    }
    pub fn validate(&self, plan: &ClaimPlan) -> Result<()> {
        plan.validate()?;
        ensure!(
            self.coefficients.len() == plan.threshold,
            "standard claim proof count"
        );
        for coefficient in &self.coefficients {
            point(coefficient)?;
        }
        ensure!(
            point(&self.coefficients[0])?
                == point(&plan.incoming_user_key)? - point(&plan.joint_user_key)?,
            "standard claim constant differs from USER key rotation"
        );
        for operator in plan.operators.values() {
            self.evaluation(operator.share_index)?;
        }
        Ok(())
    }

    fn evaluation(&self, index: u16) -> Result<ProjectivePoint> {
        let x = Scalar::from(u64::from(index));
        let value = self
            .coefficients
            .iter()
            .rev()
            .try_fold(ProjectivePoint::IDENTITY, |sum, coefficient| {
                Ok::<_, anyhow::Error>(sum * x + point(coefficient)?)
            })?;
        ensure!(
            value != ProjectivePoint::IDENTITY,
            "zero standard claim evaluation"
        );
        Ok(value)
    }

    fn public_shares(&self, plan: &ClaimPlan) -> Result<BTreeMap<String, Vec<u8>>> {
        plan.operators
            .iter()
            .map(|(id, operator)| {
                Ok((
                    id.clone(),
                    compressed(self.evaluation(operator.share_index)?),
                ))
            })
            .collect()
    }
}

fn seal(
    plan: &ClaimPlan,
    proofs: &TweakProofs,
    operator_id: &str,
    evaluation: Zeroizing<[u8; 32]>,
) -> Result<Vec<u8>> {
    proofs.validate(plan)?;
    let operator = plan
        .operators
        .get(operator_id)
        .context("unconfigured standard claim recipient")?;
    let scalar = Zeroizing::new(zark_protocol::scalar(evaluation.as_ref())?);
    ensure!(
        *scalar != Scalar::ZERO
            && ProjectivePoint::GENERATOR * *scalar == proofs.evaluation(operator.share_index)?,
        "standard claim evaluation fails Feldman proof"
    );
    let plaintext = wire::encode(
        &plan.leaf_id,
        &evaluation,
        &proofs.coefficients,
        &proofs.public_shares(plan)?,
    );
    zark_protocol::spark_ecies::encrypt(&operator.encryption_key, &plaintext)
}

fn point(bytes: &[u8]) -> Result<ProjectivePoint> {
    ensure!(
        bytes.len() == 33,
        "standard claim requires compressed native point"
    );
    let point = k256::PublicKey::from_sec1_bytes(bytes)?.to_projective();
    ensure!(
        compressed(point) == bytes,
        "noncanonical standard claim point"
    );
    Ok(point)
}

fn compressed(point: ProjectivePoint) -> Vec<u8> {
    point.to_affine().to_encoded_point(true).as_bytes().to_vec()
}

fn uuid(text: &str) -> Result<()> {
    let bytes = text.as_bytes();
    ensure!(
        bytes.len() == 36
            && bytes.iter().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    *b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(b)
                }
            })
            && bytes.iter().any(|b| *b != b'-' && *b != b'0'),
        "noncanonical standard claim UUID"
    );
    Ok(())
}
