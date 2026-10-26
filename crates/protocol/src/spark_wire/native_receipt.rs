//! Completion is attested by configured native operators after durable native
//! settlement. Wallet input alone never marks a blind signer head as exited.
use crate::{hash, scalar, spark_lineage::Digest, spark_native_vss::Cluster};
use anyhow::{Result, ensure};
use k256::{
    elliptic_curve::sec1::ToEncodedPoint,
    schnorr::{Signature, SigningKey, VerifyingKey},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCompletion {
    pub plan: Digest,
    pub cluster: Digest,
    pub packet: Digest,
}

impl NativeCompletion {
    pub fn message(&self) -> Result<Digest> {
        ensure!(
            self.plan != [0; 32] && self.cluster != [0; 32] && self.packet != [0; 32],
            "zero native completion field"
        );
        Ok(hash(&[
            b"ZARK/spark/native/completion/v1",
            &1u32.to_le_bytes(),
            &self.plan,
            &self.cluster,
            &self.packet,
            b"COMPLETED",
        ]))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAttestation {
    pub operator: Digest,
    pub signature: Vec<u8>,
}

impl NativeAttestation {
    /// Native operator code must derive this statement from its own durably
    /// completed row, never from wallet-provided completion fields.
    pub fn sign(
        completion: &NativeCompletion,
        operator: Digest,
        identity: &SigningKey,
    ) -> Result<Self> {
        ensure!(
            !bool::from(scalar(&operator)?.is_zero()),
            "zero native operator identifier"
        );
        Ok(Self {
            operator,
            signature: identity
                .sign_raw(&completion.message()?, &crate::random32())?
                .to_bytes()
                .to_vec(),
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExitReceipt {
    pub completion: NativeCompletion,
    pub attestations: Vec<NativeAttestation>,
}

impl NativeExitReceipt {
    pub fn verify(&self, cluster: &Cluster) -> Result<()> {
        ensure!(
            self.completion.cluster == cluster.digest()?,
            "native receipt cluster mismatch"
        );
        ensure!(
            (cluster.threshold..=cluster.operators.len()).contains(&self.attestations.len()),
            "native receipt threshold"
        );
        let message = self.completion.message()?;
        let mut previous = None;
        let mut signing_keys = BTreeSet::new();
        for attestation in &self.attestations {
            ensure!(
                previous.is_none_or(|id| id < attestation.operator),
                "native receipt identifiers not unique and sorted"
            );
            previous = Some(attestation.operator);
            let compressed = cluster
                .operators
                .get(&hex::encode(attestation.operator))
                .ok_or_else(|| anyhow::anyhow!("unconfigured native receipt operator"))?;
            let public = k256::PublicKey::from_sec1_bytes(compressed)?.to_encoded_point(true);
            let xonly: Digest = public.as_bytes()[1..].try_into()?;
            // Opposite compressed keys have the same BIP340 signing identity.
            // They must never count as independent quorum participants.
            ensure!(
                signing_keys.insert(xonly),
                "native receipt repeats a signing identity"
            );
            VerifyingKey::from_bytes(&xonly)?.verify_raw(
                &message,
                &Signature::try_from(attestation.signature.as_slice())?,
            )?;
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<Digest> {
        self.completion.message()?;
        ensure!(
            (2..=16).contains(&self.attestations.len()),
            "native receipt count"
        );
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.completion.message()?);
        bytes.extend_from_slice(&(self.attestations.len() as u16).to_le_bytes());
        let mut previous = None;
        for attestation in &self.attestations {
            ensure!(
                previous.is_none_or(|id| id < attestation.operator)
                    && attestation.signature.len() == 64,
                "noncanonical native receipt attestation"
            );
            previous = Some(attestation.operator);
            bytes.extend_from_slice(&attestation.operator);
            bytes.extend_from_slice(&attestation.signature);
        }
        Ok(hash(&[b"ZARK/spark/native/completion-receipt/v1", &bytes]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::{ProjectivePoint, Scalar};

    fn cluster(opposite: bool) -> Result<(Cluster, Vec<SigningKey>)> {
        let mut operators = std::collections::BTreeMap::new();
        let mut keys = Vec::new();
        for i in 1u64..=2 {
            let scalar = if opposite && i == 2 {
                -Scalar::from(11u64)
            } else {
                Scalar::from(i + 10)
            };
            let public = (ProjectivePoint::GENERATOR * scalar)
                .to_affine()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec();
            operators.insert(hex::encode(Scalar::from(i).to_bytes()), public);
            keys.push(SigningKey::from_bytes(&scalar.to_bytes())?);
        }
        Ok((
            Cluster {
                threshold: 2,
                operators,
            },
            keys,
        ))
    }

    #[test]
    fn completion_requires_exact_statement_and_independent_quorum() -> Result<()> {
        let (cluster, keys) = cluster(false)?;
        let completion = NativeCompletion {
            plan: [1; 32],
            cluster: cluster.digest()?,
            packet: [2; 32],
        };
        let receipt = NativeExitReceipt {
            completion: completion.clone(),
            attestations: keys
                .iter()
                .enumerate()
                .map(|(i, key)| {
                    NativeAttestation::sign(
                        &completion,
                        Scalar::from(i as u64 + 1).to_bytes().into(),
                        key,
                    )
                })
                .collect::<Result<Vec<_>>>()?,
        };
        receipt.verify(&cluster)?;
        receipt.digest()?;
        let mut changed = receipt.clone();
        changed.completion.packet[0] ^= 1;
        assert!(changed.verify(&cluster).is_err());
        let mut changed = receipt.clone();
        changed.attestations.pop();
        assert!(changed.verify(&cluster).is_err());
        let mut changed = receipt.clone();
        changed.attestations[1] = changed.attestations[0].clone();
        assert!(changed.verify(&cluster).is_err());
        let mut changed = receipt;
        changed.attestations.swap(0, 1);
        assert!(changed.verify(&cluster).is_err());
        Ok(())
    }

    #[test]
    fn opposite_encryption_keys_do_not_count_as_two_signing_identities() -> Result<()> {
        let (cluster, keys) = cluster(true)?;
        cluster.validate()?; // compressed ECIES points are distinct.
        let completion = NativeCompletion {
            plan: [1; 32],
            cluster: cluster.digest()?,
            packet: [2; 32],
        };
        let receipt = NativeExitReceipt {
            completion: completion.clone(),
            attestations: keys
                .iter()
                .enumerate()
                .map(|(i, key)| {
                    NativeAttestation::sign(
                        &completion,
                        Scalar::from(i as u64 + 1).to_bytes().into(),
                        key,
                    )
                })
                .collect::<Result<Vec<_>>>()?,
        };
        assert!(receipt.verify(&cluster).is_err());
        Ok(())
    }
}
