//! Versioned combined-only operator packet, separate from native submission.
use super::{
    CIPHER_BYTES, Cluster, Digest, OpaqueContribution, canonical_point, compressed,
    operator_identifier, validate_cipher,
};
use crate::{hash, scalar};
use anyhow::{Result, ensure};
use k256::{ProjectivePoint, Scalar};

pub const PACKET_MAGIC: &[u8] = b"ZARK-NATIVE-ROOT-v1\0";
const PLAN_BYTES: usize = 352;
const MASK_CIPHER_BYTES: usize = 129;
const MAX_PACKET: usize = 64 * 1024;

/// Contains native private data for the wallet-to-operator bridge. It must not
/// be sent to the blind signer or included in public evidence. No individual
/// server point or coefficient vector appears in the encoded packet.
pub struct OpaqueVssPacket {
    wire: Vec<u8>,
    plan: Digest,
    digest: Digest,
}

impl OpaqueVssPacket {
    pub fn assemble(
        canonical_plan: &[u8],
        salt: Digest,
        mask_cipher: &[u8],
        cluster: &Cluster,
        parts: [&OpaqueContribution; 2],
    ) -> Result<Self> {
        let plan = check_plan(canonical_plan, &salt, mask_cipher, cluster)?;
        let mut combined = [ProjectivePoint::IDENTITY; 2];
        for (index, part) in parts.iter().enumerate() {
            ensure!(
                part.position == (index + 1) as u16,
                "opaque native participant order"
            );
            ensure!(
                part.coefficient_commitments.len() == 2,
                "opaque native polynomial size"
            );
            part.validate(cluster, &plan, &part.coefficient_commitments[0])?;
            for (coefficient, point) in combined.iter_mut().zip(&part.coefficient_commitments) {
                let point = canonical_point(point)?;
                *coefficient += if index == 0 {
                    point * Scalar::from(2u64)
                } else {
                    -point
                };
            }
        }
        validate_combined(canonical_plan, cluster, &combined)?;
        let mut wire = PACKET_MAGIC.to_vec();
        wire.extend_from_slice(canonical_plan);
        wire.extend_from_slice(&salt);
        wire.extend_from_slice(&(mask_cipher.len() as u16).to_le_bytes());
        wire.extend_from_slice(mask_cipher);
        for point in combined {
            wire.extend_from_slice(&compressed(point)?);
        }
        wire.extend_from_slice(&(cluster.operators.len() as u16).to_le_bytes());
        for id in cluster.operators.keys() {
            wire.extend_from_slice(&operator_identifier(id)?);
            for part in parts {
                let cipher = &part.sealed_shares[id];
                wire.extend_from_slice(&(cipher.len() as u16).to_le_bytes());
                wire.extend_from_slice(cipher);
            }
        }
        ensure!(wire.len() <= MAX_PACKET, "opaque native packet size");
        Self::decode(&wire, cluster)
    }

    /// Reopening validates exact canonical bytes and all public equations. Only
    /// each authenticated operator can validate its combined decrypted share.
    pub fn decode(bytes: &[u8], cluster: &Cluster) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_PACKET && bytes.starts_with(PACKET_MAGIC),
            "opaque native packet version or size"
        );
        let mut cursor = Cursor {
            bytes,
            offset: PACKET_MAGIC.len(),
        };
        let canonical = cursor.take(PLAN_BYTES)?;
        let salt: Digest = cursor.take(32)?.try_into()?;
        let mask_length = cursor.length()?;
        ensure!(
            mask_length == MASK_CIPHER_BYTES,
            "opaque native mask ciphertext size"
        );
        let mask_cipher = cursor.take(mask_length)?;
        let plan = check_plan(canonical, &salt, mask_cipher, cluster)?;
        let combined = [
            canonical_point(cursor.take(33)?)?,
            canonical_point(cursor.take(33)?)?,
        ];
        validate_combined(canonical, cluster, &combined)?;
        ensure!(
            cursor.length()? == cluster.operators.len(),
            "opaque native operator coverage differs"
        );
        for id in cluster.operators.keys() {
            ensure!(
                cursor.take(32)? == operator_identifier(id)?,
                "opaque native operator order differs"
            );
            for _ in 0..2 {
                ensure!(
                    cursor.length()? == CIPHER_BYTES,
                    "opaque native evaluation ciphertext size"
                );
                validate_cipher(cursor.take(CIPHER_BYTES)?)?;
            }
        }
        ensure!(
            cursor.offset == bytes.len(),
            "trailing opaque native packet bytes"
        );
        Ok(Self {
            wire: bytes.to_vec(),
            plan,
            digest: hash(&[bytes]),
        })
    }

    pub fn encode_private(&self) -> &[u8] {
        &self.wire
    }
    pub fn plan_commitment(&self) -> Digest {
        self.plan
    }
    pub fn digest(&self) -> Digest {
        self.digest
    }
}

fn check_plan(plan: &[u8], salt: &Digest, mask_cipher: &[u8], cluster: &Cluster) -> Result<Digest> {
    ensure!(
        plan.len() == PLAN_BYTES && plan[..8] == [1, 0, 0, 0, 1, 0, 0, 0] && *salt != [0; 32],
        "opaque native initial-root plan shape"
    );
    ensure!(
        mask_cipher.len() == MASK_CIPHER_BYTES && mask_cipher[0] == 4,
        "opaque native mask ciphertext size"
    );
    let ephemeral = k256::PublicKey::from_sec1_bytes(&mask_cipher[..65])?;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    ensure!(
        ephemeral.to_encoded_point(false).as_bytes() == &mask_cipher[..65],
        "opaque native mask ephemeral"
    );
    for range in [92..125, 125..158, 158..191, 191..224] {
        canonical_point(&plan[range])?;
    }
    ensure!(
        plan[224..256] == hash(&[mask_cipher]) && plan[256..288] == cluster.digest()?,
        "opaque native mask ciphertext or cluster differs from plan"
    );
    Ok(hash(&[b"ZARK/spark/native/plan/v1", plan, salt]))
}

fn validate_combined(
    plan: &[u8],
    cluster: &Cluster,
    combined: &[ProjectivePoint; 2],
) -> Result<()> {
    ensure!(
        combined[0] == canonical_point(&plan[92..125])? - canonical_point(&plan[158..191])?,
        "opaque native combined constant differs"
    );
    for point in combined {
        compressed(*point)?;
    }
    for id in cluster.operators.keys() {
        let x = scalar(&operator_identifier(id)?)?;
        ensure!(
            combined[0] + combined[1] * x != ProjectivePoint::IDENTITY,
            "opaque native combined evaluation is zero"
        );
    }
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        ensure!(
            len <= self.bytes.len().saturating_sub(self.offset),
            "truncated opaque native packet"
        );
        let out = &self.bytes[self.offset..self.offset + len];
        self.offset += len;
        Ok(out)
    }
    fn length(&mut self) -> Result<usize> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into()?) as usize)
    }
}
