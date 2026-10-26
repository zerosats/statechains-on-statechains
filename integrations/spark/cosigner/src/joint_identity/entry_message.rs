//! The only messages the entry identity signs. Under blind ECDSA-2P, τ is
//! fixed per coin and the signer sees m'' = m + r·τ, so one digest it learns
//! or predicts unblinds P. Each kind therefore carries entropy the signer is
//! never sent: an operator's fresh challenge nonce, or the claim's transfer
//! and leaf IDs (in the additive receive the signer seals the packages, so
//! they add none against it). The wallet hashes the raw message itself; the
//! SDK driver never supplies a digest.
use super::*;
use sha2::{Digest as _, Sha256};

const MAX_CHALLENGE: usize = 256;

pub struct EntryMessage {
    digest: Digest,
}

impl EntryMessage {
    /// A Spark operator `Challenge {version, timestamp, nonce, public_key}`
    /// addressed to `identity`, as the SDK encodes it before hashing.
    pub fn challenge(raw: &[u8], identity: &[u8]) -> Result<Self> {
        ensure!(raw.len() <= MAX_CHALLENGE, "Spark challenge size");
        let (mut rest, mut last, mut nonce, mut public) = (raw, 0, None, None);
        while !rest.is_empty() {
            let key = varint(&mut rest)?;
            let field = key >> 3;
            ensure!(field > last, "Spark challenge field order");
            last = field;
            match (field, key & 7) {
                (1 | 2, 0) => {
                    varint(&mut rest)?;
                }
                (3, 2) => nonce = Some(delimited(&mut rest)?),
                (4, 2) => public = Some(delimited(&mut rest)?),
                _ => anyhow::bail!("Spark challenge field"),
            }
        }
        ensure!(
            nonce.is_some_and(|n| n.len() == 32),
            "Spark challenge nonce"
        );
        ensure!(
            sec1(public.context("Spark challenge public key")?)? == sec1(identity)?,
            "Spark challenge names another identity"
        );
        Ok(Self {
            digest: Sha256::digest(raw).into(),
        })
    }

    /// Spark's claim-package signing payload for this claim's own transfer ID
    /// and the packages this wallet completed.
    pub fn claim(
        raw: &[u8],
        transfer_id: &str,
        packages: &BTreeMap<String, Vec<u8>>,
    ) -> Result<Self> {
        let id = hex::decode(transfer_id.replace('-', ""))?;
        ensure!(id.len() == 16 && id != [0; 16], "Spark claim transfer ID");
        ensure!(!packages.is_empty(), "Spark claim packages");
        ensure!(
            raw == claim_payload(&id, packages),
            "Spark claim payload differs from this claim"
        );
        Ok(Self {
            digest: Sha256::digest(raw).into(),
        })
    }

    pub fn digest(&self) -> Digest {
        self.digest
    }
}

/// `TaggedHasher(["spark","claim","signing payload"]).signable_message()`:
/// tag || tag || length-prefixed transfer ID, package count and sorted pairs.
pub(crate) fn claim_payload(transfer_id: &[u8], packages: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut parts = Vec::new();
    for part in ["spark", "claim", "signing payload"] {
        append(&mut parts, part.as_bytes());
    }
    let tag: Digest = Sha256::digest(&parts).into();
    let mut out = [tag, tag].concat();
    append(&mut out, transfer_id);
    append(&mut out, &(packages.len() as u64).to_be_bytes());
    for (id, bytes) in packages {
        append(&mut out, id.as_bytes());
        append(&mut out, bytes);
    }
    out
}

fn append(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn sec1(bytes: &[u8]) -> Result<k256::PublicKey> {
    k256::PublicKey::from_sec1_bytes(bytes)
        .map_err(|_| anyhow::anyhow!("Spark challenge public key encoding"))
}

fn varint(rest: &mut &[u8]) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let (&byte, tail) = rest.split_first().context("Spark challenge truncated")?;
        *rest = tail;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    anyhow::bail!("Spark challenge varint")
}

fn delimited<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8]> {
    let length = usize::try_from(varint(rest)?)?;
    ensure!(length <= rest.len(), "Spark challenge truncated");
    let (value, tail) = rest.split_at(length);
    *rest = tail;
    Ok(value)
}

/// The SDK's encoding of an operator challenge for `identity`.
#[cfg(test)]
pub(crate) fn encode_challenge(nonce: &[u8], identity: &[u8]) -> Vec<u8> {
    let mut out = vec![
        0x08,
        0x01,
        0x10,
        0x80,
        0xa3,
        0xc5,
        0xd2,
        0x06,
        0x1a,
        nonce.len() as u8,
    ];
    out.extend_from_slice(nonce);
    out.extend_from_slice(&[0x22, identity.len() as u8]);
    out.extend_from_slice(identity);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Vec<u8> {
        (ProjectivePoint::GENERATOR * random_scalar())
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    fn uncompressed(public: &[u8]) -> Vec<u8> {
        sec1(public)
            .unwrap()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn challenge_must_carry_a_nonce_and_name_this_identity() -> Result<()> {
        let public = identity();
        let raw = encode_challenge(&random32(), &public);
        assert_eq!(
            EntryMessage::challenge(&raw, &public)?.digest(),
            <[u8; 32]>::from(Sha256::digest(&raw))
        );
        EntryMessage::challenge(
            &encode_challenge(&random32(), &uncompressed(&public)),
            &public,
        )?;
        let rejected = [
            encode_challenge(&random32(), &identity()),
            encode_challenge(&random32()[..16], &public),
            encode_challenge(&[], &public),
            [&raw[..], &[0x28, 0x01]].concat(),
            [&[0x22, 0x00][..], &raw[..]].concat(),
            raw[..raw.len() - 1].to_vec(),
            random32().to_vec(),
        ];
        for raw in rejected {
            assert!(EntryMessage::challenge(&raw, &public).is_err());
        }
        Ok(())
    }

    #[test]
    fn claim_payload_must_be_this_claims_transfer_and_packages() -> Result<()> {
        let id = "0f0e0d0c-0b0a-4908-8706-050403020100";
        let packages: BTreeMap<String, Vec<u8>> = [
            ("02".repeat(32), vec![1; 40]),
            ("01".repeat(32), vec![2; 40]),
        ]
        .into_iter()
        .collect();
        let raw = claim_payload(&hex::decode(id.replace('-', ""))?, &packages);
        // Pinned against the SDK's TaggedHasher layout.
        assert_eq!(raw.len(), 64 + 8 + 16 + 8 + 8 + 2 * (8 + 64 + 8 + 40));
        assert_eq!(&raw[64..72], &16u64.to_be_bytes());
        assert_eq!(
            &raw[88..104],
            &[[0, 0, 0, 0, 0, 0, 0, 8], 2u64.to_be_bytes()].concat()[..]
        );
        assert_eq!(&raw[112..176], "01".repeat(32).as_bytes());
        EntryMessage::claim(&raw, id, &packages)?;
        let mut other = packages.clone();
        other.insert("03".repeat(32), vec![3; 40]);
        assert!(EntryMessage::claim(&raw, id, &other).is_err());
        assert!(
            EntryMessage::claim(&raw, "0f0e0d0c-0b0a-4908-8706-050403020101", &packages).is_err()
        );
        assert!(EntryMessage::claim(&random32(), id, &packages).is_err());
        Ok(())
    }
}
