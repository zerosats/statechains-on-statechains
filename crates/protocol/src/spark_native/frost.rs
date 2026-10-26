//! Exact pinned lightspark FROST two-group transcript, fixed two-operator quorum.
//! H1 is RFC9380 expand_message_xmd(SHA256), 48 bytes reduced modulo secp256k1 n.
use super::plan::{compressed, taproot};
use super::{Digest, WalletOpening};
use crate::{even, hash, point, reduce, scalar, tagged_hash};
use anyhow::{Result, ensure};
use k256::{ProjectivePoint, Scalar};
use zeroize::Zeroizing;
const SUITE: &[u8] = b"FROST-secp256k1-SHA256-TR-v1";

pub struct Participant {
    pub identifier: Digest,
    pub hiding: [u8; 64],
    pub binding: [u8; 64],
}
pub struct JobTranscript {
    pub operators: [Participant; 2],
    pub wallet: Participant,
}
fn identifier(value: u8) -> Digest {
    let mut bytes = [0; 32];
    bytes[31] = value;
    bytes
}
impl Participant {
    fn encode(&self, group: u8) -> Result<Vec<u8>> {
        ensure!(
            !bool::from(scalar(&self.identifier)?.is_zero()),
            "zero native participant identifier"
        );
        let mut out = vec![group];
        out.extend_from_slice(&self.identifier);
        out.extend_from_slice(&compressed(point(&self.hiding)?)?);
        out.extend_from_slice(&compressed(point(&self.binding)?)?);
        Ok(out)
    }
}
/// Exact H1 used by the pinned native SDK, independent of its Rust dependency.
/// Compare this against that dependency when qualifying a new deployment.
pub fn frost_h1(message: &[u8]) -> Scalar {
    let domain = [SUITE, b"rho"].concat();
    let length = [domain.len() as u8];
    let b0 = hash(&[&[0; 64], message, &[0, 48, 0], &domain, &length]);
    let b1 = hash(&[&b0, &[1], &domain, &length]);
    let mut xor = [0; 32];
    for i in 0..32 {
        xor[i] = b0[i] ^ b1[i];
    }
    let b2 = hash(&[&xor, &[2], &domain, &length]);
    b1.into_iter()
        .chain(b2[..16].iter().copied())
        .fold(Scalar::ZERO, |value, byte| {
            value * Scalar::from(256u64) + Scalar::from(u64::from(byte))
        })
}
/// The returned challenge is only arithmetic. The two-role proof must prove
/// the current certificate, native backing, exact jobs and every private input.
pub fn blinded_native_challenge(
    server: [u8; 64],
    nonce: [u8; 64],
    combined: [u8; 64],
    message: Digest,
    opening: &WalletOpening,
    transcript: &JobTranscript,
) -> Result<Digest> {
    let server = point(&server)?;
    let nonce = point(&nonce)?;
    let alpha = Zeroizing::new(scalar(&opening.alpha)?);
    let beta = Zeroizing::new(scalar(&opening.beta)?);
    let binding = Zeroizing::new(scalar(&opening.binding)?);
    ensure!(
        *alpha != Scalar::ZERO && *beta != Scalar::ZERO && *binding != Scalar::ZERO,
        "zero native blinding scalar"
    );
    ensure!(
        transcript.wallet.identifier == identifier(1),
        "native wallet position"
    );
    ensure!(
        transcript.operators[0].identifier < transcript.operators[1].identifier,
        "native operator commitment order"
    );
    let participant = Participant {
        identifier: identifier(2),
        hiding: crate::point_bytes(nonce + ProjectivePoint::GENERATOR * *alpha + server * *beta)?,
        binding: crate::point_bytes(ProjectivePoint::GENERATOR * *binding)?,
    };
    let all = [
        (&transcript.operators[0], 0),
        (&transcript.operators[1], 0),
        (&transcript.wallet, 1),
        (&participant, 1),
    ];
    let mut commitments = Vec::with_capacity(396);
    for (entry, group) in all {
        commitments.extend_from_slice(&entry.encode(group)?);
    }
    let message_hash = hash(&[SUITE, b"msg", &message]);
    let commitments_hash = hash(&[SUITE, b"com", &commitments]);
    let (output, key_sign) = taproot(point(&combined)?)?;
    let output = compressed(output)?;
    let mut total = ProjectivePoint::IDENTITY;
    for (entry, group) in all {
        let mut bytes = vec![group];
        bytes.extend_from_slice(&output);
        bytes.extend_from_slice(&message_hash);
        bytes.extend_from_slice(&commitments_hash);
        bytes.extend_from_slice(&entry.identifier);
        total += point(&entry.hiding)? + point(&entry.binding)? * frost_h1(&bytes);
    }
    let (nonce, nonce_sign) = even(total)?;
    let e = reduce(tagged_hash(
        "BIP0340/challenge",
        &[&crate::point_bytes(nonce)?[..32], &output[1..], &message],
    ));
    Ok((*beta + nonce_sign * e * key_sign).to_bytes().into())
}
