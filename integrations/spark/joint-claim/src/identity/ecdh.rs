//! Chaum-Pedersen proof for the server's identity ECDH contribution. The native
//! ciphertext and joint USER point are never inputs to the server-side API.
use super::*;
use k256::elliptic_curve::group::Group;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcdhProof {
    pub a: Vec<u8>,
    pub b: Vec<u8>,
    pub z: [u8; 32],
}
fn encode(p: ProjectivePoint) -> Result<Vec<u8>> {
    ensure!(!bool::from(p.is_identity()), "identity ECDH infinity");
    Ok(p.to_affine().to_encoded_point(true).as_bytes().to_vec())
}
fn challenge(
    context: &[u8; 32],
    server: &[u8],
    ephemeral: &[u8],
    partial: &[u8],
    a: &[u8],
    b: &[u8],
) -> Scalar {
    let mut h = Sha256::new();
    h.update(b"ZARK/spark/joint-identity/ecdh/v1");
    for v in [context.as_slice(), server, ephemeral, partial, a, b] {
        h.update((v.len() as u32).to_le_bytes());
        h.update(v);
    }
    <Scalar as Reduce<U256>>::reduce_bytes(&h.finalize())
}
pub fn prove(secret: &[u8; 32], ephemeral: &[u8], context: &[u8; 32]) -> Result<EcdhProof> {
    use k256::elliptic_curve::Field;
    ensure!(
        ephemeral.len() == 65 && ephemeral[0] == 4,
        "native ECIES ephemeral encoding"
    );
    let s = scalar(secret)?;
    ensure!(s != Scalar::ZERO, "zero ECDH share");
    let p = k256::PublicKey::from_sec1_bytes(ephemeral)?.to_projective();
    let k = Zeroizing::new(Scalar::random(rand::rngs::OsRng));
    let a = encode(ProjectivePoint::GENERATOR * *k)?;
    let b = encode(p * *k)?;
    let c = challenge(
        context,
        &encode(ProjectivePoint::GENERATOR * s)?,
        ephemeral,
        &encode(p * s)?,
        &a,
        &b,
    );
    Ok(EcdhProof {
        a,
        b,
        z: (*k + c * s).to_bytes().into(),
    })
}
pub fn verify(
    server: &[u8],
    ephemeral: &[u8],
    partial: &[u8],
    context: &[u8; 32],
    proof: &EcdhProof,
) -> Result<()> {
    ensure!(
        server.len() == 33
            && ephemeral.len() == 65
            && ephemeral[0] == 4
            && partial.len() == 33
            && proof.a.len() == 33
            && proof.b.len() == 33,
        "identity ECDH proof encoding"
    );
    let parse = |p: &[u8]| -> Result<ProjectivePoint> {
        Ok(k256::PublicKey::from_sec1_bytes(p)?.to_projective())
    };
    let c = challenge(context, server, ephemeral, partial, &proof.a, &proof.b);
    let z = scalar(&proof.z)?;
    ensure!(
        ProjectivePoint::GENERATOR * z == parse(&proof.a)? + parse(server)? * c
            && parse(ephemeral)? * z == parse(&proof.b)? + parse(partial)? * c,
        "invalid identity ECDH contribution"
    );
    Ok(())
}
