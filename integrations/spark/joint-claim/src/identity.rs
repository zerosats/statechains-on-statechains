//! Research primitive for a fixed additive identity key, without publishing
//! that key to the contributor. ECDSA uses independent multiplicative nonce
//! shares: k = k_wallet * k_server. The malicious-secure computation emits
//! masked presigning scalars only to the wallet. A one-use server partial later
//! completes a signature, which the wallet verifies before releasing it.
//!
//! Every nonce is single-use for ONE frozen message and peer nonce point.
//! Callers MUST durably freeze all inputs/frames before releasing messages,
//! prohibit alternate retries, authenticate the current owner, and erase nonce
//! secrets on completion/abort. This primitive alone implements none of that
//! lifecycle. It is not a deployment-qualified threshold ECDSA protocol.
mod arithmetic;
mod commitment;
mod ecdh;
mod session;
#[cfg(test)]
mod tests;
use crate::{boolean::Builder, circuit::bits};
use anyhow::{Result, ensure};
pub use ecdh::{EcdhProof, prove as ecdh_prove, verify as ecdh_verify};
use k256::{
    ProjectivePoint, Scalar,
    elliptic_curve::{bigint::U256, ops::Reduce, sec1::ToEncodedPoint},
};
pub use session::{IdentityContributor, IdentityEvaluator};
use std::sync::{Arc, OnceLock};
use tandem::Circuit;
use zeroize::Zeroizing;

pub struct IdentityCircuit {
    pub(super) circuit: Arc<Circuit>,
    digest: [u8; 32],
}
struct Compiled {
    circuit: Arc<Circuit>,
    digest: [u8; 32],
}
static COMPILED: OnceLock<Result<Compiled, String>> = OnceLock::new();
impl IdentityCircuit {
    pub fn new() -> Result<Self> {
        // Only immutable validated gates are shared. Party inputs, nonces, OT
        // randomness and contributor/evaluator state remain per operation.
        let compiled = COMPILED
            .get_or_init(|| Self::compile().map_err(|e| e.to_string()))
            .as_ref()
            .map_err(|e| anyhow::anyhow!("identity circuit: {e}"))?;
        Ok(Self {
            circuit: compiled.circuit.clone(),
            digest: compiled.digest,
        })
    }
    fn compile() -> Result<Compiled> {
        // Contributor: key, inverse nonce, two independent masks, commitment.
        // Evaluator: key, inverse nonce, opening salt. No message is needed yet.
        let (mut b, c, e) = Builder::inputs(1280, 768);
        let (key, mut valid) = b.scalar_sum(&c[..256], &e[..256]);
        for input in [&c[256..512], &e[256..512], &c[512..768], &c[768..1024]] {
            let v = arithmetic::canonical_nonzero(&mut b, input);
            valid = b.and(valid, v);
        }
        let committed = commitment::digest(&mut b, &e[..256], &e[512..]);
        for (&x, &y) in c[1024..].iter().zip(&committed) {
            let diff = b.xor(x, y);
            let same = b.not(diff);
            valid = b.and(valid, same);
        }
        let inv = arithmetic::multiply(&mut b, &c[256..512], &e[256..512]);
        let product = arithmetic::multiply(&mut b, &inv, &key);
        let a = arithmetic::subtract(&mut b, &inv, &c[512..768]);
        let d = arithmetic::subtract(&mut b, &product, &c[768..1024]);
        let mut output = vec![valid];
        output.extend(a);
        output.extend(d);
        let circuit = b.finish(output);
        circuit
            .validate()
            .map_err(|e| anyhow::anyhow!("identity arithmetic circuit: {e}"))?;
        let digest = circuit.blake3_hash();
        Ok(Compiled {
            circuit: Arc::new(circuit),
            digest,
        })
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn and_gates(&self) -> usize {
        self.circuit.and_gates()
    }
}
fn factor() -> Scalar {
    let mut r = Scalar::ONE;
    for _ in 0..256 {
        r = r + r;
    }
    r
}
fn scalar(bytes: &[u8; 32]) -> Result<Scalar> {
    use k256::elliptic_curve::PrimeField;
    Option::<Scalar>::from(Scalar::from_repr((*bytes).into()))
        .ok_or_else(|| anyhow::anyhow!("noncanonical identity scalar"))
}
pub fn nonce_public(secret: &[u8; 32]) -> Result<Vec<u8>> {
    let k = scalar(secret)?;
    ensure!(k != Scalar::ZERO, "zero identity nonce");
    Ok((ProjectivePoint::GENERATOR * k)
        .to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec())
}
/// Each party independently derives this from its own nonce and the peer point.
/// Only the nonce x-coordinate is public; no key-share point is sent here.
pub fn nonce_r(secret: &[u8; 32], peer: &[u8]) -> Result<[u8; 32]> {
    let k = scalar(secret)?;
    ensure!(k != Scalar::ZERO, "zero identity nonce");
    ensure!(peer.len() == 33, "identity nonce must be compressed SEC1");
    let peer = k256::PublicKey::from_sec1_bytes(peer)?;
    let r = (peer.to_projective() * k)
        .to_affine()
        .to_encoded_point(false);
    let r = <Scalar as Reduce<U256>>::reduce_bytes(r.x().expect("finite nonce"));
    ensure!(r != Scalar::ZERO, "zero ECDSA r");
    Ok(r.to_bytes().into())
}
fn base_input(share: &[u8; 32], nonce: &[u8; 32]) -> Result<Zeroizing<Vec<bool>>> {
    let x = scalar(share)?;
    let k = scalar(nonce)?;
    ensure!(
        x != Scalar::ZERO && k != Scalar::ZERO,
        "zero identity input"
    );
    let inv = Option::<Scalar>::from(k.invert()).expect("nonzero nonce");
    let mut out = Zeroizing::new(Vec::with_capacity(1280));
    for v in [x, inv] {
        out.extend(bits(&(v * factor()).to_bytes()));
    }
    Ok(out)
}
pub fn key_commitment(share: &[u8; 32], salt: &[u8; 32]) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update((scalar(share)? * factor()).to_bytes());
    h.update(salt);
    h.update(commitment::domain());
    Ok(h.finalize().into())
}
fn server_input(
    share: &[u8; 32],
    nonce: &[u8; 32],
    masks: &[[u8; 32]; 2],
    commitment: &[u8; 32],
) -> Result<Zeroizing<Vec<bool>>> {
    let mut out = base_input(share, nonce)?;
    for mask in masks {
        let mask = scalar(mask)?;
        ensure!(mask != Scalar::ZERO, "zero identity presign mask");
        out.extend(bits(&(mask * factor()).to_bytes()));
    }
    out.extend(bits(commitment));
    Ok(out)
}
fn wallet_input(
    share: &[u8; 32],
    nonce: &[u8; 32],
    salt: &[u8; 32],
) -> Result<Zeroizing<Vec<bool>>> {
    let mut out = base_input(share, nonce)?;
    out.extend(bits(salt));
    Ok(out)
}
pub fn online_partial(masks: &[[u8; 32]; 2], r: &[u8; 32], digest: &[u8; 32]) -> Result<[u8; 32]> {
    let z = <Scalar as Reduce<U256>>::reduce_bytes(&(*digest).into());
    Ok((scalar(&masks[0])? * z + scalar(&masks[1])? * scalar(r)?)
        .to_bytes()
        .into())
}
pub fn complete_signature(
    presign: &[u8; 64],
    r: &[u8; 32],
    digest: &[u8; 32],
    partial: &[u8; 32],
    joint_key: &[u8],
) -> Result<Vec<u8>> {
    use k256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
    let z = <Scalar as Reduce<U256>>::reduce_bytes(&(*digest).into());
    let a = scalar(presign[..32].try_into()?)?;
    let b = scalar(presign[32..].try_into()?)?;
    let signature =
        Signature::from_scalars(*r, (a * z + b * scalar(r)? + scalar(partial)?).to_bytes())?;
    let signature = signature.normalize_s().unwrap_or(signature);
    VerifyingKey::from_sec1_bytes(joint_key)?.verify_prehash(digest, &signature)?;
    Ok(signature.to_der().as_bytes().to_vec())
}
