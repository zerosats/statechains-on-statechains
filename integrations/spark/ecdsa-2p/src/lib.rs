//! Two-party secp256k1 ECDSA through cb-mpc's public C API (Lindell 2017 with
//! Paillier). P1 holds the Paillier key and alone receives the signature; P2
//! only contributes. Neither party can sign or recover the key alone.
//!
//! cb-mpc runs each protocol as one blocking call with transport callbacks.
//! [`Session`] runs that call on its own thread so a party can relay one
//! message per request. Sessions are memory-only: dropping one, a receive
//! timeout or a process restart aborts the protocol and its nonce.
mod ffi;
mod session;
#[cfg(test)]
mod tests;

use anyhow::{Context, Result, ensure};
use k256::{ProjectivePoint, PublicKey, Scalar, elliptic_curve::PrimeField};
use zeroize::Zeroizing;

pub use session::{Output, Role, Session, Step};

const MAX_KEY_BLOB: usize = 16 * 1024;

/// A party's serialized cb-mpc key share. The P1 blob also holds the Paillier
/// secret key; both are as sensitive as the private share itself.
pub struct KeyBlob(Zeroizing<Vec<u8>>);

impl KeyBlob {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= MAX_KEY_BLOB, "cb-mpc key blob size");
        let key = Self(Zeroizing::new(bytes.to_vec()));
        key.public_key()?;
        Ok(key)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Joint public key Q = x1·G + x2·G, SEC1 compressed.
    pub fn public_key(&self) -> Result<[u8; 33]> {
        let mut out = ffi::Cmem::EMPTY;
        let rc = unsafe { ffi::cbmpc_ecdsa_2p_get_public_key_compressed(self.view(), &mut out) };
        point(rc, out)
    }

    /// This party's public share xi·G, SEC1 compressed.
    pub fn public_share(&self) -> Result<[u8; 33]> {
        let mut out = ffi::Cmem::EMPTY;
        let rc = unsafe { ffi::cbmpc_ecdsa_2p_get_public_share_compressed(self.view(), &mut out) };
        point(rc, out)
    }

    /// This party's additive share xi, checked against its public share.
    pub fn private_share(&self) -> Result<Zeroizing<[u8; 32]>> {
        let mut detached = ffi::Cmem::EMPTY;
        let mut scalar = ffi::Cmem::EMPTY;
        let rc = unsafe {
            ffi::cbmpc_ecdsa_2p_detach_private_scalar(self.view(), &mut detached, &mut scalar)
        };
        drop(take(rc, detached));
        let raw = take(rc, scalar)?;
        ensure!(
            !raw.is_empty() && raw.len() <= 32,
            "cb-mpc share is not a reduced scalar"
        );
        let mut share = Zeroizing::new([0; 32]);
        share[32 - raw.len()..].copy_from_slice(&raw);
        let x = Option::<Scalar>::from(Scalar::from_repr((*share).into()))
            .context("cb-mpc share exceeds the group order")?;
        let public = PublicKey::from_sec1_bytes(&self.public_share()?)?;
        ensure!(
            x != Scalar::ZERO && ProjectivePoint::GENERATOR * x == public.to_projective(),
            "cb-mpc private share differs from its public share"
        );
        Ok(share)
    }

    fn view(&self) -> ffi::Cmem {
        ffi::Cmem::view(&self.0)
    }
}

/// Copies and zeroizes a library-owned buffer, which must then be released.
fn take(rc: i32, mem: ffi::Cmem) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = if mem.data.is_null() || mem.size <= 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(mem.data, mem.size as usize) }.to_vec()
    };
    unsafe { ffi::cbmpc_cmem_free(mem) };
    ensure!(rc == ffi::SUCCESS, "cb-mpc error {rc:#x}");
    Ok(Zeroizing::new(bytes))
}

fn point(rc: i32, out: ffi::Cmem) -> Result<[u8; 33]> {
    let bytes: [u8; 33] = take(rc, out)?
        .as_slice()
        .try_into()
        .context("cb-mpc point length")?;
    PublicKey::from_sec1_bytes(&bytes)?;
    Ok(bytes)
}
