//! Server-private native ECIES mask. Only the 81-byte public header is released.
use aes::{
    Aes256,
    cipher::{BlockEncrypt, KeyInit},
};
use aes_gcm::{
    AesGcm,
    aead::{AeadInPlace, consts::U16},
};
use anyhow::{Result, ensure};
use hkdf::Hkdf;
use k256::{
    ProjectivePoint, Scalar,
    elliptic_curve::{Field, sec1::ToEncodedPoint},
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptionMask {
    header: Vec<u8>,
    stream: Vec<u8>,
    h: [u8; 16],
    tag: [u8; 16],
}
impl Drop for EncryptionMask {
    fn drop(&mut self) {
        self.stream.zeroize();
        self.h.zeroize();
        self.tag.zeroize();
    }
}
impl EncryptionMask {
    pub fn from_seed(recipient: &[u8], length: usize, seed: Zeroizing<[u8; 32]>) -> Result<Self> {
        use rand::SeedableRng;
        Self::prepare(
            recipient,
            length,
            &mut rand_chacha::ChaCha20Rng::from_seed(*seed),
        )
    }
    pub fn prepare(
        recipient: &[u8],
        length: usize,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self> {
        ensure!(
            (32..=2048).contains(&length) && recipient.len() == 33,
            "joint ECIES bounds"
        );
        let key = k256::PublicKey::from_sec1_bytes(recipient)?;
        ensure!(
            key.to_encoded_point(true).as_bytes() == recipient,
            "joint ECIES recipient encoding"
        );
        let secret = Zeroizing::new(loop {
            let s = Scalar::random(&mut *rng);
            if s != Scalar::ZERO {
                break s;
            }
        });
        let ephemeral = (ProjectivePoint::GENERATOR * *secret)
            .to_affine()
            .to_encoded_point(false);
        let shared = Zeroizing::new(key.to_projective() * *secret);
        let mut ikm = Zeroizing::new(Vec::from(ephemeral.as_bytes()));
        ikm.extend_from_slice(shared.to_affine().to_encoded_point(false).as_bytes());
        let mut symmetric = Zeroizing::new([0; 32]);
        Hkdf::<Sha256>::new(None, &ikm)
            .expand(&[], &mut *symmetric)
            .map_err(|_| anyhow::anyhow!("joint ECIES HKDF"))?;
        let mut nonce = [0; 16];
        rng.fill_bytes(&mut nonce);
        let mut h = aes::cipher::Block::<Aes256>::default();
        Aes256::new_from_slice(&*symmetric)
            .unwrap()
            .encrypt_block(&mut h);
        let mut stream = Zeroizing::new(vec![0; length]);
        type Cipher = AesGcm<Aes256, U16>;
        let tag = Cipher::new_from_slice(&*symmetric)
            .unwrap()
            .encrypt_in_place_detached(&nonce.into(), b"", &mut stream)
            .map_err(|_| anyhow::anyhow!("joint ECIES GCM"))?;
        let mut header = ephemeral.as_bytes().to_vec();
        header.extend_from_slice(&nonce);
        Ok(Self {
            header,
            stream: stream.to_vec(),
            h: h.into(),
            tag: tag.into(),
        })
    }
    pub fn header(&self) -> &[u8] {
        &self.header
    }
    pub(crate) fn input(&self, scalar: &[u8; 32]) -> Zeroizing<Vec<bool>> {
        let mut out = Zeroizing::new(crate::circuit::bits(scalar));
        out.extend(crate::circuit::bits(&self.h));
        out.extend(crate::circuit::bits(&self.tag));
        out.extend(crate::circuit::bits(&self.stream));
        out
    }
    pub(crate) fn length(&self) -> usize {
        self.stream.len()
    }
}
