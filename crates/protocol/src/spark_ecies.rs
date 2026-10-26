//! Exact Spark ECIES encryption shared by the wallet and blind signer.
//! This primitive grants no authority to release shares or disclose plaintext.
use aes_gcm::{
    AesGcm, KeyInit,
    aead::{AeadInPlace, consts::U16},
    aes::Aes256,
};
use anyhow::{Result, ensure};
use hkdf::Hkdf;
use k256::{
    ProjectivePoint, Scalar,
    elliptic_curve::{Field, sec1::ToEncodedPoint},
};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

type Cipher = AesGcm<Aes256, U16>;

/// Extracted unchanged from the wallet's Spark ECIES helper. Keep raw recipient
/// parity and the pinned 16-byte GCM nonce; BIP340 normalization would change
/// HKDF input and make Spark operators unable to decrypt this wire format.
pub fn encrypt(recipient: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let (wire, _) = seal(recipient, plaintext)?;
    Ok(wire)
}

/// Encrypts a plaintext that is zero except for `secret` at `offset`. Returns
/// the wire bytes and the GCM hash key H = AES_k(0). The completing party
/// learns the keystream outside the secret bytes, never the secret itself.
pub fn seal_slot(
    recipient: &[u8],
    length: usize,
    offset: usize,
    secret: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 16])> {
    ensure!(
        offset.checked_add(32).is_some_and(|end| end <= length),
        "ECIES slot outside plaintext"
    );
    let mut plaintext = Zeroizing::new(vec![0u8; length]);
    plaintext[offset..offset + 32].copy_from_slice(secret);
    seal(recipient, &plaintext)
}

/// XORs a template that is zero at the secret slot into `seal_slot` output and
/// corrects the tag. GHASH is linear, so the tag of C* xor D differs from C*'s
/// by GHASH_H(D) over equal lengths; the trailing zero block accounts for the
/// length block's position.
pub fn complete_slot(
    wire: &[u8],
    hash_key: &[u8; 16],
    offset: usize,
    template: &[u8],
) -> Result<Vec<u8>> {
    use ghash::{
        GHash,
        universal_hash::{KeyInit as _, UniversalHash},
    };
    ensure!(wire.len() == 97 + template.len(), "ECIES slot wire length");
    ensure!(
        offset
            .checked_add(32)
            .is_some_and(|end| end <= template.len())
            && template[offset..offset + 32] == [0; 32],
        "ECIES template overlaps secret slot"
    );
    k256::PublicKey::from_sec1_bytes(&wire[..65])?;
    let mut ghash = GHash::new(hash_key.into());
    ghash.update_padded(template);
    ghash.update_padded(&[0u8; 16]);
    let delta = ghash.finalize();
    let mut out = wire.to_vec();
    for (tag, d) in out[81..97].iter_mut().zip(delta.iter()) {
        *tag ^= d;
    }
    for (c, t) in out[97..].iter_mut().zip(template) {
        *c ^= t;
    }
    Ok(out)
}

fn seal(recipient: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 16])> {
    use aes_gcm::aes::cipher::BlockEncrypt;
    ensure!(recipient.len() == 33, "invalid contribution point length");
    let raw = recipient;
    let recipient = k256::PublicKey::from_sec1_bytes(raw)?.to_projective();
    ensure!(
        recipient.to_affine().to_encoded_point(true).as_bytes() == raw,
        "noncanonical contribution point"
    );
    ensure!(plaintext.len() <= 64 * 1024, "ECIES plaintext too large");
    let mut secret = Zeroizing::new(Scalar::random(&mut OsRng));
    while *secret == Scalar::ZERO {
        *secret = Scalar::random(&mut OsRng);
    }
    let ephemeral = ProjectivePoint::GENERATOR * *secret;
    let shared = Zeroizing::new(recipient * *secret);
    let mut ikm = Zeroizing::new([0u8; 130]);
    ikm[..65].copy_from_slice(ephemeral.to_affine().to_encoded_point(false).as_bytes());
    ikm[65..].copy_from_slice(shared.to_affine().to_encoded_point(false).as_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, &*ikm)
        .expand(&[], &mut *key)
        .map_err(|_| anyhow::anyhow!("ECIES key derivation failed"))?;
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let mut encrypted = Zeroizing::new(plaintext.to_vec());
    let tag = Cipher::new_from_slice(&*key)
        .map_err(|_| anyhow::anyhow!("invalid ECIES key"))?
        .encrypt_in_place_detached(&nonce.into(), b"", &mut encrypted)
        .map_err(|_| anyhow::anyhow!("ECIES encryption failed"))?;
    let mut hash_key = aes_gcm::aes::Block::default();
    Aes256::new_from_slice(&*key)
        .map_err(|_| anyhow::anyhow!("invalid ECIES key"))?
        .encrypt_block(&mut hash_key);
    let mut wire = ephemeral
        .to_affine()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    wire.extend_from_slice(&nonce);
    wire.extend_from_slice(&tag);
    wire.extend_from_slice(&encrypted);
    Ok((wire, hash_key.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::Aead;

    fn decrypt(secret: &Scalar, wire: &[u8]) -> Result<Vec<u8>> {
        let shared = k256::PublicKey::from_sec1_bytes(&wire[..65])?.to_projective() * *secret;
        let mut ikm = [0u8; 130];
        ikm[..65].copy_from_slice(&wire[..65]);
        ikm[65..].copy_from_slice(shared.to_affine().to_encoded_point(false).as_bytes());
        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(None, &ikm)
            .expand(&[], &mut key)
            .unwrap();
        let mut sealed = wire[97..].to_vec();
        sealed.extend_from_slice(&wire[81..97]);
        Cipher::new_from_slice(&key)?
            .decrypt(wire[65..81].into(), sealed.as_slice())
            .map_err(|_| anyhow::anyhow!("ECIES authentication failed"))
    }

    #[test]
    fn completed_slot_decrypts_to_template_with_secret() -> Result<()> {
        let operator = Scalar::random(&mut OsRng);
        let recipient = (ProjectivePoint::GENERATOR * operator)
            .to_affine()
            .to_encoded_point(true);
        for (length, offset) in [(45 + 32, 45), (400, 45), (1789, 45), (50, 0)] {
            let mut template = vec![0u8; length];
            OsRng.fill_bytes(&mut template);
            template[offset..offset + 32].fill(0);
            let mut secret = [0u8; 32];
            OsRng.fill_bytes(&mut secret);
            let (wire, hash_key) = seal_slot(recipient.as_bytes(), length, offset, &secret)?;
            let complete = complete_slot(&wire, &hash_key, offset, &template)?;
            let mut expected = template.clone();
            expected[offset..offset + 32].copy_from_slice(&secret);
            assert_eq!(decrypt(&operator, &complete)?, expected);

            let mut tampered = complete.clone();
            tampered[97 + offset] ^= 1;
            assert!(decrypt(&operator, &tampered).is_err());
            assert!(complete_slot(&wire, &hash_key, offset, &expected).is_err());
        }
        Ok(())
    }
}
