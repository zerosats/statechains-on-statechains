//! Only the ECIES ephemeral point reaches the signer. Decryption combines
//! group contributions locally; neither participant combines private scalars.
use super::*;
use aes_gcm::{
    AesGcm,
    aead::{AeadInPlace, KeyInit, consts::U16},
};
use zark_spark_claim_mpc::identity::{EcdhProof, ecdh_verify};
impl JointIdentityJournal {
    pub fn decrypt_request(&mut self, cipher: &[u8]) -> Result<Request> {
        ensure!(
            !self.record.native_scope,
            "native exit identity does not authorize decryption"
        );
        ensure!(
            cipher.len() == 129 && cipher[0] == 4,
            "incoming identity cipher size/encoding"
        );
        let ephemeral = &cipher[..65];
        k256::PublicKey::from_sec1_bytes(ephemeral)?;
        let id = hex::encode(hash(&[ephemeral]));
        if let Some(saved) = self.record.decryption.get(&id) {
            self.persist()?;
            return Request::decode(saved);
        }
        ensure!(
            self.record.decryption.len() < 16,
            "identity decryption capacity"
        );
        let req = self.signed(
            identity_decrypt_intent(&self.record.intent, ephemeral)?,
            Command::IdentityDecrypt {
                ephemeral: ephemeral.into(),
            },
        )?;
        self.record.decryption.insert(id, req.encode()?);
        self.persist()?;
        Ok(req)
    }
    pub fn decrypt_incoming(&self, cipher: &[u8], response: &Value) -> Result<Zeroizing<Digest>> {
        ensure!(
            cipher.len() == 129 && cipher[0] == 4,
            "incoming identity cipher size/encoding"
        );
        let ephemeral = &cipher[..65];
        let id = hex::encode(hash(&[ephemeral]));
        let req = Request::decode(
            self.record
                .decryption
                .get(&id)
                .context("identity decryption not frozen")?,
        )?;
        let partial: Vec<u8> = serde_json::from_value(response["partial"].clone())?;
        let proof: EcdhProof = serde_json::from_value(response["proof"].clone())?;
        let server = point(&self.server()?)?.to_affine().to_encoded_point(true);
        ecdh_verify(
            server.as_bytes(),
            ephemeral,
            &partial,
            &req.digest()?,
            &proof,
        )?;
        let shared = k256::PublicKey::from_sec1_bytes(ephemeral)?.to_projective()
            * scalar(&self.record.user)?
            + k256::PublicKey::from_sec1_bytes(&partial)?.to_projective();
        point_bytes(shared)?;
        let mut ikm = Zeroizing::new(ephemeral.to_vec());
        ikm.extend_from_slice(shared.to_affine().to_encoded_point(false).as_bytes());
        let mut key = Zeroizing::new([0; 32]);
        hkdf::Hkdf::<sha2::Sha256>::new(None, &ikm)
            .expand(&[], &mut *key)
            .map_err(|_| anyhow::anyhow!("joint identity HKDF"))?;
        let nonce: [u8; 16] = cipher[65..81].try_into()?;
        let tag: [u8; 16] = cipher[81..97].try_into()?;
        let mut plain = Zeroizing::new(cipher[97..].to_vec());
        AesGcm::<aes::Aes256, U16>::new_from_slice(&*key)
            .unwrap()
            .decrypt_in_place_detached(&nonce.into(), b"", &mut plain, &tag.into())
            .map_err(|_| anyhow::anyhow!("incoming joint identity authentication"))?;
        ensure!(
            scalar(&plain)? != k256::Scalar::ZERO,
            "zero incoming temporary USER scalar"
        );
        self.persist()?;
        Ok(Zeroizing::new(plain.as_slice().try_into()?))
    }
}
