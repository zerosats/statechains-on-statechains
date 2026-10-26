//! Wallet-local transfer authorization inputs. Never send these to a signer.
use super::{
    MAX_LEAF_SIGNATURE_LEN, MIN_LEAF_SIGNATURE_LEN, POSITIONS, SECRET_CIPHER_LEN,
    TransferAuthHeader, TransferAuthStatement, blinding_commitment,
    payload::{AuthorizationPayload, AuthorizedLeaf, LeafRefunds, SCHEME_ECDSA, refund_digest},
};
use crate::{
    hash, point, point_bytes,
    spark_auth::{AuthBlinding, IdentityKey},
    spark_lineage::Digest,
    spark_native::PlanOpening,
};
use anyhow::{Result, ensure};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use zeroize::Zeroizing;

pub struct TransferAuthWitness<'a> {
    pub key: &'a IdentityKey,
    pub plan: &'a PlanOpening,
    pub secret_cipher: &'a [u8],
    /// Strict-DER ECDSA over `SHA256(leaf_id || transfer_id || secret_cipher)`,
    /// which ordinary Spark receivers still verify.
    pub leaf_signature: &'a [u8],
    pub wallet_proofs: [[u8; 33]; 2],
    pub blinding: &'a AuthBlinding,
}

impl TransferAuthWitness<'_> {
    fn owner(&self) -> Result<[u8; 64]> {
        point_bytes(self.key.joint)
    }
    /// The plan must name the UUIDs the signer sealed and the joint key.
    pub fn check_header(&self, header: &TransferAuthHeader) -> Result<()> {
        ensure!(
            header.key_commitment == self.key.commitment()
                && header.server == self.key.server
                && header.plan == self.plan.commitment(self.owner()?)?
                && header.transfer_id == self.plan.transfer_id
                && header.leaf_id == self.plan.leaf_id,
            "Spark transfer auth witness differs from header"
        );
        ensure!(
            self.secret_cipher.len() == SECRET_CIPHER_LEN
                && hash(&[self.secret_cipher]) == self.plan.mask_cipher_sha256,
            "Spark transfer auth mask ciphertext"
        );
        ensure!(
            (MIN_LEAF_SIGNATURE_LEN..=MAX_LEAF_SIGNATURE_LEN).contains(&self.leaf_signature.len()),
            "Spark transfer auth leaf signature length"
        );
        for proof in &self.wallet_proofs {
            let parsed = k256::PublicKey::from_sec1_bytes(proof)?;
            ensure!(
                parsed.to_encoded_point(true).as_bytes() == proof,
                "noncanonical wallet MPC commitment"
            );
        }
        Ok(())
    }

    /// The exact bytes operators recompute in `verifyMpcAuthorizationSignature`.
    pub fn payload(&self, header: &TransferAuthHeader) -> Result<AuthorizationPayload> {
        self.check_header(header)?;
        let owner = self.owner()?;
        let bodies = self.plan.bodies(owner)?;
        let compressed = |raw: &[u8; 64]| -> Result<[u8; 33]> {
            Ok(point(raw)?
                .to_affine()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()?)
        };
        Ok(AuthorizationPayload {
            transfer_id: self.plan.transfer_id,
            expiry: self.plan.expiry,
            positions: POSITIONS.to_vec(),
            leaves: vec![AuthorizedLeaf {
                leaf_id: self.plan.leaf_id,
                amount: self.plan.amount,
                owner_signing: compressed(&owner)?,
                mask_commitment: compressed(&self.plan.mask_user)?,
                receiver_identity: self.plan.receiver_identity,
                secret_cipher: self.secret_cipher.to_vec(),
                signature_scheme: SCHEME_ECDSA,
                signature: self.leaf_signature.to_vec(),
                proofs: vec![self.wallet_proofs.to_vec(), header.signer_proofs.to_vec()],
            }],
            refund_digest: refund_digest(&[LeafRefunds {
                leaf_id: self.plan.leaf_id,
                cpfp: bodies.sighashes[0],
                direct: None,
                direct_from_cpfp: Some(bodies.sighashes[1]),
            }]),
        })
    }

    pub fn commitment(&self, header: &TransferAuthHeader) -> Result<Digest> {
        let message = self.payload(header)?.hash()?;
        let b = self.blinding;
        blinding_commitment(header, &message, &b.alpha, &b.beta, &b.salt)
    }

    pub fn prover_toml(&self, statement: &TransferAuthStatement) -> Result<Zeroizing<String>> {
        let header = &statement.header;
        ensure!(
            statement.commitment == self.commitment(header)?,
            "Spark transfer auth witness commitment"
        );
        let bytes = statement.encode()?;
        let owner = self.owner()?;
        let bodies = self.plan.bodies(owner)?;
        let packed = crate::public_fields(&bytes)
            .chunks_exact(32)
            .map(|b| format!("\"0x{}\"", hex::encode(b)))
            .collect::<Vec<_>>()
            .join(",");
        let mut signature = [0u8; MAX_LEAF_SIGNATURE_LEN];
        signature[..self.leaf_signature.len()].copy_from_slice(self.leaf_signature);
        let mut out = Zeroizing::new(format!(
            "packed = [{packed}]\nstatement = {}\n",
            array(&bytes)
        ));
        for (name, value) in [
            ("user", &self.key.user[..]),
            ("key_salt", &self.key.salt[..]),
            ("canonical", &self.plan.canonical_plan(owner)?[..]),
            ("plan_salt", &self.plan.salt[..]),
            ("root", &bodies.root[..]),
            ("refund_cpfp", &bodies.new_refunds[0][..]),
            ("refund_direct", &bodies.new_refunds[1][..]),
            ("secret_cipher", self.secret_cipher),
            ("leaf_signature", &signature[..]),
            ("alpha", &self.blinding.alpha[..]),
            ("beta", &self.blinding.beta[..]),
            ("salt", &self.blinding.salt[..]),
        ] {
            out.push_str(&format!("{name} = {}\n", array(value)));
        }
        out.push_str(&format!("signature_len = {}\n", self.leaf_signature.len()));
        out.push_str(&format!(
            "wallet_proofs = [{},{}]\n",
            array(&self.wallet_proofs[0]),
            array(&self.wallet_proofs[1])
        ));
        Ok(out)
    }
}

fn array(bytes: &[u8]) -> String {
    format!(
        "[{}]",
        bytes
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}
