//! Current-owner private certificate. Historical issuance, server points and
//! recovery openings never accompany a recipient offer; only its sender proof
//! does. Native reconstruction alone is deliberately not proof verification.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zark_protocol::{
    blind_signing::verify_partial,
    hash,
    proof::PROOF_BYTES,
    spark_lineage::{Certificate, Issuance, PinnedSparkVerifier, server_commitment},
    spark_wire::Predecessor,
};
use zeroize::{Zeroize, Zeroizing};

const MAX_RECORD: usize = 80 * 1024;
pub struct PrivateCertificate {
    kind: Predecessor,
    authorization: Issuance,
    proof: Vec<u8>,
    partials: [[u8; 32]; 2],
    server_salt: Zeroizing<[u8; 32]>,
    origin_signature: Option<Vec<u8>>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    version: u32,
    kind: Predecessor,
    authorization: String,
    proof: String,
    partials: [[u8; 32]; 2],
    server_salt: [u8; 32],
    origin_signature: Option<String>,
}
impl Drop for Record {
    fn drop(&mut self) {
        self.authorization.zeroize();
        self.proof.zeroize();
        self.partials.zeroize();
        self.server_salt.zeroize();
        if let Some(s) = &mut self.origin_signature {
            s.zeroize();
        }
    }
}
impl Drop for PrivateCertificate {
    fn drop(&mut self) {
        self.proof.zeroize();
        self.partials.zeroize();
        if let Some(s) = &mut self.origin_signature {
            s.zeroize();
        }
    }
}

impl PrivateCertificate {
    pub fn from_issued(
        kind: Predecessor,
        authorization: Issuance,
        proof: Vec<u8>,
        partials: [[u8; 32]; 2],
        server_salt: [u8; 32],
        origin_signature: Option<Vec<u8>>,
    ) -> Result<Self> {
        let value = Self {
            kind,
            authorization,
            proof,
            partials,
            server_salt: Zeroizing::new(server_salt),
            origin_signature,
        };
        value.native_lineage()?;
        Ok(value)
    }

    /// Signature equations and state reconstruction only. Call `verify` before
    /// treating this as an authenticated origin or recursive transfer lineage.
    pub fn native_lineage(&self) -> Result<Certificate> {
        ensure!(
            self.proof.len() == PROOF_BYTES,
            "private Spark certificate proof shape"
        );
        self.authorization.encode()?;
        let r = &self.authorization.recovery;
        ensure!(
            server_commitment(
                &r.context.deployment,
                &r.context.coin,
                &r.server,
                &self.server_salt
            )? == self.authorization.server_share,
            "private Spark certificate server opening"
        );
        for i in 0..2 {
            verify_partial(
                &r.server,
                &r.branches[i].server_nonce,
                &r.branches[i].challenge,
                &self.partials[i],
            )?;
        }
        let certificate = Certificate::from_issuance(&self.authorization, &self.partials)?;
        match self.kind {
            Predecessor::Origin => certificate.verify_origin_attestation(
                &self
                    .origin_signature
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("missing private Spark origin attestation"))?
                    .as_slice()
                    .try_into()?,
            )?,
            Predecessor::Transfer => ensure!(
                self.origin_signature.is_none(),
                "transfer certificate cannot carry an origin attestation"
            ),
        }
        Ok(certificate)
    }

    pub fn verify(&self, verifier: &PinnedSparkVerifier, scratch: &Path) -> Result<Certificate> {
        let certificate = self.native_lineage()?;
        let checked = verifier.verify_issuance(
            self.kind == Predecessor::Origin,
            &self.authorization,
            &self.proof,
            scratch,
        )?;
        ensure!(
            checked.statement_digest() == hash(&[&self.authorization.encode()?]),
            "verified private Spark statement changed"
        );
        Ok(certificate)
    }

    pub fn identity(&self) -> Result<[u8; 32]> {
        Ok(hash(&[&self.native_lineage()?.encode()?]))
    }
    pub fn kind(&self) -> Predecessor {
        self.kind
    }
    pub fn authorization(&self) -> &Issuance {
        &self.authorization
    }
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }
    pub fn partials(&self) -> [[u8; 32]; 2] {
        self.partials
    }
    pub fn server_salt(&self) -> &[u8; 32] {
        &self.server_salt
    }
    pub fn origin_signature(&self) -> Option<&[u8]> {
        self.origin_signature.as_deref()
    }

    pub fn encode_private(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.native_lineage()?;
        let record = Record {
            schema: "zark-spark-private-certificate".into(),
            version: 1,
            kind: self.kind,
            authorization: hex::encode(self.authorization.encode()?),
            proof: hex::encode(&self.proof),
            partials: self.partials,
            server_salt: *self.server_salt,
            origin_signature: self.origin_signature.as_ref().map(hex::encode),
        };
        let bytes = Zeroizing::new(serde_json::to_vec(&record)?);
        ensure!(bytes.len() <= MAX_RECORD, "private Spark certificate size");
        Ok(bytes)
    }

    /// Reopening checks canonical bytes and native equations; a separate call
    /// to the pinned verifier is mandatory before any ownership operation.
    pub fn decode_private(bytes: &[u8]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_RECORD,
            "private Spark certificate size"
        );
        let record: Record = serde_json::from_slice(bytes)?;
        ensure!(
            record.schema == "zark-spark-private-certificate" && record.version == 1,
            "private Spark certificate schema"
        );
        let authorization = Zeroizing::new(hex::decode(&record.authorization)?);
        let value = Self::from_issued(
            record.kind,
            Issuance::decode(&authorization)?,
            hex::decode(&record.proof)?,
            record.partials,
            record.server_salt,
            record
                .origin_signature
                .as_ref()
                .map(hex::decode)
                .transpose()?,
        )?;
        ensure!(
            value.encode_private()?.as_slice() == bytes,
            "noncanonical private Spark certificate"
        );
        Ok(value)
    }
}
