//! Separately pinned auth role. No ownership, native or receive key can
//! authorize it, and it cannot authorize them: its statement has its own size,
//! version and registry fingerprint.
use super::{AuthStatement, Digest, REGISTRY};
use crate::{
    assets::{AuthenticatedFile, MAX_EXECUTABLE_BYTES, VK_BYTES, read_bounded},
    hash,
    proof::{ArtifactPin, PROOF_BYTES},
    verifier::verify_proof,
};
use anyhow::{Result, ensure};
use std::path::{Path, PathBuf};

struct Asset {
    pin: ArtifactPin,
    file: AuthenticatedFile,
}
impl Asset {
    fn new(pin: ArtifactPin, limit: u64) -> Result<Self> {
        ensure!(pin.sha256 != [0; 32], "zero Spark auth verifier pin");
        let file = AuthenticatedFile::new(&pin.path, &pin.sha256, limit)?;
        Ok(Self { pin, file })
    }
    fn check(&self) -> Result<()> {
        self.file.check(&self.pin.path)
    }
}

pub struct PinnedAuthVerifier {
    deployment: Digest,
    fingerprint: Digest,
    executable: Asset,
    key: Asset,
    crs: PathBuf,
}
impl PinnedAuthVerifier {
    pub fn new(deployment: Digest, bb: ArtifactPin, crs: PathBuf, vk: ArtifactPin) -> Result<Self> {
        ensure!(deployment != [0; 32], "Spark auth verifier deployment");
        let executable = Asset::new(bb, MAX_EXECUTABLE_BYTES)?;
        let key = Asset::new(vk, VK_BYTES as u64)?;
        ensure!(
            crs.is_dir() && read_bounded(&key.pin.path, VK_BYTES)?.len() == VK_BYTES,
            "Spark auth verifier assets"
        );
        let fingerprint = hash(&[
            REGISTRY.as_bytes(),
            &deployment,
            &executable.pin.sha256,
            &key.pin.sha256,
        ]);
        Ok(Self {
            deployment,
            fingerprint,
            executable,
            key,
            crs,
        })
    }
    pub fn deployment(&self) -> Digest {
        self.deployment
    }
    pub fn registry_fingerprint(&self) -> Digest {
        self.fingerprint
    }
    /// Returns the digest of the exact verified statement bytes.
    pub fn verify(&self, expected: &AuthStatement, proof: &[u8], scratch: &Path) -> Result<Digest> {
        ensure!(proof.len() == PROOF_BYTES, "Spark auth proof size");
        let bytes = expected.encode()?;
        self.executable.check()?;
        self.key.check()?;
        verify_proof(
            &self.executable.pin.path,
            &self.key.pin.path,
            &self.crs,
            scratch,
            proof,
            &bytes,
        )?;
        self.executable.check()?;
        self.key.check()?;
        Ok(hash(&[&bytes]))
    }
}
