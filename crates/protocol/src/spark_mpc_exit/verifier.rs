//! Separately pinned transfer-authorization role. Its statement size, version
//! and registry differ from the login, ownership, native and receive roles, so
//! no other key verifies it and it verifies nothing else.
use super::{Digest, REGISTRY, TransferAuthStatement};
use crate::{
    assets::{AuthenticatedFile, MAX_EXECUTABLE_BYTES, VK_BYTES, read_bounded},
    hash,
    proof::{ArtifactPin, PROOF_BYTES},
    verifier::verify_proof,
};
use anyhow::{Result, ensure};
use std::path::{Path, PathBuf};

pub struct PinnedTransferAuthVerifier {
    deployment: Digest,
    fingerprint: Digest,
    executable: (ArtifactPin, AuthenticatedFile),
    key: (ArtifactPin, AuthenticatedFile),
    crs: PathBuf,
}
impl PinnedTransferAuthVerifier {
    pub fn new(deployment: Digest, bb: ArtifactPin, crs: PathBuf, vk: ArtifactPin) -> Result<Self> {
        ensure!(
            deployment != [0; 32] && bb.sha256 != [0; 32] && vk.sha256 != [0; 32],
            "Spark transfer auth verifier pins"
        );
        let executable = AuthenticatedFile::new(&bb.path, &bb.sha256, MAX_EXECUTABLE_BYTES)?;
        let key = AuthenticatedFile::new(&vk.path, &vk.sha256, VK_BYTES as u64)?;
        ensure!(
            crs.is_dir() && read_bounded(&vk.path, VK_BYTES)?.len() == VK_BYTES,
            "Spark transfer auth verifier assets"
        );
        let fingerprint = hash(&[REGISTRY.as_bytes(), &deployment, &bb.sha256, &vk.sha256]);
        Ok(Self {
            deployment,
            fingerprint,
            executable: (bb, executable),
            key: (vk, key),
            crs,
        })
    }
    pub fn deployment(&self) -> Digest {
        self.deployment
    }
    pub fn registry_fingerprint(&self) -> Digest {
        self.fingerprint
    }
    fn check(&self) -> Result<()> {
        self.executable.1.check(&self.executable.0.path)?;
        self.key.1.check(&self.key.0.path)
    }
    /// Returns the digest of the exact verified statement bytes.
    pub fn verify(
        &self,
        expected: &TransferAuthStatement,
        proof: &[u8],
        scratch: &Path,
    ) -> Result<Digest> {
        ensure!(proof.len() == PROOF_BYTES, "Spark transfer auth proof size");
        let bytes = expected.encode()?;
        self.check()?;
        verify_proof(
            &self.executable.0.path,
            &self.key.0.path,
            &self.crs,
            scratch,
            proof,
            &bytes,
        )?;
        self.check()?;
        Ok(hash(&[&bytes]))
    }
}
