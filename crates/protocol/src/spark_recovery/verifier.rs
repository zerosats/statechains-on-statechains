//! Pinned external verification of the recovery primitive only.
//!
//! This result deliberately cannot authorize a signer transition. A composed
//! Spark ownership role must also authenticate admission, history, current state,
//! and frozen preparations. Pins come from trusted local configuration.
use super::RecoveryAuthorization;
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
        ensure!(pin.sha256 != [0; 32], "empty Spark recovery asset pin");
        let file = AuthenticatedFile::new(&pin.path, &pin.sha256, limit)?;
        Ok(Self { pin, file })
    }

    fn check(&self) -> Result<()> {
        self.file.check(&self.pin.path)
    }
}

pub struct PinnedRecoveryVerifier {
    deployment: [u8; 32],
    executable: Asset,
    key: Asset,
    crs: PathBuf,
}

/// A checked dual-refund signing relation, without ownership or chain authority.
pub struct VerifiedRecoveryRelation {
    statement_digest: [u8; 32],
}

impl VerifiedRecoveryRelation {
    pub fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }
}

impl PinnedRecoveryVerifier {
    /// This registry is configured by the trusted deployment, never by a peer
    /// submitting a proof. The key pin must name the new Spark relation, not one
    /// of the Bitcoin ownership-role keys. CRS selection is trusted local config.
    pub fn new(
        deployment: [u8; 32],
        executable: ArtifactPin,
        key: ArtifactPin,
        crs: PathBuf,
    ) -> Result<Self> {
        ensure!(deployment != [0; 32], "empty Spark recovery deployment");
        let executable = Asset::new(executable, MAX_EXECUTABLE_BYTES)?;
        let key = Asset::new(key, VK_BYTES as u64)?;
        ensure!(
            read_bounded(&key.pin.path, VK_BYTES)?.len() == VK_BYTES,
            "Spark recovery verification key shape"
        );
        ensure!(crs.is_dir(), "Spark recovery CRS directory missing");
        Ok(Self {
            deployment,
            executable,
            key,
            crs,
        })
    }

    pub fn verify(
        &self,
        expected: &RecoveryAuthorization,
        proof: &[u8],
        scratch: &Path,
    ) -> Result<VerifiedRecoveryRelation> {
        ensure!(
            expected.context.deployment == self.deployment,
            "Spark recovery deployment mismatch"
        );
        ensure!(proof.len() == PROOF_BYTES, "Spark recovery proof shape");
        let statement = expected.encode()?;
        self.executable.check()?;
        self.key.check()?;
        // Existing process deadlines, worker limits and exact packed ABI apply.
        verify_proof(
            &self.executable.pin.path,
            &self.key.pin.path,
            &self.crs,
            scratch,
            proof,
            &statement,
        )?;
        self.executable.check()?;
        self.key.check()?;
        Ok(VerifiedRecoveryRelation {
            statement_digest: hash(&[&statement]),
        })
    }
}
