//! Pinned Spark ownership roles, scoped to one authenticated deployment.
//! Pins and recursive hashes must be paired by the trusted local manifest;
//! proof submitters cannot choose the registry or the expected statement.
use super::{Config, Digest, Handover, Issuance};
use crate::{
    assets::{AuthenticatedFile, MAX_EXECUTABLE_BYTES, VK_BYTES, read_bounded},
    hash,
    proof::{ArtifactPin, PROOF_BYTES},
    spark_wire::Predecessor,
    verifier::verify_proof,
};
use anyhow::{Result, ensure};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SparkRole {
    Deposit,
    SenderFromOrigin,
    SenderFromTransfer,
    Receiver,
}

struct Asset {
    pin: ArtifactPin,
    file: AuthenticatedFile,
}
impl Asset {
    fn new(pin: ArtifactPin, limit: u64) -> Result<Self> {
        ensure!(pin.sha256 != [0; 32], "empty Spark ownership asset pin");
        let file = AuthenticatedFile::new(&pin.path, &pin.sha256, limit)?;
        Ok(Self { pin, file })
    }
    fn check(&self) -> Result<()> {
        self.file.check(&self.pin.path)
    }
}

pub struct PinnedSparkVerifier {
    deployment: Digest,
    config: Config,
    policy: Digest,
    executable: Asset,
    crs: PathBuf,
    keys: BTreeMap<SparkRole, Asset>,
}

/// A checked mathematical role, not a fresh signer head or chain observation.
/// The engine must still match frozen state and revalidate the current revision.
pub struct VerifiedSparkRole {
    role: SparkRole,
    statement_digest: Digest,
}
impl VerifiedSparkRole {
    pub fn role(&self) -> SparkRole {
        self.role
    }
    pub fn statement_digest(&self) -> Digest {
        self.statement_digest
    }
}

impl PinnedSparkVerifier {
    pub fn new(
        deployment: Digest,
        config: Config,
        policy: Digest,
        bb: ArtifactPin,
        crs: PathBuf,
        keys: impl IntoIterator<Item = (SparkRole, ArtifactPin)>,
    ) -> Result<Self> {
        ensure!(
            deployment != [0; 32] && policy != [0; 32],
            "empty Spark ownership deployment or policy"
        );
        config.encode()?;
        let executable = Asset::new(bb, MAX_EXECUTABLE_BYTES)?;
        ensure!(crs.is_dir(), "Spark ownership CRS missing");
        let mut registry = BTreeMap::new();
        for (role, pin) in keys {
            let key = Asset::new(pin, VK_BYTES as u64)?;
            ensure!(
                read_bounded(&key.pin.path, VK_BYTES)?.len() == VK_BYTES,
                "Spark ownership VK shape"
            );
            ensure!(
                registry.insert(role, key).is_none(),
                "duplicate Spark ownership role"
            );
        }
        ensure!(
            registry.len() == 4,
            "all four Spark ownership roles must be pinned"
        );
        Ok(Self {
            deployment,
            config,
            policy,
            executable,
            crs,
            keys: registry,
        })
    }

    pub fn deployment(&self) -> Digest {
        self.deployment
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn policy(&self) -> Digest {
        self.policy
    }

    /// Exact immutable key bytes for an owner's private recursive witness.
    /// This is not a verification result or authority to issue signatures.
    pub fn recursive_key_bytes(&self, role: SparkRole) -> Result<Vec<u8>> {
        let key = self
            .keys
            .get(&role)
            .ok_or_else(|| anyhow::anyhow!("Spark ownership role missing"))?;
        key.check()?;
        let bytes = read_bounded(&key.pin.path, VK_BYTES)?;
        ensure!(
            bytes.len() == VK_BYTES && hash(&[&bytes]) == key.pin.sha256,
            "Spark recursive key differs from authenticated asset"
        );
        Ok(bytes)
    }

    fn require(&self, deployment: &Digest, config: &Config, policy: &Digest) -> Result<()> {
        ensure!(
            *deployment == self.deployment && *config == self.config && *policy == self.policy,
            "Spark ownership statement differs from pinned deployment"
        );
        Ok(())
    }

    pub fn verify_handover(
        &self,
        predecessor: Predecessor,
        expected: &Handover,
        proof: &[u8],
        scratch: &Path,
    ) -> Result<VerifiedSparkRole> {
        self.require(
            &expected.intent.deployment,
            &expected.config,
            &expected.policy,
        )?;
        let role = match predecessor {
            Predecessor::Origin => SparkRole::SenderFromOrigin,
            Predecessor::Transfer => SparkRole::SenderFromTransfer,
        };
        self.verify(role, &expected.encode()?, proof, scratch)
    }

    pub fn verify_issuance(
        &self,
        origin: bool,
        expected: &Issuance,
        proof: &[u8],
        scratch: &Path,
    ) -> Result<VerifiedSparkRole> {
        self.require(
            &expected.recovery.context.deployment,
            &expected.config,
            &expected.recovery.policy,
        )?;
        let role = if origin {
            SparkRole::Deposit
        } else {
            SparkRole::Receiver
        };
        self.verify(role, &expected.encode()?, proof, scratch)
    }

    fn verify(
        &self,
        role: SparkRole,
        statement: &[u8],
        proof: &[u8],
        scratch: &Path,
    ) -> Result<VerifiedSparkRole> {
        ensure!(proof.len() == PROOF_BYTES, "Spark ownership proof shape");
        let key = self
            .keys
            .get(&role)
            .ok_or_else(|| anyhow::anyhow!("Spark ownership role missing"))?;
        self.executable.check()?;
        key.check()?;
        verify_proof(
            &self.executable.pin.path,
            &key.pin.path,
            &self.crs,
            scratch,
            proof,
            statement,
        )?;
        self.executable.check()?;
        key.check()?;
        Ok(VerifiedSparkRole {
            role,
            statement_digest: hash(&[statement]),
        })
    }
}
