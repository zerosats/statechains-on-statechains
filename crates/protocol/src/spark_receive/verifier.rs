//! One separately pinned ordinary receive role; old exit/bootstrap VKs cannot
//! authorize it. No synthetic verifier or caller-chosen role registry exists.
use super::{Digest, REGISTRY, ReceiveAuthorization};
use crate::{
    assets::{AuthenticatedFile, MAX_EXECUTABLE_BYTES, VK_BYTES, read_bounded},
    hash,
    proof::{ArtifactPin, PROOF_BYTES},
    spark_lineage::Config,
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
        ensure!(pin.sha256 != [0; 32], "zero receive verifier pin");
        let file = AuthenticatedFile::new(&pin.path, &pin.sha256, limit)?;
        Ok(Self { pin, file })
    }
    fn check(&self) -> Result<()> {
        self.file.check(&self.pin.path)
    }
}
pub struct PinnedReceiveVerifier {
    deployment: Digest,
    config: Config,
    policy: Digest,
    cluster: Digest,
    fingerprint: Digest,
    executable: Asset,
    key: Asset,
    crs: PathBuf,
}
impl PinnedReceiveVerifier {
    pub fn new(
        deployment: Digest,
        config: Config,
        policy: Digest,
        cluster: Digest,
        bb: ArtifactPin,
        crs: PathBuf,
        vk: ArtifactPin,
    ) -> Result<Self> {
        ensure!(
            deployment != [0; 32] && policy != [0; 32] && cluster != [0; 32],
            "receive verifier deployment"
        );
        config.encode()?;
        let executable = Asset::new(bb, MAX_EXECUTABLE_BYTES)?;
        let key = Asset::new(vk, VK_BYTES as u64)?;
        ensure!(
            crs.is_dir() && read_bounded(&key.pin.path, VK_BYTES)?.len() == VK_BYTES,
            "receive verifier assets"
        );
        let fingerprint = hash(&[
            REGISTRY.as_bytes(),
            &deployment,
            &config.encode()?,
            &policy,
            &cluster,
            &executable.pin.sha256,
            &key.pin.sha256,
        ]);
        Ok(Self {
            deployment,
            config,
            policy,
            cluster,
            fingerprint,
            executable,
            key,
            crs,
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
    pub fn cluster(&self) -> Digest {
        self.cluster
    }
    pub fn registry_fingerprint(&self) -> Digest {
        self.fingerprint
    }
    pub fn verify(
        &self,
        expected: &ReceiveAuthorization,
        proof: &[u8],
        scratch: &Path,
    ) -> Result<Digest> {
        ensure!(
            expected.context.deployment == self.deployment
                && expected.config == self.config
                && expected.policy == self.policy
                && expected.cluster == self.cluster,
            "receive proof differs from pinned policy"
        );
        ensure!(proof.len() == PROOF_BYTES, "receive proof size");
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
