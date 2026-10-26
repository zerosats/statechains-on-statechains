//! Authenticated two-role native exit registry, separate from ownership pins.
use super::{Digest, ExitAuthorization, ORDINARY_REGISTRY, REGISTRY};
use crate::{
    assets::{AuthenticatedFile, MAX_EXECUTABLE_BYTES, VK_BYTES, read_bounded},
    hash,
    proof::{ArtifactPin, PROOF_BYTES},
    spark_lineage::Config,
    spark_wire::Predecessor,
    verifier::verify_proof,
};
use anyhow::{Result, ensure};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NativeExitRole {
    Origin,
    Transfer,
}
struct Asset {
    pin: ArtifactPin,
    file: AuthenticatedFile,
}
impl Asset {
    fn new(pin: ArtifactPin, limit: u64) -> Result<Self> {
        ensure!(pin.sha256 != [0; 32], "zero native verifier asset pin");
        let file = AuthenticatedFile::new(&pin.path, &pin.sha256, limit)?;
        Ok(Self { pin, file })
    }
    fn check(&self) -> Result<()> {
        self.file.check(&self.pin.path)
    }
}
pub struct PinnedNativeExitVerifier {
    deployment: Digest,
    config: Config,
    policy: Digest,
    cluster: Digest,
    fingerprint: Digest,
    ordinary: bool,
    executable: Asset,
    crs: PathBuf,
    keys: BTreeMap<NativeExitRole, Asset>,
}
pub struct VerifiedNativeExit {
    statement_digest: Digest,
}
impl VerifiedNativeExit {
    pub fn statement_digest(&self) -> Digest {
        self.statement_digest
    }
}
impl PinnedNativeExitVerifier {
    pub fn new(
        deployment: Digest,
        config: Config,
        policy: Digest,
        cluster: Digest,
        bb: ArtifactPin,
        crs: PathBuf,
        keys: impl IntoIterator<Item = (NativeExitRole, ArtifactPin)>,
    ) -> Result<Self> {
        Self::new_profile(deployment, config, policy, cluster, bb, crs, keys, false)
    }
    pub fn new_ordinary(
        deployment: Digest,
        config: Config,
        policy: Digest,
        cluster: Digest,
        bb: ArtifactPin,
        crs: PathBuf,
        keys: impl IntoIterator<Item = (NativeExitRole, ArtifactPin)>,
    ) -> Result<Self> {
        Self::new_profile(deployment, config, policy, cluster, bb, crs, keys, true)
    }
    #[allow(clippy::too_many_arguments)]
    fn new_profile(
        deployment: Digest,
        config: Config,
        policy: Digest,
        cluster: Digest,
        bb: ArtifactPin,
        crs: PathBuf,
        keys: impl IntoIterator<Item = (NativeExitRole, ArtifactPin)>,
        ordinary: bool,
    ) -> Result<Self> {
        ensure!(
            deployment != [0; 32] && policy != [0; 32] && cluster != [0; 32],
            "native verifier domain"
        );
        config.encode()?;
        let executable = Asset::new(bb, MAX_EXECUTABLE_BYTES)?;
        ensure!(crs.is_dir(), "native CRS missing");
        let mut registry = BTreeMap::new();
        for (role, pin) in keys {
            let asset = Asset::new(pin, VK_BYTES as u64)?;
            ensure!(
                read_bounded(&asset.pin.path, VK_BYTES)?.len() == VK_BYTES,
                "native exit key shape"
            );
            ensure!(
                registry.insert(role, asset).is_none(),
                "duplicate native exit role"
            );
        }
        ensure!(registry.len() == 2, "both native exit roles must be pinned");
        let registry_name = if ordinary {
            ORDINARY_REGISTRY
        } else {
            REGISTRY
        };
        let fingerprint = hash(&[
            registry_name.as_bytes(),
            &deployment,
            &config.encode()?,
            &policy,
            &cluster,
            &executable.pin.sha256,
            &registry[&NativeExitRole::Origin].pin.sha256,
            &registry[&NativeExitRole::Transfer].pin.sha256,
        ]);
        Ok(Self {
            deployment,
            config,
            policy,
            cluster,
            fingerprint,
            ordinary,
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
    pub fn cluster(&self) -> Digest {
        self.cluster
    }
    pub fn registry_fingerprint(&self) -> Digest {
        self.fingerprint
    }
    pub fn is_ordinary(&self) -> bool {
        self.ordinary
    }
    /// The caller supplies the predecessor kind from current durable state.
    /// A native proof does not authorize ciphertext export or release a lock.
    pub fn verify(
        &self,
        predecessor: Predecessor,
        expected: &ExitAuthorization,
        proof: &[u8],
        scratch: &Path,
    ) -> Result<VerifiedNativeExit> {
        ensure!(
            expected.context.deployment == self.deployment
                && expected.config == self.config
                && expected.policy == self.policy
                && expected.cluster == self.cluster,
            "native exit differs from pinned deployment"
        );
        ensure!(proof.len() == PROOF_BYTES, "native exit proof shape");
        let statement = expected.encode()?;
        let role = match predecessor {
            Predecessor::Origin => NativeExitRole::Origin,
            Predecessor::Transfer => NativeExitRole::Transfer,
        };
        let key = self
            .keys
            .get(&role)
            .ok_or_else(|| anyhow::anyhow!("native exit role missing"))?;
        self.executable.check()?;
        key.check()?;
        verify_proof(
            &self.executable.pin.path,
            &key.pin.path,
            &self.crs,
            scratch,
            proof,
            &statement,
        )?;
        self.executable.check()?;
        key.check()?;
        Ok(VerifiedNativeExit {
            statement_digest: hash(&[&statement]),
        })
    }
}
