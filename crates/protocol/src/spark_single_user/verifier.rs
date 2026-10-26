//! Independent pins for ordinary USER signing; old native keys cannot authorize it.
use super::{Digest, REGISTRY, SigningAuthorization};
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
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SigningRole {
    Origin,
    Transfer,
}
struct Asset {
    pin: ArtifactPin,
    file: AuthenticatedFile,
}
impl Asset {
    fn new(pin: ArtifactPin, limit: u64) -> Result<Self> {
        ensure!(pin.sha256 != [0; 32], "zero signing verifier pin");
        let file = AuthenticatedFile::new(&pin.path, &pin.sha256, limit)?;
        Ok(Self { pin, file })
    }
    fn check(&self) -> Result<()> {
        self.file.check(&self.pin.path)
    }
}
pub struct PinnedSingleUserVerifier {
    deployment: Digest,
    config: Config,
    policy: Digest,
    fingerprint: Digest,
    executable: Asset,
    crs: PathBuf,
    keys: BTreeMap<SigningRole, Asset>,
}
pub struct VerifiedSigning {
    statement: Digest,
}
impl VerifiedSigning {
    pub fn statement_digest(&self) -> Digest {
        self.statement
    }
}
impl PinnedSingleUserVerifier {
    pub fn new(
        deployment: Digest,
        config: Config,
        policy: Digest,
        bb: ArtifactPin,
        crs: PathBuf,
        keys: impl IntoIterator<Item = (SigningRole, ArtifactPin)>,
    ) -> Result<Self> {
        ensure!(
            deployment != [0; 32] && policy != [0; 32],
            "single-USER verifier domain"
        );
        config.encode()?;
        ensure!(crs.is_dir(), "single-USER CRS missing");
        let executable = Asset::new(bb, MAX_EXECUTABLE_BYTES)?;
        let mut registry = BTreeMap::new();
        for (role, pin) in keys {
            let asset = Asset::new(pin, VK_BYTES as u64)?;
            ensure!(
                read_bounded(&asset.pin.path, VK_BYTES)?.len() == VK_BYTES,
                "single-USER VK shape"
            );
            ensure!(
                registry.insert(role, asset).is_none(),
                "duplicate single-USER role"
            );
        }
        ensure!(registry.len() == 2, "both single-USER roles must be pinned");
        let fingerprint = hash(&[
            REGISTRY.as_bytes(),
            &deployment,
            &config.encode()?,
            &policy,
            &executable.pin.sha256,
            &registry[&SigningRole::Origin].pin.sha256,
            &registry[&SigningRole::Transfer].pin.sha256,
        ]);
        Ok(Self {
            deployment,
            config,
            policy,
            fingerprint,
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
    pub fn registry_fingerprint(&self) -> Digest {
        self.fingerprint
    }
    pub fn verify(
        &self,
        predecessor: Predecessor,
        expected: &SigningAuthorization,
        proof: &[u8],
        scratch: &Path,
    ) -> Result<VerifiedSigning> {
        ensure!(
            expected.context.deployment == self.deployment
                && expected.config == self.config
                && expected.policy == self.policy,
            "single-USER proof deployment differs"
        );
        ensure!(proof.len() == PROOF_BYTES, "single-USER proof shape");
        let bytes = expected.encode()?;
        let role = match predecessor {
            Predecessor::Origin => SigningRole::Origin,
            Predecessor::Transfer => SigningRole::Transfer,
        };
        let key = &self.keys[&role];
        self.executable.check()?;
        key.check()?;
        verify_proof(
            &self.executable.pin.path,
            &key.pin.path,
            &self.crs,
            scratch,
            proof,
            &bytes,
        )?;
        self.executable.check()?;
        key.check()?;
        Ok(VerifiedSigning {
            statement: hash(&[&bytes]),
        })
    }
}
