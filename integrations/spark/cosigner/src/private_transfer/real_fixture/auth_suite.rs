//! Opt-in blind Schnorr Spark login assets. A deployment either pins this
//! verifier before its first allocation or never uses it: the signer config
//! hash covers it, so a retained fixture cannot add or drop it later.
use super::suite::{Pin, Program, hex_digest};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
use zark_protocol::{
    assets::{MAX_CIRCUIT_BYTES, MAX_VK_METADATA_BYTES, VK_BYTES, read_bounded, sha256_bounded},
    spark_auth::{ENCODED_LEN as STATEMENT_LEN, PinnedAuthVerifier, REGISTRY},
    storage::atomic_write,
};

const DEPLOYMENT_FILE: &str = "deployment-auth.json";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    version: u32,
    registry: String,
    sources: BTreeMap<String, String>,
    role_hashes: [[u8; 32]; 1],
    nargo: Pin,
    bb: Pin,
    crs: PathBuf,
    programs: BTreeMap<String, Program>,
}

/// Recorded per fixture so a resumed run reopens the exact signer profile.
#[derive(Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct DeploymentRecord {
    registry: String,
    vk_sha256: [u8; 32],
}

pub(super) struct AuthSuite {
    manifest: Manifest,
}
impl AuthSuite {
    pub fn load_optional(nargo: &Pin, bb: &Pin, crs: &Path) -> Result<Option<Self>> {
        let Some(path) = std::env::var_os("ZARK_SPARK_AUTH_SUITE") else {
            return Ok(None);
        };
        let path = PathBuf::from(path);
        ensure!(path.is_absolute(), "auth manifest must be absolute");
        let m: Manifest = serde_json::from_slice(&fs::read(path)?)?;
        ensure!(
            m.schema == "zark-spark-auth-proof-suite"
                && m.version == 1
                && m.registry == REGISTRY
                && m.programs.len() == 1,
            "auth suite schema"
        );
        ensure!(
            m.nargo.path == nargo.path
                && m.nargo.sha256 == nargo.sha256
                && m.bb.path == bb.path
                && m.bb.sha256 == bb.sha256
                && m.crs == crs,
            "auth proving runtime differs"
        );
        let p = m.programs.get("auth").context("auth program missing")?;
        ensure!(
            p.public_bytes == STATEMENT_LEN
                && p.directory.is_absolute()
                && p.directory.join("Nargo.toml").is_file(),
            "auth program shape"
        );
        p.artifact.check(MAX_CIRCUIT_BYTES as u64)?;
        p.vk.check(VK_BYTES as u64)?;
        let metadata =
            p.vk.path
                .parent()
                .context("auth VK parent")?
                .join("vk.json");
        ensure!(
            sha256_bounded(&metadata, MAX_VK_METADATA_BYTES as u64)?
                == hex_digest(&p.metadata_sha256)?,
            "auth VK metadata pin"
        );
        let v: serde_json::Value =
            serde_json::from_slice(&read_bounded(&metadata, MAX_VK_METADATA_BYTES)?)?;
        ensure!(
            hex_digest(
                v["hash"]
                    .as_str()
                    .context("auth recursive key hash")?
                    .trim_start_matches("0x")
            )? == m.role_hashes[0]
                && v["scheme"] == "ultra_honk"
                && v["bb_version"] == "5.2.0",
            "auth recursive VK metadata"
        );
        let fields = v["vk"].as_array().context("auth VK fields")?;
        ensure!(fields.len() == 115, "auth recursive VK size");
        let mut binary = Vec::new();
        for f in fields {
            binary.extend_from_slice(&hex_digest(
                f.as_str()
                    .context("auth VK field")?
                    .trim_start_matches("0x"),
            )?);
        }
        ensure!(
            binary == read_bounded(&p.vk.path, VK_BYTES)?,
            "auth binary VK differs"
        );
        let mut count = [0; 32];
        count[24..].copy_from_slice(&(STATEMENT_LEN.div_ceil(31) as u64 + 8).to_be_bytes());
        ensure!(binary[32..64] == count, "auth public input count");
        let root = p.directory.parent().context("auth circuit root")?;
        ensure!(!m.sources.is_empty(), "auth source pins missing");
        for (name, pin) in &m.sources {
            ensure!(
                !name.is_empty()
                    && Path::new(name)
                        .components()
                        .all(|c| matches!(c, std::path::Component::Normal(_))),
                "auth source path"
            );
            ensure!(
                sha256_bounded(&root.join(name), MAX_CIRCUIT_BYTES as u64)? == hex_digest(pin)?,
                "auth source changed"
            );
        }
        Ok(Some(Self { manifest: m }))
    }
    pub fn program(&self, role: &str) -> Option<&Program> {
        self.manifest.programs.get(role)
    }
    pub fn verifier(&self, deployment: [u8; 32]) -> Result<PinnedAuthVerifier> {
        PinnedAuthVerifier::new(
            deployment,
            self.manifest.bb.artifact(),
            self.manifest.crs.clone(),
            self.manifest.programs["auth"].vk.artifact(),
        )
    }
    fn record(&self) -> DeploymentRecord {
        DeploymentRecord {
            registry: self.manifest.registry.clone(),
            vk_sha256: self.manifest.programs["auth"].vk.sha256,
        }
    }
    /// Pins login for a fresh deployment before any signer state exists.
    pub fn save_deployment(&self, root: &Path) -> Result<()> {
        atomic_write(
            &root.join(DEPLOYMENT_FILE),
            &serde_json::to_vec(&self.record())?,
        )
    }
    /// Keeps the loaded suite only if this fixture was deployed with it. A
    /// fixture deployed without login reopens without it; a fixture deployed
    /// with login refuses to reopen without the identical verifier key.
    pub fn restore_deployment(suite: Option<Self>, root: &Path) -> Result<Option<Self>> {
        let path = root.join(DEPLOYMENT_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let recorded: DeploymentRecord = serde_json::from_slice(&fs::read(path)?)?;
        let suite =
            suite.context("fixture was deployed with Schnorr login; set ZARK_SPARK_AUTH_SUITE")?;
        ensure!(
            suite.record() == recorded,
            "fixture Schnorr login suite differs"
        );
        Ok(Some(suite))
    }
}
