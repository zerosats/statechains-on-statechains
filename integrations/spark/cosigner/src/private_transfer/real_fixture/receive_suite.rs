//! Explicit receive proof assets. Native cluster configuration is separately
//! pinned by each receive deployment; old signing roles cannot substitute.
use super::suite::{Pin, Program, hex_digest};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
use zark_protocol::{
    assets::{MAX_CIRCUIT_BYTES, MAX_VK_METADATA_BYTES, VK_BYTES, read_bounded, sha256_bounded},
    spark_lineage::Config,
    spark_receive::{ENCODED_LEN, PinnedReceiveVerifier, REGISTRY},
};
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
pub(super) struct ReceiveSuite {
    manifest: Manifest,
}
impl ReceiveSuite {
    pub fn load_optional(nargo: &Pin, bb: &Pin, crs: &Path) -> Result<Option<Self>> {
        let Some(path) = std::env::var_os("ZARK_SPARK_RECEIVE_SUITE") else {
            return Ok(None);
        };
        let path = PathBuf::from(path);
        ensure!(path.is_absolute(), "receive manifest must be absolute");
        let m: Manifest = serde_json::from_slice(&fs::read(path)?)?;
        ensure!(
            m.schema == "zark-spark-receive-proof-suite"
                && m.version == 1
                && m.registry == REGISTRY
                && m.programs.len() == 1,
            "receive suite schema"
        );
        ensure!(
            m.nargo.path == nargo.path
                && m.nargo.sha256 == nargo.sha256
                && m.bb.path == bb.path
                && m.bb.sha256 == bb.sha256
                && m.crs == crs,
            "receive proving runtime differs"
        );
        let p = m
            .programs
            .get("receive")
            .context("receive program missing")?;
        ensure!(
            p.public_bytes == ENCODED_LEN
                && p.directory.is_absolute()
                && p.directory.join("Nargo.toml").is_file(),
            "receive program shape"
        );
        p.artifact.check(MAX_CIRCUIT_BYTES as u64)?;
        p.vk.check(VK_BYTES as u64)?;
        let metadata =
            p.vk.path
                .parent()
                .context("receive VK parent")?
                .join("vk.json");
        ensure!(
            sha256_bounded(&metadata, MAX_VK_METADATA_BYTES as u64)?
                == hex_digest(&p.metadata_sha256)?,
            "receive VK metadata pin"
        );
        let v: serde_json::Value =
            serde_json::from_slice(&read_bounded(&metadata, MAX_VK_METADATA_BYTES)?)?;
        ensure!(
            hex_digest(
                v["hash"]
                    .as_str()
                    .context("receive recursive key hash")?
                    .trim_start_matches("0x")
            )? == m.role_hashes[0]
                && v["scheme"] == "ultra_honk"
                && v["bb_version"] == "5.2.0",
            "receive recursive VK metadata"
        );
        let fields = v["vk"].as_array().context("receive VK fields")?;
        ensure!(fields.len() == 115, "receive recursive VK size");
        let mut binary = Vec::new();
        for f in fields {
            binary.extend_from_slice(&hex_digest(
                f.as_str()
                    .context("receive VK field")?
                    .trim_start_matches("0x"),
            )?);
        }
        ensure!(
            binary == read_bounded(&p.vk.path, VK_BYTES)?,
            "receive binary VK differs"
        );
        let mut count = [0; 32];
        count[24..].copy_from_slice(&(ENCODED_LEN.div_ceil(31) as u64 + 8).to_be_bytes());
        ensure!(binary[32..64] == count, "receive public input count");
        let root = p.directory.parent().context("receive circuit root")?;
        ensure!(!m.sources.is_empty(), "receive source pins missing");
        for (name, pin) in &m.sources {
            ensure!(
                !name.is_empty()
                    && Path::new(name)
                        .components()
                        .all(|c| matches!(c, std::path::Component::Normal(_))),
                "receive source path"
            );
            ensure!(
                sha256_bounded(&root.join(name), MAX_CIRCUIT_BYTES as u64)? == hex_digest(pin)?,
                "receive source changed"
            );
        }
        Ok(Some(Self { manifest: m }))
    }
    pub fn program(&self, role: &str) -> Option<&Program> {
        self.manifest.programs.get(role)
    }
    pub fn verifier(
        &self,
        deployment: [u8; 32],
        config: Config,
        policy: [u8; 32],
        cluster: [u8; 32],
    ) -> Result<PinnedReceiveVerifier> {
        PinnedReceiveVerifier::new(
            deployment,
            config,
            policy,
            cluster,
            self.manifest.bb.artifact(),
            self.manifest.crs.clone(),
            self.manifest.programs["receive"].vk.artifact(),
        )
    }
}
