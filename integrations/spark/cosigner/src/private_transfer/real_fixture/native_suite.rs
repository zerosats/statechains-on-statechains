//! Opt-in native proof assets. Synthetic operator encryption identities below
//! are fixture-only and are never represented as live Spark configuration.
use super::suite::{Pin, Program, hex_digest};
use anyhow::{Context, Result, ensure};
use k256::{ProjectivePoint, Scalar, elliptic_curve::sec1::ToEncodedPoint};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
use zark_protocol::{
    assets::{MAX_CIRCUIT_BYTES, MAX_VK_METADATA_BYTES, VK_BYTES, read_bounded, sha256_bounded},
    spark_lineage::Config,
    spark_native::{NativeExitRole, ORDINARY_REGISTRY, PinnedNativeExitVerifier, REGISTRY},
    spark_native_vss::Cluster,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    version: u32,
    registry: String,
    sources: BTreeMap<String, String>,
    role_hashes: [[u8; 32]; 2],
    nargo: Pin,
    bb: Pin,
    crs: PathBuf,
    programs: BTreeMap<String, Program>,
}
pub(super) struct NativeSuite {
    manifest: Manifest,
    cluster: Cluster,
}
impl NativeSuite {
    pub fn load_optional(nargo: &Pin, bb: &Pin, crs: &Path) -> Result<Option<Self>> {
        let Some(path) = std::env::var_os("ZARK_SPARK_NATIVE_SUITE") else {
            return Ok(None);
        };
        let path = PathBuf::from(path);
        ensure!(path.is_absolute(), "native suite manifest must be absolute");
        let manifest: Manifest = serde_json::from_slice(&fs::read(path)?)?;
        ensure!(
            manifest.schema == "zark-spark-native-proof-suite"
                && manifest.version == 1
                && [REGISTRY, ORDINARY_REGISTRY].contains(&manifest.registry.as_str()),
            "native proof suite schema"
        );
        // The ordinary suite already authenticated these executable/CRS files.
        // Native roles cannot silently substitute a second proving runtime.
        ensure!(
            manifest.nargo.path == nargo.path
                && manifest.nargo.sha256 == nargo.sha256
                && manifest.bb.path == bb.path
                && manifest.bb.sha256 == bb.sha256
                && manifest.crs == crs,
            "native suite runtime differs"
        );
        ensure!(manifest.programs.len() == 2, "unexpected native role");
        for (index, name) in ["exit_from_origin", "exit_from_transfer"]
            .into_iter()
            .enumerate()
        {
            let program = manifest
                .programs
                .get(name)
                .context("native proof role missing")?;
            validate_program(program, manifest.role_hashes[index])?;
        }
        ensure!(
            manifest.role_hashes[0] != manifest.role_hashes[1],
            "duplicate native role hash"
        );
        let circuits = manifest.programs["exit_from_origin"]
            .directory
            .parent()
            .context("native circuits root")?;
        ensure!(!manifest.sources.is_empty(), "native source pins missing");
        for (name, pin) in &manifest.sources {
            let relative = Path::new(name);
            ensure!(
                !name.is_empty()
                    && relative
                        .components()
                        .all(|p| matches!(p, std::path::Component::Normal(_))),
                "native source path"
            );
            ensure!(
                sha256_bounded(&circuits.join(relative), MAX_CIRCUIT_BYTES as u64)?
                    == hex_digest(pin)?,
                "native pinned source changed"
            );
        }
        let operators = (1..=3u64)
            .map(|index| {
                let mut id = [0; 32];
                id[31] = index as u8;
                let public = (ProjectivePoint::GENERATOR * Scalar::from(100 + index))
                    .to_affine()
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec();
                (hex::encode(id), public)
            })
            .collect();
        let cluster = Cluster {
            threshold: 2,
            operators,
        };
        cluster.validate()?;
        Ok(Some(Self { manifest, cluster }))
    }
    pub fn cluster(&self) -> &Cluster {
        &self.cluster
    }
    pub fn program(&self, name: &str) -> Option<&Program> {
        self.manifest.programs.get(name)
    }
    pub fn verifier(
        &self,
        deployment: [u8; 32],
        config: Config,
        policy: [u8; 32],
    ) -> Result<PinnedNativeExitVerifier> {
        self.verifier_for_cluster(deployment, config, policy, &self.cluster)
    }
    pub fn verifier_for_cluster(
        &self,
        deployment: [u8; 32],
        config: Config,
        policy: [u8; 32],
        cluster: &Cluster,
    ) -> Result<PinnedNativeExitVerifier> {
        cluster.validate()?;
        let keys = [
            ("exit_from_origin", NativeExitRole::Origin),
            ("exit_from_transfer", NativeExitRole::Transfer),
        ]
        .into_iter()
        .map(|(name, role)| (role, self.manifest.programs[name].vk.artifact()));
        if self.manifest.registry == ORDINARY_REGISTRY {
            PinnedNativeExitVerifier::new_ordinary(
                deployment,
                config,
                policy,
                cluster.digest()?,
                self.manifest.bb.artifact(),
                self.manifest.crs.clone(),
                keys,
            )
        } else {
            PinnedNativeExitVerifier::new(
                deployment,
                config,
                policy,
                cluster.digest()?,
                self.manifest.bb.artifact(),
                self.manifest.crs.clone(),
                keys,
            )
        }
    }
}
fn validate_program(program: &Program, role: [u8; 32]) -> Result<()> {
    ensure!(
        program.directory.is_absolute() && program.directory.join("Nargo.toml").is_file(),
        "native program source missing"
    );
    ensure!(program.public_bytes == 812, "native role statement shape");
    program.artifact.check(1024 * 1024 * 1024)?;
    program.vk.check(VK_BYTES as u64)?;
    let metadata_path = program
        .vk
        .path
        .parent()
        .context("native VK directory")?
        .join("vk.json");
    ensure!(
        sha256_bounded(&metadata_path, MAX_VK_METADATA_BYTES as u64)?
            == hex_digest(&program.metadata_sha256)?,
        "native VK metadata pin"
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&read_bounded(&metadata_path, MAX_VK_METADATA_BYTES)?)?;
    ensure!(
        hex_digest(
            metadata["hash"]
                .as_str()
                .context("native VK hash")?
                .strip_prefix("0x")
                .context("native VK hash encoding")?
        )? == role,
        "native recursive role hash"
    );
    let fields = metadata["vk"].as_array().context("native VK fields")?;
    ensure!(
        fields.len() == 115
            && metadata["scheme"] == "ultra_honk"
            && metadata["bb_version"] == "5.2.0",
        "native VK metadata shape"
    );
    let mut binary = Vec::with_capacity(VK_BYTES);
    for field in fields {
        binary.extend_from_slice(&hex_digest(
            field
                .as_str()
                .context("native VK field type")?
                .strip_prefix("0x")
                .context("native VK field encoding")?,
        )?);
    }
    ensure!(
        binary == read_bounded(&program.vk.path, VK_BYTES)?,
        "native VK binary differs from metadata"
    );
    let mut count = [0; 32];
    count[24..].copy_from_slice(&35u64.to_be_bytes());
    ensure!(binary[32..64] == count, "native VK public field count");
    Ok(())
}
