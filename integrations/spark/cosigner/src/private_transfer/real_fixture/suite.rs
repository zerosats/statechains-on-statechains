//! Explicitly invoked real-proof fixture runtime. No production proof oracle.
use anyhow::{Context, Result, ensure};
use k256::schnorr::SigningKey;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
};
use zark_protocol::{
    assets::{
        MAX_CRS_BYTES, MAX_EXECUTABLE_BYTES, MAX_VK_METADATA_BYTES, VK_BYTES, read_bounded,
        sha256_bounded,
    },
    handoff::{RecoverySchedule, TransferContext},
    owner_auth::generate_secret,
    proof::ArtifactPin,
    random32,
    spark_lineage::{Config, PinnedSparkVerifier, SparkRole},
    spark_recovery::TargetOpening,
    storage::atomic_write,
};
use zark_signer::engine::Admission;
use zeroize::Zeroizing;

#[path = "suite/engines.rs"]
mod engines;
#[path = "suite/proving.rs"]
mod proving;
use proving::ProvingRuntime;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pin {
    pub path: PathBuf,
    pub sha256: [u8; 32],
}
impl Pin {
    pub(super) fn check(&self, limit: u64) -> Result<()> {
        ensure!(
            self.path.is_absolute() && self.sha256 != [0; 32],
            "real-proof fixture asset pin"
        );
        ensure!(
            sha256_bounded(&self.path, limit)? == self.sha256,
            "real-proof fixture asset changed"
        );
        Ok(())
    }
    pub(super) fn artifact(&self) -> ArtifactPin {
        ArtifactPin {
            path: self.path.clone(),
            sha256: self.sha256,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Program {
    pub(super) directory: PathBuf,
    pub(super) artifact: Pin,
    pub(super) vk: Pin,
    pub(super) public_bytes: usize,
    pub(super) metadata_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    version: u32,
    registry: String,
    sources: BTreeMap<String, String>,
    role_hashes: [[u8; 32]; 4],
    nargo: Pin,
    bb: Pin,
    crs: PathBuf,
    programs: BTreeMap<String, Program>,
}

pub(super) struct Suite {
    manifest: Manifest,
    pub deployment: [u8; 32],
    pub config: Config,
    pub policy: [u8; 32],
    /// Published in every signed head, outside the database config digest.
    pub share_release: bool,
    origin: Zeroizing<[u8; 32]>,
    threads: u16,
    native: Option<super::native_suite::NativeSuite>,
    receive: Option<super::receive_suite::ReceiveSuite>,
    auth: Option<super::auth_suite::AuthSuite>,
    proving: Option<ProvingRuntime>,
}
struct FixtureAdmission([u8; 32]);
impl Admission for FixtureAdmission {
    fn authorize(&self, context: &TransferContext) -> Result<()> {
        ensure!(
            context.deployment == self.0,
            "isolated fixture admission deployment"
        );
        Ok(())
    }
    fn authorize_spark_received_origin(
        &self,
        context: &TransferContext,
        _backing: &[u8; 32],
    ) -> Result<()> {
        // Explicit synthetic-native fixture only; never used by a live run.
        self.authorize(context)
    }
}

impl Suite {
    pub fn load() -> Result<Self> {
        proving::bound_descriptor_limit();
        let path = PathBuf::from(
            std::env::var_os("ZARK_SPARK_REAL_SUITE")
                .context("set ZARK_SPARK_REAL_SUITE to the pinned real-proof manifest")?,
        );
        ensure!(
            path.is_absolute(),
            "real-proof manifest must be an absolute path"
        );
        let manifest: Manifest = serde_json::from_slice(&fs::read(path)?)?;
        ensure!(
            manifest.schema == "zark-spark-real-proof-suite"
                && manifest.version == 1
                && manifest.registry == "zark-spark-private-ownership-four-role-v1",
            "real-proof fixture suite schema"
        );
        manifest.nargo.check(MAX_EXECUTABLE_BYTES)?;
        manifest.bb.check(MAX_EXECUTABLE_BYTES)?;
        ensure!(
            manifest.crs.is_absolute() && manifest.crs.is_dir(),
            "real-proof CRS directory missing"
        );
        for (name, pin) in [
            (
                "bn254_g1.dat",
                "d777711ae9fb1951c47a0eaf7e0ebcaccc39e6731d9b3a560d7ff0c2fcdf2f0d",
            ),
            (
                "bn254_g1_compressed.dat",
                "bf9f1cdbe7b7bb2667c8ee5b887f6ce8b07ec99d60944e17da880ad3717e141b",
            ),
        ] {
            ensure!(
                sha256_bounded(&manifest.crs.join(name), MAX_CRS_BYTES)? == hex_digest(pin)?,
                "real-proof fixture CRS pin mismatch"
            );
        }
        for (index, (role, public_bytes)) in [
            ("deposit", 1036),
            ("sender_from_origin", 588),
            ("sender_from_transfer", 588),
            ("receiver", 1036),
        ]
        .into_iter()
        .enumerate()
        {
            let p = manifest
                .programs
                .get(role)
                .context("real-proof role missing")?;
            ensure!(
                p.directory.is_absolute() && p.directory.join("Nargo.toml").is_file(),
                "real-proof role source directory missing"
            );
            p.artifact.check(1024 * 1024 * 1024)?;
            p.vk.check(zark_protocol::assets::VK_BYTES as u64)?;
            ensure!(
                p.public_bytes == public_bytes,
                "real-proof role public statement shape"
            );
            let metadata_path =
                p.vk.path
                    .parent()
                    .context("real-proof VK directory")?
                    .join("vk.json");
            ensure!(
                sha256_bounded(&metadata_path, MAX_VK_METADATA_BYTES as u64)?
                    == hex_digest(&p.metadata_sha256)?,
                "real-proof VK metadata pin mismatch"
            );
            let metadata: serde_json::Value =
                serde_json::from_slice(&read_bounded(&metadata_path, MAX_VK_METADATA_BYTES)?)?;
            ensure!(
                hex_digest(
                    metadata["hash"]
                        .as_str()
                        .context("real-proof recursive VK hash")?
                        .strip_prefix("0x")
                        .context("real-proof recursive VK hash encoding")?
                )? == manifest.role_hashes[index],
                "real-proof recursive role hash differs from pinned metadata"
            );
            let fields = metadata["vk"]
                .as_array()
                .context("real-proof VK metadata fields")?;
            ensure!(
                fields.len() == 115
                    && metadata["scheme"] == "ultra_honk"
                    && metadata["bb_version"] == "5.2.0",
                "real-proof VK metadata shape, scheme or version"
            );
            let mut binary = Vec::with_capacity(VK_BYTES);
            for field in fields {
                let field = field
                    .as_str()
                    .context("real-proof VK field type")?
                    .strip_prefix("0x")
                    .context("real-proof VK field encoding")?;
                binary.extend_from_slice(&hex_digest(field)?);
            }
            ensure!(
                binary == read_bounded(&p.vk.path, VK_BYTES)?,
                "real-proof binary VK and metadata differ"
            );
            let mut public_count = [0u8; 32];
            public_count[24..]
                .copy_from_slice(&(public_bytes.div_ceil(31) as u64 + 8).to_be_bytes());
            ensure!(
                binary[32..64] == public_count,
                "real-proof VK packed public input count"
            );
        }
        let circuits = manifest.programs["deposit"]
            .directory
            .parent()
            .context("real-proof circuits root")?;
        ensure!(
            !manifest.sources.is_empty(),
            "real-proof source pins missing"
        );
        for (name, pin) in &manifest.sources {
            let relative = Path::new(name);
            ensure!(
                !name.is_empty()
                    && relative
                        .components()
                        .all(|c| matches!(c, std::path::Component::Normal(_))),
                "real-proof source path"
            );
            ensure!(
                sha256_bounded(
                    &circuits.join(relative),
                    zark_protocol::assets::MAX_CIRCUIT_BYTES as u64
                )? == hex_digest(pin)?,
                "real-proof source changed"
            );
        }
        ensure!(manifest.programs.len() == 4, "unexpected real-proof role");
        let origin = Zeroizing::new(generate_secret());
        let config = Config {
            origin_key: SigningKey::from_bytes(&origin[..])?
                .verifying_key()
                .to_bytes()
                .into(),
            role_hashes: manifest.role_hashes,
        };
        config.encode()?;
        let policy = TargetOpening {
            salt: [1; 32],
            payout: zark_protocol::point_bytes(k256::ProjectivePoint::GENERATOR)?,
            fee: 500,
            delay: 500,
            owner_index: 1,
            initial: 500,
            gap: 60,
            margin: 20,
        }
        .policy()?;
        let threads = std::env::var("ZARK_SPARK_PROVE_THREADS")
            .unwrap_or_else(|_| "2".into())
            .parse::<u16>()?;
        ensure!(
            (1..=8).contains(&threads),
            "real-proof fixture worker bound"
        );
        let native = super::native_suite::NativeSuite::load_optional(
            &manifest.nargo,
            &manifest.bb,
            &manifest.crs,
        )?;
        let receive = super::receive_suite::ReceiveSuite::load_optional(
            &manifest.nargo,
            &manifest.bb,
            &manifest.crs,
        )?;
        let auth = super::auth_suite::AuthSuite::load_optional(
            &manifest.nargo,
            &manifest.bb,
            &manifest.crs,
        )?;
        Ok(Self {
            manifest,
            deployment: random32(),
            config,
            policy,
            share_release: false,
            origin,
            threads,
            native,
            receive,
            auth,
            proving: ProvingRuntime::load_optional()?,
        })
    }
    pub fn schedule(&self) -> RecoverySchedule {
        RecoverySchedule {
            initial: 500,
            gap: 60,
            margin: 20,
        }
    }
    pub fn save_identity(&self, root: &Path) -> Result<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(&serde_json::json!({
            "deployment":self.deployment,"origin_secret":&self.origin[..],"config":self.config,"policy":self.policy,
        }))?);
        if let Some(auth) = &self.auth {
            auth.save_deployment(root)?;
        }
        atomic_write(&root.join("private-fixture-identity.json"), &bytes)
    }
    pub fn auth_verifier(&self) -> Result<Option<zark_protocol::spark_auth::PinnedAuthVerifier>> {
        self.auth
            .as_ref()
            .map(|a| a.verifier(self.deployment))
            .transpose()
    }
    /// Restore only the identity of a named, already-passed synthetic fixture.
    /// Proof assets remain authenticated against the caller's current manifests.
    pub fn restore_identity(&mut self, root: &Path) -> Result<()> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Identity {
            deployment: [u8; 32],
            origin_secret: [u8; 32],
            config: Config,
            policy: [u8; 32],
        }
        let bytes = Zeroizing::new(fs::read(root.join("private-fixture-identity.json"))?);
        let mut identity: Identity = serde_json::from_slice(&bytes)?;
        let secret = Zeroizing::new(identity.origin_secret);
        identity.origin_secret.fill(0);
        let key = zark_protocol::owner_auth::normalized_key(&secret)?;
        ensure!(
            identity.deployment != [0; 32]
                && identity.config.role_hashes == self.manifest.role_hashes
                && identity.config.origin_key[..] == key.verifying_key().to_bytes()[..]
                && identity.policy == self.policy,
            "retained synthetic fixture identity differs from pinned suite"
        );
        self.auth = super::auth_suite::AuthSuite::restore_deployment(self.auth.take(), root)?;
        self.deployment = identity.deployment;
        self.config = identity.config;
        self.origin = secret;
        Ok(())
    }
    pub fn verifier(&self) -> Result<PinnedSparkVerifier> {
        let keys = [
            ("deposit", SparkRole::Deposit),
            ("sender_from_origin", SparkRole::SenderFromOrigin),
            ("sender_from_transfer", SparkRole::SenderFromTransfer),
            ("receiver", SparkRole::Receiver),
        ]
        .into_iter()
        .map(|(name, role)| (role, self.manifest.programs[name].vk.artifact()))
        .collect::<Vec<_>>();
        PinnedSparkVerifier::new(
            self.deployment,
            self.config.clone(),
            self.policy,
            self.manifest.bb.artifact(),
            self.manifest.crs.clone(),
            keys,
        )
    }
}

pub(super) fn private_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    ensure!(
        fs::symlink_metadata(path)?.is_dir(),
        "real-proof fixture directory changed"
    );
    Ok(())
}

pub(super) fn hex_digest(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value)?;
    ensure!(
        value.len() == 64 && hex::encode(&bytes) == value,
        "real-proof digest encoding"
    );
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("real-proof digest length"))
}
