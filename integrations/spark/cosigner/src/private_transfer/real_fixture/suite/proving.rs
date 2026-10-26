//! Optional pinned accelerated tools; circuit/VK identity and verifier stay fixed.
use super::{Pin, Program, Suite, private_directory};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};
use zark_protocol::{
    assets::{MAX_EXECUTABLE_BYTES, read_bounded},
    hash,
    proof::PROOF_BYTES,
    public_fields,
    storage::atomic_write,
};

#[path = "proving/abi.rs"]
mod abi;
#[path = "proving/process.rs"]
mod process;
pub(super) use process::bound_descriptor_limit;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProvingRuntime {
    executor: Pin,
    prover: Pin,
    pub witness_threads: u16,
    pub prove_threads: u16,
    // Omitted when false so retained jobs keep their exact runtime bytes.
    #[serde(default, skip_serializing_if = "is_false")]
    fast_msm: bool,
}
impl ProvingRuntime {
    pub fn load_optional() -> Result<Option<Self>> {
        let Some(path) = std::env::var_os("ZARK_SPARK_PROVING_RUNTIME") else {
            return Ok(None);
        };
        let path = PathBuf::from(path);
        ensure!(
            path.is_absolute(),
            "Spark proving runtime must be an absolute path"
        );
        let runtime: Self = serde_json::from_slice(&read_bounded(&path, 16 * 1024)?)?;
        runtime.check()?;
        Ok(Some(runtime))
    }
    pub fn check(&self) -> Result<()> {
        ensure!(
            (1..=8).contains(&self.witness_threads) && (1..=8).contains(&self.prove_threads),
            "Spark accelerated runtime worker bound"
        );
        self.executor.check(MAX_EXECUTABLE_BYTES)?;
        self.prover.check(MAX_EXECUTABLE_BYTES)
    }
    pub fn executor(&self, program: &Program, job: &Path) -> Command {
        let mut command = Command::new(&self.executor.path);
        command
            .args(["execute", "--artifact-path"])
            .arg(&program.artifact.path)
            .arg("--prover-file")
            .arg(job.join("input.toml"))
            .arg("--output-dir")
            .arg(job)
            .args(["--witness-name", "witness"]);
        command
    }
    pub fn prover(&self) -> &Path {
        &self.prover.path
    }
}

fn is_false(value: &bool) -> bool {
    !value
}

impl Suite {
    pub fn prove(&self, role: &str, input: &str, statement: &[u8], job: &Path) -> Result<Vec<u8>> {
        let p = self
            .manifest
            .programs
            .get(role)
            .or_else(|| self.native.as_ref().and_then(|native| native.program(role)))
            .or_else(|| self.receive.as_ref().and_then(|s| s.program(role)))
            .or_else(|| self.auth.as_ref().and_then(|s| s.program(role)))
            .context("unknown real-proof role")?;
        self.check(p)?;
        // Circuit optimizations change the private sender ABI. Reject a legacy
        // suite before creating or rewriting any frozen job inputs or runtime.
        abi::require_sender_profile(role, p)?;
        private_directory(job)?;
        private_directory(&job.join("output"))?;
        let runtime = serde_json::json!({"accelerated":self.proving,"threads":self.threads,
            "nargo":self.manifest.nargo,"verifier":self.manifest.bb,
            "role":role,"artifact":p.artifact,"vk":p.vk,
            "input_sha256":hex::encode(hash(&[input.as_bytes()])),
            "statement_sha256":hex::encode(hash(&[statement]))});
        let runtime_path = job.join("runtime.json");
        if runtime_path.exists() {
            ensure!(
                fs::read(&runtime_path)? == serde_json::to_vec(&runtime)?,
                "frozen Spark proving runtime changed"
            );
        } else {
            ensure!(
                !job.join("input.toml").exists() && !job.join("statement.bin").exists(),
                "legacy proof job has no frozen runtime; preserve it with the build that created it"
            );
            atomic_write(&runtime_path, &serde_json::to_vec(&runtime)?)?;
        }
        for (path, bytes) in [
            (job.join("input.toml"), input.as_bytes()),
            (job.join("statement.bin"), statement),
        ] {
            if path.exists() {
                ensure!(
                    fs::read(&path)? == bytes,
                    "frozen Spark proof input changed"
                );
            } else {
                atomic_write(&path, bytes)?;
            }
        }
        self.check(p)?;
        let execute_started = Instant::now();
        let mut execute = if let Some(runtime) = &self.proving {
            runtime.executor(p, job)
        } else {
            let mut command = Command::new(&self.manifest.nargo.path);
            command
                .arg("execute")
                .arg(job.join("witness"))
                .arg("--program-dir")
                .arg(&p.directory)
                .arg("--prover-name")
                .arg(job.join("input"));
            command
        };
        process::run(
            &mut execute,
            job,
            "execute",
            self.proving
                .as_ref()
                .map_or(self.threads, |r| r.witness_threads),
            false,
        )?;
        let execute_time = execute_started.elapsed();
        self.check(p)?;
        let mut prove = Command::new(
            self.proving
                .as_ref()
                .map_or(self.manifest.bb.path.as_path(), |r| r.prover()),
        );
        prove
            .args(["prove", "-t", "noir-recursive", "-b"])
            .arg(&p.artifact.path)
            .arg("-w")
            .arg(job.join("witness.gz"))
            .arg("-k")
            .arg(&p.vk.path)
            .arg("-o")
            .arg(job.join("output"))
            .arg("-c")
            .arg(&self.manifest.crs);
        let prove_time = process::run(
            &mut prove,
            job,
            "prove",
            self.proving
                .as_ref()
                .map_or(self.threads, |r| r.prove_threads),
            self.proving
                .as_ref()
                .is_some_and(|runtime| runtime.fast_msm),
        )?;
        self.check(p)?;
        let proof = fs::read(job.join("output/proof"))?;
        ensure!(proof.len() == PROOF_BYTES, "real-proof fixture proof shape");
        ensure!(
            fs::read(job.join("output/public_inputs"))? == public_fields(statement),
            "real-proof fixture public inputs changed"
        );
        let mut verify = Command::new(&self.manifest.bb.path);
        verify
            .args(["verify", "-t", "noir-recursive", "-p"])
            .arg(job.join("output/proof"))
            .arg("-i")
            .arg(job.join("output/public_inputs"))
            .arg("-k")
            .arg(&p.vk.path)
            .arg("-c")
            .arg(&self.manifest.crs);
        let verify_time = process::run(&mut verify, job, "verify", self.threads, false)?;
        self.check(p)?;
        atomic_write(
            &job.join("completed.json"),
            &serde_json::to_vec(
                &serde_json::json!({"role":role,"real_proof_verified":true,"statement_sha256":hex::encode(hash(&[statement])),"proof_sha256":hex::encode(hash(&[&proof])),
                    "timing_ms":{"execute":execute_time.as_millis(),"prove":prove_time.as_millis(),"verify":verify_time.as_millis()},"threads":self.threads,
                    "artifact_sha256":hex::encode(p.artifact.sha256),"vk_sha256":hex::encode(p.vk.sha256),
                    "runtime_sha256":hex::encode(hash(&[&serde_json::to_vec(&runtime)?])),
                    "nargo_sha256":hex::encode(self.manifest.nargo.sha256),"bb_sha256":hex::encode(self.manifest.bb.sha256)}),
            )?,
        )?;
        Ok(proof)
    }
    fn check(&self, p: &Program) -> Result<()> {
        if let Some(runtime) = &self.proving {
            runtime.check()?;
        }
        self.manifest.nargo.check(MAX_EXECUTABLE_BYTES)?;
        self.manifest.bb.check(MAX_EXECUTABLE_BYTES)?;
        p.artifact.check(1024 * 1024 * 1024)?;
        p.vk.check(zark_protocol::assets::VK_BYTES as u64)
    }
}
