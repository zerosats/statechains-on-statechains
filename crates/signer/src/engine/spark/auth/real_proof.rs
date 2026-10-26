//! Explicit local end-to-end timing with a real proof and the pinned verifier.
//! No Spark service is contacted. Requires a compiled `spark-auth-authorize`
//! program, its recursive VK, pinned nargo/bb and the CRS:
//! ZARK_SPARK_AUTH_PROGRAM, ZARK_SPARK_AUTH_VK, ZARK_NARGO, ZARK_BB, ZARK_CRS.
use super::tests::{Fixture, fixture};
use super::*;
use std::{path::PathBuf, process::Command as Process, time::Instant};
use zark_protocol::{
    proof::ArtifactPin,
    spark_auth::{AuthWitness, PinnedAuthVerifier},
};

fn env(name: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(
        std::env::var(name).with_context(|| format!("{name} is required"))?,
    ))
}

fn pin(path: PathBuf) -> Result<ArtifactPin> {
    Ok(ArtifactPin {
        sha256: hash(&[&std::fs::read(&path)?]),
        path,
    })
}

fn run(command: &mut Process) -> Result<()> {
    let output = command.output()?;
    ensure!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
#[ignore]
fn real_proof_blind_auth_end_to_end_timing() -> Result<()> {
    let (program, vk, nargo, bb, crs) = (
        env("ZARK_SPARK_AUTH_PROGRAM")?,
        env("ZARK_SPARK_AUTH_VK")?,
        env("ZARK_NARGO")?,
        env("ZARK_BB")?,
        env("ZARK_CRS")?,
    );
    let scratch = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../work/spark-auth-e2e")
        .join(hex::encode(random32()));
    std::fs::create_dir_all(scratch.join("out"))?;
    let artifact = program.join("target/spark_auth_authorize.json");
    let verifier =
        PinnedAuthVerifier::new([1; 32], pin(bb.clone())?, crs.clone(), pin(vk.clone())?)?;
    let mut f: Fixture = fixture()?;

    let started = Instant::now();
    let now = now()?;
    let wallet = f.wallet_prepare(now)?;
    let nonce = f.prepare(&wallet, now)?;
    let message = wallet.challenge.message()?;
    let bound = wallet.blinding.bind(&f.wallet, &nonce, &message)?;
    let request = f.issue_request(&wallet, bound.challenge)?;
    let Command::AuthIssue {
        ticket, challenge, ..
    } = &request.command
    else {
        unreachable!()
    };
    let spec = plan_issue(&f.coin, &request, &f.base, ticket, challenge, now)?;
    let statement = AuthStatement::decode(&spec.statement)?;
    let input = AuthWitness {
        key: &f.wallet,
        challenge: &wallet.challenge,
        blinding: &wallet.blinding,
    }
    .prover_toml(&statement)?;
    std::fs::write(scratch.join("input.toml"), input.as_bytes())?;
    let prepared = started.elapsed();

    let witness_started = Instant::now();
    run(Process::new(&nargo)
        .args(["execute", "witness", "--program-dir"])
        .arg(&program)
        .arg("--prover-name")
        .arg(scratch.join("input")))?;
    let witness = witness_started.elapsed();
    let prove_started = Instant::now();
    run(Process::new(&bb)
        .args(["prove", "-t", "noir-recursive", "-b"])
        .arg(&artifact)
        .arg("-w")
        .arg(program.join("target/witness.gz"))
        .arg("-k")
        .arg(&vk)
        .arg("-o")
        .arg(scratch.join("out"))
        .arg("-c")
        .arg(&crs))?;
    let proving = prove_started.elapsed();
    let proof = std::fs::read(scratch.join("out/proof"))?;

    let verify_started = Instant::now();
    ensure!(verifier.verify(&statement, &proof, &scratch)? == hash(&[&spec.statement]));
    let verification = verify_started.elapsed();
    let (_, partial) = f.issue(&request, now)?;
    let signature = wallet
        .blinding
        .finish(&f.wallet, &bound, &nonce, &partial, &message)?;
    let total = started.elapsed();
    k256::schnorr::VerifyingKey::from_bytes(&f.wallet.compressed()?[1..])?.verify_raw(
        &message,
        &k256::schnorr::Signature::try_from(signature.as_slice())?,
    )?;
    // A proof for this ticket cannot be replayed with another challenge.
    let mut other = statement.clone();
    other.challenge = (zark_protocol::scalar(&statement.challenge)? + k256::Scalar::ONE)
        .to_bytes()
        .into();
    assert!(verifier.verify(&other, &proof, &scratch).is_err());
    eprintln!(
        "blind auth: prepare {prepared:?}, witness {witness:?}, prove {proving:?}, verify {verification:?}, total {total:?}"
    );
    let _ = std::fs::remove_dir_all(&scratch);
    Ok(())
}
