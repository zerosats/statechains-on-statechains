//! Wallet journal against the real signer Engine, without Spark. The inert
//! fixture's auth verifier cannot accept a proof, which exercises every retry
//! path short of release; the ignored test proves for real and needs
//! ZARK_SPARK_AUTH_PROGRAM, ZARK_SPARK_AUTH_VK, ZARK_NARGO, ZARK_BB, ZARK_CRS.
use super::*;
use k256::{ProjectivePoint, elliptic_curve::sec1::ToEncodedPoint};
use std::{
    cell::RefCell, fs, os::unix::fs::DirBuilderExt, path::PathBuf, sync::Arc, time::Instant,
};
use zark_protocol::{
    handoff::TransferContext,
    owner_auth::generate_secret,
    proof::{ArtifactPin, PROOF_BYTES},
    random_scalar, random32,
    spark_auth::PinnedAuthVerifier,
    spark_lineage::{Config, PinnedSparkVerifier, SparkRole, origin_field, origin_previous_state},
    spark_receive::{ClaimCluster, ClaimOperator, PinnedReceiveVerifier},
};
use zark_signer::engine::{
    Admission,
    spark::{Engine, NativeProtocols, ReceiveProtocol},
};

struct Allow(Digest);
impl Admission for Allow {
    fn authorize(&self, context: &TransferContext) -> Result<()> {
        ensure!(context.deployment == self.0, "test deployment");
        Ok(())
    }
}

/// Proof tools for the auth role: inert files, or the real pinned toolchain.
struct Tools {
    bb: PathBuf,
    vk: PathBuf,
    crs: PathBuf,
    real: Option<(PathBuf, PathBuf)>,
}

struct Fixture {
    root: PathBuf,
    deployment: Digest,
    origin: Digest,
    tools: Tools,
}
impl Fixture {
    fn new(real: bool) -> Result<Self> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../work/spark-auth-journal")
            .join(hex::encode(random32()));
        fs::create_dir_all(root.parent().context("fixture parent")?)?;
        for dir in ["", "signer", "checkpoint", "wallets", "scratch"] {
            fs::DirBuilder::new().mode(0o700).create(root.join(dir))?;
        }
        fs::write(root.join("unused-verifier"), b"never executed")?;
        fs::write(
            root.join("unused-vk"),
            vec![1u8; zark_protocol::assets::VK_BYTES],
        )?;
        let env = |name: &str| -> Result<PathBuf> {
            Ok(std::env::var_os(name)
                .with_context(|| format!("{name} is required"))?
                .into())
        };
        let tools = if real {
            Tools {
                bb: env("ZARK_BB")?,
                vk: env("ZARK_SPARK_AUTH_VK")?,
                crs: env("ZARK_CRS")?,
                real: Some((env("ZARK_SPARK_AUTH_PROGRAM")?, env("ZARK_NARGO")?)),
            }
        } else {
            Tools {
                bb: root.join("unused-verifier"),
                vk: root.join("unused-vk"),
                crs: root.clone(),
                real: None,
            }
        };
        Ok(Self {
            root,
            deployment: random32(),
            origin: generate_secret(),
            tools,
        })
    }
    fn pin(path: PathBuf) -> Result<ArtifactPin> {
        Ok(ArtifactPin {
            sha256: hash(&[&fs::read(&path)?]),
            path,
        })
    }
    fn engine(&self) -> Result<Engine> {
        let origin = k256::schnorr::SigningKey::from_bytes(&self.origin)?;
        let config = Config {
            origin_key: origin.verifying_key().to_bytes().into(),
            role_hashes: std::array::from_fn(|i| [i as u8 + 1; 32]),
        };
        let cluster = ClaimCluster {
            threshold: 2,
            operators: (1..=3u16)
                .map(|i| {
                    let key = ProjectivePoint::GENERATOR * k256::Scalar::from(u64::from(i) + 20);
                    let operator = ClaimOperator {
                        index: i,
                        encryption_key: key.to_affine().to_encoded_point(true).as_bytes().to_vec(),
                    };
                    (
                        hex::encode(k256::Scalar::from(u64::from(i) + 10).to_bytes()),
                        operator,
                    )
                })
                .collect(),
        };
        let inert = || Self::pin(self.root.join("unused-vk"));
        let ownership = PinnedSparkVerifier::new(
            self.deployment,
            config.clone(),
            [9; 32],
            Self::pin(self.root.join("unused-verifier"))?,
            self.root.clone(),
            [
                SparkRole::Deposit,
                SparkRole::SenderFromOrigin,
                SparkRole::SenderFromTransfer,
                SparkRole::Receiver,
            ]
            .into_iter()
            .map(|role| Ok((role, inert()?)))
            .collect::<Result<Vec<_>>>()?,
        )?;
        let receive = PinnedReceiveVerifier::new(
            self.deployment,
            config,
            [9; 32],
            cluster.digest()?,
            Self::pin(self.root.join("unused-verifier"))?,
            self.root.clone(),
            inert()?,
        )?;
        let auth = PinnedAuthVerifier::new(
            self.deployment,
            Self::pin(self.tools.bb.clone())?,
            self.tools.crs.clone(),
            Self::pin(self.tools.vk.clone())?,
        )?;
        Engine::open_with_protocols(
            &self.root.join("signer/state.sqlite"),
            &self.root.join("checkpoint/floor.json"),
            ownership,
            Arc::new(Allow(self.deployment)),
            origin,
            NativeProtocols {
                receive: Some(ReceiveProtocol {
                    verifier: receive,
                    cluster,
                }),
                identity: true,
                auth: Some(auth),
                ..Default::default()
            },
        )
    }
    /// Allocates the coin's signer identity share, as the receive wallet does.
    fn parameters(&self, engine: &Engine) -> Result<AuthParameters> {
        let coin = random32();
        let intent = Intent {
            deployment: self.deployment,
            coin,
            previous_state: origin_previous_state(&self.deployment, &coin)?,
            operation: random32(),
            recipient_claim: origin_field(&self.deployment, &coin, 0)?,
            revision: 1,
        };
        let session = generate_secret();
        let response = engine.handle(&Request::sign(
            intent.clone(),
            Command::Allocate {},
            &normalized_key(&session)?,
        )?)?;
        let server: Vec<u8> = serde_json::from_value(response["server"].clone())?;
        Ok(AuthParameters {
            intent,
            session,
            user: random_scalar().to_bytes().into(),
            key_salt: random32(),
            server: server.as_slice().try_into()?,
        })
    }
    fn challenge(p: &AuthParameters, timestamp: u64) -> Result<Vec<u8>> {
        let public_key = p.key()?.compressed()?;
        Ok(SparkChallenge {
            timestamp,
            nonce: random32(),
            public_key,
        }
        .encode()?
        .to_vec())
    }
    fn journal(&self) -> PathBuf {
        self.root.join("wallets/auth")
    }
    fn prove(&self, input: &str) -> Result<Vec<u8>> {
        let (program, nargo) = self.tools.real.as_ref().context("real auth prover")?;
        let job = self.root.join("scratch").join(hex::encode(random32()));
        fs::DirBuilder::new().mode(0o700).create(&job)?;
        zark_protocol::storage::atomic_write(&job.join("input.toml"), input.as_bytes())?;
        let run = |command: &mut std::process::Command| -> Result<()> {
            let output = command.output()?;
            ensure!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            Ok(())
        };
        // nargo takes a git-cache lock under HOME even for path-only dependencies.
        run(std::process::Command::new(nargo)
            .env("HOME", &job)
            .args(["execute", "witness", "--program-dir"])
            .arg(program)
            .arg("--prover-name")
            .arg(job.join("input")))?;
        run(std::process::Command::new(&self.tools.bb)
            .args(["prove", "-t", "noir-recursive", "-b"])
            .arg(program.join("target/spark_auth_authorize.json"))
            .arg("-w")
            .arg(program.join("target/witness.gz"))
            .arg("-k")
            .arg(&self.tools.vk)
            .arg("-o")
            .arg(&job)
            .arg("-c")
            .arg(&self.tools.crs))?;
        Ok(fs::read(job.join("proof"))?)
    }
}

fn verify(p: &AuthParameters, raw: &[u8], signature: &[u8; 64]) -> Result<()> {
    let message = SparkChallenge::decode(raw)?.message()?;
    k256::schnorr::VerifyingKey::from_bytes(&p.key()?.compressed()?[1..])?.verify_raw(
        &message,
        &k256::schnorr::Signature::try_from(&signature[..])?,
    )?;
    Ok(())
}

#[test]
fn interrupted_ticket_resends_exact_requests_and_keeps_its_first_nonce() -> Result<()> {
    let f = Fixture::new(false)?;
    let mut engine = f.engine()?;
    let p = f.parameters(&engine)?;
    let raw = Fixture::challenge(&p, now()?)?;
    let mut journal = BlindAuthJournal::create(&f.journal(), &p)?;
    let sent = RefCell::new(Vec::new());

    // The signer commits the preparation, but its response is lost.
    let lost = journal.sign(
        &p,
        &raw,
        |r| {
            sent.borrow_mut().push(r.encode()?);
            engine.handle(r)?;
            anyhow::bail!("response lost")
        },
        |_, _| unreachable!("no proof before a nonce"),
    );
    assert!(lost.is_err());
    drop((engine, journal));
    (engine, journal) = (f.engine()?, BlindAuthJournal::open(&f.journal())?);

    // Exact resend: the Engine replays the same nonce; the inert verifier then
    // rejects the proof, so the nonce stays live for this ticket only.
    let failed = journal.sign(
        &p,
        &raw,
        |r| {
            sent.borrow_mut().push(r.encode()?);
            engine.handle(r)
        },
        |_, statement| {
            assert_eq!(statement.len(), spark_auth::ENCODED_LEN);
            Ok(vec![0; PROOF_BYTES])
        },
    );
    assert!(failed.is_err());
    let sent_now = sent.borrow().clone();
    assert_eq!(sent_now.len(), 3);
    assert_eq!(sent_now[0], sent_now[1], "preparation retry changed");
    let id = hex::encode(hash(&[&raw]));
    let nonce = journal.record.tickets[&id]
        .nonce
        .clone()
        .context("nonce stored")?;
    drop((engine, journal));
    (engine, journal) = (f.engine()?, BlindAuthJournal::open(&f.journal())?);

    // The issue request is resent byte-for-byte; nothing is reproven or rebound.
    let again = journal.sign(
        &p,
        &raw,
        |r| {
            sent.borrow_mut().push(r.encode()?);
            engine.handle(r)
        },
        |_, _| unreachable!("frozen issue request must be reused"),
    );
    assert!(again.is_err());
    assert_eq!(sent.borrow()[3], sent_now[2], "issue retry changed");
    assert_eq!(journal.record.tickets[&id].nonce.as_ref(), Some(&nonce));
    assert!(journal.record.tickets[&id].blinding.is_some());
    Ok(())
}

#[test]
fn journal_refuses_foreign_stale_and_other_scope_challenges() -> Result<()> {
    let f = Fixture::new(false)?;
    let engine = f.engine()?;
    let p = f.parameters(&engine)?;
    let mut journal = BlindAuthJournal::create(&f.journal(), &p)?;
    let never = |_: &Request| -> Result<Value> { unreachable!("nothing may reach the signer") };
    let no_proof = |_: &str, _: &[u8]| -> Result<Vec<u8>> { unreachable!() };

    let other = AuthParameters {
        intent: p.intent.clone(),
        session: p.session,
        user: random_scalar().to_bytes().into(),
        key_salt: p.key_salt,
        server: p.server,
    };
    assert!(
        journal
            .sign(&p, &Fixture::challenge(&other, now()?)?, never, no_proof)
            .is_err()
    );
    assert!(
        journal
            .sign(
                &other,
                &Fixture::challenge(&other, now()?)?,
                never,
                no_proof
            )
            .is_err()
    );
    let stale = now()? - spark_auth::MAX_AGE_SECONDS - 1;
    assert!(
        journal
            .sign(&p, &Fixture::challenge(&p, stale)?, never, no_proof)
            .is_err()
    );
    let mut noncanonical = Fixture::challenge(&p, now()?)?;
    noncanonical.push(0);
    assert!(journal.sign(&p, &noncanonical, never, no_proof).is_err());
    assert!(journal.record.tickets.is_empty());
    Ok(())
}

#[test]
#[ignore = "real auth proof; run with --ignored --nocapture and the tool variables"]
fn real_proof_journal_signs_spark_challenge_through_engine() -> Result<()> {
    let f = Fixture::new(true)?;
    let mut engine = f.engine()?;
    let p = f.parameters(&engine)?;
    let raw = Fixture::challenge(&p, now()?)?;
    let mut journal = BlindAuthJournal::create(&f.journal(), &p)?;
    let issued = RefCell::new(None);
    let started = Instant::now();
    let signature = journal.sign(
        &p,
        &raw,
        |r| {
            let response = engine.handle(r)?;
            if matches!(r.command, Command::AuthIssue { .. }) {
                *issued.borrow_mut() = Some((r.encode()?, response.clone()));
            }
            Ok(response)
        },
        |input, _| f.prove(input),
    )?;
    eprintln!(
        "journalled blind auth through Engine with real proof: {:?}",
        started.elapsed()
    );
    verify(&p, &raw, &signature)?;
    // Released only from the journal afterwards, and the signer replays its
    // committed response exactly after restart without a second nonce.
    let never = |_: &Request| -> Result<Value> { unreachable!() };
    assert_eq!(
        journal.sign(&p, &raw, never, |_, _| unreachable!())?,
        signature
    );
    drop((engine, journal));
    (engine, journal) = (f.engine()?, BlindAuthJournal::open(&f.journal())?);
    assert_eq!(
        journal.sign(&p, &raw, never, |_, _| unreachable!())?,
        signature
    );
    let (request, response) = issued.into_inner().context("issue sent")?;
    assert_eq!(engine.handle(&Request::decode(&request)?)?, response);
    let _ = fs::remove_dir_all(&f.root);
    Ok(())
}
