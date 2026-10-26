//! Opt-in local presign+sign through the real Engine and wallet journal, without
//! Spark. Its inert pinned proof assets are never executed: identity commands
//! verify no proofs. Fixtures stay under ignored `work/identity-perf`.
use super::*;
use k256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use std::{fs, os::unix::fs::DirBuilderExt, sync::Arc, time::Instant};
use zark_protocol::{
    handoff::TransferContext,
    owner_auth::generate_secret,
    proof::ArtifactPin,
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

struct Fixture {
    root: PathBuf,
    deployment: Digest,
    origin: Digest,
    ecdsa_2p: bool,
}
impl Fixture {
    fn new() -> Result<Self> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../work/identity-perf")
            .join(hex::encode(random32()));
        fs::create_dir_all(root.parent().context("fixture parent")?)?;
        for dir in ["", "signer", "checkpoint", "wallets"] {
            fs::DirBuilder::new().mode(0o700).create(root.join(dir))?;
        }
        fs::write(root.join("unused-verifier"), b"never executed")?;
        fs::write(
            root.join("unused-vk"),
            vec![1u8; zark_protocol::assets::VK_BYTES],
        )?;
        Ok(Self {
            root,
            deployment: random32(),
            origin: generate_secret(),
            ecdsa_2p: false,
        })
    }
    fn pin(&self, name: &str) -> Result<ArtifactPin> {
        let path = self.root.join(name);
        let sha256 = hash(&[&fs::read(&path)?]);
        Ok(ArtifactPin { path, sha256 })
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
        let ownership = PinnedSparkVerifier::new(
            self.deployment,
            config.clone(),
            [9; 32],
            self.pin("unused-verifier")?,
            self.root.clone(),
            [
                SparkRole::Deposit,
                SparkRole::SenderFromOrigin,
                SparkRole::SenderFromTransfer,
                SparkRole::Receiver,
            ]
            .into_iter()
            .map(|role| Ok((role, self.pin("unused-vk")?)))
            .collect::<Result<Vec<_>>>()?,
        )?;
        let receive = PinnedReceiveVerifier::new(
            self.deployment,
            config,
            [9; 32],
            cluster.digest()?,
            self.pin("unused-verifier")?,
            self.root.clone(),
            self.pin("unused-vk")?,
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
                ecdsa_2p: self.ecdsa_2p,
                ..Default::default()
            },
        )
    }
    fn wallet(&self, engine: &Engine) -> Result<JointIdentityJournal> {
        self.wallet_with(engine, JointIdentityJournal::create)
    }
    fn wallet_with(
        &self,
        engine: &Engine,
        create: fn(&Path, &Path, &IdentityParameters) -> Result<JointIdentityJournal>,
    ) -> Result<JointIdentityJournal> {
        let coin = random32();
        let params = IdentityParameters {
            intent: Intent {
                deployment: self.deployment,
                coin,
                previous_state: origin_previous_state(&self.deployment, &coin)?,
                operation: random32(),
                recipient_claim: origin_field(&self.deployment, &coin, 0)?,
                revision: 1,
            },
            session: generate_secret(),
            user: random_scalar().to_bytes().into(),
            owner: generate_secret(),
        };
        // Like the local regtest fixture, both parties share only opaque frames.
        let mut wallet = create(
            &self.root.join("wallets/identity"),
            &self.root.join("signer/state.sqlite.identity-frames"),
            &params,
        )?;
        wallet.bind_allocation(&engine.handle(&wallet.allocation_request()?)?)?;
        Ok(wallet)
    }
    fn reopen(&self) -> Result<(Engine, JointIdentityJournal)> {
        Ok((
            self.engine()?,
            JointIdentityJournal::open(&self.root.join("wallets/identity"))?,
        ))
    }
}

/// Interruption points for one presign; `None` runs uninterrupted.
#[derive(Clone, Copy, PartialEq)]
enum Interrupt {
    /// Restart both parties before sending this round's frame.
    BeforeRequest(usize),
    /// Restart after the signer committed this round but before the wallet bound it.
    BeforeBind(usize),
}

fn presign_and_sign(interrupts: &[Interrupt]) -> Result<()> {
    let fixture = Fixture::new()?;
    let mut engine = fixture.engine()?;
    let mut wallet = fixture.wallet(&engine)?;
    let digest = random32();
    let started = Instant::now();
    let request = wallet.prepare_message_request(digest)?;
    let id = request.intent.operation;
    let response = engine.handle(&request)?;
    let initial = engine.identity_initial_frame(&request)?;
    wallet.bind_prepare(&id, &response, &initial)?;
    eprintln!(
        "identity prepare: {:?}, initial {} bytes",
        started.elapsed(),
        initial.len()
    );
    let mut step = 0;
    let mut frame_bytes = initial.len();
    while !wallet.presign_rounds_complete(&id)? {
        if interrupts.contains(&Interrupt::BeforeRequest(step)) {
            wallet.next_request(&id)?;
            drop((engine, wallet));
            (engine, wallet) = fixture.reopen()?;
        }
        let round = Instant::now();
        let (request, frame) = wallet.next_request(&id)?;
        let evaluated = round.elapsed();
        let signer = Instant::now();
        let (response, reply) = engine.handle_identity_frame(&request, &frame)?;
        let contributed = signer.elapsed();
        let reply = reply.context("identity presign aborted")?;
        if interrupts.contains(&Interrupt::BeforeBind(step)) {
            drop((engine, wallet));
            (engine, wallet) = fixture.reopen()?;
            let (retry, again) = wallet.next_request(&id)?;
            ensure!(
                retry.encode()? == request.encode()? && again == frame,
                "identity request retry changed"
            );
            ensure!(
                engine.handle_identity_frame(&request, &frame)?
                    == (response.clone(), Some(reply.clone())),
                "identity frame exact replay changed after restart"
            );
        }
        let bind = Instant::now();
        wallet.bind_reply(&id, &request, &response, &reply)?;
        eprintln!(
            "identity round {step}: wallet {evaluated:?} -> {} bytes, signer {contributed:?} -> {} bytes, bind {:?}",
            frame.len(),
            reply.len(),
            bind.elapsed()
        );
        frame_bytes += frame.len() + reply.len();
        step += 1;
    }
    let finish = Instant::now();
    wallet.finish_presign(&id)?;
    eprintln!("identity finish: {:?}", finish.elapsed());
    eprintln!(
        "identity presign total: {:?}, {frame_bytes} frame bytes",
        started.elapsed()
    );
    let online = Instant::now();
    let request = wallet.sign_request(digest)?;
    let response = engine.handle(&request)?;
    ensure!(
        engine.handle(&request)? == response,
        "identity sign exact replay changed"
    );
    let signature = wallet.complete_signature(&request, &response)?;
    VerifyingKey::from_sec1_bytes(&wallet.public_key()?)?
        .verify_prehash(&digest, &Signature::from_der(&signature)?)?;
    eprintln!("identity online signature: {:?}", online.elapsed());
    ensure!(
        wallet.saved_signature(&digest)? == Some(signature),
        "identity signature was not retained"
    );
    drop((engine, wallet));
    fixture.reopen()?;
    // Each transcript retains about 1 GB of frames; keep only failed fixtures.
    fs::remove_dir_all(&fixture.root)?;
    Ok(())
}

#[test]
#[ignore = "about 20 s of optimized MPC; run with --ignored --nocapture"]
fn local_identity_presign_and_sign_timing() -> Result<()> {
    presign_and_sign(&[])
}

#[test]
#[ignore = "replays several MPC prefixes; run with --ignored --nocapture"]
fn local_identity_presign_resumes_exactly_after_restarts() -> Result<()> {
    presign_and_sign(&[
        Interrupt::BeforeRequest(0),
        Interrupt::BeforeBind(2),
        Interrupt::BeforeRequest(4),
    ])
}

#[cfg(feature = "ecdsa-2p")]
mod ecdsa_2p {
    use super::*;
    use zark_protocol::spark_wire::ecdsa_2p::{self as wire, Frame};

    fn fixture() -> Result<(Fixture, Engine, JointIdentityJournal)> {
        let mut fixture = Fixture::new()?;
        fixture.ecdsa_2p = true;
        let engine = fixture.engine()?;
        let wallet = fixture.wallet_with(&engine, JointIdentityJournal::create_ecdsa)?;
        Ok((fixture, engine, wallet))
    }

    /// A fresh operator challenge addressed to this identity, and its digest.
    fn challenge(wallet: &JointIdentityJournal) -> Result<(EntryMessage, Digest)> {
        let public = wallet.public_key()?;
        let message = EntryMessage::challenge(&encode_challenge(&random32(), &public), &public)?;
        let digest = message.digest();
        Ok((message, digest))
    }

    #[test]
    fn keygen_replaces_both_shares_and_signs_frozen_digests() -> Result<()> {
        let (fixture, engine, mut wallet) = fixture()?;
        let allocated = wallet.record.server.clone();
        assert!(
            wallet.public_key().is_err(),
            "identity is unusable before key generation"
        );
        let started = Instant::now();
        let mut send = |r: &Request| engine.handle(r);
        wallet.ecdsa_keygen(&mut send)?;
        eprintln!("ECDSA-2P key generation: {:?}", started.elapsed());
        ensure!(
            wallet.record.server == allocated,
            "allocation response must stay replayable"
        );
        ensure!(
            wallet.server()?.to_vec() != allocated.context("allocation")?,
            "server share not replaced"
        );
        // Allocation replays still return the original point, which the wallet accepts.
        wallet.bind_allocation(&engine.handle(&wallet.allocation_request()?)?)?;

        let (message, digest) = challenge(&wallet)?;
        let started = Instant::now();
        let signature = wallet.ecdsa_sign(&message, &mut send)?;
        eprintln!("ECDSA-2P signature: {:?}", started.elapsed());
        VerifyingKey::from_sec1_bytes(&wallet.public_key()?)?
            .verify_prehash(&digest, &Signature::from_der(&signature)?)?;
        ensure!(
            wallet.saved_signature(&digest)? == Some(signature),
            "signature not retained"
        );

        let public = wallet.public_key()?;
        drop((engine, wallet));
        let (engine, mut wallet) = fixture.reopen()?;
        ensure!(
            wallet.public_key()? == public,
            "identity changed after restart"
        );
        let mut send = |r: &Request| engine.handle(r);
        ensure!(
            wallet.ecdsa_keygen(&mut send).is_ok(),
            "finished key generation is idempotent"
        );
        let (message, other) = challenge(&wallet)?;
        let signature = wallet.ecdsa_sign(&message, &mut send)?;
        VerifyingKey::from_sec1_bytes(&public)?
            .verify_prehash(&other, &Signature::from_der(&signature)?)?;
        fs::remove_dir_all(&fixture.root)?;
        Ok(())
    }

    #[test]
    fn signer_rejects_reuse_garbled_entry_signing_and_late_keygen() -> Result<()> {
        let (fixture, engine, mut wallet) = fixture()?;
        let gc = wallet.prepare_message_request(random32());
        ensure!(
            gc.is_err() || engine.handle(&gc?).is_err(),
            "allocation must wait for cb-mpc key generation"
        );
        wallet.record.signing.clear();
        let mut send = |r: &Request| engine.handle(r);
        wallet.ecdsa_keygen(&mut send)?;
        let gc = wallet.prepare_message_request(random32())?;
        ensure!(
            engine.handle(&gc).is_err(),
            "garbled-circuit entry ECDSA must stay closed"
        );
        wallet.record.signing.clear();
        wallet.persist()?;

        // A second key generation would replace the share the wallet relies on.
        let mut session = zark_spark_ecdsa_2p::Session::keygen(
            zark_spark_ecdsa_2p::Role::P1,
            std::time::Duration::from_secs(10),
        )?;
        let frame = zark_protocol::spark_wire::ecdsa_2p::Frame::new(session.exchange(None)?)?;
        let again = wallet.signed(
            zark_protocol::spark_wire::ecdsa_2p::keygen_intent(&wallet.record.intent, &frame)?,
            Command::EcdsaKeygen { frame },
        )?;
        ensure!(
            engine.handle(&again).is_err(),
            "ECDSA-2P key generation must run once"
        );

        // Finishing an unknown ticket, or one whose session was lost, fails.
        let ticket =
            zark_protocol::spark_wire::ecdsa_2p::sign_intent(&wallet.record.intent, &[6; 32])?;
        let frame = zark_protocol::spark_wire::ecdsa_2p::Frame::new(vec![1; 8])?;
        let finish = wallet.signed(
            zark_protocol::spark_wire::ecdsa_2p::sign_finish_intent(&ticket, &frame)?,
            Command::EcdsaSignFinish {
                ticket: ticket.operation,
                frame,
            },
        )?;
        ensure!(
            engine.handle(&finish).is_err(),
            "unknown ECDSA-2P ticket finished"
        );
        fs::remove_dir_all(&fixture.root)?;
        Ok(())
    }

    #[test]
    fn lost_signer_session_aborts_only_that_attempt() -> Result<()> {
        let (fixture, engine, mut wallet) = fixture()?;
        wallet.ecdsa_keygen(&mut |r: &Request| engine.handle(r))?;
        let (message, digest) = challenge(&wallet)?;
        // Restart the signer between the ticket's start and finish requests.
        let mut engine = Some(engine);
        let mut restarted = false;
        let mut interrupting = |r: &Request| -> Result<Value> {
            if matches!(r.command, Command::EcdsaSignFinish { .. }) && !restarted {
                restarted = true;
                engine = None;
                engine = Some(fixture.engine()?);
            }
            engine.as_ref().context("engine")?.handle(r)
        };
        ensure!(
            wallet.ecdsa_sign(&message, &mut interrupting).is_err(),
            "lost session must abort"
        );
        let signature = wallet.ecdsa_sign(&message, &mut interrupting)?;
        VerifyingKey::from_sec1_bytes(&wallet.public_key()?)?
            .verify_prehash(&digest, &Signature::from_der(&signature)?)?;
        fs::remove_dir_all(&fixture.root)?;
        Ok(())
    }

    /// A finish request for `ticket` carrying `frame`, signed with the wallet session.
    fn finish_with(
        wallet_intent: &Intent,
        key: &k256::schnorr::SigningKey,
        ticket: Digest,
        frame: Frame,
    ) -> Result<Request> {
        let mut opened = wallet_intent.clone();
        opened.operation = ticket;
        Request::sign(
            wire::sign_finish_intent(&opened, &frame)?,
            Command::EcdsaSignFinish { ticket, frame },
            key,
        )
    }

    fn flipped(frame: &Frame) -> Result<Frame> {
        let mut bytes = frame.as_bytes().to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        Frame::new(bytes)
    }

    #[test]
    fn released_ticket_replays_message_4_exactly_and_refuses_another_blind_message() -> Result<()> {
        let (fixture, engine, mut wallet) = fixture()?;
        let key = normalized_key(&wallet.record.session)?;
        let base = wallet.record.intent.clone();
        wallet.ecdsa_keygen(&mut |r: &Request| engine.handle(r))?;

        // The signer never accepts the digest itself.
        let nonce = random32();
        let plain = Request::sign(
            wire::sign_intent(&base, &nonce)?,
            Command::EcdsaSign {
                message: Some(random32()),
                nonce,
                frame: Frame::new(vec![1; 8])?,
            },
            &key,
        )?;
        let error = engine
            .handle(&plain)
            .err()
            .context("signer accepted a plaintext digest")?;
        ensure!(error.to_string().contains("must not receive"), "{error}");

        let mut finished: Option<(Request, Value)> = None;
        let mut probes = Vec::new();
        let mut probing = |r: &Request| -> Result<Value> {
            let response = engine.handle(r)?;
            if let Command::EcdsaSignFinish { ticket, frame } = &r.command {
                probes.push(("exact retry replays", engine.handle(r)? == response));
                let other = finish_with(&base, &key, *ticket, flipped(frame)?)?;
                probes.push(("second m'' refused", engine.handle(&other).is_err()));
                finished = Some((r.clone(), response.clone()));
            }
            Ok(response)
        };
        let (message, digest) = challenge(&wallet)?;
        let signature = wallet.ecdsa_sign(&message, &mut probing)?;
        VerifyingKey::from_sec1_bytes(&wallet.public_key()?)?
            .verify_prehash(&digest, &Signature::from_der(&signature)?)?;
        for (name, ok) in probes {
            ensure!(ok, "{name}");
        }

        let (request, response) = finished.context("finish not observed")?;
        drop(engine);
        let engine = fixture.engine()?;
        ensure!(
            engine.handle(&request)? == response,
            "replay after restart changed message 4"
        );
        let Command::EcdsaSignFinish { ticket, frame } = &request.command else {
            unreachable!()
        };
        let other = finish_with(&base, &key, *ticket, flipped(frame)?)?;
        ensure!(
            engine.handle(&other).is_err(),
            "second m'' accepted after restart"
        );
        fs::remove_dir_all(&fixture.root)?;
        Ok(())
    }

    #[test]
    fn tampered_blind_message_fails_and_tickets_are_capped() -> Result<()> {
        let (fixture, engine, mut wallet) = fixture()?;
        let key = normalized_key(&wallet.record.session)?;
        let base = wallet.record.intent.clone();
        wallet.ecdsa_keygen(&mut |r: &Request| engine.handle(r))?;
        let mut tampering = |r: &Request| -> Result<Value> {
            match &r.command {
                Command::EcdsaSignFinish { ticket, frame } => {
                    engine.handle(&finish_with(&base, &key, *ticket, flipped(frame)?)?)
                }
                _ => engine.handle(r),
            }
        };
        ensure!(
            wallet
                .ecdsa_sign(&challenge(&wallet)?.0, &mut tampering)
                .is_err(),
            "tampered m'' produced a signature"
        );

        // Entry needs one operator challenge and one claim payload; the
        // tampered attempt burned the first of those two tickets.
        let mut send = |r: &Request| engine.handle(r);
        let (message, digest) = challenge(&wallet)?;
        let signature = wallet.ecdsa_sign(&message, &mut send)?;
        VerifyingKey::from_sec1_bytes(&wallet.public_key()?)?
            .verify_prehash(&digest, &Signature::from_der(&signature)?)?;
        let error = wallet
            .ecdsa_sign(&challenge(&wallet)?.0, &mut send)
            .err()
            .context("a third ECDSA-2P ticket opened")?;
        ensure!(error.to_string().contains("exhausted"), "{error}");
        fs::remove_dir_all(&fixture.root)?;
        Ok(())
    }

    #[test]
    fn wallet_retains_its_share_until_the_signer_confirms() -> Result<()> {
        let (fixture, engine, mut wallet) = fixture()?;
        // Drop the finish response after the signer committed it.
        let mut dropped = false;
        let mut lossy = |r: &Request| -> Result<Value> {
            let response = engine.handle(r)?;
            if matches!(r.command, Command::EcdsaKeygenFinish { .. }) && !dropped {
                dropped = true;
                anyhow::bail!("response lost");
            }
            Ok(response)
        };
        ensure!(
            wallet.ecdsa_keygen(&mut lossy).is_err(),
            "lost response must surface"
        );
        drop(wallet);
        let mut wallet = JointIdentityJournal::open(&fixture.root.join("wallets/identity"))?;
        let mut send = |r: &Request| engine.handle(r);
        wallet.ecdsa_keygen(&mut send)?;
        let (message, digest) = challenge(&wallet)?;
        let signature = wallet.ecdsa_sign(&message, &mut send)?;
        VerifyingKey::from_sec1_bytes(&wallet.public_key()?)?
            .verify_prehash(&digest, &Signature::from_der(&signature)?)?;
        fs::remove_dir_all(&fixture.root)?;
        Ok(())
    }
}
