//! One explicit real-proof ownership flow on a signed synthetic native prefix.
//! No Spark services or existing wallet state are accessed by this fixture.
#[path = "real_fixture/auth_suite.rs"]
mod auth_suite;
#[path = "real_fixture/live_receive.rs"]
mod live_receive;
#[path = "real_fixture/native.rs"]
mod native;
#[path = "real_fixture/native_suite.rs"]
mod native_suite;
#[path = "real_fixture/receive.rs"]
mod receive;
#[path = "real_fixture/receive_suite.rs"]
mod receive_suite;
#[path = "real_fixture/suite.rs"]
mod suite;
use self::suite::{Suite, private_directory};
use super::{
    IssuedRecovery, NextRecipient, PrivateBacking, PrivateCertificate, PrivateReceiver,
    PrivateRecovery, PrivateSender, RecoveryJournal, RecoveryParameters, SenderParameters,
    origin_issuance, origin_prover_toml,
};
use anyhow::{Context, Result, ensure};
use k256::schnorr::SigningKey;
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};
use zark_protocol::{
    hash,
    owner_auth::generate_secret,
    random_scalar, random32,
    spark_lineage::{
        Intent, PinnedSparkVerifier, capability_commitment, origin_field, origin_previous_state,
        recipient_claim_commitment,
    },
    spark_wire::{Command, Predecessor, Request},
    storage::atomic_write,
};
use zark_signer::engine::spark::Engine;
use zeroize::Zeroizing;

struct Snapshot {
    backing: PrivateBacking,
    recovery: PrivateRecovery,
    certificate: PrivateCertificate,
    revision: u64,
}
struct Received {
    material: PrivateReceiver,
    snapshot: Snapshot,
}

#[test]
#[ignore = "requires pinned Nargo/BB/CRS and all four compiled Spark ownership roles"]
fn real_proof_alice_bob_carol_on_signed_synthetic_spark_prefix() -> Result<()> {
    run_fixture(2000)
}

#[test]
#[ignore = "requires pinned Nargo/BB/CRS and compiled Spark ownership/signing roles; synthetic backing only"]
fn real_proof_alice_bob_carol_on_signed_synthetic_received_root() -> Result<()> {
    run_fixture(1900)
}

fn run_fixture(native_delay: u32) -> Result<()> {
    let suite = Suite::load()?;
    let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../work/zark-spark/real-private-transfer-tests");
    fs::create_dir_all(&parent)?;
    let root = parent.join(hex::encode(random32()));
    private_directory(&root)?;
    for name in ["wire", "proofs", "scratch", "wallets"] {
        private_directory(&root.join(name))?;
    }
    suite.save_identity(&root)?;
    eprintln!(
        "Private real-proof Spark transfer fixture: {}",
        root.display()
    );
    atomic_write(
        &root.join("public-report.json"),
        &serde_json::to_vec_pretty(
            &json!({"status":"running","native_backing":"signed synthetic Spark prefix","native_refund_delay":native_delay,"live_spark_transfer":false}),
        )?,
    )?;
    let result = run(&suite, &root, native_delay);
    match result {
        Ok(report) => {
            atomic_write(
                &root.join("public-report.json"),
                &serde_json::to_vec_pretty(&report)?,
            )?;
            eprintln!(
                "Real-proof Alice -> Bob -> Carol PASS; public report: {}",
                root.join("public-report.json").display()
            );
            Ok(())
        }
        Err(error) => {
            atomic_write(
                &root.join("public-report.json"),
                &serde_json::to_vec_pretty(
                    &json!({"status":"failed","live_spark_transfer":false,"error":error.to_string()}),
                )?,
            )?;
            Err(error)
        }
    }
}

fn run(suite: &Suite, root: &Path, native_delay: u32) -> Result<Value> {
    let verifier = suite.verifier()?;
    let mut engine = suite.engine(root)?;
    let coin = random32();
    let owner = Zeroizing::new(generate_secret());
    let session = Zeroizing::new(generate_secret());
    let user = Zeroizing::new(random_scalar());
    let intent = Intent {
        deployment: suite.deployment,
        coin,
        previous_state: origin_previous_state(&suite.deployment, &coin)?,
        operation: random32(),
        recipient_claim: origin_field(&suite.deployment, &coin, 0)?,
        revision: 1,
    };
    let allocate = Request::sign(
        intent.clone(),
        Command::Allocate {},
        &SigningKey::from_bytes(&session[..])?,
    )?;
    let allocation = send(&engine, root, "alice-allocate", &allocate)?;
    let backing = if native_delay == 2000 {
        native::backing(suite.deployment, coin, *user, point(&allocation, "server")?)?
    } else {
        native::backing_at_delay(
            suite.deployment,
            coin,
            *user,
            point(&allocation, "server")?,
            native_delay,
        )?
    };
    let initial_prefix = hash(&[&serde_json::to_vec(backing.prefix())?]);
    let recovery = PrivateRecovery::prepare(
        &backing,
        RecoveryParameters {
            intent: intent.clone(),
            session: allocate.session,
            server: point(&allocation, "server")?,
            server_salt: digest(&allocation, "server_salt")?,
            user: user.to_bytes().into(),
            next_capability: capability_commitment(&suite.deployment, &coin, &owner)?,
            payout_secret: generate_secret(),
            fee: 500,
            owner_index: 1,
            schedule: suite.schedule(),
        },
    )?;
    let mut journal = RecoveryJournal::create(
        &root.join("wallets/alice-recovery"),
        Predecessor::Origin,
        &backing,
        recovery,
        *session,
    )?;
    let freeze = Request::sign(
        intent,
        Command::FreezeOrigin {
            backing: journal.recovery().frozen().backing,
            capability: journal.recovery().next_capability(),
        },
        &SigningKey::from_bytes(&session[..])?,
    )?;
    send(&engine, root, "alice-freeze-origin", &freeze)?;
    let prepare = journal.prepare_request()?;
    let prepared = send(&engine, root, "alice-prepare", &prepare)?;
    bind_nonce_reply(&mut journal, &prepared)?;
    ensure!(
        journal
            .saved_recovery_acknowledgement(&verifier, &root.join("scratch"))
            .is_err(),
        "acknowledgement existed before completed recoveries"
    );
    let issuance = origin_issuance(journal.recovery(), &verifier)?;
    let input = origin_prover_toml(journal.recovery(), &owner, &verifier)?;
    let proof = suite.prove(
        "deposit",
        &input,
        &issuance.encode()?,
        &root.join("proofs/alice-origin"),
    )?;
    let mut corrupt = proof.clone();
    corrupt[0] ^= 1;
    let invalid = Request::sign(
        allocate.intent.clone(),
        Command::Issue {
            statement: issuance.encode()?,
            proof: corrupt,
        },
        &SigningKey::from_bytes(&session[..])?,
    )?;
    ensure!(
        engine.handle(&invalid).is_err(),
        "actual signer accepted corrupted origin proof"
    );
    let issue = journal.issue_request(&issuance, &proof, &verifier, &root.join("scratch"))?;
    let issued = send(&engine, root, "alice-issue", &issue)?;
    drop(journal);
    let mut journal = RecoveryJournal::open(&root.join("wallets/alice-recovery"))?;
    let saved_issue = journal
        .saved_issue_request(&verifier, &root.join("scratch"))?
        .context("origin exact issuance request not retained")?;
    ensure!(
        saved_issue.encode()? == issue.encode()?,
        "origin request/proof changed after wallet reopen"
    );
    drop(engine);
    engine = suite.engine(root)?;
    ensure!(
        send(
            &engine,
            root,
            "alice-issue-exact-replay-after-reopen",
            &saved_issue
        )? == issued,
        "signer origin issuance replay changed"
    );
    journal.complete_issuance(issued_response(&issued)?, &verifier, &root.join("scratch"))?;
    drop(journal);
    let mut journal = RecoveryJournal::open(&root.join("wallets/alice-recovery"))?;
    let ack = journal.saved_recovery_acknowledgement(&verifier, &root.join("scratch"))?;
    let accepted = send(&engine, root, "alice-ack-synthetic-native-fixture", &ack)?;
    ensure!(accepted["accepted"] == true, "origin not acknowledged");
    let alice = snapshot(&journal, &verifier, root, number(&accepted, "revision")?)?;
    drop(journal);
    let bob_claim = Zeroizing::new(generate_secret());
    let bob_next = destination(suite, &alice, &bob_claim)?;
    let alice_sender = PrivateSender::create(
        &root.join("wallets/alice-sender"),
        SenderParameters {
            intent: bob_next.intent.clone(),
            session_secret: generate_secret(),
            owner_secret: *owner,
            claim_key: bob_next.claim_key,
            claim_salt: bob_next.claim_salt,
        },
        &alice.backing,
        &alice.recovery,
        &alice.certificate,
        &verifier,
        &root.join("scratch"),
    )?;
    let bob = transfer(
        suite,
        &mut engine,
        root,
        "bob",
        alice_sender,
        *bob_claim,
        "sender_from_origin",
    )?;
    let carol_claim = Zeroizing::new(generate_secret());
    let carol_next = destination(suite, &bob.snapshot, &carol_claim)?;
    let bob_sender = bob.material.start_sender(
        &root.join("wallets/bob-sender"),
        carol_next,
        &bob.snapshot.recovery,
        &bob.snapshot.certificate,
        &verifier,
        &root.join("scratch"),
    )?;
    let carol = transfer(
        suite,
        &mut engine,
        root,
        "carol",
        bob_sender,
        *carol_claim,
        "sender_from_transfer",
    )?;
    let prefix = |s: &Snapshot| -> Result<[u8; 32]> {
        Ok(hash(&[&serde_json::to_vec(s.backing.prefix())?]))
    };
    ensure!(
        prefix(&alice)? == initial_prefix
            && prefix(&bob.snapshot)? == initial_prefix
            && prefix(&carol.snapshot)? == initial_prefix,
        "native Spark prefix changed during private transfers"
    );
    let a = alice.certificate.native_lineage()?;
    let b = bob.snapshot.certificate.native_lineage()?;
    let c = carol.snapshot.certificate.native_lineage()?;
    ensure!(
        a.backing == b.backing
            && b.backing == c.backing
            && a.state != b.state
            && b.state != c.state,
        "private lineage or stable backing mismatch"
    );
    ensure!(
        alice.recovery.completed()?.delay_blocks() == 500
            && bob.snapshot.recovery.completed()?.delay_blocks() == 440
            && carol.snapshot.recovery.completed()?.delay_blocks() == 380,
        "private recovery schedule mismatch"
    );
    let report = json!({
        "status":"passed","flow":["Alice","Bob","Carol"],"amount_sats":64_000,
        "real_proofs_verified":5,"roles":["deposit","sender_from_origin","receiver","sender_from_transfer","receiver"],
        "backing_commitment":hex::encode(a.backing),"native_signed_prefix_sha256":hex::encode(initial_prefix),
        "native_prefix_unchanged":true,"internal_native_transfers":0,"both_recovery_variants_verified_for_each_owner":true,
        "recipient_recovery_and_certificate_saved_before_ack":true,"exact_issuance_replay_after_signer_reopen":true,
        "exact_proof_requests_retrieved_after_wallet_reopen":true,
        "corrupted_origin_proof_rejected":true,"previous_server_points_absent_from_recipient_offers":true,
        "native_openings_sent_to_blind_signer":false,"native_backing":"signed synthetic Spark prefix",
        "native_refund_delay":native_delay,"received_root_layout":native_delay != 2000,
        "native_prefix_provisioning":"known synthetic combined key; derived operator public key",
        "live_spark_transfer":false,"native_entry_exit_qualified":false,"live_chain_and_fresh_head_admission_qualified":false,
        "transport":"same-process authenticated request boundary; private offers and delta remain local fixture data",
    });
    Ok(report)
}

fn transfer(
    suite: &Suite,
    engine: &mut Engine,
    root: &Path,
    name: &str,
    sender: PrivateSender,
    claim: [u8; 32],
    sender_role: &str,
) -> Result<Received> {
    transfer_reopening(
        suite,
        engine,
        root,
        name,
        sender,
        claim,
        sender_role,
        &|| suite.engine(root),
    )
}

#[allow(clippy::too_many_arguments)]
fn transfer_reopening(
    suite: &Suite,
    engine: &mut Engine,
    root: &Path,
    name: &str,
    mut sender: PrivateSender,
    claim: [u8; 32],
    sender_role: &str,
    reopen: &dyn Fn() -> Result<Engine>,
) -> Result<Received> {
    let verifier = suite.verifier()?;
    let reserve = sender.reservation_request()?;
    let sender_path = root.join(match sender_role {
        "sender_from_origin" => "wallets/alice-sender",
        "sender_from_transfer" => "wallets/bob-sender",
        _ => anyhow::bail!("unexpected fixture sender role"),
    });
    let offer = hand_over(
        suite,
        engine,
        root,
        name,
        sender,
        &sender_path,
        sender_role,
        &root.join(format!("proofs/{name}-sender")),
        &mut |_| Ok(()),
    )?;
    atomic_write(
        &root.join(format!("wallets/{name}-offer.private.json")),
        &offer,
    )?;
    let material = PrivateReceiver::create(
        &root.join(format!("wallets/{name}-recipient")),
        &offer,
        claim,
        &verifier,
        &root.join("scratch"),
    )?;
    let retired_mask = |engine: &Engine| -> Result<()> {
        let retired = send(
            engine,
            root,
            &format!("{name}-retired-mask-replay"),
            &reserve,
        )?;
        ensure!(
            retired["superseded"] == true && retired.get("mask").is_none(),
            "retired mask returned after recipient refresh"
        );
        Ok(())
    };
    claim_offer(
        suite,
        engine,
        root,
        name,
        material,
        &root.join(format!("wallets/{name}-recovery")),
        &root.join(format!("proofs/{name}-receiver")),
        reopen,
        &retired_mask,
        &mut |_| Ok(()),
    )
}

/// Sender half of a private handover: reserve, prove the handover once, send
/// the exact retained request and return the recipient offer. A sender whose
/// handover request is already journaled resends those exact bytes and never
/// proves again. `root` holds the wire transcript and scratch space.
#[allow(clippy::too_many_arguments)]
fn hand_over(
    suite: &Suite,
    engine: &Engine,
    root: &Path,
    name: &str,
    mut sender: PrivateSender,
    sender_path: &Path,
    sender_role: &str,
    proof_job: &Path,
    stage: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Zeroizing<Vec<u8>>> {
    let verifier = suite.verifier()?;
    let scratch = root.join("scratch");
    let saved_request = if let Some(saved) = sender.saved_handover_request(&verifier, &scratch)? {
        saved
    } else {
        let reserve = sender.reservation_request()?;
        let mask = send(engine, root, &format!("{name}-reserve"), &reserve)?;
        sender.save_mask(
            digest(&mask, "mask")?,
            digest(&mask, "mask_salt")?,
            digest(&mask, "mask_commitment")?,
        )?;
        stage("prove_sender")?;
        let input = sender.prover_toml(&verifier, &scratch)?;
        let handover = sender.handover()?;
        let proof = suite.prove(sender_role, &input, &handover.encode()?, proof_job)?;
        let request = sender.handover_request(&proof, &verifier, &scratch)?;
        drop(sender);
        sender = PrivateSender::open(sender_path, &verifier, &scratch)?;
        let saved_request = sender
            .saved_handover_request(&verifier, &scratch)?
            .context("exact sender proof/request not retained")?;
        ensure!(
            saved_request.encode()? == request.encode()?,
            "sender request/proof changed after reopen"
        );
        saved_request
    };
    stage("authorize")?;
    ensure!(
        send(engine, root, &format!("{name}-handover"), &saved_request)?["authorized"] == true,
        "sender handover not authorized"
    );
    let offer = sender.private_offer(&verifier, &scratch)?;
    let fields: Value = serde_json::from_slice(&offer)?;
    for forbidden in [
        "certificate",
        "server",
        "server_point",
        "authorization",
        "previous_authorization",
        "recovery",
        "owner_secret",
    ] {
        ensure!(
            fields.get(forbidden).is_none(),
            "historical private material included in recipient offer"
        );
    }
    // Drop the innermost sender lock before the caller creates recipient locks.
    drop(sender);
    Ok(offer)
}

/// Recipient half: refresh the share, prove receipt, take the issued recovery
/// and acknowledge it only after the exact issuance survives a signer reopen.
/// An existing recovery journal resumes with its exact retained requests.
/// `between` runs after the proposal is accepted (fixture-only checks).
#[allow(clippy::too_many_arguments)]
fn claim_offer(
    suite: &Suite,
    engine: &mut Engine,
    root: &Path,
    name: &str,
    mut material: PrivateReceiver,
    recovery_dir: &Path,
    proof_job: &Path,
    reopen: &dyn Fn() -> Result<Engine>,
    between: &dyn Fn(&Engine) -> Result<()>,
    stage: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Received> {
    let verifier = suite.verifier()?;
    let scratch = root.join("scratch");
    stage("propose")?;
    let proposal = material.proposal_request()?;
    let draft = send(engine, root, &format!("{name}-private-proposal"), &proposal)?;
    between(engine)?;
    stage("prepare")?;
    let mut journal = if recovery_dir.join("private-receiver.json").exists() {
        RecoveryJournal::open(recovery_dir)?
    } else {
        let recovery = material.recovery(
            point(&draft, "draft_server")?,
            digest(&draft, "server_salt")?,
            generate_secret(),
            500,
            suite.schedule(),
        )?;
        material.create_recovery_journal(recovery_dir, recovery)?
    };
    let issue = if let Some(saved) = journal.saved_issue_request(&verifier, &scratch)? {
        saved
    } else {
        let prepare = journal.prepare_request()?;
        bind_nonce_reply(
            &mut journal,
            &send(engine, root, &format!("{name}-prepare"), &prepare)?,
        )?;
        let issuance = material.issuance(journal.recovery(), &verifier)?;
        let input = material.prover_toml(journal.recovery(), &verifier, &scratch)?;
        stage("prove_receiver")?;
        let proof = suite.prove("receiver", &input, &issuance.encode()?, proof_job)?;
        journal.issue_request(&issuance, &proof, &verifier, &scratch)?
    };
    stage("issue")?;
    let issued = send(engine, root, &format!("{name}-issue"), &issue)?;
    drop(journal);
    let mut journal = RecoveryJournal::open(recovery_dir)?;
    let saved_issue = journal
        .saved_issue_request(&verifier, &scratch)?
        .context("recipient exact issuance request not retained")?;
    ensure!(
        saved_issue.encode()? == issue.encode()?,
        "recipient request/proof changed after wallet reopen"
    );
    // Reopening the real signer must retrieve the exact committed dual response.
    *engine = reopen()?;
    ensure!(
        send(
            engine,
            root,
            &format!("{name}-issue-exact-replay-after-reopen"),
            &saved_issue
        )? == issued,
        "recipient issuance replay changed"
    );
    journal.complete_issuance(issued_response(&issued)?, &verifier, &scratch)?;
    stage("acknowledge")?;
    drop(journal);
    let mut journal = RecoveryJournal::open(recovery_dir)?;
    let ack = journal.saved_recovery_acknowledgement(&verifier, &scratch)?;
    let accepted = send(
        engine,
        root,
        &format!("{name}-ack-synthetic-native-fixture"),
        &ack,
    )?;
    ensure!(accepted["accepted"] == true, "recipient not acknowledged");
    let snapshot = snapshot(&journal, &verifier, root, number(&accepted, "revision")?)?;
    // Recovery lock was acquired after the recipient-material lock. Close it
    // first, preserving ProcessLock's nesting and child prover inheritance.
    drop(journal);
    Ok(Received { material, snapshot })
}

fn snapshot(
    journal: &RecoveryJournal,
    verifier: &PinnedSparkVerifier,
    root: &Path,
    revision: u64,
) -> Result<Snapshot> {
    let backing = PrivateBacking::decode_private(&journal.backing().encode_private()?)?;
    let recovery =
        PrivateRecovery::decode_private(&backing, &journal.recovery().encode_private()?)?;
    let certificate = journal.certificate(verifier, &root.join("scratch"))?;
    Ok(Snapshot {
        backing,
        recovery,
        certificate,
        revision,
    })
}
fn destination(suite: &Suite, current: &Snapshot, claim: &[u8; 32]) -> Result<NextRecipient> {
    let claim_key = SigningKey::from_bytes(claim)?
        .verifying_key()
        .to_bytes()
        .into();
    destination_key(suite, current, claim_key)
}
/// The sender needs only the recipient's public claim key.
fn destination_key(
    suite: &Suite,
    current: &Snapshot,
    claim_key: [u8; 32],
) -> Result<NextRecipient> {
    let c = current.certificate.native_lineage()?;
    let operation = random32();
    let claim_salt = random32();
    Ok(NextRecipient {
        intent: Intent {
            deployment: suite.deployment,
            coin: c.coin,
            previous_state: c.state,
            operation,
            recipient_claim: recipient_claim_commitment(
                &suite.deployment,
                &c.coin,
                &operation,
                &claim_key,
                &claim_salt,
            )?,
            revision: current.revision,
        },
        claim_key,
        claim_salt,
    })
}
fn send(engine: &Engine, root: &Path, label: &str, request: &Request) -> Result<Value> {
    let wire = request.encode()?;
    atomic_write(&root.join(format!("wire/{label}.request.json")), &wire)?;
    let response = engine
        .handle(request)
        .with_context(|| format!("actual Spark signer phase {label}"))?;
    let encoded = Zeroizing::new(serde_json::to_vec(&response)?);
    atomic_write(
        &root.join(format!("wire/{label}.response.private.json")),
        &encoded,
    )?;
    Ok(response)
}
fn bind_nonce_reply(journal: &mut RecoveryJournal, reply: &Value) -> Result<()> {
    let branches = reply["server_nonces"]
        .as_array()
        .context("missing actual signer nonce set")?;
    ensure!(branches.len() == 2, "actual signer nonce count");
    let mut points = Vec::new();
    let mut ids = Vec::new();
    for (i, b) in branches.iter().enumerate() {
        ensure!(
            number(b, "index")? == i as u64
                && digest(b, "commitment")? == journal.recovery().frozen().nonce_commitments[i],
            "actual signer nonce role or frozen commitment"
        );
        let id = digest(b, "id")?;
        ensure!(id != [0; 32], "empty actual signer nonce identity");
        ids.push(id);
        points.push(point(b, "point")?);
    }
    ensure!(ids[0] != ids[1], "actual signer repeated nonce identity");
    journal.bind_nonces(
        points
            .try_into()
            .map_err(|_| anyhow::anyhow!("missing actual signer nonce"))?,
    )
}
fn issued_response(reply: &Value) -> Result<IssuedRecovery> {
    ensure!(
        reply["issued"] == true,
        "actual signer did not issue recovery"
    );
    Ok(IssuedRecovery {
        partials: serde_json::from_value(reply["partials"].clone())?,
        certificate: serde_json::from_value(reply["certificate"].clone())?,
        certificate_id: digest(reply, "certificate_id")?,
        state: digest(reply, "state")?,
        capability: digest(reply, "capability")?,
        origin_signature: serde_json::from_value(reply["origin_signature"].clone())?,
    })
}
fn digest(reply: &Value, key: &str) -> Result<[u8; 32]> {
    serde_json::from_value(reply[key].clone()).with_context(|| format!("actual signer field {key}"))
}
fn point(reply: &Value, key: &str) -> Result<[u8; 64]> {
    let value: Vec<u8> = serde_json::from_value(reply[key].clone())?;
    let point: [u8; 64] = value
        .try_into()
        .map_err(|_| anyhow::anyhow!("actual signer point {key} length"))?;
    zark_protocol::point(&point)?;
    Ok(point)
}
fn number(reply: &Value, key: &str) -> Result<u64> {
    reply[key]
        .as_u64()
        .with_context(|| format!("actual signer integer {key}"))
}
