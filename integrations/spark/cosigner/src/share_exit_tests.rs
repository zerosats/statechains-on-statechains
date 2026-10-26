//! Journal ordering and verification only. The signer response is sealed with
//! the protocol primitive the Engine uses; the Engine path itself is covered
//! by the signer's share-release tests, and no Spark operator is contacted.
use super::*;
use std::{cell::RefCell, collections::BTreeMap, fs, os::unix::fs::DirBuilderExt, path::PathBuf};
use zark_protocol::{point_bytes, random32, spark_lineage as lineage};

struct Fixture {
    root: PathBuf,
    owner: SigningKey,
    wallet: Digest,
    server_secret: Digest,
    coin: ExitCoin,
}

impl Fixture {
    fn new() -> Result<Self> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../work/spark-share-exit-tests")
            .join(hex::encode(random32()));
        fs::create_dir_all(&root)?;
        let owner = SigningKey::from_bytes(&random_scalar().to_bytes())?;
        let (wallet, server) = (random_scalar(), random_scalar());
        let (deployment, coin) = (random32(), random32());
        let capability = lineage::public_capability_commitment(
            &deployment,
            &coin,
            &owner.verifying_key().to_bytes().into(),
        )?;
        Ok(Self {
            coin: ExitCoin {
                deployment,
                coin,
                state: random32(),
                capability,
                server: point_bytes(k256::ProjectivePoint::GENERATOR * server)?.to_vec(),
                joint: point_bytes(k256::ProjectivePoint::GENERATOR * (wallet + server))?.to_vec(),
                root: random32(),
                refunds: [random32(), random32()],
                receiver: compressed(&random_scalar()).to_vec(),
            },
            root,
            owner,
            wallet: wallet.to_bytes().into(),
            server_secret: server.to_bytes().into(),
        })
    }
    fn dir(&self) -> PathBuf {
        self.root.join("exit")
    }
    /// What the Engine returns after committing this exact request.
    fn respond(&self, request: &Request, server_secret: &Digest) -> Result<Value> {
        let Command::ShareRelease { recipient, .. } = &request.command else {
            unreachable!()
        };
        let binding = Binding {
            deployment: self.coin.deployment,
            coin: self.coin.coin,
            intent: release::intent_digest(&request.intent)?,
            request: request.digest()?,
            session: request.session,
            recipient: recipient.as_slice().try_into()?,
            server: point_bytes(k256::ProjectivePoint::GENERATOR * scalar(server_secret)?)?,
            state: self.coin.state,
            capability: self.coin.capability,
            revision: request.intent.revision,
            committed_revision: request.intent.revision + 1,
        };
        Ok(serde_json::json!({
            "ciphertext": release::seal(&binding, server_secret)?,
            "server": binding.server.to_vec(),
            "state": self.coin.state,
            "capability": self.coin.capability,
            "revision": request.intent.revision + 1,
        }))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Default)]
struct Chain(RefCell<BTreeMap<Digest, TxStatus>>, RefCell<bool>);
impl ChainView for Chain {
    fn status(&self, txid: &Digest) -> Result<TxStatus> {
        ensure!(!*self.1.borrow(), "node unavailable");
        Ok(*self.0.borrow().get(txid).unwrap_or(&TxStatus::Absent))
    }
}

#[test]
fn journal_resends_exact_bytes_and_stores_only_a_share_that_completes_p() -> Result<()> {
    let f = Fixture::new()?;
    let mut exit = ShareExit::create(&f.dir(), f.coin.clone())?;
    assert!(exit.pending()?.is_none());
    let request = exit.new_attempt(&f.owner, random32(), 3)?;
    let Command::ShareRelease { recipient, owner } = &request.command else {
        unreachable!()
    };
    release::verify_owner(
        owner,
        &release::context(&request.intent, request.session),
        recipient,
        f.coin.server.as_slice().try_into()?,
        &f.coin.capability,
    )?;
    drop(exit);
    // Crash after journaling: the reopened journal resends the identical bytes.
    let mut exit = ShareExit::open(&f.dir())?;
    let resent = exit.pending()?.context("journaled request")?;
    assert_eq!(serde_json::to_vec(&resent)?, serde_json::to_vec(&request)?);

    // A response for another share, revision or request is never accepted.
    let other: Digest = random_scalar().to_bytes().into();
    assert!(
        exit.accept(&f.respond(&request, &other)?, &f.wallet)
            .is_err()
    );
    let mut stale = f.respond(&request, &f.server_secret)?;
    stale["revision"] = serde_json::json!(9);
    assert!(exit.accept(&stale, &f.wallet).is_err());
    let foreign = Request {
        intent: Intent {
            operation: random32(),
            ..request.intent.clone()
        },
        ..request.clone()
    };
    assert!(
        exit.accept(&f.respond(&foreign, &f.server_secret)?, &f.wallet)
            .is_err()
    );
    // The right share with a different wallet share does not complete P.
    let wrong_wallet: Digest = random_scalar().to_bytes().into();
    assert!(
        exit.accept(&f.respond(&request, &f.server_secret)?, &wrong_wallet)
            .is_err()
    );

    exit.accept(&f.respond(&request, &f.server_secret)?, &f.wallet)?;
    assert!(exit.pending()?.is_none());
    let saved = fs::read_to_string(f.dir().join(FILE))?;
    assert!(
        saved.contains("\"recipient\":null"),
        "recipient secrets erased after acceptance"
    );
    assert!(exit.new_attempt(&f.owner, random32(), 3).is_err());
    Ok(())
}

#[test]
fn a_later_attempt_still_accepts_the_first_attempts_committed_response() -> Result<()> {
    let f = Fixture::new()?;
    let mut exit = ShareExit::create(&f.dir(), f.coin.clone())?;
    let first = exit.new_attempt(&f.owner, random32(), 3)?;
    exit.new_attempt(&f.owner, random32(), 3)?;
    exit.accept(&f.respond(&first, &f.server_secret)?, &f.wallet)?;
    Ok(())
}

#[test]
fn chain_gate_runs_before_every_send_and_transfer_id_survives_restart() -> Result<()> {
    let f = Fixture::new()?;
    let mut exit = ShareExit::create(&f.dir(), f.coin.clone())?;
    let chain = Chain::default();
    assert!(exit.prepare_send(&chain).is_err(), "no verified share yet");
    let request = exit.new_attempt(&f.owner, random32(), 1)?;
    exit.accept(&f.respond(&request, &f.server_secret)?, &f.wallet)?;

    for (txid, status) in [
        (f.coin.root, TxStatus::Mempool),
        (f.coin.refunds[1], TxStatus::Confirmed),
    ] {
        chain.0.borrow_mut().insert(txid, status);
        assert!(exit.prepare_send(&chain).is_err());
        chain.0.borrow_mut().clear();
    }
    *chain.1.borrow_mut() = true;
    assert!(
        exit.prepare_send(&chain).is_err(),
        "unknown chain state is not absence"
    );
    *chain.1.borrow_mut() = false;
    assert!(
        exit.transfer_id().is_none(),
        "no transfer ID before a permitted send"
    );

    let plan = exit.prepare_send(&chain)?;
    let joint = scalar(&*plan.secret)?;
    assert_eq!(
        point_bytes(k256::ProjectivePoint::GENERATOR * joint)?.to_vec(),
        f.coin.joint
    );
    assert_eq!(plan.transfer_id[6] >> 4, 4);
    let uuid = plan.transfer_uuid();
    assert!(uuid.len() == 36 && uuid.as_bytes()[14] == b'4');
    let port = plan.answer(
        &serde_json::json!({"op":"exit_send"}),
        &serde_json::json!({"id":"leaf"}),
    )?;
    assert!(port["transfer_id"] == uuid && port["leaf"]["id"] == "leaf");
    let inner = random_scalar();
    let sealed: Vec<u8> = serde_json::from_value(plan.answer(
        &serde_json::json!({"op":"seal_leaf_key","public":compressed(&inner).to_vec()}),
        &Value::Null,
    )?)?;
    assert!(!sealed.windows(32).any(|w| w == plan.secret.as_slice()));
    assert!(
        plan.answer(&serde_json::json!({"op":"identity_digest"}), &Value::Null)
            .is_err()
    );
    drop(exit);
    let mut exit = ShareExit::open(&f.dir())?;
    assert_eq!(exit.prepare_send(&chain)?.transfer_id, plan.transfer_id);
    // A refund broadcast after the first attempt still blocks the retry.
    chain
        .0
        .borrow_mut()
        .insert(f.coin.refunds[0], TxStatus::Mempool);
    assert!(exit.prepare_send(&chain).is_err());
    chain.0.borrow_mut().clear();

    assert!(exit.complete(&[0; 16]).is_err());
    exit.complete(&plan.transfer_id)?;
    assert!(exit.completed() && exit.prepare_send(&chain).is_err());
    assert!(fs::read_to_string(f.dir().join(FILE))?.contains("\"secret\":null"));
    Ok(())
}

#[test]
fn journal_refuses_reuse_of_an_existing_directory_and_tampered_records() -> Result<()> {
    let f = Fixture::new()?;
    ShareExit::create(&f.dir(), f.coin.clone())?;
    assert!(ShareExit::create(&f.dir(), f.coin.clone()).is_err());
    let path = f.dir().join(FILE);
    let pretty = serde_json::to_vec_pretty(&serde_json::from_slice::<Value>(&fs::read(&path)?)?)?;
    fs::write(&path, pretty)?;
    assert!(ShareExit::open(&f.dir()).is_err());
    let other = f.root.join("other");
    fs::DirBuilder::new().mode(0o700).create(&other)?;
    assert!(ShareExit::open(&other).is_err());
    Ok(())
}
