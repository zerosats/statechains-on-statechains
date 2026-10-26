//! Synthetic accepted coins with a real certificate shape. The inert pinned
//! proof assets are never executed: share release has no proof, and nothing
//! here installs a proof oracle or qualifies an ownership transfer.
use super::super::{
    Command, Engine, NativeProtocols, Predecessor, Request, lock_guarded,
    persistence::Store,
    state::{Coin, Phase},
};
use crate::engine::Admission;
use anyhow::{Result, ensure};
use k256::{ProjectivePoint, Scalar, elliptic_curve::sec1::ToEncodedPoint, schnorr::SigningKey};
use serde_json::{Value, json};
use std::{
    cell::Cell,
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    sync::Arc,
};
use zark_protocol::{
    hash, point_bytes,
    proof::ArtifactPin,
    random_scalar, random32, scalar,
    spark_lineage::{
        self as lineage, Config, Digest, Intent, Issuance, PinnedSparkVerifier, SparkRole,
    },
    spark_recovery::{BranchAuthorization, RecoveryAuthorization, RecoveryContext},
    spark_share_release::{self as release, Binding},
    spark_wire::{HeadAuthorization, HeadPhase, OwnerAuthorization, SignedHead},
};

struct Allow(Digest);
impl Admission for Allow {
    fn authorize(&self, context: &zark_protocol::handoff::TransferContext) -> Result<()> {
        ensure!(context.deployment == self.0, "test deployment");
        Ok(())
    }
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&random_scalar().to_bytes()).unwrap()
}
fn public(key: &SigningKey) -> Digest {
    key.verifying_key().to_bytes().into()
}
fn compressed(secret: &Scalar) -> [u8; 33] {
    (ProjectivePoint::GENERATOR * secret)
        .to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap()
}

struct Fixture {
    root: PathBuf,
    db: PathBuf,
    checkpoint: PathBuf,
    deployment: Digest,
    origin: SigningKey,
}

/// The wallet's view of one accepted coin: its own share, the joint key and
/// the current owner key. The signer only ever sees the coin record.
struct Owned {
    coin: Coin,
    owner: SigningKey,
    wallet: [u8; 32],
    joint: [u8; 64],
}

impl Fixture {
    fn new() -> Result<Self> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../work/spark-share-release-tests")
            .join(hex::encode(random32()));
        fs::create_dir_all(root.parent().unwrap())?;
        for directory in [&root, &root.join("state"), &root.join("floor")] {
            fs::DirBuilder::new().mode(0o700).create(directory)?;
        }
        fs::write(root.join("unused-verifier"), b"never executed")?;
        fs::write(root.join("unused-vk"), vec![1u8; 115 * 32])?;
        Ok(Self {
            db: root.join("state/signer.sqlite"),
            checkpoint: root.join("floor/checkpoint.json"),
            root,
            deployment: random32(),
            origin: key(),
        })
    }

    fn config(&self) -> Config {
        Config {
            origin_key: public(&self.origin),
            role_hashes: std::array::from_fn(|i| [i as u8 + 1; 32]),
        }
    }

    fn verifier(&self) -> Result<PinnedSparkVerifier> {
        let bb = ArtifactPin {
            path: self.root.join("unused-verifier"),
            sha256: hash(&[b"never executed"]),
        };
        let vk = ArtifactPin {
            path: self.root.join("unused-vk"),
            sha256: hash(&[&vec![1u8; 115 * 32]]),
        };
        PinnedSparkVerifier::new(
            self.deployment,
            self.config(),
            [9; 32],
            bb,
            self.root.clone(),
            [
                SparkRole::Deposit,
                SparkRole::SenderFromOrigin,
                SparkRole::SenderFromTransfer,
                SparkRole::Receiver,
            ]
            .into_iter()
            .map(|role| {
                (
                    role,
                    ArtifactPin {
                        path: vk.path.clone(),
                        sha256: vk.sha256,
                    },
                )
            }),
        )
    }

    fn protocols(enabled: bool) -> NativeProtocols {
        NativeProtocols {
            share_release: enabled,
            ..Default::default()
        }
    }

    fn engine(&self, enabled: bool) -> Result<Engine> {
        Engine::open_with_protocols(
            &self.db,
            &self.checkpoint,
            self.verifier()?,
            Arc::new(Allow(self.deployment)),
            self.origin.clone(),
            Self::protocols(enabled),
        )
    }

    fn repair(&self) -> Result<Engine> {
        Engine::repair_and_open_with_protocols(
            &self.db,
            &self.checkpoint,
            self.verifier()?,
            Arc::new(Allow(self.deployment)),
            self.origin.clone(),
            Self::protocols(true),
        )
    }

    fn initialise(&self) -> Result<Engine> {
        Engine::initialise_witness_and_open_with_protocols(
            &self.db,
            &self.checkpoint,
            self.verifier()?,
            Arc::new(Allow(self.deployment)),
            self.origin.clone(),
            Self::protocols(true),
        )
    }

    /// An acknowledged transfer-owned coin whose certificate validates.
    fn owned(&self, engine: &Engine, origin_owner: bool) -> Result<Owned> {
        self.owned_with(engine, origin_owner, random_scalar(), random_scalar())
    }

    fn owned_with(
        &self,
        engine: &Engine,
        origin_owner: bool,
        server_secret: Scalar,
        wallet: Scalar,
    ) -> Result<Owned> {
        let (deployment, coin) = (self.deployment, random32());
        let owner = key();
        let server = point_bytes(ProjectivePoint::GENERATOR * server_secret)?;
        let salt = random32();
        let capability =
            lineage::public_capability_commitment(&deployment, &coin, &public(&owner))?;
        let nonces = [random_scalar(), random_scalar()];
        let challenges = [random_scalar(), random_scalar()];
        let branches = std::array::from_fn(|i| BranchAuthorization {
            server_nonce: point_bytes(ProjectivePoint::GENERATOR * nonces[i]).unwrap(),
            challenge: challenges[i].to_bytes().into(),
            nonce_commitment: random32(),
        });
        let partials: [Digest; 2] = std::array::from_fn(|i| {
            (nonces[i] + challenges[i] * server_secret)
                .to_bytes()
                .into()
        });
        let session = key();
        let recovery = RecoveryAuthorization {
            context: RecoveryContext {
                deployment,
                coin,
                previous_state: random32(),
                operation: random32(),
                session: public(&session),
                successor_state: random32(),
                revision: 1,
            },
            backing: random32(),
            recovery: random32(),
            policy: [9; 32],
            server,
            branches,
        };
        let issuance = Issuance {
            recipient_claim: random32(),
            mask: random32(),
            masked_share: random32(),
            bridge: random32(),
            delta: random32(),
            previous_capability: random32(),
            next_capability: capability,
            server_share: lineage::server_commitment(&deployment, &coin, &server, &salt)?,
            config: self.config(),
            recovery,
        };
        let certificate = lineage::Certificate::from_issuance(&issuance, &partials)?;
        let origin_signature = origin_owner.then(|| {
            self.origin
                .sign_raw(&certificate.origin_message().unwrap(), &random32())
                .unwrap()
                .to_bytes()
                .to_vec()
        });
        let record = Coin {
            deployment,
            coin,
            backing: issuance.recovery.backing,
            state: certificate.state,
            capability,
            secret: server_secret.to_bytes().into(),
            salt,
            session: public(&session),
            owner: Some(if origin_owner {
                Predecessor::Origin
            } else {
                Predecessor::Transfer
            }),
            phase: Phase::Accepted,
            pending: None,
            issuance: Some(issuance.encode()?),
            partials: Some(partials),
            origin_signature,
            native: None,
            bootstrap: None,
            single_user: None,
            receive: None,
            identities: None,
            auth: None,
            ecdsa: None,
            exit: None,
        };
        record.validate(&engine.policy)?;
        Ok(Owned {
            joint: point_bytes(ProjectivePoint::GENERATOR * (wallet + server_secret))?,
            wallet: wallet.to_bytes().into(),
            coin: record,
            owner,
        })
    }

    /// Installs the coin at revision 1 through the real commit and publication.
    fn install(&self, engine: &Engine, owned: &Owned) -> Result<()> {
        let _lock = lock_guarded(&self.db, &self.checkpoint, &|| Ok(()))?;
        let mut store = Store::open(&self.db, engine.config)?;
        let floor = store.verify_floor(&self.checkpoint)?;
        let seed = Request::sign(
            Intent {
                deployment: self.deployment,
                coin: owned.coin.coin,
                previous_state: random32(),
                operation: random32(),
                recipient_claim: random32(),
                revision: 1,
            },
            Command::Allocate {},
            &key(),
        )?;
        store.commit(
            &owned.coin,
            None,
            &seed,
            seed.digest()?,
            &json!({"seeded":true}),
            &floor,
            false,
        )?;
        store.publish(&self.checkpoint)
    }

    fn stored(&self, engine: &Engine, coin: &Digest) -> Result<(Coin, u64)> {
        let _lock = lock_guarded(&self.db, &self.checkpoint, &|| Ok(()))?;
        let store = Store::open(&self.db, engine.config)?;
        store
            .coin(coin)?
            .ok_or_else(|| anyhow::anyhow!("coin missing"))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct Release {
    request: Request,
    recipient: Scalar,
    session: SigningKey,
}

fn intent(owned: &Owned, revision: u64, recipient: &[u8; 33]) -> Result<Intent> {
    Ok(Intent {
        deployment: owned.coin.deployment,
        coin: owned.coin.coin,
        previous_state: owned.coin.state,
        operation: random32(),
        recipient_claim: release::recipient_claim(
            &owned.coin.deployment,
            &owned.coin.coin,
            recipient,
        )?,
        revision,
    })
}

fn release_request(owned: &Owned, revision: u64) -> Result<Release> {
    let recipient = random_scalar();
    let point = compressed(&recipient);
    let session = key();
    let intent = intent(owned, revision, &point)?;
    let owner = release::sign_owner(
        &release::context(&intent, public(&session)),
        &point,
        &owned.coin.server()?,
        &owned.owner,
    )?;
    let request = Request::sign(
        intent,
        Command::ShareRelease {
            recipient: point.to_vec(),
            owner,
        },
        &session,
    )?;
    Ok(Release {
        request,
        recipient,
        session,
    })
}

/// The wallet checks every bound field against its own records and the
/// decrypted share against the joint key before it would touch Spark.
fn wallet_open(owned: &Owned, release_: &Release, response: &Value) -> Result<[u8; 32]> {
    let request = &release_.request;
    let Command::ShareRelease { recipient, .. } = &request.command else {
        unreachable!()
    };
    let issuance = Issuance::decode(owned.coin.issuance.as_ref().unwrap())?;
    ensure!(
        response["server"] == json!(issuance.recovery.server.to_vec()),
        "response names another server point"
    );
    ensure!(
        response["revision"] == json!(request.intent.revision + 1),
        "release revision"
    );
    let binding = Binding {
        deployment: request.intent.deployment,
        coin: request.intent.coin,
        intent: release::intent_digest(&request.intent)?,
        request: request.digest()?,
        session: request.session,
        recipient: recipient.as_slice().try_into()?,
        server: issuance.recovery.server,
        state: owned.coin.state,
        capability: owned.coin.capability,
        revision: request.intent.revision,
        committed_revision: request.intent.revision + 1,
    };
    let wire: Vec<u8> = serde_json::from_value(response["ciphertext"].clone())?;
    let share = release::open(&binding, &release_.recipient, &wire)?;
    let joint = release::joint_secret(&owned.wallet, &share, &owned.joint)?;
    Ok(*joint)
}

fn head(fixture: &Fixture, engine: &Engine, owned: &Owned) -> Result<SignedHead> {
    let session = key();
    let challenge = random32();
    let intent = Intent {
        operation: random32(),
        ..intent(owned, 1, &compressed(&random_scalar()))?
    };
    let owner = HeadAuthorization::sign(&intent, &public(&session), &challenge, &owned.owner)?;
    let request = Request::sign(
        intent,
        Command::Head {
            challenge,
            owner: Some(owner),
        },
        &session,
    )?;
    let signed: SignedHead = serde_json::from_value(engine.handle(&request)?["head"].clone())?;
    signed.verify(&request, &public(&fixture.origin))?;
    Ok(signed)
}

#[test]
fn release_exits_erases_share_and_replays_identical_bytes() -> Result<()> {
    let f = Fixture::new()?;
    let engine = f.engine(true)?;
    let owned = f.owned(&engine, false)?;
    f.install(&engine, &owned)?;
    let before = head(&f, &engine, &owned)?;
    assert!(before.head.share_release && before.head.phase == HeadPhase::Available);

    let release_ = release_request(&owned, 1)?;
    let response = engine.handle(&release_.request)?;
    let joint = wallet_open(&owned, &release_, &response)?;
    assert_eq!(
        point_bytes(ProjectivePoint::GENERATOR * scalar(&joint)?)?,
        owned.joint
    );

    let (exited, revision) = f.stored(&engine, &owned.coin.coin)?;
    assert!(
        revision == 2
            && exited.phase == Phase::Exited
            && exited.secret == [0; 32]
            && exited.exit.is_some()
    );
    assert_eq!(exited.server()?, owned.coin.server()?);
    let after = head(&f, &engine, &owned)?;
    assert!(
        after.head.phase == HeadPhase::Exited
            && after.head.locked_operation.is_none()
            && after.head.revision == 2
    );

    // Exact retries, also after a restart, return the committed bytes.
    assert_eq!(engine.handle(&release_.request)?, response);
    drop(engine);
    let reopened = f.engine(true)?;
    assert_eq!(reopened.handle(&release_.request)?, response);
    // A disabled restart still opens the database and replays the release.
    drop(reopened);
    let disabled = f.engine(false)?;
    assert_eq!(disabled.handle(&release_.request)?, response);
    assert!(!head(&f, &disabled, &owned)?.head.share_release);
    Ok(())
}

#[test]
fn exited_coin_refuses_second_release_conflicts_and_every_mutation() -> Result<()> {
    let f = Fixture::new()?;
    let engine = f.engine(true)?;
    let owned = f.owned(&engine, true)?;
    f.install(&engine, &owned)?;
    let first = release_request(&owned, 1)?;
    engine.handle(&first.request)?;

    let exited = Owned {
        coin: f.stored(&engine, &owned.coin.coin)?.0,
        ..owned
    };
    let second = release_request(&exited, 2)?;
    let refused = engine.handle(&second.request).unwrap_err().to_string();
    assert!(refused.contains("exited"), "{refused}");
    // The same operation and session with another recipient conflicts with
    // the stored request instead of releasing again.
    let point = compressed(&random_scalar());
    let changed = Intent {
        recipient_claim: release::recipient_claim(
            &exited.coin.deployment,
            &exited.coin.coin,
            &point,
        )?,
        ..first.request.intent.clone()
    };
    let owner = release::sign_owner(
        &release::context(&changed, first.request.session),
        &point,
        &exited.coin.server()?,
        &exited.owner,
    )?;
    let conflict = Request::sign(
        changed,
        Command::ShareRelease {
            recipient: point.to_vec(),
            owner,
        },
        &first.session,
    )?;
    let error = engine.handle(&conflict).unwrap_err().to_string();
    assert!(error.contains("changed frozen request"), "{error}");
    // A reservation for the next owner is refused too.
    let reserve = Intent {
        operation: random32(),
        revision: 2,
        ..second.request.intent.clone()
    };
    let reserve_session = key();
    let reserve = Request::sign(
        reserve.clone(),
        Command::Reserve {
            owner: OwnerAuthorization::sign(&reserve, &public(&reserve_session), &exited.owner)?,
        },
        &reserve_session,
    )?;
    assert!(
        engine
            .handle(&reserve)
            .unwrap_err()
            .to_string()
            .contains("exited")
    );
    assert_eq!(f.stored(&engine, &exited.coin.coin)?.1, 2);
    Ok(())
}

#[test]
fn release_refuses_wrong_owner_stale_revision_and_foreign_signatures() -> Result<()> {
    let f = Fixture::new()?;
    let engine = f.engine(true)?;
    let owned = f.owned(&engine, false)?;
    f.install(&engine, &owned)?;
    let refuse = |request: &Request, why: &str| {
        let error = engine.handle(request).expect_err(why).to_string();
        eprintln!("{why}: {error}");
    };
    refuse(&release_request(&owned, 2)?.request, "stale revision");
    let former = Owned {
        owner: key(),
        coin: owned.coin.clone(),
        wallet: owned.wallet,
        joint: owned.joint,
    };
    refuse(
        &release_request(&former, 1)?.request,
        "former or wrong owner",
    );

    let point = compressed(&random_scalar());
    let base = intent(&owned, 1, &point)?;
    let server = owned.coin.server()?;
    // The owner key doubling as the session.
    let owner_session = Request::sign(
        base.clone(),
        Command::ShareRelease {
            recipient: point.to_vec(),
            owner: OwnerAuthorization {
                public_key: public(&owned.owner),
                signature: owned
                    .owner
                    .sign_raw(
                        &release::owner_message(
                            &release::context(&base, public(&owned.owner)),
                            &point,
                            &server,
                        )?,
                        &random32(),
                    )?
                    .to_bytes()
                    .to_vec(),
            },
        },
        &owned.owner,
    )?;
    refuse(&owner_session, "owner equals session");
    // A Reserve signature for the identical intent does not authorize release.
    let session = key();
    let reserve_auth = OwnerAuthorization::sign(&base, &public(&session), &owned.owner)?;
    refuse(
        &Request::sign(
            base.clone(),
            Command::ShareRelease {
                recipient: point.to_vec(),
                owner: reserve_auth,
            },
            &session,
        )?,
        "reserve signature",
    );
    // The signed intent must name exactly the recipient in the command.
    let other = compressed(&random_scalar());
    let owner = release::sign_owner(
        &release::context(&base, public(&session)),
        &other,
        &server,
        &owned.owner,
    )?;
    refuse(
        &Request::sign(
            base.clone(),
            Command::ShareRelease {
                recipient: other.to_vec(),
                owner,
            },
            &session,
        )?,
        "recipient claim",
    );
    // A stale predecessor state.
    let stale = Intent {
        previous_state: random32(),
        ..base.clone()
    };
    let owner = release::sign_owner(
        &release::context(&stale, public(&session)),
        &point,
        &server,
        &owned.owner,
    )?;
    refuse(
        &Request::sign(
            stale,
            Command::ShareRelease {
                recipient: point.to_vec(),
                owner,
            },
            &session,
        )?,
        "stale state",
    );
    // Uncompressed or invalid recipient points.
    let mut bad = point;
    bad[0] = 4;
    refuse(
        &Request::sign(
            base.clone(),
            Command::ShareRelease {
                recipient: bad.to_vec(),
                owner: OwnerAuthorization {
                    public_key: public(&owned.owner),
                    signature: vec![0; 64],
                },
            },
            &session,
        )?,
        "bad point",
    );

    let (coin, revision) = f.stored(&engine, &owned.coin.coin)?;
    assert!(revision == 1 && coin.phase == Phase::Accepted && coin.secret == owned.coin.secret);
    // Disabled deployments refuse a fully valid request.
    drop(engine);
    let disabled = f.engine(false)?;
    assert!(
        disabled
            .handle(&release_request(&owned, 1)?.request)
            .unwrap_err()
            .to_string()
            .contains("not enabled")
    );
    Ok(())
}

#[test]
fn every_unsettled_or_locked_phase_refuses_release() -> Result<()> {
    let f = Fixture::new()?;
    let engine = f.engine(true)?;
    let owned = f.owned(&engine, false)?;
    let request = release_request(&owned, 1)?.request;
    engine.plan_share_release(&owned.coin, &request)?;
    for phase in [
        Phase::Allocated,
        Phase::Origin,
        Phase::Reserved,
        Phase::Handover,
        Phase::Proposed,
        Phase::Prepared,
        Phase::Issued,
        Phase::Exited,
    ] {
        let mut coin = owned.coin.clone();
        coin.phase = phase;
        assert!(engine.plan_share_release(&coin, &request).is_err());
    }
    let mut pending = owned.coin.clone();
    pending.pending = Some(super::super::state::Pending::new(&request, false));
    assert!(engine.plan_share_release(&pending, &request).is_err());
    let mut unowned = owned.coin.clone();
    unowned.owner = None;
    assert!(engine.plan_share_release(&unowned, &request).is_err());
    // Through the engine: a fresh allocation has no owner capability yet.
    let allocation = Intent {
        deployment: f.deployment,
        coin: random32(),
        previous_state: [0; 32],
        operation: random32(),
        recipient_claim: [0; 32],
        revision: 1,
    };
    let allocation = Intent {
        previous_state: lineage::origin_previous_state(&allocation.deployment, &allocation.coin)?,
        recipient_claim: lineage::origin_field(&allocation.deployment, &allocation.coin, 0)?,
        ..allocation
    };
    let session = key();
    engine.handle(&Request::sign(
        allocation.clone(),
        Command::Allocate {},
        &session,
    )?)?;
    let point = compressed(&random_scalar());
    let fresh = Intent {
        operation: random32(),
        recipient_claim: release::recipient_claim(
            &allocation.deployment,
            &allocation.coin,
            &point,
        )?,
        ..allocation
    };
    let owner = key();
    let auth = release::sign_owner(
        &release::context(&fresh, public(&session)),
        &point,
        &owned.coin.server()?,
        &owner,
    )?;
    assert!(
        engine
            .handle(&Request::sign(
                fresh,
                Command::ShareRelease {
                    recipient: point.to_vec(),
                    owner: auth
                },
                &session
            )?)
            .is_err()
    );
    Ok(())
}

/// The first critical section plans; the lock is dropped; the second section
/// must notice any commit in between and refuse the now-stale release.
#[test]
fn concurrent_commit_between_the_two_locks_makes_the_release_stale() -> Result<()> {
    for competitor_is_release in [true, false] {
        let f = Fixture::new()?;
        let engine = f.engine(true)?;
        let owned = f.owned(&engine, false)?;
        f.install(&engine, &owned)?;
        let outer = release_request(&owned, 1)?;
        let competitor = if competitor_is_release {
            release_request(&owned, 1)?.request
        } else {
            let session = key();
            let intent = Intent {
                operation: random32(),
                recipient_claim: random32(),
                ..outer.request.intent.clone()
            };
            Request::sign(
                intent.clone(),
                Command::Reserve {
                    owner: OwnerAuthorization::sign(&intent, &public(&session), &owned.owner)?,
                },
                &session,
            )?
        };
        let calls = Cell::new(0);
        let committed = Cell::new(None);
        let result = engine.handle_guarded(&outer.request, || {
            calls.set(calls.get() + 1);
            if calls.get() == 2 {
                committed.set(Some(engine.handle(&competitor)?));
            }
            Ok(())
        });
        let error = result.expect_err("stale release").to_string();
        assert!(error.contains("stale Spark verified revision"), "{error}");
        let won = committed.take().expect("competitor ran between the locks");
        assert_eq!(engine.handle(&competitor)?, won);
        let (coin, revision) = f.stored(&engine, &owned.coin.coin)?;
        assert_eq!(revision, 2);
        assert!(
            coin.phase
                == if competitor_is_release {
                    Phase::Exited
                } else {
                    Phase::Reserved
                }
        );
        // The loser's exact retry never commits a second outcome.
        assert!(engine.handle(&outer.request).is_err());
        assert_eq!(f.stored(&engine, &owned.coin.coin)?.1, 2);
    }
    Ok(())
}

#[test]
fn crash_before_commit_leaves_the_share_and_allows_a_fresh_exact_retry() -> Result<()> {
    let f = Fixture::new()?;
    let engine = f.engine(true)?;
    let owned = f.owned(&engine, false)?;
    f.install(&engine, &owned)?;
    let release_ = release_request(&owned, 1)?;
    let calls = Cell::new(0);
    let crashed = engine.handle_guarded(&release_.request, || {
        calls.set(calls.get() + 1);
        ensure!(calls.get() < 3, "simulated crash before commit");
        Ok(())
    });
    assert!(crashed.is_err());
    let (coin, revision) = f.stored(&engine, &owned.coin.coin)?;
    assert!(revision == 1 && coin.phase == Phase::Accepted && coin.secret == owned.coin.secret);
    let response = f.engine(true)?.handle(&release_.request)?;
    wallet_open(&owned, &release_, &response)?;
    Ok(())
}

#[test]
fn crash_after_commit_before_publication_needs_explicit_repair_then_replays() -> Result<()> {
    let f = Fixture::new()?;
    let engine = f.engine(true)?;
    let owned = f.owned(&engine, false)?;
    f.install(&engine, &owned)?;
    let witness = super::super::persistence::witness_path(&f.checkpoint);
    let published = (fs::read(&f.checkpoint)?, fs::read(&witness)?);
    let release_ = release_request(&owned, 1)?;
    let response = engine.handle(&release_.request)?;
    drop(engine);
    // Committed but unpublished: the files still hold the previous floor.
    fs::write(&f.checkpoint, &published.0)?;
    fs::write(&witness, &published.1)?;
    let error = f
        .engine(true)
        .err()
        .expect("unpublished commit pauses service")
        .to_string();
    assert!(error.contains("checkpoint mismatch"), "{error}");
    let repaired = f.repair()?;
    assert_eq!(repaired.handle(&release_.request)?, response);
    wallet_open(&owned, &release_, &response)?;
    Ok(())
}

fn copy_state(f: &Fixture, to: &Path) -> Result<()> {
    fs::create_dir_all(to)?;
    fs::copy(&f.db, to.join("db"))?;
    fs::copy(&f.checkpoint, to.join("checkpoint"))?;
    Ok(())
}
fn restore_state(f: &Fixture, from: &Path, checkpoint: bool) -> Result<()> {
    fs::copy(from.join("db"), &f.db)?;
    if checkpoint {
        fs::copy(from.join("checkpoint"), &f.checkpoint)?;
    }
    Ok(())
}

#[test]
fn rollback_witness_refuses_restored_state_and_accepts_normal_restarts() -> Result<()> {
    let f = Fixture::new()?;
    let engine = f.engine(true)?;
    let owned = f.owned(&engine, false)?;
    f.install(&engine, &owned)?;
    let backup = f.root.join("backup");
    copy_state(&f, &backup)?;
    let release_ = release_request(&owned, 1)?;
    let response = engine.handle(&release_.request)?;
    drop(engine);
    // Normal restarts.
    for _ in 0..2 {
        assert_eq!(f.engine(true)?.handle(&release_.request)?, response);
    }
    let current = f.root.join("current");
    copy_state(&f, &current)?;
    // Database alone restored: the checkpoint already refuses it.
    restore_state(&f, &backup, false)?;
    assert!(f.engine(true).is_err());
    // Database and checkpoint restored together: only the witness refuses it,
    // also through the explicit repair path.
    restore_state(&f, &backup, true)?;
    let error = f
        .engine(true)
        .err()
        .expect("rolled-back state refused")
        .to_string();
    assert!(error.contains("behind its rollback witness"), "{error}");
    assert!(f.repair().is_err());
    // Back to the newest state, service resumes and still replays the release.
    restore_state(&f, &current, true)?;
    assert_eq!(f.engine(true)?.handle(&release_.request)?, response);
    Ok(())
}

#[test]
fn fresh_store_creates_its_witness_beside_the_checkpoint() -> Result<()> {
    let f = Fixture::new()?;
    let witness = super::super::persistence::witness_path(&f.checkpoint);
    assert_eq!(witness, f.root.join("floor/checkpoint.witness"));
    assert!(!witness.exists());
    f.engine(true)?;
    let created: Value = serde_json::from_slice(&fs::read(&witness)?)?;
    assert_eq!(created["sequence"], json!(0));
    f.engine(true)?;
    Ok(())
}

#[test]
fn missing_witness_for_existing_state_refuses_until_explicitly_initialised() -> Result<()> {
    let f = Fixture::new()?;
    let engine = f.engine(false)?;
    let owned = f.owned(&engine, false)?;
    f.install(&engine, &owned)?;
    drop(engine);
    // An upgraded deployment, a restored snapshot or a new host: committed
    // state and checkpoint, but no witness.
    let witness = super::super::persistence::witness_path(&f.checkpoint);
    fs::remove_file(&witness)?;
    for refused in [f.engine(true).err(), f.repair().err()] {
        let error = refused.expect("missing witness refused").to_string();
        assert!(error.contains("rollback witness missing"), "{error}");
    }
    assert!(!witness.exists());
    // Explicit initialisation refuses an unpublished commit.
    let published = fs::read(&f.checkpoint)?;
    let mut stale: Value = serde_json::from_slice(&published)?;
    stale["sequence"] = json!(0);
    fs::write(&f.checkpoint, serde_json::to_vec(&stale)?)?;
    assert!(f.initialise().is_err() && !witness.exists());
    fs::write(&f.checkpoint, &published)?;

    let engine = f.initialise()?;
    assert!(witness.exists());
    let release_ = release_request(&owned, 1)?;
    let response = engine.handle(&release_.request)?;
    drop(engine);
    assert_eq!(f.engine(true)?.handle(&release_.request)?, response);
    // Initialisation never replaces a witness: one from another database
    // still refuses this one.
    let mut foreign: Value = serde_json::from_slice(&fs::read(&witness)?)?;
    foreign["database"] = json!(random32());
    fs::write(&witness, serde_json::to_vec(&foreign)?)?;
    for refused in [f.engine(true).err(), f.initialise().err()] {
        assert!(
            refused
                .unwrap()
                .to_string()
                .contains("differs from its rollback witness")
        );
    }
    Ok(())
}

#[test]
fn share_release_and_profiles_without_ecdsa_2p_keep_the_original_config_digest() -> Result<()> {
    let f = Fixture::new()?;
    let original = hash(&[
        b"ZARK/spark/signer/config/v1",
        &f.deployment,
        &f.config().encode()?,
        &[9; 32],
    ]);
    for enabled in [false, true] {
        assert_eq!(f.engine(enabled)?.config, original);
    }
    Ok(())
}

/// A coin entered through blind cb-mpc keeps its retired ECDSA-2P record
/// (public key and finished tickets) through acceptance and every handover.
/// Key generation, the blind entry signature, the freeze-time retirement and
/// the release are real; acceptance is the synthetic certificate above, since
/// it needs ownership proofs.
#[cfg(feature = "ecdsa-2p")]
mod ecdsa_entry {
    use super::super::super::{ReceiveProtocol, transitions::retire_for_freeze};
    use super::*;
    use anyhow::Context;
    use k256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
    use std::time::Duration;
    use zark_protocol::{
        spark_receive::{ClaimCluster, ClaimOperator, PinnedReceiveVerifier},
        spark_wire::ecdsa_2p::{self as wire, Frame},
    };
    use zark_spark_ecdsa_2p::{Output, Role, Session};

    const TIMEOUT: Duration = Duration::from_secs(60);

    /// Joint identity requires the ordinary receive deployment; no receive
    /// proof or MPC runs here.
    fn engine(f: &Fixture) -> Result<Engine> {
        let cluster = ClaimCluster {
            threshold: 2,
            operators: (1..=3u16)
                .map(|i| {
                    let encryption_key = compressed(&Scalar::from(u64::from(i) + 20)).to_vec();
                    (
                        hex::encode(Scalar::from(u64::from(i) + 10).to_bytes()),
                        ClaimOperator {
                            index: i,
                            encryption_key,
                        },
                    )
                })
                .collect(),
        };
        let bb = ArtifactPin {
            path: f.root.join("unused-verifier"),
            sha256: hash(&[b"never executed"]),
        };
        let vk = ArtifactPin {
            path: f.root.join("unused-vk"),
            sha256: hash(&[&vec![1u8; 115 * 32]]),
        };
        let verifier = PinnedReceiveVerifier::new(
            f.deployment,
            f.config(),
            [9; 32],
            cluster.digest()?,
            bb,
            f.root.clone(),
            vk,
        )?;
        Engine::open_with_protocols(
            &f.db,
            &f.checkpoint,
            f.verifier()?,
            Arc::new(Allow(f.deployment)),
            f.origin.clone(),
            NativeProtocols {
                share_release: true,
                receive: Some(ReceiveProtocol { verifier, cluster }),
                identity: true,
                ecdsa_2p: true,
                additive_receive: true,
                ..Default::default()
            },
        )
    }

    fn frame(response: &Value) -> Result<Frame> {
        Ok(serde_json::from_value(response["frame"].clone())?)
    }

    #[test]
    fn release_serves_a_coin_entered_through_blind_ecdsa_2p() -> Result<()> {
        let f = Fixture::new()?;
        let engine = engine(&f)?;
        let session = key();
        let coin = random32();
        let base = Intent {
            deployment: f.deployment,
            coin,
            previous_state: lineage::origin_previous_state(&f.deployment, &coin)?,
            operation: random32(),
            recipient_claim: lineage::origin_field(&f.deployment, &coin, 0)?,
            revision: 1,
        };
        engine.handle(&Request::sign(
            base.clone(),
            Command::Allocate {},
            &session,
        )?)?;

        // The wallet is cb-mpc P1; the signer adopts its P2 share as x_s.
        let mut p1 = Session::keygen(Role::P1, TIMEOUT)?;
        let m1 = Frame::new(p1.exchange(None)?)?;
        let start = Request::sign(
            wire::keygen_intent(&base, &m1)?,
            Command::EcdsaKeygen { frame: m1 },
            &session,
        )?;
        let m3 =
            Frame::new(p1.exchange(Some(frame(&engine.handle(&start)?)?.as_bytes().to_vec()))?)?;
        let Output::Key(key_blob) = p1.finish(None)? else {
            anyhow::bail!("no cb-mpc key")
        };
        let finish = Request::sign(
            wire::keygen_finish_intent(&start.intent, &m3)?,
            Command::EcdsaKeygenFinish {
                keygen: start.intent.operation,
                frame: m3,
            },
            &session,
        )?;
        engine.handle(&finish)?;
        let tau = random_scalar();
        let user = scalar(key_blob.private_share()?.as_slice())? + tau;

        // One blind entry signature; the signer sees only m''.
        let digest = random32();
        let nonce = random32();
        let ticket = wire::sign_intent(&base, &nonce)?;
        let tau_bytes: Digest = tau.to_bytes().into();
        let mut signing = Session::sign_blind_wallet(
            &key_blob,
            digest,
            &tau_bytes,
            wire::session_id(&ticket)?,
            TIMEOUT,
        )?;
        let m1 = Frame::new(signing.exchange(None)?)?;
        let open = Request::sign(
            ticket.clone(),
            Command::EcdsaSign {
                message: None,
                nonce,
                frame: m1,
            },
            &session,
        )?;
        let m3 = Frame::new(
            signing.exchange(Some(frame(&engine.handle(&open)?)?.as_bytes().to_vec()))?,
        )?;
        let close = Request::sign(
            wire::sign_finish_intent(&ticket, &m3)?,
            Command::EcdsaSignFinish {
                ticket: ticket.operation,
                frame: m3,
            },
            &session,
        )?;
        let m4 = frame(&engine.handle(&close)?)?;
        let Output::Signature(Some(signature)) = signing.finish(Some(m4.as_bytes().to_vec()))?
        else {
            anyhow::bail!("no blind signature")
        };

        // Freeze retires the key but keeps the record; acceptance and
        // handovers carry it unchanged.
        let (mut allocated, _) = f.stored(&engine, &coin)?;
        retire_for_freeze(&mut allocated);
        let retired = allocated.ecdsa.take().context("ECDSA-2P record")?;
        assert!(!retired.ready());
        let mut owned = f.owned_with(&engine, false, scalar(&allocated.secret)?, user)?;
        owned.coin.ecdsa = Some(retired);
        owned.coin.validate(&engine.policy)?;
        f.install(&engine, &owned)?;
        assert!(f.stored(&engine, &owned.coin.coin)?.0.ecdsa.is_some());

        let release_ = release_request(&owned, 1)?;
        let response = engine.handle(&release_.request)?;
        let joint = wallet_open(&owned, &release_, &response)?;
        let entry_key = ProjectivePoint::GENERATOR * scalar(&joint)?;
        assert_eq!(point_bytes(entry_key)?, owned.joint);
        VerifyingKey::from_affine(entry_key.to_affine())?
            .verify_prehash(&digest, &Signature::from_der(&signature)?)?;
        let (exited, revision) = f.stored(&engine, &owned.coin.coin)?;
        assert!(
            revision == 2
                && exited.phase == Phase::Exited
                && exited.ecdsa.is_none()
                && exited.secret == [0; 32]
        );
        assert_eq!(engine.handle(&release_.request)?, response);
        Ok(())
    }
}

#[test]
fn absent_exit_record_preserves_existing_coin_json() -> Result<()> {
    let f = Fixture::new()?;
    let engine = f.engine(true)?;
    let owned = f.owned(&engine, false)?;
    let bytes = serde_json::to_string(&owned.coin)?;
    assert!(!bytes.contains("exit"));
    let decoded: Coin = serde_json::from_str(&bytes)?;
    assert_eq!(serde_json::to_string(&decoded)?, bytes);
    Ok(())
}
