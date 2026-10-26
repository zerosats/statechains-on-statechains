//! Storage/authentication fixtures only. No test proof oracle is installed in
//! the Spark engine; these tests do not qualify an ownership or native transfer.
use super::state::{Coin, Pending, Phase};
use super::*;
use std::fs;
use zark_protocol::{
    random_scalar, random32,
    spark_lineage::{self as lineage, Intent},
};

struct Fixture {
    root: PathBuf,
    db: PathBuf,
    checkpoint: PathBuf,
    policy: Policy,
    request: Request,
    coin: Coin,
    key: SigningKey,
}

impl Fixture {
    fn new() -> Result<Self> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../work/spark-signer-tests")
            .join(hex::encode(random32()));
        let db = root.join("private/state.sqlite");
        let checkpoint = root.join("floor/checkpoint.json");
        let deployment = [7; 32];
        let coin_id = [8; 32];
        let key = SigningKey::from_bytes(&random_scalar().to_bytes())?;
        let origin = SigningKey::from_bytes(&random_scalar().to_bytes())?;
        let config = Config {
            origin_key: origin.verifying_key().to_bytes().into(),
            role_hashes: std::array::from_fn(|index| [index as u8 + 1; 32]),
        };
        let policy = Policy {
            deployment,
            config,
            policy: [9; 32],
            native: None,
            native_cluster: None,
            bootstrap: None,
            single_user: None,
            receive: None,
            receive_cluster: None,
            identity: None,
            auth: None,
            ecdsa_2p: false,
            additive_receive: false,
        };
        let intent = Intent {
            deployment,
            coin: coin_id,
            previous_state: lineage::origin_previous_state(&deployment, &coin_id)?,
            operation: [10; 32],
            recipient_claim: lineage::origin_field(&deployment, &coin_id, 0)?,
            revision: 1,
        };
        let request = Request::sign(intent, Command::Allocate {}, &key)?;
        let coin = Coin {
            deployment,
            coin: coin_id,
            backing: [0; 32],
            state: request.intent.previous_state,
            capability: [0; 32],
            secret: random_scalar().to_bytes().into(),
            salt: [11; 32],
            session: request.session,
            owner: None,
            phase: Phase::Allocated,
            pending: Some(Pending::new(&request, true)),
            issuance: None,
            partials: None,
            origin_signature: None,
            native: None,
            bootstrap: None,
            single_user: None,
            receive: None,
            identities: None,
            auth: None,
            ecdsa: None,
            exit: None,
        };
        coin.validate(&policy)?;
        Ok(Self {
            root,
            db,
            checkpoint,
            policy,
            request,
            coin,
            key,
        })
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn allocation_commit_requires_floor_publication_and_exact_retry() -> Result<()> {
    let fixture = Fixture::new()?;
    let _lock = lock_guarded(&fixture.db, &fixture.checkpoint, &|| Ok(()))?;
    let mut store = Store::open(&fixture.db, [12; 32])?;
    let floor = store.verify_floor(&fixture.checkpoint)?;
    let response = json!({"server":fixture.coin.server()?.to_vec(),"revision":1});
    store.commit(
        &fixture.coin,
        None,
        &fixture.request,
        fixture.request.digest()?,
        &response,
        &floor,
        false,
    )?;
    assert!(store.verify_floor(&fixture.checkpoint).is_err());
    // Recovery is explicit and bounded to the independently saved prior floor.
    store.repair_floor(&fixture.checkpoint)?;
    store.verify_floor(&fixture.checkpoint)?;
    assert_eq!(
        store.replay(&fixture.request, &fixture.request.digest()?)?,
        Some(response)
    );
    let mut changed = fixture.request.clone();
    changed.intent.previous_state = [13; 32];
    assert!(store.replay(&changed, &changed.digest()?).is_err());
    store.validate(&fixture.policy)?;
    // A new ordinary exit must fit its entire bounded response transcript.
    // Admission rejects exhaustion before taking the irreversible native lock.
    store.require_response_capacity(&fixture.coin.coin, 255)?;
    assert!(
        store
            .require_response_capacity(&fixture.coin.coin, 256)
            .is_err()
    );
    assert!(
        store
            .require_response_capacity(&fixture.coin.coin, u64::MAX)
            .is_err()
    );
    Ok(())
}

#[test]
fn wrong_store_config_and_changed_checkpoint_fail_closed() -> Result<()> {
    let fixture = Fixture::new()?;
    let _lock = lock_guarded(&fixture.db, &fixture.checkpoint, &|| Ok(()))?;
    let store = Store::open(&fixture.db, [12; 32])?;
    store.verify_floor(&fixture.checkpoint)?;
    assert!(Store::open(&fixture.db, [13; 32]).is_err());
    let mut floor: serde_json::Value = serde_json::from_slice(&fs::read(&fixture.checkpoint)?)?;
    floor["sequence"] = json!(1);
    fs::write(&fixture.checkpoint, serde_json::to_vec(&floor)?)?;
    assert!(store.verify_floor(&fixture.checkpoint).is_err());
    assert!(store.repair_floor(&fixture.checkpoint).is_err());
    Ok(())
}

#[test]
fn spark_wire_roundtrip_authenticates_full_command_and_domain() -> Result<()> {
    let fixture = Fixture::new()?;
    let decoded = Request::decode(&fixture.request.encode()?)?;
    assert_eq!(decoded.digest()?, fixture.request.digest()?);
    let mut substituted = decoded;
    substituted.command = Command::FreezeOrigin {
        backing: [2; 32],
        capability: [3; 32],
    };
    assert!(substituted.authenticate().is_err());
    Ok(())
}

#[test]
fn observed_native_completion_checkpoint_retains_exact_packet_and_evidence_on_reopen() -> Result<()>
{
    // Storage-only fixture: observer admission and real native issuance are
    // exercised separately. No Engine transition or proof is bypassed here.
    let f = Fixture::new()?;
    let _lock = lock_guarded(&f.db, &f.checkpoint, &|| Ok(()))?;
    let mut store = Store::open(&f.db, [12; 32])?;
    let floor = store.verify_floor(&f.checkpoint)?;
    store.commit(
        &f.coin,
        None,
        &f.request,
        f.request.digest()?,
        &json!({"allocated":true}),
        &floor,
        false,
    )?;
    store.publish(&f.checkpoint)?;
    let mut intent = f.request.intent.clone();
    intent.operation = [81; 32];
    let completion = zark_protocol::spark_wire::NativeCompletion {
        plan: [82; 32],
        cluster: [83; 32],
        packet: [84; 32],
    };
    let request = Request::sign(
        intent,
        Command::NativeExitObservedComplete {
            completion: completion.clone(),
            evidence: [85; 32],
        },
        &f.key,
    )?;
    let evidence = [85; 32];
    let response = json!({"native_completed":true,"observation":evidence});
    let floor = store.verify_floor(&f.checkpoint)?;
    store.commit(
        &f.coin,
        Some(1),
        &request,
        request.digest()?,
        &response,
        &floor,
        false,
    )?;
    assert!(store.verify_floor(&f.checkpoint).is_err());
    store.repair_floor(&f.checkpoint)?;
    assert_eq!(
        store.replay(&request, &request.digest()?)?,
        Some(response.clone())
    );
    drop(store);
    let store = Store::open(&f.db, [12; 32])?;
    store.verify_floor(&f.checkpoint)?;
    assert_eq!(store.replay(&request, &request.digest()?)?, Some(response));
    let mut changed = request.clone();
    let Command::NativeExitObservedComplete { completion, .. } = &mut changed.command else {
        unreachable!()
    };
    completion.packet[0] ^= 1;
    assert!(store.replay(&changed, &changed.digest()?).is_err());
    let mut changed = request.clone();
    let Command::NativeExitObservedComplete { evidence, .. } = &mut changed.command else {
        unreachable!()
    };
    *evidence = [86; 32];
    assert!(store.replay(&changed, &changed.digest()?).is_err());
    Ok(())
}

#[test]
fn absent_native_addon_preserves_existing_coin_json() -> Result<()> {
    let fixture = Fixture::new()?;
    let bytes = serde_json::to_vec(&fixture.coin)?;
    let object: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert!(object.get("native").is_none());
    assert!(object.get("bootstrap").is_none());
    assert!(object.get("single_user").is_none());
    let restored: Coin = serde_json::from_slice(&bytes)?;
    assert!(restored.native.is_none());
    assert_eq!(serde_json::to_vec(&restored)?, bytes);
    Ok(())
}

#[test]
fn native_cancellation_burns_prepare_replay_and_survives_checkpoint_gap() -> Result<()> {
    // Storage-only fixture: no native proof or transition is bypassed by Engine.
    let fixture = Fixture::new()?;
    let _lock = lock_guarded(&fixture.db, &fixture.checkpoint, &|| Ok(()))?;
    let mut store = Store::open(&fixture.db, [12; 32])?;
    let floor = store.verify_floor(&fixture.checkpoint)?;
    store.commit(
        &fixture.coin,
        None,
        &fixture.request,
        fixture.request.digest()?,
        &json!({"allocated":true}),
        &floor,
        false,
    )?;
    store.publish(&fixture.checkpoint)?;
    let mut intent = fixture.request.intent.clone();
    intent.operation = [61; 32];
    intent.recipient_claim = [62; 32];
    let context = zark_protocol::spark_native::ExitContext {
        deployment: intent.deployment,
        coin: intent.coin,
        current_state: intent.previous_state,
        operation: intent.operation,
        session: fixture.request.session,
        revision: intent.revision,
    };
    let owner = SigningKey::from_bytes(&random_scalar().to_bytes())?;
    let commitments = [[63; 32], [64; 32]];
    let prepare = Request::sign(
        intent.clone(),
        Command::NativeExitPrepare {
            plan: intent.recipient_claim,
            nonce_commitments: commitments,
            owner: OwnerAuthorization::sign_native(
                &context,
                &intent.recipient_claim,
                &commitments,
                &owner,
            )?,
        },
        &fixture.key,
    )?;
    let floor = store.verify_floor(&fixture.checkpoint)?;
    store.commit(
        &fixture.coin,
        Some(1),
        &prepare,
        prepare.digest()?,
        &json!({"nonces":[1,2]}),
        &floor,
        false,
    )?;
    store.publish(&fixture.checkpoint)?;
    let cancel = Request::sign(intent, Command::NativeExitCancel {}, &fixture.key)?;
    let floor = store.verify_floor(&fixture.checkpoint)?;
    store.commit(
        &fixture.coin,
        Some(2),
        &cancel,
        cancel.digest()?,
        &json!({"cancelled":true}),
        &floor,
        false,
    )?;
    assert!(store.verify_floor(&fixture.checkpoint).is_err());
    store.repair_floor(&fixture.checkpoint)?;
    assert!(store.replay(&prepare, &prepare.digest()?).is_err());
    assert_eq!(
        store.replay(&cancel, &cancel.digest()?)?,
        Some(json!({"cancelled":true}))
    );
    drop(store);
    let reopened = Store::open(&fixture.db, [12; 32])?;
    reopened.verify_floor(&fixture.checkpoint)?;
    assert!(reopened.replay(&prepare, &prepare.digest()?).is_err());
    Ok(())
}

#[test]
fn single_user_prepare_cancel_purposes_survive_checkpoint_publication_and_reopen() -> Result<()> {
    // Storage-only fixture: this does not install an ownership/proof bypass.
    let f = Fixture::new()?;
    let _lock = lock_guarded(&f.db, &f.checkpoint, &|| Ok(()))?;
    let mut store = Store::open(&f.db, [12; 32])?;
    let floor = store.verify_floor(&f.checkpoint)?;
    store.commit(
        &f.coin,
        None,
        &f.request,
        f.request.digest()?,
        &json!({"allocated":true}),
        &floor,
        false,
    )?;
    store.publish(&f.checkpoint)?;
    let mut intent = f.request.intent.clone();
    intent.operation = [71; 32];
    intent.recipient_claim = [72; 32];
    let context = zark_protocol::spark_native::ExitContext {
        deployment: intent.deployment,
        coin: intent.coin,
        current_state: intent.previous_state,
        operation: intent.operation,
        session: f.request.session,
        revision: intent.revision,
    };
    let owner = SigningKey::from_bytes(&random_scalar().to_bytes())?;
    let commitment = [73; 32];
    let prepare = Request::sign(
        intent.clone(),
        Command::SingleUserPrepare {
            plan: intent.recipient_claim,
            nonce_commitment: commitment,
            owner: OwnerAuthorization::sign_single_user(
                &context,
                &intent.recipient_claim,
                &commitment,
                &owner,
            )?,
        },
        &f.key,
    )?;
    let floor = store.verify_floor(&f.checkpoint)?;
    store.commit(
        &f.coin,
        Some(1),
        &prepare,
        prepare.digest()?,
        &json!({"nonce":[1,2]}),
        &floor,
        false,
    )?;
    store.publish(&f.checkpoint)?;
    let cancel = Request::sign(intent, Command::SingleUserCancel {}, &f.key)?;
    let floor = store.verify_floor(&f.checkpoint)?;
    store.commit(
        &f.coin,
        Some(2),
        &cancel,
        cancel.digest()?,
        &json!({"cancelled":true}),
        &floor,
        false,
    )?;
    assert!(store.verify_floor(&f.checkpoint).is_err());
    store.repair_floor(&f.checkpoint)?;
    assert!(store.replay(&prepare, &prepare.digest()?).is_err());
    assert!(store.replay(&cancel, &cancel.digest()?)?.is_some());
    drop(store);
    let store = Store::open(&f.db, [12; 32])?;
    store.verify_floor(&f.checkpoint)?;
    assert!(store.replay(&prepare, &prepare.digest()?).is_err());
    Ok(())
}

#[test]
fn persisted_nonce_set_rejects_changed_purpose_context_and_opposite_reuse() -> Result<()> {
    let mut fixture = Fixture::new()?;
    fixture.coin.backing = [14; 32];
    fixture.coin.capability = [15; 32];
    fixture.coin.phase = Phase::Prepared;
    let successor = [16; 32];
    let recovery = [17; 32];
    let mut branches = Vec::new();
    for index in 0u8..2 {
        let secret: [u8; 32] = k256::Scalar::from(u64::from(index) + 20).to_bytes().into();
        let point = zark_protocol::point_bytes(
            k256::ProjectivePoint::GENERATOR * zark_protocol::scalar(&secret)?,
        )?
        .to_vec();
        let commitment = [index + 30; 32];
        branches.push(state::Branch {
            index,
            id: state::nonce_id(
                &fixture.request.intent,
                &fixture.request.session,
                &successor,
                &recovery,
                index,
                &point,
                &commitment,
            )?,
            point,
            commitment,
            secret: Some(secret),
        });
    }
    let pending = fixture.coin.pending.as_mut().unwrap();
    pending.next_capability = Some(fixture.coin.capability);
    pending.preparation = Some(state::Preparation {
        purpose: "wrapped-recovery-v1".into(),
        successor_state: successor,
        recovery,
        branches: branches.try_into().ok().unwrap(),
    });
    fixture.coin.validate(&fixture.policy)?;
    let valid = fixture.coin.clone();
    fixture
        .coin
        .pending
        .as_mut()
        .unwrap()
        .preparation
        .as_mut()
        .unwrap()
        .purpose = "native-leaf-v1".into();
    assert!(fixture.coin.validate(&fixture.policy).is_err());
    fixture.coin = valid.clone();
    fixture
        .coin
        .pending
        .as_mut()
        .unwrap()
        .preparation
        .as_mut()
        .unwrap()
        .recovery = [18; 32];
    assert!(fixture.coin.validate(&fixture.policy).is_err());
    fixture.coin = valid;
    let preparation = fixture
        .coin
        .pending
        .as_mut()
        .unwrap()
        .preparation
        .as_mut()
        .unwrap();
    let opposite = (-zark_protocol::scalar(&preparation.branches[0].secret.unwrap())?)
        .to_bytes()
        .into();
    let second = &mut preparation.branches[1];
    second.secret = Some(opposite);
    second.point = zark_protocol::point_bytes(
        k256::ProjectivePoint::GENERATOR * zark_protocol::scalar(&opposite)?,
    )?
    .to_vec();
    second.id = state::nonce_id(
        &fixture.request.intent,
        &fixture.request.session,
        &successor,
        &recovery,
        second.index,
        &second.point,
        &second.commitment,
    )?;
    assert!(fixture.coin.validate(&fixture.policy).is_err());
    Ok(())
}

#[test]
fn unissued_record_cannot_skip_into_accepted_ownership() -> Result<()> {
    let mut fixture = Fixture::new()?;
    fixture.coin.phase = Phase::Accepted;
    fixture.coin.pending = None;
    fixture.coin.backing = [14; 32];
    fixture.coin.capability = [15; 32];
    assert!(fixture.coin.validate(&fixture.policy).is_err());
    Ok(())
}

#[test]
fn cancellation_journal_tombstones_old_responses_before_replay() -> Result<()> {
    // Journal-only simulation: it exercises the atomic storage operation, not
    // authorization, proofs or transitions. Engine never exposes this store.
    let fixture = Fixture::new()?;
    let _lock = lock_guarded(&fixture.db, &fixture.checkpoint, &|| Ok(()))?;
    let mut store = Store::open(&fixture.db, [12; 32])?;
    let floor = store.verify_floor(&fixture.checkpoint)?;
    store.commit(
        &fixture.coin,
        None,
        &fixture.request,
        fixture.request.digest()?,
        &json!({"allocated":true}),
        &floor,
        false,
    )?;
    store.publish(&fixture.checkpoint)?;
    let mut intent = fixture.request.intent.clone();
    intent.operation = [19; 32];
    let owner = SigningKey::from_bytes(&random_scalar().to_bytes())?;
    let reserve = Request::sign(
        intent.clone(),
        Command::Reserve {
            owner: OwnerAuthorization::sign(&intent, &fixture.request.session, &owner)?,
        },
        &fixture.key,
    )?;
    let floor = store.verify_floor(&fixture.checkpoint)?;
    store.commit(
        &fixture.coin,
        Some(1),
        &reserve,
        reserve.digest()?,
        &json!({"mask":vec![42;32]}),
        &floor,
        false,
    )?;
    store.publish(&fixture.checkpoint)?;
    let cancel = Request::sign(intent, Command::Cancel {}, &fixture.key)?;
    let floor = store.verify_floor(&fixture.checkpoint)?;
    let response = json!({"cancelled":true});
    store.commit(
        &fixture.coin,
        Some(2),
        &cancel,
        cancel.digest()?,
        &response,
        &floor,
        false,
    )?;
    assert!(store.verify_floor(&fixture.checkpoint).is_err());
    store.repair_floor(&fixture.checkpoint)?;
    assert!(store.replay(&reserve, &reserve.digest()?).is_err());
    assert_eq!(store.replay(&cancel, &cancel.digest()?)?, Some(response));
    Ok(())
}
