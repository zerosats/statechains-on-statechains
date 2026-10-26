//! Persistence invariants only; no proof oracle is installed.
use super::*;
use k256::{ProjectivePoint, Scalar, elliptic_curve::sec1::ToEncodedPoint};
use zark_protocol::{
    spark_lineage::{self as lineage, Config},
    spark_receive::{ClaimCluster, ClaimOperator},
};
fn fixture() -> Result<(Coin, Policy, Workflow)> {
    let session = k256::schnorr::SigningKey::from_bytes(&random_scalar().to_bytes())?;
    let config = Config {
        origin_key: session.verifying_key().to_bytes().into(),
        role_hashes: [[1; 32], [2; 32], [3; 32], [4; 32]],
    };
    let cluster = ClaimCluster {
        threshold: 2,
        operators: (1..=3u16)
            .map(|i| {
                (
                    hex::encode(Scalar::from(u64::from(i) + 10).to_bytes()),
                    ClaimOperator {
                        index: i,
                        encryption_key: (ProjectivePoint::GENERATOR
                            * Scalar::from(u64::from(i) + 20))
                        .to_affine()
                        .to_encoded_point(true)
                        .as_bytes()
                        .to_vec(),
                    },
                )
            })
            .collect(),
    };
    let policy = Policy {
        deployment: [5; 32],
        config,
        policy: [6; 32],
        native: None,
        native_cluster: None,
        bootstrap: None,
        single_user: None,
        receive: Some(([7; 32], cluster.digest()?, [9; 32])),
        receive_cluster: Some(cluster.clone()),
        identity: None,
        auth: None,
        ecdsa_2p: false,
        additive_receive: false,
    };
    let intent = Intent {
        deployment: policy.deployment,
        coin: [10; 32],
        previous_state: lineage::origin_previous_state(&policy.deployment, &[10; 32])?,
        operation: [11; 32],
        recipient_claim: lineage::origin_field(&policy.deployment, &[10; 32], 0)?,
        revision: 1,
    };
    let request = Request::sign(intent.clone(), Command::Allocate {}, &session)?;
    let coin = Coin {
        deployment: policy.deployment,
        coin: intent.coin,
        backing: [0; 32],
        state: intent.previous_state,
        capability: [0; 32],
        secret: random_scalar().to_bytes().into(),
        salt: [12; 32],
        session: request.session,
        owner: None,
        phase: Phase::Allocated,
        pending: Some(super::super::state::Pending::new(&request, true)),
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
    let mut w = Workflow {
        purpose: PURPOSE.into(),
        registry: [7; 32],
        cluster: cluster.digest()?,
        circuit: [9; 32],
        intent,
        session: request.session,
        server: coin.server()?.to_vec(),
        backing: [13; 32],
        capability: [14; 32],
        plan: [15; 32],
        branches: std::array::from_fn(|i| {
            let secret: Digest = Scalar::from(30 + i as u64).to_bytes().into();
            Branch {
                index: i as u8,
                id: [0; 32],
                point: point_bytes(ProjectivePoint::GENERATOR * scalar(&secret).unwrap())
                    .unwrap()
                    .to_vec(),
                commitment: [40 + i as u8; 32],
                secret: Some(secret),
            }
        }),
        secrets: Some(Secrets {
            slope: Scalar::from(50u64).to_bytes().into(),
            seed: random32(),
        }),
        transcripts: cluster
            .operators
            .keys()
            .map(|id| {
                (
                    id.clone(),
                    Transcript {
                        initial: [51; 32],
                        rounds: Vec::new(),
                    },
                )
            })
            .collect(),
        statement: None,
        partials: None,
        stage: Stage::Prepared,
        additive: false,
    };
    for i in 0..2 {
        w.branches[i].id = nonce_id(&w, &w.branches[i])?;
    }
    w.validate(&coin, &policy)?;
    w.validate_revision(2)?;
    Ok((coin, policy, w))
}
#[test]
fn receive_retains_inputs_only_until_every_operator_finishes() -> Result<()> {
    let (coin, policy, mut w) = fixture()?;
    for t in w.transcripts.values_mut() {
        t.rounds = vec![([60; 32], [61; 32]); 7];
    }
    assert!(w.validate(&coin, &policy).is_err());
    w.secrets = None;
    w.stage = Stage::TweaksReady;
    w.validate(&coin, &policy)?;
    w.validate_revision(23)?;
    let mut altered = w.clone();
    altered
        .transcripts
        .values_mut()
        .next()
        .unwrap()
        .rounds
        .pop();
    assert!(altered.validate(&coin, &policy).is_err());
    let mut altered = w.clone();
    altered.circuit = [62; 32];
    assert!(altered.validate(&coin, &policy).is_err());
    let mut altered = w;
    altered.branches[0].secret = None;
    assert!(altered.validate(&coin, &policy).is_err());
    Ok(())
}
#[test]
fn aborted_receive_erases_every_nonce_and_cannot_claim_readiness() -> Result<()> {
    let (coin, policy, mut w) = fixture()?;
    w.stage = Stage::Aborted;
    assert!(w.validate(&coin, &policy).is_err());
    w.secrets = None;
    for b in &mut w.branches {
        b.secret = None;
    }
    w.validate(&coin, &policy)?;
    w.validate_revision(3)?;
    w.stage = Stage::TweaksReady;
    assert!(w.validate(&coin, &policy).is_err());
    Ok(())
}
#[test]
fn garbled_workflow_bytes_omit_the_additive_mode() -> Result<()> {
    let (coin, policy, w) = fixture()?;
    let bytes = serde_json::to_vec(&w)?;
    assert!(!String::from_utf8(bytes.clone())?.contains("additive"));
    let reopened: Workflow = serde_json::from_slice(&bytes)?;
    assert_eq!(serde_json::to_vec(&reopened)?, bytes);
    reopened.validate(&coin, &policy)?;
    let mut additive_policy = policy;
    additive_policy.additive_receive = true;
    assert!(reopened.validate(&coin, &additive_policy).is_err());
    Ok(())
}
#[test]
fn additive_receive_keeps_no_mpc_state_and_counts_one_release() -> Result<()> {
    let (coin, mut policy, mut w) = fixture()?;
    policy.additive_receive = true;
    w.additive = true;
    assert!(w.validate(&coin, &policy).is_err());
    let transcripts = std::mem::take(&mut w.transcripts);
    w.secrets = None;
    w.validate(&coin, &policy)?;
    w.validate_revision(2)?;
    let mut altered = w.clone();
    altered.transcripts = transcripts;
    assert!(altered.validate(&coin, &policy).is_err());
    let tweak: Digest = random_scalar().to_bytes().into();
    Engine::check_receive_tweak(&w, &tweak)?;
    assert!(Engine::check_receive_tweak(&w, &[0; 32]).is_err());
    w.stage = Stage::TweaksReady;
    w.validate(&coin, &policy)?;
    w.validate_revision(3)?;
    assert!(w.validate_revision(2).is_err());
    assert!(Engine::check_receive_tweak(&w, &tweak).is_err());
    w.stage = Stage::Aborted;
    assert!(w.validate(&coin, &policy).is_err());
    Ok(())
}
#[test]
fn commit_refuses_receive_revision_accounting_that_would_not_load() -> Result<()> {
    use super::super::{lock_guarded, persistence::Store};
    use std::{fs, path::PathBuf};
    let (coin, _, w) = fixture()?;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../work/spark-receive-commit-tests")
        .join(hex::encode(random32()));
    fs::create_dir_all(root.join("floor"))?;
    let (db, checkpoint) = (
        root.join("state.sqlite"),
        root.join("floor/checkpoint.json"),
    );
    let run = || -> Result<()> {
        let _lock = lock_guarded(&db, &checkpoint, &|| Ok(()))?;
        let mut store = Store::open(&db, [12; 32])?;
        let key = k256::schnorr::SigningKey::from_bytes(&random_scalar().to_bytes())?;
        let request = |operation| {
            Request::sign(
                Intent {
                    operation,
                    ..w.intent.clone()
                },
                Command::Allocate {},
                &key,
            )
        };
        let allocate = request([20; 32])?;
        let floor = store.verify_floor(&checkpoint)?;
        store.commit(
            &coin,
            None,
            &allocate,
            allocate.digest()?,
            &json!({"allocated":true}),
            &floor,
            false,
        )?;
        store.publish(&checkpoint)?;

        // One garbled round more than the committed revision accounts for.
        let mut slipped = coin.clone();
        let mut extra = w.clone();
        extra
            .transcripts
            .values_mut()
            .next()
            .context("transcript")?
            .rounds
            .push(([60; 32], [61; 32]));
        slipped.receive = Some(extra);
        let prepare = request([21; 32])?;
        let floor = store.verify_floor(&checkpoint)?;
        let error = store
            .commit(
                &slipped,
                Some(1),
                &prepare,
                prepare.digest()?,
                &json!({}),
                &floor,
                false,
            )
            .err()
            .context("unloadable receive accounting committed")?;
        ensure!(
            error.to_string().contains("receive transcript revision"),
            "{error}"
        );
        store.verify_floor(&checkpoint)?;
        ensure!(
            store.coin(&coin.coin)?.context("coin")?.1 == 1,
            "refused commit changed the coin"
        );

        let mut prepared = coin.clone();
        prepared.receive = Some(w.clone());
        store.commit(
            &prepared,
            Some(1),
            &prepare,
            prepare.digest()?,
            &json!({}),
            &floor,
            false,
        )?;
        store.publish(&checkpoint)?;
        let (loaded, revision) = store.coin(&coin.coin)?.context("coin")?;
        ensure!(
            revision == 2 && loaded.receive.is_some(),
            "accounted receive commit"
        );
        Ok(())
    };
    let result = run();
    let _ = fs::remove_dir_all(&root);
    result
}
#[test]
fn frame_replay_keys_bind_operator_round_and_complete_allocation() -> Result<()> {
    let (_, policy, w) = fixture()?;
    let ids = policy
        .receive_cluster
        .unwrap()
        .operators
        .into_keys()
        .collect::<Vec<_>>();
    assert_ne!(
        frame_intent(&w.intent, &ids[0], 0)?.operation,
        frame_intent(&w.intent, &ids[0], 1)?.operation
    );
    assert_ne!(
        frame_intent(&w.intent, &ids[0], 0)?.operation,
        frame_intent(&w.intent, &ids[1], 0)?.operation
    );
    let mut other = w.intent.clone();
    other.coin = [70; 32];
    assert_ne!(
        frame_intent(&w.intent, &ids[0], 0)?.operation,
        frame_intent(&other, &ids[0], 0)?.operation
    );
    assert!(frame_intent(&w.intent, &ids[0], 7).is_err());
    Ok(())
}
