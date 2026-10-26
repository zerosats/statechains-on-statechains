//! Harness pieces that need no Spark stack: the chain adapter, the driver port
//! loop, receiver observations, head checks and the timing helper.
use super::*;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use std::collections::VecDeque;
use zeroize::Zeroizing;

struct Scripted {
    requests: Vec<Value>,
    replies: VecDeque<Result<Value>>,
}
impl Scripted {
    fn new(replies: Vec<Result<Value>>) -> Self {
        Self {
            requests: Vec::new(),
            replies: replies.into(),
        }
    }
}
impl NativeCall for Scripted {
    fn call(&mut self, request: &Value) -> Result<Value> {
        self.requests.push(request.clone());
        self.replies.pop_front().context("unscripted native call")?
    }
}

fn status_reply(txid: &[u8; 32], status: &str) -> Value {
    json!({"txid":bitcoin::Txid::from_byte_array(*txid).to_string(),"status":status,"txindex_synced":true})
}

#[test]
fn chain_view_maps_exact_statuses_and_never_turns_failures_into_absence() -> Result<()> {
    let txid = random32();
    for (status, expected) in [
        ("absent", TxStatus::Absent),
        ("mempool", TxStatus::Mempool),
        ("confirmed", TxStatus::Confirmed),
    ] {
        let mut native = Scripted::new(vec![Ok(status_reply(&txid, status))]);
        let chain = NativeChain(RefCell::new(&mut native));
        let view: &dyn ChainView = &chain;
        assert_eq!(view.status(&txid)?, expected);
        let request = &native.requests[0];
        assert!(request["op"] == "chain_status" && request["directory"] == NATIVE);
        // Display order, as bitcoind expects: reversed internal bytes.
        let mut reversed = txid;
        reversed.reverse();
        assert_eq!(request["txid"], hex::encode(reversed));
    }
    let mut unsynced = status_reply(&txid, "absent");
    unsynced["txindex_synced"] = json!(false);
    let mut missing = status_reply(&txid, "absent");
    missing.as_object_mut().unwrap().remove("status");
    for reply in [
        Err(anyhow::anyhow!("node unavailable")),
        Ok(status_reply(&random32(), "absent")),
        Ok(status_reply(&txid, "unknown")),
        Ok(unsynced),
        Ok(missing),
        Ok(Value::Null),
    ] {
        let mut native = Scripted::new(vec![reply]);
        assert!(
            NativeChain(RefCell::new(&mut native))
                .status(&txid)
                .is_err()
        );
    }
    Ok(())
}

struct Port {
    driver: VecDeque<Value>,
    replies: Vec<Value>,
}
impl Port {
    fn new(driver: Vec<Value>) -> Self {
        Self {
            driver: driver.into(),
            replies: Vec::new(),
        }
    }
}
impl DriverPort for Port {
    fn request(&mut self) -> Result<Value> {
        self.driver.pop_front().context("driver stopped")
    }
    fn reply(&mut self, value: &Value) -> Result<()> {
        self.replies.push(value.clone());
        Ok(())
    }
}

fn compressed() -> Vec<u8> {
    (k256::ProjectivePoint::GENERATOR * random_scalar())
        .to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec()
}

fn plan() -> SendPlan {
    SendPlan {
        secret: Zeroizing::new(random_scalar().to_bytes().into()),
        driver_seed: Zeroizing::new(random32()),
        transfer_id: [0x11; 16],
        receiver: compressed(),
    }
}

#[test]
fn driver_port_serves_exactly_the_two_requests_for_the_durable_transfer() -> Result<()> {
    let plan = plan();
    let leaf = json!({"id":"leaf"});
    let sent = json!({"op":"sent","transfer_id":plan.transfer_uuid(),"status":"SenderKeyTweaked"});
    let mut port = Port::new(vec![
        json!({"op":"exit_send"}),
        json!({"op":"seal_leaf_key","public":compressed()}),
        sent.clone(),
    ]);
    assert_eq!(drive(&mut port, &plan, &leaf)?, sent);
    assert!(port.replies.iter().all(|r| r["ok"] == true) && port.replies.len() == 2);
    let exit = &port.replies[0]["value"];
    assert!(
        exit["transfer_id"] == plan.transfer_uuid()
            && exit["leaf"] == leaf
            && exit["receiver"] == json!(plan.receiver)
    );
    let sealed: Vec<u8> = serde_json::from_value(port.replies[1]["value"].clone())?;
    assert!(!sealed.windows(32).any(|w| w == plan.secret.as_slice()));
    Ok(())
}

#[test]
fn driver_port_refuses_out_of_order_unknown_or_foreign_results() -> Result<()> {
    let plan = plan();
    let leaf = json!({"id":"leaf"});
    let sent = json!({"op":"sent","transfer_id":plan.transfer_uuid()});
    for (driver, refusals) in [
        (vec![json!({"op":"seal_leaf_key","public":compressed()})], 1),
        (
            vec![json!({"op":"identity_digest","digest":vec![0u8; 32]})],
            1,
        ),
        (
            vec![
                json!({"op":"exit_send"}),
                json!({"op":"seal_leaf_key","public":vec![5u8; 33]}),
            ],
            1,
        ),
        (
            vec![json!({"op":"exit_send"}), json!({"op":"exit_send"})],
            1,
        ),
        (vec![json!({"op":"exit_send"})], 0),
    ] {
        let mut port = Port::new(driver);
        assert!(drive(&mut port, &plan, &leaf).is_err());
        assert_eq!(
            port.replies.iter().filter(|r| r["ok"] == false).count(),
            refusals
        );
        if refusals == 1 {
            assert_eq!(port.replies.last(), Some(&json!({"ok":false})));
        }
    }
    let mut foreign = sent.clone();
    foreign["transfer_id"] = json!("00000000-0000-4000-8000-000000000000");
    for last in [
        foreign,
        json!({"op":"claimed","transfer_id":plan.transfer_uuid()}),
    ] {
        let mut port = Port::new(vec![
            json!({"op":"exit_send"}),
            json!({"op":"seal_leaf_key","public":compressed()}),
            last,
        ]);
        assert!(drive(&mut port, &plan, &leaf).is_err());
    }
    Ok(())
}

#[test]
fn receiver_observations_require_the_fresh_wallet_to_hold_exactly_the_leaf() -> Result<()> {
    let identity = compressed();
    let user = compressed();
    let recipient = json!({"identity":identity,"user":user});
    let balance =
        json!({"identity":identity,"available_sats":64000,"leaves":["leaf"],"operators_agreed":3});
    assert_eq!(receiver_balance(&balance, &identity, "leaf")?, 64000);
    for (key, value) in [
        ("identity", json!(compressed())),
        ("operators_agreed", json!(2)),
        ("leaves", json!(["leaf", "other"])),
        ("leaves", json!(["other"])),
        ("available_sats", json!("64000")),
    ] {
        let mut changed = balance.clone();
        changed[key] = value;
        assert!(
            receiver_balance(&changed, &identity, "leaf").is_err(),
            "{key}"
        );
    }
    let received = json!({"operators_completed":3,"leaf_id":"leaf","owner":identity,"user":user});
    claimed(&received, &recipient, "leaf")?;
    for (key, value) in [
        ("operators_completed", json!(2)),
        ("leaf_id", json!("other")),
        ("owner", json!(compressed())),
        ("user", json!(compressed())),
    ] {
        let mut changed = received.clone();
        changed[key] = value;
        assert!(claimed(&changed, &recipient, "leaf").is_err(), "{key}");
    }
    Ok(())
}

fn signed_head(phase: HeadPhase, revision: u64) -> Head {
    Head {
        deployment: [1; 32],
        coin: [2; 32],
        query: random32(),
        challenge: random32(),
        session: random32(),
        state: [3; 32],
        capability: [4; 32],
        policy: [5; 32],
        revision,
        phase,
        locked_operation: None,
        share_release: true,
    }
}

#[test]
fn heads_must_offer_release_before_and_be_exited_one_revision_later() -> Result<()> {
    let before = signed_head(HeadPhase::Available, 7);
    releasable(&before)?;
    assert!(
        releasable(&Head {
            share_release: false,
            ..before.clone()
        })
        .is_err()
    );
    assert!(
        releasable(&Head {
            locked_operation: Some(random32()),
            ..before.clone()
        })
        .is_err()
    );
    assert!(releasable(&signed_head(HeadPhase::Locked, 7)).is_err());
    terminal(&before, &signed_head(HeadPhase::Exited, 8))?;
    for after in [
        signed_head(HeadPhase::Available, 8),
        signed_head(HeadPhase::Exited, 7),
        signed_head(HeadPhase::Exited, 9),
        Head {
            state: random32(),
            ..signed_head(HeadPhase::Exited, 8)
        },
    ] {
        assert!(terminal(&before, &after).is_err());
    }
    Ok(())
}

#[test]
fn timed_phases_pass_values_through_and_propagate_failures() -> Result<()> {
    assert_eq!(timed("share_verify", || Ok(5))?, 5);
    let error = timed::<()>("chain_gate", || anyhow::bail!("gate refused")).unwrap_err();
    assert_eq!(error.to_string(), "gate refused");
    Ok(())
}
