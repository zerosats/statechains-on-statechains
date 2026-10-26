//! Scope checks isolate authority and retirement; they do not accept proof or
//! native-settlement fixtures in place of the production verifier.
use super::super::state::Pending;
use super::*;
use k256::{Scalar, schnorr::SigningKey};
use zark_protocol::spark_lineage::Config;

fn fixture() -> Result<(Coin, Policy, Request)> {
    let key = SigningKey::from_bytes(&Scalar::from(17u64).to_bytes())?;
    let intent = Intent {
        deployment: [1; 32],
        coin: [2; 32],
        previous_state: [3; 32],
        operation: [4; 32],
        recipient_claim: [5; 32],
        revision: 8,
    };
    let request = Request::sign(intent, Command::Allocate {}, &key)?;
    let coin = Coin {
        deployment: [1; 32],
        coin: [2; 32],
        backing: [6; 32],
        state: [3; 32],
        capability: [7; 32],
        secret: Scalar::from(19u64).to_bytes().into(),
        salt: [8; 32],
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
    let policy = Policy {
        deployment: [1; 32],
        config: Config {
            origin_key: request.session,
            role_hashes: std::array::from_fn(|i| [i as u8 + 1; 32]),
        },
        policy: [9; 32],
        native: None,
        native_cluster: None,
        bootstrap: None,
        single_user: None,
        receive: None,
        receive_cluster: None,
        identity: Some([10; 32]),
        auth: None,
        ecdsa_2p: false,
        additive_receive: false,
    };
    Ok((coin, policy, request))
}

fn native(coin: &mut Coin, request: &Request) -> Result<()> {
    coin.phase = Phase::Accepted;
    coin.pending = None;
    coin.native = Some(serde_json::from_value(json!({
        "purpose":"native-initial-root-exit-v1", "registry":vec![11;32], "cluster":vec![12;32],
        "intent":request.intent, "session":request.session, "plan":vec![5;32],
        "branches":[{"index":0,"id":vec![1;32],"point":coin.server()?.to_vec(),"commitment":vec![2;32],"secret":null},
                    {"index":1,"id":vec![3;32],"point":coin.server()?.to_vec(),"commitment":vec![4;32],"secret":null}],
        "statement":null,"partials":null
    }))?);
    Ok(())
}

#[test]
fn identity_requires_current_locked_native_owner_session() -> Result<()> {
    let (mut coin, _, request) = fixture()?;
    assert_eq!(scope(&coin, &request.session)?, &request.intent);
    assert!(scope(&coin, &[21; 32]).is_err());
    coin.phase = Phase::Accepted;
    coin.pending = None;
    assert!(scope(&coin, &request.session).is_err());
    native(&mut coin, &request)?;
    assert_eq!(scope(&coin, &request.session)?, &request.intent);
    assert!(scope(&coin, &[21; 32]).is_err());
    coin.state[0] ^= 1;
    assert!(scope(&coin, &request.session).is_err());
    Ok(())
}

#[test]
fn ready_identity_masks_cannot_survive_share_or_scope_rotation() -> Result<()> {
    let (mut coin, policy, request) = fixture()?;
    native(&mut coin, &request)?;
    let nonce = nonce_public(&Scalar::from(23u64).to_bytes().into())?;
    let commitment = [24; 32];
    let intent = identity_intent(&request.intent, &commitment, &nonce)?;
    let w = Workflow {
        intent: intent.clone(),
        session: request.session,
        server: coin.server()?.to_vec(),
        commitment,
        wallet_nonce: nonce.clone(),
        server_nonce: nonce,
        r: Scalar::ONE.to_bytes().into(),
        initial: [25; 32],
        rounds: vec![([26; 32], [27; 32]); 7],
        secrets: None,
        aborted: false,
        masks: Some([Scalar::ONE.to_bytes().into(); 2]),
        message: None,
        digest: None,
        partial: None,
    };
    let mut sessions = Sessions {
        circuit: [10; 32],
        commitment,
        sessions: BTreeMap::from([(hex::encode(intent.operation), w)]),
    };
    sessions.validate(&coin, &policy)?;
    coin.secret = Scalar::from(29u64).to_bytes().into();
    assert!(sessions.validate(&coin, &policy).is_err());
    // Explicit retirement erases the only usable scalar masks. Historical
    // public transcripts may remain after ownership moves.
    sessions.retire_unused();
    coin.native = None;
    sessions.validate(&coin, &policy)?;
    assert!(!sessions.active());
    assert!(
        sessions
            .sessions
            .values()
            .all(|w| w.masks.is_none() && w.secrets.is_none())
    );
    Ok(())
}

#[test]
fn restoring_ready_ticket_never_authorizes_an_alternate_message() -> Result<()> {
    let (mut coin, _, allocation) = fixture()?;
    let message = [41; 32];
    let nonce = nonce_public(&Scalar::from(23u64).to_bytes().into())?;
    let commitment = [24; 32];
    let intent = identity_message_intent(&allocation.intent, &commitment, &nonce, &message)?;
    let identity = intent.operation;
    let w = Workflow {
        intent: intent.clone(),
        session: allocation.session,
        server: coin.server()?.to_vec(),
        commitment,
        wallet_nonce: nonce.clone(),
        server_nonce: nonce,
        r: Scalar::ONE.to_bytes().into(),
        initial: [25; 32],
        rounds: vec![([26; 32], [27; 32]); 7],
        secrets: None,
        aborted: false,
        masks: Some([Scalar::ONE.to_bytes().into(); 2]),
        message: Some(message),
        digest: None,
        partial: None,
    };
    // Serialize the ready state, as a database/checkpoint backup would do.
    let backup = serde_json::to_vec(&w)?;
    coin.identities = Some(Sessions {
        circuit: [10; 32],
        commitment,
        sessions: BTreeMap::from([(hex::encode(identity), w)]),
    });
    let request_for = |digest| -> Result<Request> {
        Ok(Request {
            intent: identity_sign_intent(&intent, &digest)?,
            session: allocation.session,
            command: Command::IdentitySign { identity, digest },
            signature: Vec::new(),
        })
    };
    authorize_signature(&coin, &request_for(message)?, &identity, &message)?;
    let w = coin
        .identities
        .as_mut()
        .unwrap()
        .sessions
        .get_mut(&hex::encode(identity))
        .unwrap();
    w.masks = None;
    w.digest = Some(message);
    w.partial = Some([42; 32]);
    assert!(authorize_signature(&coin, &request_for(message)?, &identity, &message).is_err());

    let restored: Workflow = serde_json::from_slice(&backup)?;
    coin.identities
        .as_mut()
        .unwrap()
        .sessions
        .insert(hex::encode(identity), restored);
    authorize_signature(&coin, &request_for(message)?, &identity, &message)?;
    let alternate = [43; 32];
    assert_ne!(
        request_for(message)?.intent.operation,
        request_for(alternate)?.intent.operation
    );
    assert!(authorize_signature(&coin, &request_for(alternate)?, &identity, &alternate).is_err());
    // Erasing the new field cannot reinterpret a legacy ticket as message-bound.
    coin.identities
        .as_mut()
        .unwrap()
        .sessions
        .get_mut(&hex::encode(identity))
        .unwrap()
        .message = None;
    assert!(authorize_signature(&coin, &request_for(message)?, &identity, &message).is_err());
    Ok(())
}
