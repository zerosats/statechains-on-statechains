//! Record invariants, not a proof oracle. Real Engine acceptance is exercised
//! by the opt-in real ownership/single-USER proof fixture.
use super::*;
use k256::schnorr::SigningKey;
use zark_protocol::{random32, spark_lineage::Config};
fn fixture() -> Result<(Coin, Policy, Workflow)> {
    let owner = SigningKey::from_bytes(&random_scalar().to_bytes())?;
    let session = SigningKey::from_bytes(&random_scalar().to_bytes())?;
    let config = Config {
        origin_key: owner.verifying_key().to_bytes().into(),
        role_hashes: [[1; 32], [2; 32], [3; 32], [4; 32]],
    };
    let policy = Policy {
        deployment: [1; 32],
        config,
        policy: [2; 32],
        native: None,
        native_cluster: None,
        bootstrap: None,
        single_user: Some([3; 32]),
        receive: None,
        receive_cluster: None,
        identity: None,
        auth: None,
        ecdsa_2p: false,
        additive_receive: false,
    };
    let coin = Coin {
        deployment: policy.deployment,
        coin: [4; 32],
        backing: [5; 32],
        state: [6; 32],
        capability: [7; 32],
        secret: random_scalar().to_bytes().into(),
        salt: [8; 32],
        session: session.verifying_key().to_bytes().into(),
        owner: Some(super::super::Predecessor::Transfer),
        phase: Phase::Accepted,
        pending: None,
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
    let secret: Digest = random_scalar().to_bytes().into();
    let mut w = Workflow {
        purpose: PURPOSE.into(),
        registry: [3; 32],
        intent: Intent {
            deployment: coin.deployment,
            coin: coin.coin,
            previous_state: coin.state,
            operation: [9; 32],
            recipient_claim: [10; 32],
            revision: 17,
        },
        session: coin.session,
        plan: [10; 32],
        branch: Branch {
            index: 0,
            id: [0; 32],
            point: point_bytes(k256::ProjectivePoint::GENERATOR * scalar(&secret)?)?.to_vec(),
            commitment: [11; 32],
            secret: Some(secret),
        },
        statement: None,
        partial: None,
    };
    w.branch.id = nonce_id(&w)?;
    w.validate(&coin, &policy)?;
    Ok((coin, policy, w))
}
#[test]
fn nonce_record_binds_purpose_registry_intent_session_and_revision() -> Result<()> {
    let (coin, policy, w) = fixture()?;
    w.validate_revision(18)?;
    assert!(w.validate_revision(17).is_err());
    for index in 0..5 {
        let mut changed = w.clone();
        match index {
            0 => changed.purpose = "wrapped-recovery-v1".into(),
            1 => changed.registry = random32(),
            2 => changed.intent.operation = random32(),
            3 => changed.plan = random32(),
            _ => {
                changed.session = SigningKey::from_bytes(&random_scalar().to_bytes())?
                    .verifying_key()
                    .to_bytes()
                    .into()
            }
        };
        assert!(changed.validate(&coin, &policy).is_err());
    }
    let mut policy = policy;
    policy.single_user = None;
    assert!(w.validate(&coin, &policy).is_err());
    Ok(())
}
#[test]
fn consumed_nonce_and_retained_response_cannot_be_substituted() -> Result<()> {
    let (coin, policy, mut w) = fixture()?;
    let a = SigningAuthorization {
        context: context(&w.intent, w.session),
        backing: coin.backing,
        policy: policy.policy,
        capability: coin.capability,
        plan: w.plan,
        server: coin.server()?,
        config: policy.config.clone(),
        nonce: w.branch.point.as_slice().try_into()?,
        challenge: [0; 32],
        blinding: w.branch.commitment,
    };
    w.partial = w.branch.secret.take();
    w.statement = Some(a.encode()?);
    w.validate(&coin, &policy)?;
    w.validate_revision(19)?;
    let mut changed = w.clone();
    changed.branch.secret = Some([12; 32]);
    assert!(changed.validate(&coin, &policy).is_err());
    let mut changed = w.clone();
    changed.partial = Some([13; 32]);
    assert!(changed.validate(&coin, &policy).is_err());
    let mut changed = w;
    changed.statement = None;
    assert!(changed.validate(&coin, &policy).is_err());
    Ok(())
}
