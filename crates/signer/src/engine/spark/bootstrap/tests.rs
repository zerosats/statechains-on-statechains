//! Record/nonce invariant fixtures only. No test installs a proof oracle or
//! claims that a native deposit or an ownership certificate was admitted.
use super::*;
use k256::schnorr::SigningKey;
use zark_protocol::{
    random32,
    spark_bootstrap::BootstrapBranch,
    spark_lineage::{self as lineage, Config},
};

fn fixture() -> Result<(Coin, Policy, Workflow)> {
    let session = SigningKey::from_bytes(&random_scalar().to_bytes())?;
    let owner = SigningKey::from_bytes(&random_scalar().to_bytes())?;
    let config = Config {
        origin_key: SigningKey::from_bytes(&random_scalar().to_bytes())?
            .verifying_key()
            .to_bytes()
            .into(),
        role_hashes: std::array::from_fn(|i| [i as u8 + 1; 32]),
    };
    let policy = Policy {
        deployment: [1; 32],
        config,
        policy: [2; 32],
        native: None,
        native_cluster: None,
        bootstrap: Some(([3; 32], [4; 32])),
        single_user: None,
        receive: None,
        receive_cluster: None,
        identity: None,
        auth: None,
        ecdsa_2p: false,
        additive_receive: false,
    };
    let coin_id = [5; 32];
    let intent = Intent {
        deployment: policy.deployment,
        coin: coin_id,
        previous_state: lineage::origin_previous_state(&policy.deployment, &coin_id)?,
        operation: [6; 32],
        recipient_claim: lineage::origin_field(&policy.deployment, &coin_id, 0)?,
        revision: 1,
    };
    let request = Request::sign(intent.clone(), Command::Allocate {}, &session)?;
    let coin = Coin {
        deployment: policy.deployment,
        coin: coin_id,
        backing: [0; 32],
        state: intent.previous_state,
        capability: [0; 32],
        secret: random_scalar().to_bytes().into(),
        salt: [7; 32],
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
    let mut bootstrap = Workflow {
        purpose: PURPOSE.into(),
        registry: [3; 32],
        cluster: [4; 32],
        intent,
        session: request.session,
        server: coin.server()?.to_vec(),
        backing: [8; 32],
        capability: lineage::public_capability_commitment(
            &coin.deployment,
            &coin.coin,
            &owner.verifying_key().to_bytes().into(),
        )?,
        plan: [9; 32],
        branches: std::array::from_fn(|i| {
            let secret: Digest = k256::Scalar::from(20 + i as u64).to_bytes().into();
            Branch {
                index: i as u8,
                id: [0; 32],
                point: point_bytes(k256::ProjectivePoint::GENERATOR * scalar(&secret).unwrap())
                    .unwrap()
                    .to_vec(),
                commitment: [30 + i as u8; 32],
                secret: Some(secret),
            }
        }),
        statement: None,
        partials: None,
        stage: Stage::Prepared,
    };
    for i in 0..3 {
        bootstrap.branches[i].id = nonce_id(&bootstrap, &bootstrap.branches[i])?;
    }
    bootstrap.validate(&coin, &policy)?;
    bootstrap.validate_revision(2)?;
    Ok((coin, policy, bootstrap))
}

#[test]
fn bootstrap_three_nonces_are_frozen_to_allocation_and_registry() -> Result<()> {
    let (coin, policy, valid) = fixture()?;
    let mut changed = valid.clone();
    changed.purpose = "wrapped-recovery-v1".into();
    assert!(changed.validate(&coin, &policy).is_err());
    let mut changed = valid.clone();
    changed.registry = random32();
    assert!(changed.validate(&coin, &policy).is_err());
    let mut changed = valid.clone();
    changed.intent.operation = random32();
    assert!(changed.validate(&coin, &policy).is_err());
    assert!(valid.validate_revision(1).is_err());
    assert!(valid.validate_revision(3).is_err());
    let mut changed = valid;
    changed.branches[2].secret = changed.branches[0].secret;
    changed.branches[2].point = changed.branches[0].point.clone();
    changed.branches[2].id = nonce_id(&changed, &changed.branches[2])?;
    assert!(changed.validate(&coin, &policy).is_err());
    Ok(())
}

#[test]
fn issued_bootstrap_history_survives_private_share_refresh_without_old_secret() -> Result<()> {
    let (mut coin, policy, mut bootstrap) = fixture()?;
    let statement = BootstrapAuthorization {
        context: context(&bootstrap.intent, bootstrap.session),
        backing: bootstrap.backing,
        policy: policy.policy,
        capability: bootstrap.capability,
        plan: bootstrap.plan,
        cluster: bootstrap.cluster,
        server: coin.server()?,
        config: policy.config.clone(),
        branches: std::array::from_fn(|i| BootstrapBranch {
            server_nonce: bootstrap.branches[i].point.as_slice().try_into().unwrap(),
            challenge: k256::Scalar::from(i as u64 + 1).to_bytes().into(),
            blinding_commitment: bootstrap.branches[i].commitment,
        }),
    };
    bootstrap.partials = Some(std::array::from_fn(|i| {
        (scalar(&bootstrap.branches[i].secret.unwrap()).unwrap()
            + scalar(&statement.branches[i].challenge).unwrap() * scalar(&coin.secret).unwrap())
        .to_bytes()
        .into()
    }));
    for branch in &mut bootstrap.branches {
        branch.secret = None;
    }
    bootstrap.statement = Some(statement.encode()?);
    bootstrap.stage = Stage::Issued;
    bootstrap.validate(&coin, &policy)?;
    bootstrap.validate_revision(3)?;
    bootstrap.freeze()?;
    coin.phase = Phase::Origin;
    coin.backing = bootstrap.backing;
    coin.capability = bootstrap.capability;
    coin.pending.as_mut().unwrap().next_capability = Some(coin.capability);
    bootstrap.validate(&coin, &policy)?;
    bootstrap.validate_revision(4)?;
    // Only the historical public point remains. The current share/capability
    // may refresh after a proof-verified transfer; full Coin authority is not
    // mocked here, only bootstrap history's independent validation is tested.
    coin.secret = random_scalar().to_bytes().into();
    coin.capability = [91; 32];
    coin.owner = Some(super::super::Predecessor::Transfer);
    coin.phase = Phase::Accepted;
    coin.pending = None;
    bootstrap.validate(&coin, &policy)?;
    let mut changed = bootstrap;
    changed.partials.as_mut().unwrap()[2] = [0; 32];
    assert!(changed.validate(&coin, &policy).is_err());
    Ok(())
}
