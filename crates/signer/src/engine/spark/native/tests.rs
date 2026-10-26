//! Frozen-record adversarial checks only; these are not native proof fixtures.
use super::*;
use k256::schnorr::SigningKey;
use zark_protocol::{random32, spark_lineage::Config};

fn fixture() -> Result<(Coin, Policy, Workflow)> {
    let session = SigningKey::from_bytes(&random_scalar().to_bytes())?;
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
        native: Some(([3; 32], [4; 32])),
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
    // Full Coin::validate also requires actual retained ownership issuance.
    // This local skeleton isolates Workflow's phase/nonce binding checks.
    let coin = Coin {
        deployment: policy.deployment,
        coin: [5; 32],
        backing: [6; 32],
        state: [7; 32],
        capability: [8; 32],
        secret: random_scalar().to_bytes().into(),
        salt: [9; 32],
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
    let intent = Intent {
        deployment: coin.deployment,
        coin: coin.coin,
        previous_state: coin.state,
        operation: [10; 32],
        recipient_claim: [11; 32],
        revision: 17,
    };
    let mut workflow = Workflow {
        purpose: PURPOSE.into(),
        registry: [3; 32],
        cluster: [4; 32],
        intent,
        session: coin.session,
        plan: [11; 32],
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
        contribution: None,
        tweaks: None,
        mpc: None,
        completion: None,
        observed_completion: None,
    };
    for index in 0..2 {
        workflow.branches[index].id = nonce_id(&workflow, &workflow.branches[index])?;
    }
    workflow.validate(&coin, &policy)?;
    Ok((coin, policy, workflow))
}

#[test]
fn native_registry_purpose_and_context_are_frozen_before_nonce_release() -> Result<()> {
    let (coin, policy, valid) = fixture()?;
    valid.validate_revision(18)?;
    assert!(valid.validate_revision(17).is_err());
    assert!(valid.validate_revision(19).is_err());
    let mut changed = valid.clone();
    changed.purpose = "wrapped-recovery-v1".into();
    assert!(changed.validate(&coin, &policy).is_err());
    let mut changed = valid.clone();
    changed.registry = random32();
    assert!(changed.validate(&coin, &policy).is_err());
    let mut changed = valid.clone();
    changed.session = SigningKey::from_bytes(&random_scalar().to_bytes())?
        .verifying_key()
        .to_bytes()
        .into();
    assert!(changed.validate(&coin, &policy).is_err());
    let mut changed = valid.clone();
    changed.intent.revision += 1;
    assert!(changed.validate(&coin, &policy).is_err());
    let mut disabled = policy.clone();
    disabled.native = None;
    assert!(valid.validate(&coin, &disabled).is_err());
    Ok(())
}

#[test]
fn native_opposite_nonce_and_partial_state_corruption_are_rejected() -> Result<()> {
    let (coin, policy, mut workflow) = fixture()?;
    workflow.partials = Some([[0; 32]; 2]);
    assert!(workflow.validate(&coin, &policy).is_err());
    workflow.partials = None;
    let opposite: Digest = (-scalar(&workflow.branches[0].secret.unwrap())?)
        .to_bytes()
        .into();
    workflow.branches[1].secret = Some(opposite);
    workflow.branches[1].point =
        point_bytes(k256::ProjectivePoint::GENERATOR * scalar(&opposite)?)?.to_vec();
    workflow.branches[1].id = nonce_id(&workflow, &workflow.branches[1])?;
    assert!(workflow.validate(&coin, &policy).is_err());
    Ok(())
}

#[test]
fn native_owner_preparation_auth_is_bound_to_both_blindings_and_purpose() -> Result<()> {
    let (_, _, workflow) = fixture()?;
    let owner = SigningKey::from_bytes(&random_scalar().to_bytes())?;
    let public: Digest = owner.verifying_key().to_bytes().into();
    let capability = zark_protocol::spark_lineage::public_capability_commitment(
        &workflow.intent.deployment,
        &workflow.intent.coin,
        &public,
    )?;
    let context = context(&workflow.intent, workflow.session);
    let commitments = std::array::from_fn(|i| workflow.branches[i].commitment);
    let auth = super::super::OwnerAuthorization::sign_native(
        &context,
        &workflow.plan,
        &commitments,
        &owner,
    )?;
    context.verify_owner(
        &workflow.plan,
        &commitments,
        &capability,
        &auth.public_key,
        &auth.signature.as_slice().try_into()?,
    )?;
    let mut changed = commitments;
    changed[1] = random32();
    assert!(
        context
            .verify_owner(
                &workflow.plan,
                &changed,
                &capability,
                &auth.public_key,
                &auth.signature.as_slice().try_into()?
            )
            .is_err()
    );
    let reserve =
        super::super::OwnerAuthorization::sign(&workflow.intent, &workflow.session, &owner)?;
    assert!(
        context
            .verify_owner(
                &workflow.plan,
                &commitments,
                &capability,
                &reserve.public_key,
                &reserve.signature.as_slice().try_into()?
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn retained_native_ciphertexts_require_issued_pair_and_pinned_recipients() -> Result<()> {
    // Direct record validation, deliberately not an Engine/proof acceptance test.
    let (coin, mut policy, mut workflow) = fixture()?;
    let cluster = zark_protocol::spark_native_vss::Cluster {
        threshold: 2,
        operators: (1u64..=2)
            .map(|i| {
                let id = hex::encode(k256::Scalar::from(i).to_bytes());
                let key = (k256::ProjectivePoint::GENERATOR * k256::Scalar::from(70 + i))
                    .to_affine()
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec();
                (id, key)
            })
            .collect(),
    };
    workflow.cluster = cluster.digest()?;
    policy.native = Some((workflow.registry, workflow.cluster));
    policy.native_cluster = Some(cluster.clone());
    for index in 0..2 {
        workflow.branches[index].id = nonce_id(&workflow, &workflow.branches[index])?;
    }
    let contribution = spark_native_vss::prepare(
        2,
        (-scalar(&coin.secret)?).to_bytes().into(),
        workflow.plan,
        &cluster,
    )?;
    workflow.contribution = Some(contribution);
    assert!(workflow.validate(&coin, &policy).is_err());
    let authorization = ExitAuthorization {
        context: context(&workflow.intent, workflow.session),
        backing: coin.backing,
        policy: policy.policy,
        capability: coin.capability,
        plan: workflow.plan,
        cluster: workflow.cluster,
        server: coin.server()?,
        config: policy.config.clone(),
        branches: std::array::from_fn(|i| zark_protocol::spark_native::NativeBranch {
            server_nonce: workflow.branches[i].point.as_slice().try_into().unwrap(),
            challenge: [0; 32],
            blinding_commitment: workflow.branches[i].commitment,
        }),
    };
    workflow.statement = Some(authorization.encode()?);
    workflow.partials = Some(std::array::from_fn(|i| {
        workflow.branches[i].secret.unwrap()
    }));
    for branch in &mut workflow.branches {
        branch.secret = None;
    }
    workflow.validate(&coin, &policy)?;
    workflow.validate_revision(20)?;
    assert!(workflow.validate_revision(19).is_err());
    let valid = workflow.clone();
    let completion = zark_protocol::spark_wire::NativeCompletion {
        plan: workflow.plan,
        cluster: workflow.cluster,
        packet: [90; 32],
    };
    let mut observed = valid.clone();
    observed.observed_completion = Some(ObservedCompletion {
        completion: completion.clone(),
        evidence: [91; 32],
    });
    observed.validate(&coin, &policy)?;
    observed.validate_revision(21)?;
    assert!(observed.completed() && observed.identity_scope().is_none());
    let bytes = serde_json::to_vec(&observed)?;
    let reopened: Workflow = serde_json::from_slice(&bytes)?;
    reopened.validate(&coin, &policy)?;
    assert_eq!(serde_json::to_vec(&reopened)?, bytes);
    let mut invalid = observed.clone();
    invalid.observed_completion.as_mut().unwrap().evidence = [0; 32];
    assert!(invalid.validate(&coin, &policy).is_err());
    let mut invalid = observed;
    invalid
        .observed_completion
        .as_mut()
        .unwrap()
        .completion
        .plan[0] ^= 1;
    assert!(invalid.validate(&coin, &policy).is_err());
    let attestations = (1u64..=2)
        .map(|i| {
            zark_protocol::spark_wire::NativeAttestation::sign(
                &completion,
                k256::Scalar::from(i).to_bytes().into(),
                &SigningKey::from_bytes(&k256::Scalar::from(70 + i).to_bytes())?,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let receipt = zark_protocol::spark_wire::NativeExitReceipt {
        completion: completion.clone(),
        attestations,
    };
    let mut completed = valid.clone();
    completed.completion = Some(receipt);
    completed.validate(&coin, &policy)?;
    completed.validate_revision(21)?;
    assert!(completed.validate_revision(20).is_err());
    let mut mixed = completed.clone();
    mixed.observed_completion = Some(ObservedCompletion {
        completion: completion.clone(),
        evidence: [91; 32],
    });
    assert!(mixed.validate(&coin, &policy).is_err());
    let mut invalid = completed.clone();
    invalid.contribution = None;
    assert!(invalid.validate(&coin, &policy).is_err());
    let mut invalid = completed;
    invalid.completion.as_mut().unwrap().completion.packet[0] ^= 1;
    assert!(invalid.validate(&coin, &policy).is_err());
    workflow.contribution.as_mut().unwrap().position = 1;
    assert!(workflow.validate(&coin, &policy).is_err());
    let mut disabled = policy.clone();
    disabled.native_cluster = None;
    assert!(valid.validate(&coin, &disabled).is_err());
    let mut changed = valid;
    changed
        .contribution
        .as_mut()
        .unwrap()
        .sealed_shares
        .values_mut()
        .next()
        .unwrap()[0] = 2;
    assert!(changed.validate(&coin, &policy).is_err());
    Ok(())
}

#[test]
fn external_completion_is_default_denied_and_exact_observer_permit_is_required() -> Result<()> {
    use crate::engine::Admission;
    use zark_protocol::handoff::TransferContext;
    struct Unconfigured;
    impl Admission for Unconfigured {
        fn authorize(&self, _: &TransferContext) -> Result<()> {
            Ok(())
        }
    }
    struct Permit {
        context: TransferContext,
        completion: NativeCompletion,
        evidence: Digest,
    }
    impl Admission for Permit {
        fn authorize(&self, _: &TransferContext) -> Result<()> {
            Ok(())
        }
        fn authorize_spark_native_completion(
            &self,
            context: &TransferContext,
            completion: &NativeCompletion,
            evidence: &Digest,
        ) -> Result<()> {
            ensure!(
                context == &self.context
                    && completion == &self.completion
                    && evidence == &self.evidence,
                "observer did not establish this exact native settlement"
            );
            Ok(())
        }
    }
    let (_, _, workflow) = fixture()?;
    let completion = NativeCompletion {
        plan: workflow.plan,
        cluster: workflow.cluster,
        packet: [90; 32],
    };
    let evidence = [91; 32];
    let key = SigningKey::from_bytes(&random_scalar().to_bytes())?;
    let request = Request::sign(
        workflow.intent,
        Command::NativeExitObservedComplete {
            completion: completion.clone(),
            evidence,
        },
        &key,
    )?;
    assert!(authorize_observed(&Unconfigured, &request, &completion, &evidence).is_err());
    let permit = Permit {
        context: super::super::admission_context(&request),
        completion: completion.clone(),
        evidence,
    };
    authorize_observed(&permit, &request, &completion, &evidence)?;
    let reopened = Request::decode(&request.encode()?)?;
    authorize_observed(&permit, &reopened, &completion, &evidence)?;
    let mut changed = completion.clone();
    changed.packet[0] ^= 1;
    assert!(authorize_observed(&permit, &request, &changed, &evidence).is_err());
    assert!(authorize_observed(&permit, &request, &completion, &[92; 32]).is_err());
    assert!(authorize_observed(&permit, &request, &completion, &[0; 32]).is_err());
    Ok(())
}

/// An issued two-role native pair over `plan`, for sibling addon record tests.
pub(in super::super) fn issued(
    cluster: &zark_protocol::spark_native_vss::Cluster,
    plan: impl FnOnce(&Coin) -> Result<Digest>,
) -> Result<(Coin, Policy, Workflow)> {
    let (coin, mut policy, mut workflow) = fixture()?;
    let plan = plan(&coin)?;
    workflow.plan = plan;
    workflow.intent.recipient_claim = plan;
    workflow.cluster = cluster.digest()?;
    policy.native = Some((workflow.registry, workflow.cluster));
    policy.native_cluster = Some(cluster.clone());
    for index in 0..2 {
        workflow.branches[index].id = nonce_id(&workflow, &workflow.branches[index])?;
    }
    let authorization = ExitAuthorization {
        context: context(&workflow.intent, workflow.session),
        backing: coin.backing,
        policy: policy.policy,
        capability: coin.capability,
        plan: workflow.plan,
        cluster: workflow.cluster,
        server: coin.server()?,
        config: policy.config.clone(),
        branches: std::array::from_fn(|i| zark_protocol::spark_native::NativeBranch {
            server_nonce: workflow.branches[i].point.as_slice().try_into().unwrap(),
            challenge: [0; 32],
            blinding_commitment: workflow.branches[i].commitment,
        }),
    };
    workflow.statement = Some(authorization.encode()?);
    workflow.partials = Some(std::array::from_fn(|i| {
        workflow.branches[i].secret.unwrap()
    }));
    for branch in &mut workflow.branches {
        branch.secret = None;
    }
    workflow.validate(&coin, &policy)?;
    Ok((coin, policy, workflow))
}

/// Unissued variant: the native pair is frozen but no response was released.
pub(in super::super) fn unissued(workflow: &mut Workflow) {
    workflow.statement = None;
    workflow.partials = None;
}

pub(in super::super) fn observe(workflow: &mut Workflow, packet: Digest) {
    workflow.observed_completion = Some(ObservedCompletion {
        completion: NativeCompletion {
            plan: workflow.plan,
            cluster: workflow.cluster,
            packet,
        },
        evidence: [91; 32],
    });
}
