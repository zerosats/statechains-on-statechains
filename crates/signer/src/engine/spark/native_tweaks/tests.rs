//! Direct persisted-record checks only: no ownership or native proof oracle.
use super::super::state::Phase;
use super::*;
use k256::{ProjectivePoint, Scalar};
use zark_protocol::spark_lineage::Config;

#[test]
fn native_tweak_seal_requires_every_exact_operator_transcript_and_current_share() -> Result<()> {
    let session =
        zark_protocol::owner_auth::normalized_key(&zark_protocol::owner_auth::generate_secret())?;
    let coin = Coin {
        deployment: [1; 32],
        coin: [2; 32],
        backing: [3; 32],
        state: [4; 32],
        capability: [5; 32],
        secret: Scalar::from(7u64).to_bytes().into(),
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
    let cluster = zark_protocol::spark_native_vss::Cluster {
        threshold: 2,
        operators: (1u64..=2)
            .map(|i| {
                use k256::elliptic_curve::sec1::ToEncodedPoint;
                (
                    hex::encode(Scalar::from(i).to_bytes()),
                    (ProjectivePoint::GENERATOR * Scalar::from(i + 60))
                        .to_affine()
                        .to_encoded_point(true)
                        .as_bytes()
                        .to_vec(),
                )
            })
            .collect(),
    };
    let policy = Policy {
        deployment: coin.deployment,
        config: Config {
            origin_key: coin.session,
            role_hashes: std::array::from_fn(|i| [i as u8 + 1; 32]),
        },
        policy: [9; 32],
        native: None,
        native_cluster: Some(cluster.clone()),
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
        deployment: coin.deployment,
        coin: coin.coin,
        previous_state: coin.state,
        operation: [10; 32],
        recipient_claim: [11; 32],
        revision: 12,
    };
    let valid = Workflow {
        circuit: [13; 32],
        spec: CircuitSpec {
            plaintext_bytes: 64,
            scalar_offset: 8,
        },
        server: coin.server()?.to_vec(),
        slope: point_bytes(ProjectivePoint::GENERATOR * Scalar::from(17u64))?.to_vec(),
        secrets: None,
        transcripts: cluster
            .operators
            .keys()
            .map(|id| {
                (
                    id.clone(),
                    Transcript {
                        initial: [18; 32],
                        rounds: vec![([19; 32], [20; 32]); 7],
                    },
                )
            })
            .collect(),
        aborted: false,
        packet: Some([21; 32]),
    };
    valid.validate(&coin, &policy, &intent, coin.session)?;
    let mut changed = valid.clone();
    changed
        .transcripts
        .values_mut()
        .next()
        .unwrap()
        .rounds
        .pop();
    assert!(
        changed
            .validate(&coin, &policy, &intent, coin.session)
            .is_err()
    );
    let mut changed = valid.clone();
    changed.aborted = true;
    assert!(
        changed
            .validate(&coin, &policy, &intent, coin.session)
            .is_err()
    );
    let mut changed = valid.clone();
    changed.server = point_bytes(ProjectivePoint::GENERATOR * Scalar::from(23u64))?.to_vec();
    assert!(
        changed
            .validate(&coin, &policy, &intent, coin.session)
            .is_err()
    );
    let mut changed = valid;
    changed.secrets = Some(Secrets {
        slope: Scalar::from(17u64).to_bytes().into(),
        seed: [24; 32],
    });
    assert!(
        changed
            .validate(&coin, &policy, &intent, coin.session)
            .is_err()
    );
    Ok(())
}
