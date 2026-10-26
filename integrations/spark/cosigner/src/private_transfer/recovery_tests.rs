use super::backing_tests::setup;
use super::{PrivateBacking, PrivateRecovery, RecoveryParameters};
use anyhow::Result;
use k256::{ProjectivePoint, Scalar, schnorr::SigningKey};
use zark_protocol::{
    handoff::RecoverySchedule,
    point_bytes, random_scalar, scalar,
    spark_lineage::{Intent, capability_commitment},
};
use zeroize::Zeroizing;

pub(super) fn parameters(
    backing: &PrivateBacking,
    user: Scalar,
    server: [u8; 64],
) -> Result<RecoveryParameters> {
    let scope = backing.keys().scope();
    let session = SigningKey::from_bytes(&[9; 32])?;
    Ok(RecoveryParameters {
        intent: Intent {
            deployment: scope.deployment,
            coin: scope.coin,
            previous_state: [3; 32],
            operation: [4; 32],
            recipient_claim: [7; 32],
            revision: 19,
        },
        session: session.verifying_key().to_bytes().into(),
        server,
        server_salt: [15; 32],
        user: user.to_bytes().into(),
        next_capability: capability_commitment(
            &scope.deployment,
            &scope.coin,
            &SigningKey::from_bytes(&[10; 32])?.to_bytes().into(),
        )?,
        payout_secret: [12; 32],
        fee: 500,
        owner_index: 2,
        schedule: RecoverySchedule {
            initial: 500,
            gap: 60,
            margin: 20,
        },
    })
}

fn issue(draft: &PrivateRecovery, secret: Scalar, nonces: &[Scalar; 2]) -> Result<[[u8; 32]; 2]> {
    let auth = draft.authorization()?;
    Ok(std::array::from_fn(|i| {
        (nonces[i] + scalar(&auth.branches[i].challenge).unwrap() * secret)
            .to_bytes()
            .into()
    }))
}

#[test]
fn private_recovery_retains_exact_blindings_nonce_bindings_and_both_spends_across_reopen()
-> Result<()> {
    let (keys, backing) = setup()?;
    let user = Zeroizing::new(
        keys.wallet
            .additive_scalar(keys.authority.user_authority())?,
    );
    let server = Zeroizing::new(
        keys.signer
            .additive_scalar(keys.authority.user_authority())?,
    );
    let server_point = point_bytes(ProjectivePoint::GENERATOR * *server)?;
    let draft = PrivateRecovery::prepare(&backing, parameters(&backing, *user, server_point)?)?;
    let prepared = draft.encode_private()?;
    let mut reopened = PrivateRecovery::decode_private(&backing, &prepared)?;
    assert_eq!(reopened.frozen(), draft.frozen());
    assert_eq!(reopened.encode_private()?.as_slice(), prepared.as_slice());
    let nonces = Zeroizing::new([random_scalar(), random_scalar()]);
    let points = [
        point_bytes(ProjectivePoint::GENERATOR * nonces[0])?,
        point_bytes(ProjectivePoint::GENERATOR * nonces[1])?,
    ];
    let authorization = reopened.bind_nonces(points)?.encode()?;
    assert_eq!(reopened.bind_nonces(points)?.encode()?, authorization);
    let bound = reopened.encode_private()?;
    let mut resumed = PrivateRecovery::decode_private(&backing, &bound)?;
    assert_eq!(resumed.authorization()?.encode()?, authorization);
    let partials = issue(&resumed, *server, &nonces)?;
    let complete = resumed.finish(partials)?;
    let completed = resumed.encode_private()?;
    let mut recovered = PrivateRecovery::decode_private(&backing, &completed)?;
    assert_eq!(recovered.finish(partials)?.digest(), complete.digest());
    assert_eq!(recovered.encode_private()?.as_slice(), completed.as_slice());
    assert_eq!(complete.payout_sats(), [63_500, 62_545]);
    assert_eq!(complete.delay_blocks(), 440);
    assert_eq!(recovered.witness().target.owner_index, 2);
    assert_eq!(recovered.frozen().context.revision, 19);
    Ok(())
}

#[test]
fn private_recovery_rejects_nonce_or_partial_retry_substitution_without_replacing_saved_bytes()
-> Result<()> {
    let (keys, backing) = setup()?;
    let user = Zeroizing::new(
        keys.wallet
            .additive_scalar(keys.authority.user_authority())?,
    );
    let server = Zeroizing::new(
        keys.signer
            .additive_scalar(keys.authority.user_authority())?,
    );
    let mut draft = PrivateRecovery::prepare(
        &backing,
        parameters(
            &backing,
            *user,
            point_bytes(ProjectivePoint::GENERATOR * *server)?,
        )?,
    )?;
    let nonces = Zeroizing::new([random_scalar(), random_scalar()]);
    let points = [
        point_bytes(ProjectivePoint::GENERATOR * nonces[0])?,
        point_bytes(ProjectivePoint::GENERATOR * nonces[1])?,
    ];
    draft.bind_nonces(points)?;
    let bound = draft.encode_private()?;
    let mut changed = points;
    changed.swap(0, 1);
    assert!(draft.bind_nonces(changed).is_err());
    assert_eq!(draft.encode_private()?.as_slice(), bound.as_slice());
    let partials = issue(&draft, *server, &nonces)?;
    let mut wrong = partials;
    wrong.swap(0, 1);
    assert!(draft.finish(wrong).is_err());
    assert_eq!(draft.encode_private()?.as_slice(), bound.as_slice());
    draft.finish(partials)?;
    let completed = draft.encode_private()?;
    assert!(draft.finish(wrong).is_err());
    assert_eq!(draft.encode_private()?.as_slice(), completed.as_slice());
    assert!(
        PrivateRecovery::decode_private(
            &backing,
            &serde_json::to_vec_pretty(&serde_json::from_slice::<serde_json::Value>(&completed)?)?
        )
        .is_err()
    );
    Ok(())
}
