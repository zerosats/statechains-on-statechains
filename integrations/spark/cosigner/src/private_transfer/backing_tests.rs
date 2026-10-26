use super::PrivateBacking;
use crate::{
    initial_exit::NativeLeafKeys,
    legacy_signing::tests::{Fixture, fixture},
    wrapped_recovery::test_support::backing_with_keys,
};
use anyhow::Result;
use k256::{ProjectivePoint, Scalar};
use zark_protocol::{
    blind_signing::FundingKey, point_bytes, random_scalar, spark_recovery::RecoveryContext,
};
use zeroize::Zeroizing;

pub(super) fn setup() -> Result<(Fixture, PrivateBacking)> {
    let (keys, backing) = backing_with_keys(fixture())?;
    let native = NativeLeafKeys::new(
        keys.wallet.public().scope.clone(),
        &keys.authority.user_authority().public_key()?,
        &keys.public.verifying_key().serialize()?,
        &keys.authority.combined_key()?,
    )?;
    let prefix = backing.package().clone();
    // The root helper's signed prefix spends this isolated synthetic anchor.
    let root: bitcoin::Transaction = bitcoin::consensus::deserialize(&prefix.root_node)?;
    let anchor = crate::initial_exit::DepositAnchor {
        outpoint: root.input[0].previous_output,
        output: root.output[0].clone(),
    };
    Ok((keys, PrivateBacking::new(anchor, native, prefix, [31; 32])?))
}

fn context() -> RecoveryContext {
    RecoveryContext {
        deployment: [1; 32],
        coin: [2; 32],
        previous_state: [3; 32],
        operation: [4; 32],
        session: [5; 32],
        successor_state: [6; 32],
        revision: 19,
    }
}

#[test]
fn stable_private_backing_survives_masked_owner_refresh_without_historical_share_keys() -> Result<()>
{
    let (keys, backing) = setup()?;
    let original_user = Zeroizing::new(
        keys.wallet
            .additive_scalar(keys.authority.user_authority())?,
    );
    let server = k256::PublicKey::from_sec1_bytes(&hex::decode(&keys.signer.public().public_key)?)?
        .to_projective();
    let alice_key = backing.owner_key(&point_bytes(server)?, *original_user)?;
    let original = backing.commitment(&context(), &alice_key)?;
    assert_eq!(backing.observed_commitment(&context())?, original);
    let bytes = backing.encode_private()?;
    let reopened = PrivateBacking::decode_private(&bytes)?;
    assert_eq!(reopened.encode_private()?.as_slice(), bytes.as_slice());
    let fields = serde_json::from_slice::<serde_json::Value>(&bytes)?;
    assert!(fields.get("server").is_none() && fields.get("authority").is_none());
    assert!(fields.get("user_share").is_none() && fields.get("members").is_none());

    // Distinct party views: sender knows old user + mask; receiver knows masked
    // user and its fresh user; signer knows mask and delta. No wallet API accepts
    // the signer's secret scalar, and no aggregate secret is reconstructed.
    let mask = Zeroizing::new(random_scalar());
    let masked = Zeroizing::new(*original_user + *mask);
    let bob = Zeroizing::new(random_scalar());
    let delta = Zeroizing::new(*masked - *bob);
    let bob_server = server + ProjectivePoint::GENERATOR * (*delta - *mask);
    let bob_key = reopened.owner_key(&point_bytes(bob_server)?, *bob)?;
    assert_eq!(bob_key.xonly()?, alice_key.xonly()?);
    assert_eq!(reopened.commitment(&context(), &bob_key)?, original);
    assert_eq!(reopened.encode_private()?.as_slice(), bytes.as_slice());
    Ok(())
}

#[test]
fn native_backing_rejects_key_parity_substitution_and_wrong_proof_opening() -> Result<()> {
    let (keys, backing) = setup()?;
    let user = Zeroizing::new(
        keys.wallet
            .additive_scalar(keys.authority.user_authority())?,
    );
    let aggregate = k256::PublicKey::from_sec1_bytes(backing.keys().user_key())?.to_projective();
    let flipped_server = -aggregate - ProjectivePoint::GENERATOR * *user;
    assert!(
        backing
            .owner_key(&point_bytes(flipped_server)?, *user)
            .is_err()
    );
    let unrelated = FundingKey::new(
        ProjectivePoint::GENERATOR * Scalar::from(13u64),
        Scalar::from(7u64),
    )?;
    assert!(backing.commitment(&context(), &unrelated).is_err());
    let server = k256::PublicKey::from_sec1_bytes(&hex::decode(&keys.signer.public().public_key)?)?
        .to_projective();
    let key = backing.owner_key(&point_bytes(server)?, *user)?;
    let mut changed = context();
    changed.coin[0] ^= 1;
    assert!(backing.commitment(&changed, &key).is_err());
    Ok(())
}

#[test]
fn reopening_rechecks_native_signatures_anchor_and_canonical_private_bytes() -> Result<()> {
    let (_, backing) = setup()?;
    let encoded = backing.encode_private()?;
    for attack in 0..5 {
        let mut value: serde_json::Value = serde_json::from_slice(&encoded)?;
        match attack {
            0 => value["anchor_amount"] = serde_json::json!(63_999),
            1 => value["anchor_vout"] = serde_json::json!(4),
            2 => value["prefix"]["cpfp_refund"][0] = serde_json::json!(255),
            3 => {
                let byte = value["combined_key"][1].as_u64().unwrap();
                value["combined_key"][1] = serde_json::json!(byte ^ 1);
            }
            _ => value["ignored"] = serde_json::json!(true),
        }
        assert!(
            PrivateBacking::decode_private(&serde_json::to_vec(&value)?).is_err(),
            "attack {attack}"
        );
    }
    assert!(
        PrivateBacking::decode_private(&serde_json::to_vec_pretty(&serde_json::from_slice::<
            serde_json::Value,
        >(&encoded)?)?)
        .is_err()
    );
    Ok(())
}
