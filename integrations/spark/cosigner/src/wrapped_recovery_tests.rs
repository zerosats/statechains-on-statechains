use super::{RecoveryPackage, RecoveryPlan, RecoveryTarget, test_support::backing};
use crate::{
    keys::{Authority, Purpose, Scope, Share},
    user_recovery,
};
use anyhow::Result;
use bitcoin::{
    Sequence, Transaction, Witness,
    consensus::{deserialize, serialize},
    secp256k1::{PublicKey, Secp256k1, SecretKey, XOnlyPublicKey},
};
use zark_protocol::{
    handoff::{RecoveryDelay, RecoverySchedule},
    random_scalar,
};
use zeroize::Zeroizing;

fn schedule() -> RecoverySchedule {
    RecoverySchedule {
        initial: 500,
        gap: 60,
        margin: 20,
    }
}
fn payout(value: u8) -> XOnlyPublicKey {
    PublicKey::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[value; 32]).unwrap(),
    )
    .x_only_public_key()
    .0
}
fn target(revision: u64) -> RecoveryTarget {
    RecoveryTarget {
        revision,
        payout: payout((revision % 32) as u8 + 10),
        fee_sats: 500,
    }
}

fn sign(
    plan: &RecoveryPlan,
    user: &Authority,
    wallet: &Share,
    signer: &Share,
) -> Result<super::ValidatedRecovery> {
    let mut signatures = Vec::new();
    for sighash in plan.sighashes() {
        let first = user_recovery::Nonce::prepare(wallet, user)?;
        let second = user_recovery::Nonce::prepare(signer, user)?;
        let commitments = [first.commitment()?, second.commitment()?];
        let refs = [&commitments[0][..], &commitments[1][..]];
        let first = first.sign(wallet, user, sighash, refs)?;
        let second = second.sign(signer, user, sighash, refs)?;
        signatures.push(user_recovery::aggregate(
            user,
            sighash,
            refs,
            [&first, &second],
        )?);
    }
    plan.finalize(signatures.try_into().unwrap())
}

#[test]
fn masked_handover_gives_bob_earlier_exits_for_both_spark_refunds_without_rebuilding_backing()
-> Result<()> {
    let (keys, backing) = backing()?;
    let alice = keys.authority.user_authority();
    let alice_plan = RecoveryPlan::new(&backing, alice, schedule(), target(1))?;
    let old = sign(&alice_plan, alice, &keys.wallet, &keys.signer)?;
    assert_eq!(old.delay_blocks(), 500);
    assert_ne!(old.prevouts()[0], old.prevouts()[1]);
    assert_eq!(old.payout_sats(), [63_500, 62_545]);

    // Match the application's private refresh equation. No aggregate scalar is
    // reconstructed; Bob generates his own fresh key independently.
    let bob = Share::generate(keys.wallet.public().scope.clone(), 1)?;
    let bob_old_server = Authority::new(bob.public().clone(), keys.signer.public().clone())?;
    let mask = Zeroizing::new(random_scalar());
    let delta = Zeroizing::new(
        keys.wallet.additive_scalar(alice)? + *mask - bob.additive_scalar(&bob_old_server)?,
    );
    let next = Zeroizing::new(keys.signer.additive_scalar(alice)? + *delta - *mask);
    let next_bytes = Zeroizing::new(<[u8; 32]>::from(next.to_bytes()));
    let next_server = Share::from_scalar(keys.signer.public().scope.clone(), 2, &next_bytes)?;
    let bob_authority = Authority::new(bob.public().clone(), next_server.public().clone())?;
    assert_eq!(bob_authority.public_key()?, alice.public_key()?);
    assert_ne!(bob.public().public_key, keys.wallet.public().public_key);
    assert_ne!(
        next_server.public().public_key,
        keys.signer.public().public_key
    );
    let bob_plan = RecoveryPlan::new(&backing, &bob_authority, schedule(), target(2))?;
    let new = sign(&bob_plan, &bob_authority, &bob, &next_server)?;
    assert_eq!(new.delay_blocks(), 440);
    assert_eq!(new.prevouts(), old.prevouts());
    assert_ne!(new.digest(), old.digest());
    assert!(bob_plan.validate(old.package()).is_err());
    assert_eq!(bob_plan.validate(new.package())?.digest(), new.digest());
    // Old spends remain Bitcoin-valid later; they do not vanish on handover.
    // The real protocol must observe the corresponding refund's confirmation
    // and reject a handover if its authenticated safety window is exhausted.
    let old_delay = RecoveryDelay::from_sequence(old.delay_blocks())?;
    let new_delay = RecoveryDelay::from_sequence(new.delay_blocks())?;
    schedule().check_transition(old_delay, new_delay)?;
    assert!(
        schedule()
            .confirmed_transfer_window(old_delay, new_delay, 1000, 1001, 3)
            .is_ok()
    );
    assert!(
        schedule()
            .confirmed_transfer_window(old_delay, new_delay, 1000, 1490, 3)
            .is_err()
    );
    let bytes = serde_json::to_vec(new.package())?;
    assert_eq!(RecoveryPackage::decode(&bytes)?, *new.package());
    assert_eq!(backing.digest(), new.package().backing);
    Ok(())
}

#[test]
fn every_recovery_variant_transaction_field_and_policy_is_checked() -> Result<()> {
    let (keys, backing) = backing()?;
    let user = keys.authority.user_authority();
    let plan = RecoveryPlan::new(&backing, user, schedule(), target(1))?;
    let valid = sign(&plan, user, &keys.wallet, &keys.signer)?;
    for variant in 0..2 {
        for attack in 0..17 {
            let mut package = valid.package().clone();
            if attack < 5 {
                match attack {
                    0 => package.backing[0] ^= 1,
                    1 => package.policy[0] ^= 1,
                    2 => package.revision += 1,
                    3 => package.schema.push('x'),
                    _ => package.transactions[variant] = package.transactions[1 - variant].clone(),
                }
            } else {
                let mut tx: Transaction = deserialize(&package.transactions[variant])?;
                match attack {
                    5 => tx.input[0].previous_output.vout += 1,
                    6 => tx.input[0].sequence = Sequence::from_consensus((1 << 31) | 500),
                    7 => tx.input[0].sequence = Sequence::from_consensus((1 << 22) | 500),
                    8 => tx.input[0].sequence = Sequence::from_consensus(499),
                    9 => tx.output[0].value -= bitcoin::Amount::from_sat(1),
                    10 => tx.output[0].script_pubkey = bitcoin::ScriptBuf::new(),
                    11 => tx.lock_time = bitcoin::absolute::LockTime::from_consensus(1),
                    12 => tx.version = bitcoin::transaction::Version::ONE,
                    13 => tx.input.push(tx.input[0].clone()),
                    14 => {
                        let mut signature = tx.input[0].witness.iter().next().unwrap().to_vec();
                        signature.push(1);
                        tx.input[0].witness = Witness::from_slice(&[signature]);
                    }
                    15 => tx.input[0].witness.push([0]),
                    _ => tx.output.push(tx.output[0].clone()),
                }
                package.transactions[variant] = serialize(&tx);
            }
            assert!(
                plan.validate(&package).is_err(),
                "variant {variant}, attack {attack}"
            );
        }
    }
    let mut changed_policy = schedule();
    changed_policy.margin += 1;
    let different = RecoveryPlan::new(&backing, user, changed_policy, target(1))?;
    assert!(
        different.validate(valid.package()).is_err(),
        "same sequence cannot silently change policy margin"
    );
    assert!(RecoveryPackage::decode(&serde_json::to_vec_pretty(valid.package())?).is_err());
    let mut extra = serde_json::to_value(valid.package())?;
    extra["ignored_alternative"] = serde_json::json!(true);
    assert!(RecoveryPackage::decode(&serde_json::to_vec(&extra)?).is_err());
    assert!(RecoveryPackage::decode(&vec![0; 32 * 1024 + 1]).is_err());
    let mut missing_prefix = valid.package().clone();
    missing_prefix.spark_exit.root_node.clear();
    assert!(plan.validate(&missing_prefix).is_err());
    let mut changed_prefix = valid.package().clone();
    changed_prefix.spark_exit.cpfp_refund[0] ^= 1;
    assert!(plan.validate(&changed_prefix).is_err());
    Ok(())
}

#[test]
fn recovery_requires_the_authenticated_user_key_and_eight_owner_schedule() -> Result<()> {
    let (keys, backing) = backing()?;
    let user = keys.authority.user_authority();
    for revision in 1..=8 {
        let plan = RecoveryPlan::new(&backing, user, schedule(), target(revision))?;
        assert_eq!(plan.delay_blocks(), 500 - (revision as u32 - 1) * 60);
    }
    for revision in [0, 9, u64::MAX] {
        assert!(RecoveryPlan::new(&backing, user, schedule(), target(revision)).is_err());
    }
    for fee_sats in [0, 10_001, u64::MAX] {
        let target = RecoveryTarget {
            fee_sats,
            ..target(1)
        };
        assert!(RecoveryPlan::new(&backing, user, schedule(), target).is_err());
    }
    for policy in [
        RecoverySchedule {
            initial: 1,
            ..schedule()
        },
        RecoverySchedule {
            gap: 0,
            ..schedule()
        },
        RecoverySchedule {
            margin: 60,
            ..schedule()
        },
        RecoverySchedule {
            initial: 65536,
            ..schedule()
        },
    ] {
        assert!(RecoveryPlan::new(&backing, user, policy, target(1)).is_err());
    }
    for purpose in [Purpose::Identity, Purpose::LeafSigning] {
        let scope = Scope {
            purpose,
            deployment: [1; 32],
            coin: [2; 32],
        };
        let first = Share::generate(scope.clone(), 1)?;
        let second = Share::generate(scope, 2)?;
        let unrelated = Authority::new(first.public().clone(), second.public().clone())?;
        assert!(RecoveryPlan::new(&backing, &unrelated, schedule(), target(1)).is_err());
    }
    for wrong_coin in [false, true] {
        let mut scope = keys.wallet.public().scope.clone();
        if wrong_coin {
            scope.coin = [3; 32];
        } else {
            scope.deployment = [3; 32];
        }
        let first_scalar = Zeroizing::new(keys.wallet.additive_scalar(user)?);
        let second_scalar = Zeroizing::new(keys.signer.additive_scalar(user)?);
        let first = Share::from_scalar(scope.clone(), 1, &first_scalar.to_bytes().into())?;
        let second = Share::from_scalar(scope, 2, &second_scalar.to_bytes().into())?;
        let wrong_scope = Authority::new(first.public().clone(), second.public().clone())?;
        assert_eq!(wrong_scope.public_key()?, user.public_key()?);
        assert!(
            RecoveryPlan::new(&backing, &wrong_scope, schedule(), target(1)).is_err(),
            "identical Bitcoin key cannot replace the authenticated deployment/coin domain"
        );
    }
    Ok(())
}
