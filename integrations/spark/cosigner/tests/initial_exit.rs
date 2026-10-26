//! Independent Bitcoin signatures over SYNTHETIC known-key transactions.
//! No funded leaf, distributed signing, chain observation or Zark proof is tested.
use anyhow::Result;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute::LockTime,
    consensus::{deserialize, serialize},
    hashes::Hash,
    key::TapTweak,
    secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    transaction::Version,
};
use frost_secp256k1_tr as frost;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zark_spark_cosigner::{
    initial_exit::{
        DepositAnchor, InitialRootLeafExitV1, NativeLeafKeys, validate_initial_root_exit,
        validate_received_root_claim_custody, validate_received_root_exit_keys,
    },
    keys::{Authority, PublicShare, Purpose, Scope},
    leaf_signing::LeafAuthority,
};

struct Fixture {
    anchor: DepositAnchor,
    authority: LeafAuthority,
    package: InitialRootLeafExitV1,
}

#[test]
fn received_claim_rejects_valid_same_window_refunds_to_an_independent_identity() -> Result<()> {
    let mut f = Fixture::new(64_000)?;
    f.package = f.mutate(1, |tx| tx.input[0].sequence = Sequence((1 << 30) | 1900))?;
    f.package = f.mutate(2, |tx| tx.input[0].sequence = Sequence((1 << 30) | 1950))?;
    let keys = |user: u8, operator: u8| {
        NativeLeafKeys::new(
            Scope {
                deployment: [1; 32],
                coin: [2; 32],
                purpose: Purpose::LeafSigning,
            },
            &public(user).serialize(),
            &public(operator).serialize(),
            &public(12).serialize(),
        )
    };
    let joint = keys(5, 7)?;
    validate_received_root_claim_custody(&f.anchor, &joint, &f.package, &f.package, 1900)?;
    for index in [1, 2] {
        // Re-sign the malicious destination. Signature validity alone must not
        // qualify either competing native refund as jointly controlled.
        let independent = f.mutate(index, |tx| tx.output[0].script_pubkey = script(6))?;
        assert!(
            validate_received_root_claim_custody(&f.anchor, &joint, &f.package, &independent, 1900)
                .is_err()
        );
    }
    let mut independent = f.mutate(1, |tx| tx.output[0].script_pubkey = script(6))?;
    independent.direct_from_cpfp_refund = f
        .mutate(2, |tx| tx.output[0].script_pubkey = script(6))?
        .direct_from_cpfp_refund;
    // Each prefix is independently authentic under the SAME root. Replacing
    // the persisted final prefix does not revoke the independent earlier one.
    validate_received_root_exit_keys(&f.anchor, &joint, &f.package, 1900)?;
    validate_received_root_exit_keys(&f.anchor, &keys(6, 6)?, &independent, 1900)?;
    assert!(
        validate_received_root_claim_custody(&f.anchor, &joint, &f.package, &independent, 1900)
            .is_err()
    );
    let mut missing = f.package.clone();
    missing.direct_from_cpfp_refund.clear();
    assert!(
        validate_received_root_claim_custody(&f.anchor, &joint, &f.package, &missing, 1900)
            .is_err()
    );
    let mut unsigned = f.package.clone();
    let mut tx: Transaction = deserialize(&unsigned.cpfp_refund)?;
    tx.input[0].witness = Witness::new();
    unsigned.cpfp_refund = serialize(&tx);
    assert!(
        validate_received_root_claim_custody(&f.anchor, &joint, &f.package, &unsigned, 1900)
            .is_err()
    );
    Ok(())
}

fn scalar(value: u8) -> [u8; 32] {
    let mut scalar = [0; 32];
    scalar[31] = value;
    scalar
}

fn public(value: u8) -> PublicKey {
    PublicKey::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&scalar(value)).unwrap(),
    )
}

// Construct valid public possession proofs for deliberately known synthetic
// scalars. This tests the validator independently of its distributed signers.
fn public_share(value: u8, position: u16) -> Result<PublicShare> {
    let key = frost::SigningKey::deserialize(&scalar(value))?;
    let scope = Scope {
        deployment: [1; 32],
        coin: [2; 32],
        purpose: Purpose::LeafSigning,
    };
    let public = frost::VerifyingKey::from(&key).serialize()?;
    let mut message = Sha256::new();
    message.update(b"ZARK/spark/regtest/key-possession/v1");
    message.update(scope.deployment);
    message.update(scope.coin);
    message.update([scope.purpose as u8]);
    message.update(position.to_be_bytes());
    message.update(&public);
    Ok(PublicShare {
        scope,
        position,
        public_key: hex::encode(public),
        proof_of_possession: hex::encode(key.sign(OsRng, &message.finalize()).serialize()?),
    })
}

fn authority(second_user: u8, operator: u8) -> Result<LeafAuthority> {
    let user = Authority::new(public_share(2, 1)?, public_share(second_user, 2)?)?;
    LeafAuthority::new(
        user,
        &public(operator).serialize(),
        &public(2 + second_user + operator).serialize(),
    )
}

fn script(value: u8) -> ScriptBuf {
    ScriptBuf::new_p2tr(&Secp256k1::new(), public(value).x_only_public_key().0, None)
}

fn anchor_output() -> TxOut {
    TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x02, 0x4e, 0x73]),
    }
}

fn transaction(
    outpoint: OutPoint,
    sequence: u32,
    value: u64,
    destination: ScriptBuf,
    anchor: bool,
) -> Transaction {
    let mut output = vec![TxOut {
        value: Amount::from_sat(value),
        script_pubkey: destination,
    }];
    if anchor {
        output.push(anchor_output());
    }
    Transaction {
        version: Version::non_standard(3),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_consensus(sequence),
            witness: Witness::new(),
        }],
        output,
    }
}

fn sign(tx: &mut Transaction, previous: &TxOut) -> Result<()> {
    let secp = Secp256k1::new();
    let key = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&scalar(12))?)
        .tap_tweak(&secp, None)
        .to_keypair();
    let sighash = SighashCache::new(&*tx).taproot_key_spend_signature_hash(
        0,
        &Prevouts::All(&[previous]),
        TapSighashType::Default,
    )?;
    let signature =
        secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash.to_byte_array()), &key);
    tx.input[0].witness = Witness::from_slice(&[signature.as_ref()]);
    Ok(())
}

impl Fixture {
    fn new(value: u64) -> Result<Self> {
        let anchor = DepositAnchor {
            outpoint: OutPoint {
                txid: Txid::from_byte_array([11; 32]),
                vout: 3,
            },
            output: TxOut {
                value: Amount::from_sat(value),
                script_pubkey: script(12),
            },
        };
        let mut root = transaction(anchor.outpoint, 1 << 30, value, script(12), true);
        sign(&mut root, &anchor.output)?;
        let outpoint = OutPoint {
            txid: root.compute_txid(),
            vout: 0,
        };
        let mut refund = transaction(outpoint, (1 << 30) | 2000, value, script(5), true);
        sign(&mut refund, &root.output[0])?;
        let mut direct = transaction(
            outpoint,
            (1 << 30) | 2050,
            if value > 955 { value - 955 } else { value },
            script(5),
            false,
        );
        sign(&mut direct, &root.output[0])?;
        Ok(Self {
            anchor,
            authority: authority(3, 7)?,
            package: InitialRootLeafExitV1::new(
                serialize(&root),
                serialize(&refund),
                serialize(&direct),
            ),
        })
    }

    fn validate(&self, package: &InitialRootLeafExitV1) -> Result<()> {
        validate_initial_root_exit(&self.anchor, &self.authority, package).map(|_| ())
    }

    fn mutate(
        &self,
        index: usize,
        change: impl FnOnce(&mut Transaction),
    ) -> Result<InitialRootLeafExitV1> {
        let mut package = self.package.clone();
        let previous = if index == 0 {
            self.anchor.output.clone()
        } else {
            deserialize::<Transaction>(&package.root_node)?.output[0].clone()
        };
        let bytes = match index {
            0 => &mut package.root_node,
            1 => &mut package.cpfp_refund,
            _ => &mut package.direct_from_cpfp_refund,
        };
        let mut tx = deserialize(bytes)?;
        change(&mut tx);
        // Re-sign layout attacks: rejection cannot merely rely on invalidated
        // signatures instead of the exact destination/value/sequence checks.
        if tx.input.len() == 1 {
            sign(&mut tx, &previous)?;
        }
        *bytes = serialize(&tx);
        Ok(package)
    }
}

#[test]
fn independent_bitcoin_fixture_preserves_bytes_and_fee_boundaries() -> Result<()> {
    for value in [500, 955, 956, 64_000] {
        let f = Fixture::new(value)?;
        let encoded = serde_json::to_vec(&f.package)?;
        let decoded = InitialRootLeafExitV1::decode(&encoded)?;
        assert_eq!(decoded, f.package);
        let checked = validate_initial_root_exit(&f.anchor, &f.authority, &decoded)?;
        assert_eq!(checked.package(), &f.package);
        assert_eq!(
            checked.payout_sats(),
            [value, if value > 955 { value - 955 } else { value }]
        );
        let root: Transaction = deserialize(&f.package.root_node)?;
        let cpfp: Transaction = deserialize(&f.package.cpfp_refund)?;
        let direct: Transaction = deserialize(&f.package.direct_from_cpfp_refund)?;
        assert_eq!(
            checked.txids(),
            [
                root.compute_txid(),
                cpfp.compute_txid(),
                direct.compute_txid()
            ]
        );
        assert_ne!(checked.digest(), [0; 32]);
    }
    Ok(())
}

#[test]
fn every_signed_transaction_field_is_restricted_to_the_initial_root_profile() -> Result<()> {
    let f = Fixture::new(64_000)?;
    for index in 0..3 {
        for attack in 0..12 {
            let package = f.mutate(index, |tx| match attack {
                0 => tx.version = Version::TWO,
                1 => tx.lock_time = LockTime::from_consensus(1),
                2 => tx.input[0].previous_output.txid = Txid::from_byte_array([12; 32]),
                3 => tx.input[0].previous_output.vout += 1,
                4 => tx.input[0].script_sig = ScriptBuf::from_bytes(vec![0x51]),
                5 => {
                    tx.input[0].sequence =
                        Sequence::from_consensus(tx.input[0].sequence.to_consensus_u32() + 1)
                }
                6 => tx.output[0].value = Amount::from_sat(tx.output[0].value.to_sat() - 1),
                7 => tx.output[0].script_pubkey = script(6),
                8 => tx.output.push(TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: script(6),
                }),
                9 => tx.input.push(tx.input[0].clone()),
                10 => {
                    tx.input[0].sequence = Sequence::from_consensus(
                        tx.input[0].sequence.to_consensus_u32() | (1 << 31),
                    )
                }
                _ => {
                    tx.input[0].sequence = Sequence::from_consensus(
                        tx.input[0].sequence.to_consensus_u32() | (1 << 22),
                    )
                }
            })?;
            assert!(
                f.validate(&package).is_err(),
                "transaction {index}, attack {attack}"
            );
        }
    }
    for index in [0, 1] {
        for attack in 0..3 {
            let package = f.mutate(index, |tx| match attack {
                0 => tx.output[1].value = Amount::from_sat(1),
                1 => tx.output[1].script_pubkey = ScriptBuf::from_bytes(vec![0x51]),
                _ => {
                    tx.output.pop();
                }
            })?;
            assert!(f.validate(&package).is_err());
        }
    }
    // Neither operator+user nor an attacker-only destination is a USER refund.
    assert!(
        f.validate(&f.mutate(1, |tx| tx.output[0].script_pubkey = script(12))?)
            .is_err()
    );
    assert!(
        f.validate(&f.mutate(2, |tx| tx.output[0].script_pubkey = script(12))?)
            .is_err()
    );
    Ok(())
}

#[test]
fn signatures_witness_modes_and_raw_encodings_fail_closed() -> Result<()> {
    let f = Fixture::new(64_000)?;
    for index in 0..3 {
        for attack in 0..7 {
            let mut package = f.package.clone();
            let bytes = match index {
                0 => &mut package.root_node,
                1 => &mut package.cpfp_refund,
                _ => &mut package.direct_from_cpfp_refund,
            };
            let mut tx: Transaction = deserialize(bytes)?;
            let signature = tx.input[0].witness.iter().next().unwrap().to_vec();
            match attack {
                0 => tx.input[0].witness = Witness::new(),
                1 => {
                    let mut signature = signature;
                    signature[0] ^= 1;
                    tx.input[0].witness = Witness::from_slice(&[signature]);
                }
                2 => {
                    let mut signature = signature;
                    signature.push(0);
                    tx.input[0].witness = Witness::from_slice(&[signature]);
                }
                3 => tx.input[0].witness = Witness::from_slice(&[signature, vec![0x50]]),
                4 => {
                    tx.input[0].witness =
                        Witness::from_slice(&[signature, vec![0x51], vec![0xc0; 33]])
                }
                _ => (),
            }
            *bytes = serialize(&tx);
            if attack == 5 {
                bytes.push(0);
            }
            if attack == 6 {
                bytes.splice(6..7, [0xfd, 1, 0]);
            }
            assert!(
                f.validate(&package).is_err(),
                "transaction {index}, witness attack {attack}"
            );
        }
    }
    Ok(())
}

#[test]
fn trusted_anchor_and_separately_expected_user_authority_are_bound() -> Result<()> {
    let f = Fixture::new(64_000)?;
    for attack in 0..5 {
        let mut anchor = f.anchor.clone();
        match attack {
            0 => anchor.outpoint.txid = Txid::from_byte_array([13; 32]),
            1 => anchor.outpoint.vout += 1,
            2 => anchor.output.value = Amount::from_sat(63_999),
            3 => anchor.output.script_pubkey = script(13),
            _ => anchor.outpoint = OutPoint::null(),
        }
        assert!(validate_initial_root_exit(&anchor, &f.authority, &f.package).is_err());
    }
    // Same combined key (2+4+6=12), different USER key: root still authentic,
    // but refunds must fail the independently supplied expected USER authority.
    let wrong_user = authority(4, 6)?;
    assert!(validate_initial_root_exit(&f.anchor, &wrong_user, &f.package).is_err());
    let wrong_combined = authority(3, 8)?;
    assert!(validate_initial_root_exit(&f.anchor, &wrong_combined, &f.package).is_err());
    Ok(())
}

#[test]
fn schema_variants_and_transaction_bounds_are_not_optional() -> Result<()> {
    let f = Fixture::new(64_000)?;
    for field in ["root_node", "cpfp_refund", "direct_from_cpfp_refund"] {
        let mut json = serde_json::to_value(&f.package)?;
        json.as_object_mut().unwrap().remove(field);
        assert!(InitialRootLeafExitV1::decode(&serde_json::to_vec(&json)?).is_err());
    }
    for field in ["direct_node", "direct_refund", "ancestors", "branches"] {
        let mut json = serde_json::to_value(&f.package)?;
        json[field] = serde_json::json!([]);
        assert!(InitialRootLeafExitV1::decode(&serde_json::to_vec(&json)?).is_err());
    }
    for attack in 0..7 {
        let mut package = f.package.clone();
        match attack {
            0 => package.version = 2,
            1 => package.schema.push_str("-other"),
            2 => package.cpfp_refund.clear(),
            3 => package.direct_from_cpfp_refund.clear(),
            4 => package.root_node = vec![0; 1025],
            5 => package.cpfp_refund = vec![0; 1025],
            _ => package.direct_from_cpfp_refund = vec![0; 1025],
        }
        assert!(f.validate(&package).is_err());
    }
    assert!(InitialRootLeafExitV1::decode(&vec![0; 16 * 1024 + 1]).is_err());
    assert!(InitialRootLeafExitV1::decode(&[]).is_err());
    assert!(InitialRootLeafExitV1::decode(&serde_json::to_vec_pretty(&f.package)?).is_err());
    Ok(())
}
