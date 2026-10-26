//! Synthetic outpoint, independently generated USER shares and test operators.
//! No Spark RPC, Bitcoin chain or ownership proof is supplied by this fixture.
use crate::{
    initial_exit::{
        DepositAnchor, InitialRootLeafExitV1, ValidatedExitPackage, validate_initial_root_exit,
    },
    legacy_signing::{
        self,
        tests::{Fixture, fixture, operator_round},
    },
};
use anyhow::Result;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute::LockTime,
    consensus::serialize,
    hashes::Hash,
    secp256k1::{PublicKey, Secp256k1},
    sighash::{Prevouts, SighashCache, TapSighashType},
    transaction::Version,
};
use frost_secp256k1_tr as frost;
use std::collections::BTreeMap;

pub(super) fn backing() -> Result<(Fixture, ValidatedExitPackage)> {
    let keys = fixture();
    backing_with_keys(keys)
}

pub(crate) fn backing_with_keys(keys: Fixture) -> Result<(Fixture, ValidatedExitPackage)> {
    backing_for_anchor(keys, [11; 32])
}

pub(crate) fn backing_for_anchor(
    keys: Fixture,
    txid: [u8; 32],
) -> Result<(Fixture, ValidatedExitPackage)> {
    let script = |key: &[u8]| -> Result<ScriptBuf> {
        Ok(ScriptBuf::new_p2tr(
            &Secp256k1::verification_only(),
            PublicKey::from_slice(key)?.x_only_public_key().0,
            None,
        ))
    };
    let anchor = DepositAnchor {
        outpoint: OutPoint {
            txid: Txid::from_byte_array(txid),
            vout: 3,
        },
        output: TxOut {
            value: Amount::from_sat(64_000),
            script_pubkey: script(&keys.authority.combined_key()?)?,
        },
    };
    let mut root = transaction(anchor.outpoint, 1 << 30, anchor.output.clone(), true);
    sign_spark(&keys, &mut root, &anchor.output, [21; 32])?;
    let root_outpoint = OutPoint {
        txid: root.compute_txid(),
        vout: 0,
    };
    let user = script(&keys.authority.user_authority().public_key()?)?;
    let mut refund = transaction(
        root_outpoint,
        (1 << 30) | 2000,
        TxOut {
            value: anchor.output.value,
            script_pubkey: user.clone(),
        },
        true,
    );
    let mut direct = transaction(
        root_outpoint,
        (1 << 30) | 2050,
        TxOut {
            value: Amount::from_sat(64_000 - 955),
            script_pubkey: user,
        },
        false,
    );
    sign_spark(&keys, &mut refund, &root.output[0], [22; 32])?;
    sign_spark(&keys, &mut direct, &root.output[0], [23; 32])?;
    let package =
        InitialRootLeafExitV1::new(serialize(&root), serialize(&refund), serialize(&direct));
    let checked = validate_initial_root_exit(&anchor, &keys.authority, &package)?;
    Ok((keys, checked))
}

fn transaction(outpoint: OutPoint, sequence: u32, output: TxOut, anchor: bool) -> Transaction {
    let mut output = vec![output];
    if anchor {
        output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x02, 0x4e, 0x73]),
        });
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

pub(crate) fn sign_spark(
    keys: &Fixture,
    tx: &mut Transaction,
    previous: &TxOut,
    operation: [u8; 32],
) -> Result<()> {
    let sighash = SighashCache::new(&*tx)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&[previous]), TapSighashType::Default)?
        .to_byte_array();
    let session = legacy_signing::Session { operation, sighash };
    let wallet = legacy_signing::Nonce::prepare(&keys.wallet, &keys.authority, session)?;
    let signer = legacy_signing::Nonce::prepare(&keys.signer, &keys.authority, session)?;
    let commitments = [wallet.commitment().clone(), signer.commitment().clone()];
    let wallet = wallet.reveal(commitments.clone())?;
    let signer = signer.reveal(commitments.clone())?;
    let reveals = [wallet.public().clone(), signer.public().clone()];
    let (nonces, operators) = operator_round(keys);
    let transcript =
        legacy_signing::Transcript::new(&keys.authority, session, commitments, reveals, operators)?;
    let first = wallet.sign(&keys.wallet, &keys.authority, &transcript)?;
    let second = signer.sign(&keys.signer, &keys.authority, &transcript)?;
    let user = transcript.aggregate(&keys.authority, [&first, &second])?;
    let user_id = frost::Identifier::derive(b"user")?;
    let mut shares = BTreeMap::from([(
        user_id,
        frost::round2::SignatureShare::deserialize(&user.signature_share)?,
    )]);
    let combined = frost::VerifyingKey::deserialize(&keys.authority.combined_key()?)?;
    for (id, nonce) in nonces {
        let raw = &keys.operators[&id];
        let key = frost::keys::KeyPackage::new(
            id,
            *raw.signing_share(),
            *raw.verifying_share(),
            combined,
            2,
        );
        shares.insert(
            id,
            frost::round2::sign_with_tweak(transcript.signing_package(), &nonce, &key, None)?,
        );
    }
    let mut verifying = keys.public.verifying_shares().clone();
    verifying.insert(
        user_id,
        frost::keys::VerifyingShare::deserialize(&keys.authority.user_authority().public_key()?)?,
    );
    let public = frost::keys::PublicKeyPackage::new(verifying, combined, None);
    let signature =
        frost::aggregate_with_tweak(transcript.signing_package(), &shares, &public, None)?
            .serialize()?;
    tx.input[0].witness = Witness::from_slice(&[signature]);
    Ok(())
}
