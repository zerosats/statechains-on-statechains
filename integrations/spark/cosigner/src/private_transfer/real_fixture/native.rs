//! Signed synthetic native prefix only. The actual engine's server secret is
//! never read. A known fixture combined key signs the prefix; its derived
//! operator PUBLIC key is not a live Spark operator allocation or native claim.
use super::super::PrivateBacking;
use crate::{
    initial_exit::{DepositAnchor, InitialRootLeafExitV1, NativeLeafKeys},
    keys::{Purpose, Scope},
};
use anyhow::{Result, ensure};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute::LockTime,
    consensus::serialize,
    hashes::Hash,
    key::TapTweak,
    secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    transaction::Version,
};
use k256::{ProjectivePoint, Scalar, elliptic_curve::sec1::ToEncodedPoint};
use zark_protocol::{point, random32};

pub(super) fn backing(
    deployment: [u8; 32],
    coin: [u8; 32],
    wallet: Scalar,
    server: [u8; 64],
) -> Result<PrivateBacking> {
    backing_at_delay(deployment, coin, wallet, server, 2000)
}

pub(super) fn backing_at_delay(
    deployment: [u8; 32],
    coin: [u8; 32],
    wallet: Scalar,
    server: [u8; 64],
    native_delay: u32,
) -> Result<PrivateBacking> {
    ensure!(
        native_delay == 2000 || native_delay == 1900,
        "isolated synthetic native window"
    );
    let user = point(&server)? + ProjectivePoint::GENERATOR * wallet;
    ensure!(
        user != ProjectivePoint::IDENTITY,
        "synthetic native USER at infinity"
    );
    let secp = Secp256k1::new();
    let mut combined_secret = SecretKey::from_slice(&[77; 32])?;
    let combined = PublicKey::from_secret_key(&secp, &combined_secret).serialize();
    let combined_point = k256::PublicKey::from_sec1_bytes(&combined)?.to_projective();
    let operator = combined_point - user;
    ensure!(
        operator != ProjectivePoint::IDENTITY,
        "synthetic native operator at infinity"
    );
    let user = user.to_affine().to_encoded_point(true);
    let operator = operator.to_affine().to_encoded_point(true);
    let keys = NativeLeafKeys::new(
        Scope {
            deployment,
            coin,
            purpose: Purpose::LeafSigning,
        },
        user.as_bytes(),
        operator.as_bytes(),
        &combined,
    )?;
    let script = |key: &[u8]| -> Result<ScriptBuf> {
        Ok(ScriptBuf::new_p2tr(
            &secp,
            PublicKey::from_slice(key)?.x_only_public_key().0,
            None,
        ))
    };
    let anchor = DepositAnchor {
        outpoint: OutPoint {
            txid: Txid::from_byte_array(random32()),
            vout: 3,
        },
        output: TxOut {
            value: Amount::from_sat(64_000),
            script_pubkey: script(&combined)?,
        },
    };
    let sign = |tx: &mut Transaction, previous: &TxOut| -> Result<()> {
        let digest = SighashCache::new(&*tx)
            .taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(&[previous]),
                TapSighashType::Default,
            )?
            .to_byte_array();
        let key = Keypair::from_secret_key(&secp, &combined_secret)
            .tap_tweak(&secp, None)
            .to_keypair();
        tx.input[0].witness = Witness::from_slice(&[secp
            .sign_schnorr_no_aux_rand(&Message::from_digest(digest), &key)
            .serialize()]);
        Ok(())
    };
    let mut root = transaction(anchor.outpoint, 1 << 30, anchor.output.clone(), true);
    sign(&mut root, &anchor.output)?;
    let outpoint = OutPoint {
        txid: root.compute_txid(),
        vout: 0,
    };
    let mut refund = transaction(
        outpoint,
        (1 << 30) | native_delay,
        TxOut {
            value: Amount::from_sat(64_000),
            script_pubkey: script(user.as_bytes())?,
        },
        true,
    );
    sign(&mut refund, &root.output[0])?;
    let mut direct = transaction(
        outpoint,
        (1 << 30) | (native_delay + 50),
        TxOut {
            value: Amount::from_sat(63_045),
            script_pubkey: script(user.as_bytes())?,
        },
        false,
    );
    sign(&mut direct, &root.output[0])?;
    let prefix =
        InitialRootLeafExitV1::new(serialize(&root), serialize(&refund), serialize(&direct));
    combined_secret.non_secure_erase();
    if native_delay == 2000 {
        PrivateBacking::new(anchor, keys, prefix, random32())
    } else {
        PrivateBacking::new_received_root(anchor, keys, prefix, native_delay, random32())
    }
}
fn transaction(
    previous_output: OutPoint,
    sequence: u32,
    output: TxOut,
    anchor: bool,
) -> Transaction {
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
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_consensus(sequence),
            witness: Witness::new(),
        }],
        output,
    }
}
