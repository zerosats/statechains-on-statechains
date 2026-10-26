//! Test-only signed native evidence. Direct witnesses are omitted by Spark's
//! RPC interceptor; the local observer supplies the exact signed transaction.
use super::bytes;
use crate::initial_exit::InitialRootLeafExitV1;
use anyhow::{Result, ensure};
use bitcoin::{
    Transaction,
    consensus::{deserialize, serialize},
};
use serde_json::Value;

pub(super) fn checked(
    callback: &Value,
    observed: &Value,
    receiver: &[u8],
) -> Result<InitialRootLeafExitV1> {
    let leaf = &callback["leaves"][0];
    ensure!(
        observed["operators_agreed"] == 3
            && observed["transfer_id"] == callback["transfer_id"]
            && observed["leaf_id"] == leaf["node"]["id"]
            && bytes(observed, "receiver")? == receiver,
        "intermediate observer context differs"
    );
    let prefix = InitialRootLeafExitV1::new(
        bytes(observed, "root")?,
        bytes(observed, "cpfp_refund")?,
        bytes(observed, "direct_from_cpfp_refund")?,
    );
    ensure!(
        prefix.root_node == bytes(leaf, "node_raw")?
            && prefix.cpfp_refund == bytes(leaf, "refund_raw")?,
        "signed intermediate root/refund differs from SDK"
    );
    let direct: Transaction =
        serde_json::from_value(leaf["node"]["direct_from_cpfp_refund_tx"].clone())?;
    let signed: Transaction = deserialize(&prefix.direct_from_cpfp_refund)?;
    ensure!(
        same_body(&direct, &signed),
        "signed intermediate direct refund body differs from SDK"
    );
    // This is only a body/context binding. The caller MUST still verify all
    // signatures, destinations, amounts and native delays before using it.
    Ok(prefix)
}

fn same_body(a: &Transaction, b: &Transaction) -> bool {
    let without_witness = |tx: &Transaction| {
        let mut tx = tx.clone();
        for input in &mut tx.input {
            input.witness.clear();
        }
        serialize(&tx)
    };
    without_witness(a) == without_witness(b)
}

#[test]
fn stripped_direct_evidence_binds_every_nonwitness_byte() {
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness, absolute, transaction,
    };
    let tx = Transaction {
        version: transaction::Version(3),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence(1950),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(63045),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    let mut signed = tx.clone();
    signed.input[0].witness.push([7; 64]);
    assert!(same_body(&tx, &signed));
    for change in 0..5 {
        let mut substituted = signed.clone();
        match change {
            0 => substituted.input[0].sequence = Sequence(1900),
            1 => substituted.input[0].previous_output.vout = 1,
            2 => substituted.output[0].value = Amount::from_sat(63044),
            3 => substituted.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x51]),
            _ => substituted.lock_time = absolute::LockTime::from_consensus(1),
        }
        assert!(!same_body(&tx, &substituted));
    }
}
