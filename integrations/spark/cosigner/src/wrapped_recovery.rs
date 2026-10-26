//! Zark's timed Bitcoin spends above the two initial Spark refund variants.
//!
//! Native transaction checks are not ZK ownership proofs or chain observations.
//! A receiver must authenticate the backing and predecessor, check each live
//! transfer window, and durably save this package before acknowledging ownership.
use crate::{
    initial_exit::{InitialRootLeafExitV1, ValidatedExitPackage},
    keys::{Authority, Purpose, Scope},
};
use anyhow::{Result, ensure};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    absolute::LockTime,
    consensus::{deserialize, serialize},
    hashes::Hash,
    secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature},
    sighash::{Prevouts, SighashCache, TapSighashType},
    transaction::Version,
};
use serde::{Deserialize, Serialize};
use zark_protocol::{handoff::RecoverySchedule, hash};

const SCHEMA: &str = "zark-spark-wrapped-initial-recovery";
const MAX_TX_BYTES: usize = 1024;
const MAX_JSON_BYTES: usize = 32 * 1024;

/// These expectations come from the pinned policy and authenticated receiver.
#[derive(Clone, Copy)]
pub struct RecoveryTarget {
    pub revision: u64,
    pub payout: XOnlyPublicKey,
    pub fee_sats: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPackage {
    pub schema: String,
    pub version: u32,
    pub backing: [u8; 32],
    pub policy: [u8; 32],
    pub revision: u64,
    /// Retain the full signed prefix; refund-spend bytes alone cannot recover.
    pub spark_exit: InitialRootLeafExitV1,
    /// CPFP-refund spend, then direct-from-CPFP-refund spend. Both are required.
    pub transactions: [Vec<u8>; 2],
}

impl RecoveryPackage {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_JSON_BYTES,
            "wrapped recovery size"
        );
        let package: Self = serde_json::from_slice(bytes)?;
        package.bounds()?;
        ensure!(
            serde_json::to_vec(&package)? == bytes,
            "noncanonical wrapped recovery"
        );
        Ok(package)
    }

    fn bounds(&self) -> Result<()> {
        ensure!(
            self.schema == SCHEMA
                && self.version == 1
                && self.backing != [0; 32]
                && self.policy != [0; 32]
                && self.revision > 0,
            "wrapped recovery schema or domain"
        );
        ensure!(
            self.transactions
                .iter()
                .all(|tx| !tx.is_empty() && tx.len() <= MAX_TX_BYTES),
            "wrapped recovery transaction size or missing variant"
        );
        self.spark_exit.check_bounds()?;
        Ok(())
    }
}

/// Deterministic recovery transactions, checked before releasing a nonce.
pub struct RecoveryPlan {
    scope: Scope,
    backing: [u8; 32],
    policy: [u8; 32],
    revision: u64,
    spark_exit: InitialRootLeafExitV1,
    delay_blocks: u32,
    transactions: [Transaction; 2],
    sighashes: [[u8; 32]; 2],
    output_key: XOnlyPublicKey,
}

impl RecoveryPlan {
    pub fn new(
        backing: &ValidatedExitPackage,
        user: &Authority,
        schedule: RecoverySchedule,
        target: RecoveryTarget,
    ) -> Result<Self> {
        user.public_package()?;
        ensure!(
            user.members()[0].scope.purpose == Purpose::LeafSigning,
            "wrapped recovery requires leaf USER authority"
        );
        ensure!(
            &user.members()[0].scope == backing.scope(),
            "wrapped recovery deployment or coin scope differs from backing"
        );
        Self::from_user_key(backing, &user.public_key()?, schedule, target)
    }

    /// Wallet-only recovery from authenticated aggregate native keys. Historical
    /// holders' component points and proofs of possession are not required.
    pub fn from_native_backing(
        backing: &ValidatedExitPackage,
        schedule: RecoverySchedule,
        target: RecoveryTarget,
    ) -> Result<Self> {
        Self::from_user_key(backing, backing.native_keys().user_key(), schedule, target)
    }

    fn from_user_key(
        backing: &ValidatedExitPackage,
        user_key: &[u8],
        schedule: RecoverySchedule,
        target: RecoveryTarget,
    ) -> Result<Self> {
        let transfers = u32::try_from(
            target
                .revision
                .checked_sub(1)
                .ok_or_else(|| anyhow::anyhow!("zero wrapped revision"))?,
        )?;
        let delay_blocks = schedule.delay_after(transfers)?.blocks();
        ensure!(
            (1..=10_000).contains(&target.fee_sats),
            "wrapped recovery fee bound"
        );
        let internal = bitcoin::secp256k1::PublicKey::from_slice(user_key)?
            .x_only_public_key()
            .0;
        let user_script = ScriptBuf::new_p2tr(&Secp256k1::verification_only(), internal, None);
        let output_key = XOnlyPublicKey::from_slice(&user_script.as_bytes()[2..])?;
        let payout_script =
            ScriptBuf::new_p2tr(&Secp256k1::verification_only(), target.payout, None);
        let refunds: [Transaction; 2] = [
            deserialize(&backing.package().cpfp_refund)?,
            deserialize(&backing.package().direct_from_cpfp_refund)?,
        ];
        let prevouts = [refunds[0].output[0].clone(), refunds[1].output[0].clone()];
        for prevout in &prevouts {
            ensure!(
                prevout.script_pubkey == user_script,
                "Spark refund does not pay expected shared USER authority"
            );
            ensure!(
                prevout.value.to_sat() > target.fee_sats + 330,
                "wrapped recovery payout below policy"
            );
        }
        let transactions = std::array::from_fn(|index| Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: refunds[index].compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_consensus(delay_blocks),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(prevouts[index].value.to_sat() - target.fee_sats),
                script_pubkey: payout_script.clone(),
            }],
        });
        let sighashes = [
            sighash(&transactions[0], &prevouts[0])?,
            sighash(&transactions[1], &prevouts[1])?,
        ];
        let policy = hash(&[
            b"ZARK/spark/wrapped-recovery-policy/v1",
            &schedule.initial.to_be_bytes(),
            &schedule.gap.to_be_bytes(),
            &schedule.margin.to_be_bytes(),
        ]);
        Ok(Self {
            scope: backing.scope().clone(),
            backing: backing.digest(),
            policy,
            revision: target.revision,
            spark_exit: backing.package().clone(),
            delay_blocks,
            transactions,
            sighashes,
            output_key,
        })
    }

    pub fn sighashes(&self) -> [[u8; 32]; 2] {
        self.sighashes
    }

    /// Exact TapTweaked USER output key checked against both Spark refunds.
    /// A wallet-local blind signer must match this before binding challenges.
    pub fn output_key(&self) -> XOnlyPublicKey {
        self.output_key
    }

    pub(crate) fn policy_digest(&self) -> [u8; 32] {
        self.policy
    }

    pub(crate) fn scope(&self) -> &Scope {
        &self.scope
    }

    /// Relative to this variant's Spark refund confirmation, not the deposit.
    pub fn delay_blocks(&self) -> u32 {
        self.delay_blocks
    }
    pub fn unsigned_transactions(&self) -> [Vec<u8>; 2] {
        self.transactions.each_ref().map(serialize)
    }

    /// Commitment available before either party releases a signature share.
    pub fn draft_digest(&self) -> Result<[u8; 32]> {
        Ok(hash(&[
            b"ZARK/spark/wrapped-recovery-draft/v1",
            &self.backing,
            &self.policy,
            &self.revision.to_be_bytes(),
            &serde_json::to_vec(&self.unsigned_transactions())?,
        ]))
    }

    /// Verify both contributions' combined BIP341 signatures before packaging.
    pub fn finalize(&self, signatures: [Vec<u8>; 2]) -> Result<ValidatedRecovery> {
        let mut transactions = self.transactions.clone();
        for (tx, signature) in transactions.iter_mut().zip(&signatures) {
            ensure!(
                signature.len() == 64,
                "wrapped recovery requires default BIP341 signature"
            );
            tx.input[0].witness = Witness::from_slice(&[signature]);
        }
        self.validate(&RecoveryPackage {
            schema: SCHEMA.into(),
            version: 1,
            backing: self.backing,
            policy: self.policy,
            revision: self.revision,
            spark_exit: self.spark_exit.clone(),
            transactions: transactions.each_ref().map(serialize),
        })
    }

    pub fn validate(&self, package: &RecoveryPackage) -> Result<ValidatedRecovery> {
        package.bounds()?;
        ensure!(
            package.backing == self.backing
                && package.spark_exit == self.spark_exit
                && package.policy == self.policy
                && package.revision == self.revision,
            "wrapped recovery backing, policy or revision differs"
        );
        for (index, bytes) in package.transactions.iter().enumerate() {
            let mut tx: Transaction = deserialize(bytes)?;
            ensure!(
                serialize(&tx) == *bytes && tx.input.len() == 1,
                "noncanonical wrapped recovery transaction"
            );
            let witness = &tx.input[0].witness;
            ensure!(
                witness.len() == 1,
                "wrapped recovery must be a single key-path spend"
            );
            let signature = witness
                .iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("recovery signature missing"))?;
            ensure!(
                signature.len() == 64,
                "wrapped recovery sighash mode differs"
            );
            Secp256k1::verification_only().verify_schnorr(
                &Signature::from_slice(signature)?,
                &Message::from_digest(self.sighashes[index]),
                &self.output_key,
            )?;
            tx.input[0].witness = Witness::new();
            // Comparing the complete unsigned transaction rejects every alternate
            // input, destination, amount, fee, lock time, sequence and version.
            ensure!(
                serialize(&tx) == serialize(&self.transactions[index]),
                "wrapped recovery transaction differs from authorized plan"
            );
        }
        Ok(ValidatedRecovery {
            package: package.clone(),
            digest: hash(&[
                b"ZARK/spark/wrapped-initial-recovery/v1",
                &serde_json::to_vec(package)?,
            ]),
            delay_blocks: self.delay_blocks,
            prevouts: self
                .transactions
                .each_ref()
                .map(|tx| tx.input[0].previous_output),
            payout_sats: self
                .transactions
                .each_ref()
                .map(|tx| tx.output[0].value.to_sat()),
        })
    }
}

/// Native checks only. This does not prove ownership, chain state or durability.
pub struct ValidatedRecovery {
    package: RecoveryPackage,
    digest: [u8; 32],
    delay_blocks: u32,
    prevouts: [OutPoint; 2],
    payout_sats: [u64; 2],
}
impl ValidatedRecovery {
    pub fn package(&self) -> &RecoveryPackage {
        &self.package
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn delay_blocks(&self) -> u32 {
        self.delay_blocks
    }
    pub fn prevouts(&self) -> [OutPoint; 2] {
        self.prevouts
    }
    pub fn payout_sats(&self) -> [u64; 2] {
        self.payout_sats
    }
}

fn sighash(tx: &Transaction, previous: &TxOut) -> Result<[u8; 32]> {
    Ok(SighashCache::new(tx)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&[previous]), TapSighashType::Default)?
        .to_byte_array())
}

#[cfg(test)]
#[path = "wrapped_recovery_test_support.rs"]
pub(crate) mod test_support;
#[cfg(test)]
#[path = "wrapped_recovery_tests.rs"]
mod tests;
