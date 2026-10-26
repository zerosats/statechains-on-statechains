//! Native validation aid for the pinned Spark initial deposit root-leaf layout.
//!
//! This checks signed Bitcoin bytes, not chain confirmation, unspentness, Spark
//! ownership, Zark proofs, CPFP funding, relay policy, or recovery persistence.
//! The explicit received-root validator supports reduced refund windows.
//! Split, renewed and non-root leaves require different schemas.
use crate::keys::Scope;
use crate::leaf_signing::LeafAuthority;
use anyhow::{Context, Result, ensure};
use bitcoin::{
    OutPoint, ScriptBuf, Transaction, TxOut, Txid,
    consensus::{deserialize, serialize},
    hashes::Hash,
    secp256k1::{Message, PublicKey, Secp256k1, schnorr::Signature},
    sighash::{Prevouts, SighashCache, TapSighashType},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const SCHEMA: &str = "zark-spark-initial-root-leaf-exit";
const MAX_JSON_BYTES: usize = 16 * 1024;
const MAX_TX_BYTES: usize = 1024;
const MAX_TOTAL_TX_BYTES: usize = 3 * MAX_TX_BYTES;
const MAX_MONEY: u64 = 21_000_000 * 100_000_000;
const ZERO_SEQUENCE: u32 = 1 << 30;
const DIRECT_OFFSET: u32 = 50;
const DIRECT_FEE_SATS: u64 = 955;

mod keys;
mod received;
pub use keys::NativeLeafKeys;
pub use received::{validate_received_root_claim_custody, validate_received_root_exit_keys};

/// An external trusted Bitcoin observer must separately establish that this
/// exact prevout is confirmed on the active chain and still available. Merely
/// constructing this value or validating a package establishes neither fact.
#[derive(Clone, Debug)]
pub struct DepositAnchor {
    pub outpoint: OutPoint,
    pub output: TxOut,
}

/// Exactly the variants required for an initial zero-timelock deposit root.
/// The pinned schema deliberately has no direct node/direct refund fields:
/// accepting those here would silently admit an unmodeled competing path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitialRootLeafExitV1 {
    pub schema: String,
    pub version: u32,
    pub root_node: Vec<u8>,
    pub cpfp_refund: Vec<u8>,
    pub direct_from_cpfp_refund: Vec<u8>,
}

impl InitialRootLeafExitV1 {
    pub fn new(root_node: Vec<u8>, cpfp_refund: Vec<u8>, direct_from_cpfp_refund: Vec<u8>) -> Self {
        Self {
            schema: SCHEMA.into(),
            version: 1,
            root_node,
            cpfp_refund,
            direct_from_cpfp_refund,
        }
    }

    /// Bound before parsing; reject unknown fields and alternate JSON encodings.
    /// Bitcoin canonicality/signatures are checked by validate_initial_root_exit.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_JSON_BYTES,
            "initial exit package size"
        );
        let package: Self =
            serde_json::from_slice(bytes).context("invalid initial exit package")?;
        package.check_bounds()?;
        ensure!(
            serde_json::to_vec(&package)? == bytes,
            "noncanonical initial exit package"
        );
        Ok(package)
    }

    pub(crate) fn check_bounds(&self) -> Result<()> {
        ensure!(
            self.schema == SCHEMA && self.version == 1,
            "unsupported initial exit schema"
        );
        let transactions = [
            &self.root_node,
            &self.cpfp_refund,
            &self.direct_from_cpfp_refund,
        ];
        ensure!(
            transactions
                .iter()
                .all(|bytes| !bytes.is_empty() && bytes.len() <= MAX_TX_BYTES)
                && transactions.iter().map(|bytes| bytes.len()).sum::<usize>()
                    <= MAX_TOTAL_TX_BYTES,
            "initial exit transaction size or missing variant"
        );
        Ok(())
    }
}

/// The original signed bytes remain intact. This type records native checks
/// only, and must never substitute for a proof or trusted chain observation.
#[derive(Clone, Debug)]
pub struct ValidatedExitPackage {
    scope: Scope,
    native_keys: NativeLeafKeys,
    package: InitialRootLeafExitV1,
    digest: [u8; 32],
    txids: [Txid; 3],
    payout_sats: [u64; 2],
    native_delay: u32,
}

impl ValidatedExitPackage {
    pub(crate) fn native_keys(&self) -> &NativeLeafKeys {
        &self.native_keys
    }
    pub(crate) fn scope(&self) -> &Scope {
        &self.scope
    }
    pub fn package(&self) -> &InitialRootLeafExitV1 {
        &self.package
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Root node, CPFP refund, direct-from-CPFP refund, in that order.
    pub fn txids(&self) -> [Txid; 3] {
        self.txids
    }
    /// CPFP and direct-from-CPFP payouts, excluding external CPFP costs.
    pub fn payout_sats(&self) -> [u64; 2] {
        self.payout_sats
    }
    /// Authenticated CPFP refund window; the other refund adds 50 blocks.
    pub fn native_delay(&self) -> u32 {
        self.native_delay
    }
}

pub fn validate_initial_root_exit(
    anchor: &DepositAnchor,
    authority: &LeafAuthority,
    package: &InitialRootLeafExitV1,
) -> Result<ValidatedExitPackage> {
    let keys = NativeLeafKeys::new(
        authority.user_authority().members()[0].scope.clone(),
        &authority.user_authority().public_key()?,
        authority.operator_key(),
        &authority.combined_key()?,
    )?;
    // Preserve the original digest for callers with existing saved packages.
    validate_exit(
        anchor,
        &keys,
        package,
        b"ZARK/spark/regtest/initial-root-exit/v1",
        authority.binding()?,
        2000,
    )
}

/// Native prefix validation without exposing old holders' component keys.
/// The aggregate-only digest stays unchanged when private USER shares rotate.
/// Live backing and private ownership proofs remain separate caller duties.
pub fn validate_initial_root_exit_keys(
    anchor: &DepositAnchor,
    keys: &NativeLeafKeys,
    package: &InitialRootLeafExitV1,
) -> Result<ValidatedExitPackage> {
    validate_exit(
        anchor,
        keys,
        package,
        b"ZARK/spark/aggregate-initial-root-exit/v1",
        keys.binding(),
        2000,
    )
}

fn validate_exit(
    anchor: &DepositAnchor,
    keys: &NativeLeafKeys,
    package: &InitialRootLeafExitV1,
    domain: &[u8],
    binding: [u8; 32],
    native_delay: u32,
) -> Result<ValidatedExitPackage> {
    package.check_bounds()?;
    ensure!(
        !anchor.outpoint.is_null() && (1..=MAX_MONEY).contains(&anchor.output.value.to_sat()),
        "invalid trusted deposit anchor"
    );
    let combined_script = output_script(keys.combined_key())?;
    let user_script = output_script(keys.user_key())?;
    ensure!(
        anchor.output.script_pubkey == combined_script,
        "deposit does not fund the shared leaf authority"
    );
    let root = parse(&package.root_node)?;
    check_spend(&root, anchor.outpoint, &anchor.output, ZERO_SEQUENCE)?;
    check_outputs(&root, &combined_script, anchor.output.value.to_sat(), true)?;
    let prevout = OutPoint {
        txid: root.compute_txid(),
        vout: 0,
    };
    let refund = parse(&package.cpfp_refund)?;
    check_spend(
        &refund,
        prevout,
        &root.output[0],
        ZERO_SEQUENCE | native_delay,
    )?;
    check_outputs(&refund, &user_script, anchor.output.value.to_sat(), true)?;
    let direct = parse(&package.direct_from_cpfp_refund)?;
    check_spend(
        &direct,
        prevout,
        &root.output[0],
        ZERO_SEQUENCE | (native_delay + DIRECT_OFFSET),
    )?;
    let value = anchor.output.value.to_sat();
    // Pinned Spark common.MaybeApplyFee preserves values <= 955 exactly.
    let direct_value = if value > DIRECT_FEE_SATS {
        value - DIRECT_FEE_SATS
    } else {
        value
    };
    check_outputs(&direct, &user_script, direct_value, false)?;
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(binding);
    digest.update(serialize(&anchor.outpoint));
    digest.update(serialize(&anchor.output));
    for bytes in [
        &package.root_node,
        &package.cpfp_refund,
        &package.direct_from_cpfp_refund,
    ] {
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    Ok(ValidatedExitPackage {
        scope: keys.scope().clone(),
        native_keys: keys.clone(),
        package: package.clone(),
        digest: digest.finalize().into(),
        txids: [
            root.compute_txid(),
            refund.compute_txid(),
            direct.compute_txid(),
        ],
        payout_sats: [value, direct_value],
        native_delay,
    })
}

fn output_script(compressed_key: &[u8]) -> Result<ScriptBuf> {
    let key = PublicKey::from_slice(compressed_key)?;
    Ok(ScriptBuf::new_p2tr(
        &Secp256k1::verification_only(),
        key.x_only_public_key().0,
        None,
    ))
}

fn parse(bytes: &[u8]) -> Result<Transaction> {
    let tx: Transaction = deserialize(bytes).context("invalid initial exit Bitcoin transaction")?;
    ensure!(
        serialize(&tx) == bytes,
        "noncanonical initial exit Bitcoin transaction"
    );
    ensure!(
        tx.version.0 == 3 && tx.lock_time.to_consensus_u32() == 0 && tx.input.len() == 1,
        "unsupported initial exit transaction layout"
    );
    Ok(tx)
}

fn check_spend(
    tx: &Transaction,
    outpoint: OutPoint,
    previous: &TxOut,
    sequence: u32,
) -> Result<()> {
    let input = &tx.input[0];
    ensure!(
        input.previous_output == outpoint
            && input.script_sig.is_empty()
            && input.sequence.to_consensus_u32() == sequence,
        "initial exit input differs from pinned layout"
    );
    // No annex, script path, explicit sighash byte or partially signed variant.
    ensure!(
        input.witness.len() == 1,
        "initial exit requires one complete key-spend signature"
    );
    let bytes = input
        .witness
        .iter()
        .next()
        .context("missing initial exit signature")?;
    ensure!(
        bytes.len() == 64,
        "initial exit requires SIGHASH_DEFAULT signature"
    );
    ensure!(
        previous.script_pubkey.is_p2tr(),
        "initial exit prevout must be P2TR"
    );
    let key =
        bitcoin::secp256k1::XOnlyPublicKey::from_slice(&previous.script_pubkey.as_bytes()[2..])?;
    let sighash = SighashCache::new(tx).taproot_key_spend_signature_hash(
        0,
        &Prevouts::All(&[previous]),
        TapSighashType::Default,
    )?;
    Secp256k1::verification_only()
        .verify_schnorr(
            &Signature::from_slice(bytes)?,
            &Message::from_digest(sighash.to_byte_array()),
            &key,
        )
        .context("invalid initial exit signature")
}

fn check_outputs(tx: &Transaction, script: &ScriptBuf, value: u64, anchor: bool) -> Result<()> {
    ensure!(
        tx.output.len() == if anchor { 2 } else { 1 },
        "initial exit has unsupported output branch"
    );
    ensure!(
        tx.output[0].value.to_sat() == value && tx.output[0].script_pubkey == *script,
        "initial exit payout script or amount differs"
    );
    if anchor {
        ensure!(
            tx.output[1].value.to_sat() == 0
                && tx.output[1].script_pubkey.as_bytes() == [0x51, 0x02, 0x4e, 0x73],
            "initial exit ephemeral anchor differs"
        );
    }
    Ok(())
}
