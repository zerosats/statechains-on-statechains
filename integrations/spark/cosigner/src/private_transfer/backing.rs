//! Wallet-only common Spark backing; no component shares or historical server
//! points travel with this record. Native signatures and key sums are checked
//! here, while origin/lineage proofs and live chain observations remain required.
use crate::initial_exit::{
    DepositAnchor, InitialRootLeafExitV1, NativeLeafKeys, ValidatedExitPackage,
    validate_initial_root_exit_keys, validate_received_root_exit_keys,
};
use crate::keys::Scope;
use anyhow::{Result, ensure};
use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, Txid, hashes::Hash};
use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use zark_protocol::{
    blind_signing::FundingKey,
    point,
    spark_recovery::{BackingOpening, RecoveryContext, RefundOpening},
};
use zeroize::{Zeroize, Zeroizing};

const SCHEMA: &str = "zark-spark-private-backing";
const MAX_RECORD: usize = 64 * 1024;

/// Common private backing bytes given to a recipient after sender authorization.
/// No Serialize/Debug on the runtime type: explicit private export is required.
pub struct PrivateBacking {
    anchor: DepositAnchor,
    keys: NativeLeafKeys,
    checked: ValidatedExitPackage,
    salt: Zeroizing<[u8; 32]>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    version: u32,
    scope: Scope,
    anchor_txid: [u8; 32],
    anchor_vout: u32,
    anchor_amount: u64,
    anchor_script: Vec<u8>,
    user_key: Vec<u8>,
    operator_key: Vec<u8>,
    combined_key: Vec<u8>,
    prefix: InitialRootLeafExitV1,
    salt: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    received_root_delay: Option<u32>,
}
impl Drop for Record {
    fn drop(&mut self) {
        self.salt.zeroize();
    }
}

impl PrivateBacking {
    pub fn new(
        anchor: DepositAnchor,
        keys: NativeLeafKeys,
        prefix: InitialRootLeafExitV1,
        salt: [u8; 32],
    ) -> Result<Self> {
        ensure!(salt != [0; 32], "zero private Spark backing salt");
        let checked = validate_initial_root_exit_keys(&anchor, &keys, &prefix)?;
        Ok(Self {
            anchor,
            keys,
            checked,
            salt: Zeroizing::new(salt),
        })
    }

    /// Received-root layout only, with complete signed refunds. This validates
    /// native bytes, not a committed Spark claim, origin proof or live funding.
    /// Native observations and Zark admission remain separate gates.
    pub fn new_received_root(
        anchor: DepositAnchor,
        keys: NativeLeafKeys,
        prefix: InitialRootLeafExitV1,
        native_delay: u32,
        salt: [u8; 32],
    ) -> Result<Self> {
        ensure!(salt != [0; 32], "zero private Spark backing salt");
        let checked = validate_received_root_exit_keys(&anchor, &keys, &prefix, native_delay)?;
        Ok(Self {
            anchor,
            keys,
            checked,
            salt: Zeroizing::new(salt),
        })
    }

    /// This record is wallet-to-wallet material. It includes native outpoints,
    /// value, aggregate keys and the signed prefix, and never belongs on the
    /// blind signer's transport. Ingress disclosure must be evaluated separately.
    pub fn encode_private(&self) -> Result<Zeroizing<Vec<u8>>> {
        let record = Record {
            schema: SCHEMA.into(),
            version: if self.checked.native_delay() == 2000 {
                1
            } else {
                2
            },
            scope: self.keys.scope().clone(),
            anchor_txid: self.anchor.outpoint.txid.to_byte_array(),
            anchor_vout: self.anchor.outpoint.vout,
            anchor_amount: self.anchor.output.value.to_sat(),
            anchor_script: self.anchor.output.script_pubkey.as_bytes().to_vec(),
            user_key: self.keys.user_key().to_vec(),
            operator_key: self.keys.operator_key().to_vec(),
            combined_key: self.keys.combined_key().to_vec(),
            prefix: self.checked.package().clone(),
            salt: *self.salt,
            received_root_delay: (self.checked.native_delay() != 2000)
                .then_some(self.checked.native_delay()),
        };
        let encoded = Zeroizing::new(serde_json::to_vec(&record)?);
        ensure!(
            encoded.len() <= MAX_RECORD,
            "private Spark backing record size"
        );
        Ok(encoded)
    }

    /// Reopening rechecks native key relationships and every signed prefix
    /// transaction. A decoded object is not a current ownership certificate.
    pub fn decode_private(bytes: &[u8]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_RECORD,
            "private Spark backing record size"
        );
        let record: Record = serde_json::from_slice(bytes)?;
        ensure!(
            record.schema == SCHEMA
                && ((record.version == 1 && record.received_root_delay.is_none())
                    || (record.version == 2 && record.received_root_delay.is_some())),
            "private Spark backing schema"
        );
        let keys = NativeLeafKeys::new(
            record.scope.clone(),
            &record.user_key,
            &record.operator_key,
            &record.combined_key,
        )?;
        let anchor = DepositAnchor {
            outpoint: OutPoint {
                txid: Txid::from_byte_array(record.anchor_txid),
                vout: record.anchor_vout,
            },
            output: TxOut {
                value: Amount::from_sat(record.anchor_amount),
                script_pubkey: ScriptBuf::from_bytes(record.anchor_script.clone()),
            },
        };
        let value = match record.received_root_delay {
            None => Self::new(anchor, keys, record.prefix.clone(), record.salt)?,
            Some(delay) => {
                Self::new_received_root(anchor, keys, record.prefix.clone(), delay, record.salt)?
            }
        };
        ensure!(
            value.encode_private()?.as_slice() == bytes,
            "noncanonical private Spark backing"
        );
        Ok(value)
    }

    /// Stable across masked share refresh: only aggregate native keys, the two
    /// immutable refunds, the scope and the retained private salt are involved.
    pub fn opening(&self) -> BackingOpening {
        let txids = self.checked.txids();
        let amounts = self.checked.payout_sats();
        BackingOpening {
            salt: *self.salt,
            refunds: std::array::from_fn(|index| RefundOpening {
                txid: txids[index + 1].to_byte_array(),
                amount: amounts[index],
            }),
        }
    }

    /// `user` is this wallet's additive share; `server` is only the co-signer's
    /// public point. Compare raw parity before normalizing for BIP341: a sign
    /// flip could leave the refund x-only key unchanged but change the native
    /// USER-plus-operator signing authority used at exit.
    pub fn owner_key(&self, server: &[u8; 64], user: Scalar) -> Result<FundingKey> {
        ensure!(user != Scalar::ZERO, "zero private Spark user share");
        let user = Zeroizing::new(user);
        let server = point(server)?;
        let aggregate = server + ProjectivePoint::GENERATOR * *user;
        let native = k256::PublicKey::from_sec1_bytes(self.keys.user_key())?.to_projective();
        ensure!(
            aggregate == native,
            "refreshed Spark USER key or parity changed"
        );
        FundingKey::new(server, *user)
    }

    pub fn commitment(&self, context: &RecoveryContext, key: &FundingKey) -> Result<[u8; 32]> {
        ensure!(
            context.deployment == self.keys.scope().deployment
                && context.coin == self.keys.scope().coin,
            "private Spark backing context domain"
        );
        let native = k256::PublicKey::from_sec1_bytes(self.keys.user_key())?.to_projective();
        ensure!(
            key.internal == zark_protocol::even(native)?.0,
            "private Spark backing internal key differs"
        );
        let internal = bitcoin::secp256k1::PublicKey::from_slice(self.keys.user_key())?
            .x_only_public_key()
            .0;
        let script = ScriptBuf::new_p2tr(
            &bitcoin::secp256k1::Secp256k1::verification_only(),
            internal,
            None,
        );
        ensure!(
            key.xonly()?.as_slice() == &script.as_bytes()[2..],
            "private Spark backing output key differs"
        );
        self.opening().commitment(context, key)
    }

    /// Explicit disclosure to the interim native observer. The observer must
    /// obtain the opening and independently match its native transactions.
    pub fn observed_commitment(&self, context: &RecoveryContext) -> Result<[u8; 32]> {
        ensure!(
            context.deployment == self.keys.scope().deployment
                && context.coin == self.keys.scope().coin,
            "observed backing context domain"
        );
        let user = k256::PublicKey::from_sec1_bytes(self.keys.user_key())?.to_projective();
        self.opening()
            .commitment_for_public_key(context, &zark_protocol::point_bytes(user)?)
    }

    pub fn keys(&self) -> &NativeLeafKeys {
        &self.keys
    }
    pub fn anchor(&self) -> &DepositAnchor {
        &self.anchor
    }
    pub fn prefix(&self) -> &InitialRootLeafExitV1 {
        self.checked.package()
    }
    pub fn validated_exit(&self) -> &ValidatedExitPackage {
        &self.checked
    }
}
