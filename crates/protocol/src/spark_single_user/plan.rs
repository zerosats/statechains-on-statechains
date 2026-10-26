//! Fixed initial-root profile: reconstruct both authenticated old refunds and
//! the one new refund being signed. No caller-selected digest grants authority.
use super::Digest;
use crate::{
    blind_signing::FundingKey,
    hash, point, point_bytes,
    spark_native::{native_compressed, native_sighash, native_taproot, native_transaction},
};
use anyhow::{Result, ensure};
use k256::Scalar;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningPlan {
    pub salt: Digest,
    pub anchor_txid: Digest,
    pub anchor_vout: u32,
    pub amount: u64,
    pub native_delay: u32,
    pub operator: Vec<u8>,
    pub receiver: Vec<u8>,
    pub variant: u8,
}
impl Drop for SigningPlan {
    fn drop(&mut self) {
        self.salt.zeroize();
    }
}
pub struct SigningBodies {
    pub old_refunds: [Vec<u8>; 2],
    pub transaction: Vec<u8>,
    pub sighash: Digest,
    pub root_txid: Digest,
    pub combined: [u8; 64],
}
impl SigningPlan {
    pub fn bodies(&self, user: [u8; 64]) -> Result<SigningBodies> {
        ensure!(
            self.salt != [0; 32] && self.anchor_txid != [0; 32] && self.variant < 2,
            "single-USER plan domain"
        );
        ensure!(
            (1..=2_100_000_000_000_000).contains(&self.amount)
                && (200..=2000).contains(&self.native_delay)
                && self.native_delay.is_multiple_of(100),
            "single-USER initial-root profile"
        );
        let raw_user = point(&user)?;
        let combined = raw_user + point(&self.operator)?;
        let output = native_taproot(combined)?.0;
        let user_output = FundingKey::new(raw_user, Scalar::ZERO)?.output;
        let receiver = FundingKey::new(point(&self.receiver)?, Scalar::ZERO)?.output;
        let x = |p| -> Result<Digest> { Ok(point_bytes(p)?[..32].try_into()?) };
        let root = native_transaction(
            self.anchor_txid,
            self.anchor_vout,
            1 << 30,
            self.amount,
            x(output)?,
            true,
        );
        let root_txid = hash(&[&hash(&[&root])]);
        let direct = if self.amount > 955 {
            self.amount - 955
        } else {
            self.amount
        };
        let old_refunds = [
            native_transaction(
                root_txid,
                0,
                (1 << 30) | self.native_delay,
                self.amount,
                x(user_output)?,
                true,
            ),
            native_transaction(
                root_txid,
                0,
                (1 << 30) | (self.native_delay + 50),
                direct,
                x(user_output)?,
                false,
            ),
        ];
        let anchored = self.variant == 0;
        let amount = if anchored { self.amount } else { direct };
        let sequence = (1 << 30) | (self.native_delay - 100 + if anchored { 0 } else { 50 });
        let transaction =
            native_transaction(root_txid, 0, sequence, amount, x(receiver)?, anchored);
        let sighash = native_sighash(
            root_txid,
            0,
            self.amount,
            x(output)?,
            sequence,
            amount,
            x(receiver)?,
            anchored,
        );
        Ok(SigningBodies {
            old_refunds,
            transaction,
            sighash,
            root_txid,
            combined: point_bytes(combined)?,
        })
    }
    pub fn commitment(&self, user: [u8; 64]) -> Result<Digest> {
        let bodies = self.bodies(user)?;
        Ok(hash(&[
            b"ZARK/spark/single-user/plan/v1",
            &bodies.root_txid,
            &self.amount.to_le_bytes(),
            &self.native_delay.to_le_bytes(),
            &native_compressed(point(&user)?)?,
            &native_compressed(point(&self.operator)?)?,
            &native_compressed(point(&self.receiver)?)?,
            &[self.variant],
            &hash(&[&hash(&[&bodies.transaction])]),
            &self.salt,
        ]))
    }
}
