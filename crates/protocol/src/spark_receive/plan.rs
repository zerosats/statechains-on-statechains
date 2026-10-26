//! Root-only native claim: both refunds pay the allocated joint USER key at
//! the current receive window. Native operators authenticate the actual claim.
use super::Digest;
use crate::{
    blind_signing::FundingKey,
    hash, point,
    spark_recovery::{BackingOpening, RecoveryContext, RefundOpening},
    spark_single_user::SigningPlan,
};
use anyhow::{Result, ensure};
use k256::Scalar;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceivePlan {
    pub salt: Digest,
    pub anchor_txid: Digest,
    pub anchor_vout: u32,
    pub amount: u64,
    pub native_delay: u32,
    pub operator: Vec<u8>,
    pub cluster: Digest,
}
impl Drop for ReceivePlan {
    fn drop(&mut self) {
        self.salt.zeroize();
    }
}
pub struct ReceiveBodies {
    pub refunds: [Vec<u8>; 2],
    pub sighashes: [Digest; 2],
    pub combined: [u8; 64],
    pub root_txid: Digest,
}
impl ReceivePlan {
    pub fn bodies(&self, user: [u8; 64]) -> Result<ReceiveBodies> {
        ensure!(
            (200..=1900).contains(&self.native_delay)
                && self.native_delay.is_multiple_of(100)
                && self.cluster != [0; 32],
            "ordinary received-root profile"
        );
        let mut p = SigningPlan {
            salt: self.salt,
            anchor_txid: self.anchor_txid,
            anchor_vout: self.anchor_vout,
            amount: self.amount,
            native_delay: self.native_delay + 100,
            operator: self.operator.clone(),
            receiver: user.to_vec(),
            variant: 0,
        };
        let first = p.bodies(user)?;
        p.variant = 1;
        let second = p.bodies(user)?;
        Ok(ReceiveBodies {
            refunds: [first.transaction, second.transaction],
            sighashes: [first.sighash, second.sighash],
            combined: first.combined,
            root_txid: first.root_txid,
        })
    }
    pub fn commitment(&self, user: [u8; 64]) -> Result<Digest> {
        let b = self.bodies(user)?;
        Ok(hash(&[
            b"ZARK/spark/receive/plan/v1",
            &b.root_txid,
            &self.amount.to_le_bytes(),
            &self.native_delay.to_le_bytes(),
            &user,
            &self.operator,
            &self.cluster,
            &hash(&[&hash(&[&b.refunds[0]])]),
            &hash(&[&hash(&[&b.refunds[1]])]),
            &self.salt,
        ]))
    }
    pub fn backing(
        &self,
        context: &RecoveryContext,
        user: [u8; 64],
        salt: Digest,
    ) -> Result<Digest> {
        let b = self.bodies(user)?;
        let opening = BackingOpening {
            salt,
            refunds: std::array::from_fn(|i| RefundOpening {
                txid: hash(&[&hash(&[&b.refunds[i]])]),
                amount: if i == 0 || self.amount <= 955 {
                    self.amount
                } else {
                    self.amount - 955
                },
            }),
        };
        opening.commitment(context, &FundingKey::new(point(&user)?, Scalar::ZERO)?)
    }
}
