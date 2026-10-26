//! Exact native creation namespace and three signed initial-root jobs.
use super::{Digest, VERSION};
use crate::{
    even, hash, point, point_bytes, scalar,
    spark_native::{native_compressed, native_sighash, native_taproot, native_transaction},
    tagged_hash,
};
use anyhow::{Result, ensure};
use k256::ProjectivePoint;
pub const INITIAL_DELAY: u32 = 2000;
pub struct PlanOpening {
    pub salt: Digest,
    pub signing_keyshare_id: [u8; 16],
    pub anchor_txid: Digest,
    pub anchor_vout: u32,
    pub amount: u64,
    pub operator: [u8; 64],
    pub cluster: Digest,
}
pub struct CreationBodies {
    pub root: Vec<u8>,
    pub refunds: [Vec<u8>; 2],
    pub sighashes: [Digest; 3],
}
impl PlanOpening {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.salt != [0; 32]
                && self.signing_keyshare_id != [0; 16]
                && self.anchor_txid != [0; 32]
                && self.cluster != [0; 32],
            "bootstrap private native namespace"
        );
        ensure!(
            (1..=2_100_000_000_000_000).contains(&self.amount),
            "bootstrap amount bound"
        );
        point(&self.operator)?;
        Ok(())
    }
    pub fn bodies(&self, user: [u8; 64]) -> Result<CreationBodies> {
        self.validate()?;
        let user = point(&user)?;
        let (combined, _) = native_taproot(user + point(&self.operator)?)?;
        let (internal, _) = even(user)?;
        let tweak = scalar(&tagged_hash("TapTweak", &[&point_bytes(internal)?[..32]]))?;
        let (output, _) = even(internal + ProjectivePoint::GENERATOR * tweak)?;
        let combined_x = point_bytes(combined)?[..32].try_into()?;
        let user_x = point_bytes(output)?[..32].try_into()?;
        let root = native_transaction(
            self.anchor_txid,
            self.anchor_vout,
            1 << 30,
            self.amount,
            combined_x,
            true,
        );
        let root_txid = hash(&[&hash(&[&root])]);
        let direct_amount = if self.amount > 955 {
            self.amount - 955
        } else {
            self.amount
        };
        let refunds = [
            native_transaction(
                root_txid,
                0,
                (1 << 30) | INITIAL_DELAY,
                self.amount,
                user_x,
                true,
            ),
            native_transaction(
                root_txid,
                0,
                (1 << 30) | (INITIAL_DELAY + 50),
                direct_amount,
                user_x,
                false,
            ),
        ];
        let sighashes = [
            native_sighash(
                self.anchor_txid,
                self.anchor_vout,
                self.amount,
                combined_x,
                1 << 30,
                self.amount,
                combined_x,
                true,
            ),
            native_sighash(
                root_txid,
                0,
                self.amount,
                combined_x,
                (1 << 30) | INITIAL_DELAY,
                self.amount,
                user_x,
                true,
            ),
            native_sighash(
                root_txid,
                0,
                self.amount,
                combined_x,
                (1 << 30) | (INITIAL_DELAY + 50),
                direct_amount,
                user_x,
                false,
            ),
        ];
        Ok(CreationBodies {
            root,
            refunds,
            sighashes,
        })
    }
    pub fn canonical_plan(&self, user: [u8; 64]) -> Result<Vec<u8>> {
        let bodies = self.bodies(user)?;
        let mut bytes = VERSION.to_le_bytes().to_vec();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&self.signing_keyshare_id);
        bytes.extend_from_slice(&self.anchor_txid);
        bytes.extend_from_slice(&self.anchor_vout.to_le_bytes());
        bytes.extend_from_slice(&self.amount.to_le_bytes());
        bytes.extend_from_slice(&INITIAL_DELAY.to_le_bytes());
        bytes.extend_from_slice(&native_compressed(point(&user)?)?);
        bytes.extend_from_slice(&native_compressed(point(&self.operator)?)?);
        bytes.extend_from_slice(&self.cluster);
        for tx in [&bodies.root, &bodies.refunds[0], &bodies.refunds[1]] {
            bytes.extend_from_slice(&hash(&[&hash(&[tx])]));
        }
        ensure!(bytes.len() == 266, "bootstrap canonical plan length");
        Ok(bytes)
    }
    pub fn commitment(&self, user: [u8; 64]) -> Result<Digest> {
        Ok(hash(&[
            b"ZARK/spark/native/bootstrap-plan/v1",
            &self.canonical_plan(user)?,
            &self.salt,
        ]))
    }
}
