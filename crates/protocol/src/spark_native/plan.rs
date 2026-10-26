//! Fixed native root/old-refund/new-refund reconstruction. SHA plan bytes are
//! independently reproducible by Spark operators and contain no Zark context.
use super::{Digest, PROFILE_INITIAL_ROOT, VERSION};
use crate::{even, hash, point, point_bytes, reduce, scalar, tagged_hash};
use anyhow::{Result, ensure};
use k256::{ProjectivePoint, Scalar, elliptic_curve::sec1::ToEncodedPoint};

#[derive(Clone)]
pub struct PlanOpening {
    pub salt: Digest,
    pub transfer_id: [u8; 16],
    pub leaf_id: [u8; 16],
    pub expiry: u64,
    pub cluster: Digest,
    pub anchor_txid: Digest,
    pub anchor_vout: u32,
    pub amount: u64,
    pub native_delay: u32,
    pub operator: [u8; 64],
    /// Temporary post-transfer USER/mask point, distinct from refund payout.
    pub mask_user: [u8; 64],
    /// Ordinary Spark recipient identity; native refunds pay its P2TR script.
    pub receiver_identity: [u8; 33],
    /// SHA256 of the exact receiver-encrypted mask ciphertext, checked by the
    /// native operator against the packet. The proof does not establish ECIES.
    pub mask_cipher_sha256: Digest,
}
pub struct NativeBodies {
    pub root: Vec<u8>,
    pub root_txid: Digest,
    pub old_refunds: [Vec<u8>; 2],
    pub new_refunds: [Vec<u8>; 2],
    pub sighashes: [Digest; 2],
}
impl PlanOpening {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.salt != [0; 32]
                && self.transfer_id != [0; 16]
                && self.leaf_id != [0; 16]
                && self.expiry > 0
                && self.cluster != [0; 32],
            "native plan metadata"
        );
        ensure!(
            self.anchor_txid != [0; 32] && (1..=2_100_000_000_000_000).contains(&self.amount),
            "native root anchor"
        );
        ensure!(
            (200..=2000).contains(&self.native_delay) && self.native_delay.is_multiple_of(100),
            "native initial-root delay"
        );
        point(&self.operator)?;
        point(&self.mask_user)?;
        let identity = k256::PublicKey::from_sec1_bytes(&self.receiver_identity)?.to_projective();
        ensure!(
            compressed(identity)? == self.receiver_identity && self.mask_cipher_sha256 != [0; 32],
            "native receiver identity or mask cipher"
        );
        Ok(())
    }
    pub fn bodies(&self, user: [u8; 64]) -> Result<NativeBodies> {
        self.validate()?;
        let user = point(&user)?;
        let (combined, _) = taproot(user + point(&self.operator)?)?;
        let user_output = bitcoin_taproot(user)?;
        let identity = k256::PublicKey::from_sec1_bytes(&self.receiver_identity)?.to_projective();
        let destination = bitcoin_taproot(identity)?;
        let combined_x = point_bytes(combined)?[..32].try_into()?;
        let user_x = point_bytes(user_output)?[..32].try_into()?;
        let destination_x = point_bytes(destination)?[..32].try_into()?;
        let root = transaction(
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
        let old_refunds = [
            transaction(
                root_txid,
                0,
                (1 << 30) | self.native_delay,
                self.amount,
                user_x,
                true,
            ),
            transaction(
                root_txid,
                0,
                (1 << 30) | (self.native_delay + 50),
                direct_amount,
                user_x,
                false,
            ),
        ];
        let next = self.native_delay - 100;
        let new_refunds = [
            transaction(
                root_txid,
                0,
                (1 << 30) | next,
                self.amount,
                destination_x,
                true,
            ),
            transaction(
                root_txid,
                0,
                (1 << 30) | (next + 50),
                direct_amount,
                destination_x,
                false,
            ),
        ];
        let sighashes = [
            sighash(
                root_txid,
                self.amount,
                combined_x,
                (1 << 30) | next,
                self.amount,
                destination_x,
                true,
            ),
            sighash(
                root_txid,
                self.amount,
                combined_x,
                (1 << 30) | (next + 50),
                direct_amount,
                destination_x,
                false,
            ),
        ];
        Ok(NativeBodies {
            root,
            root_txid,
            old_refunds,
            new_refunds,
            sighashes,
        })
    }
    pub fn canonical_plan(&self, user: [u8; 64]) -> Result<Vec<u8>> {
        let bodies = self.bodies(user)?;
        let mut bytes = VERSION.to_le_bytes().to_vec();
        bytes.extend_from_slice(&PROFILE_INITIAL_ROOT.to_le_bytes());
        bytes.extend_from_slice(&self.transfer_id);
        bytes.extend_from_slice(&self.leaf_id);
        bytes.extend_from_slice(&self.expiry.to_le_bytes());
        bytes.extend_from_slice(&bodies.root_txid);
        bytes.extend_from_slice(&self.amount.to_le_bytes());
        bytes.extend_from_slice(&self.native_delay.to_le_bytes());
        bytes.extend_from_slice(&compressed(point(&user)?)?);
        bytes.extend_from_slice(&compressed(point(&self.operator)?)?);
        bytes.extend_from_slice(&compressed(point(&self.mask_user)?)?);
        bytes.extend_from_slice(&self.receiver_identity);
        bytes.extend_from_slice(&self.mask_cipher_sha256);
        bytes.extend_from_slice(&self.cluster);
        for tx in &bodies.new_refunds {
            bytes.extend_from_slice(&hash(&[&hash(&[tx])]));
        }
        ensure!(bytes.len() == 352, "native canonical plan length");
        Ok(bytes)
    }
    /// Operators receive this private salt alongside the canonical native plan;
    /// the blind signer receives only this commitment. Unsalted plan hashes can
    /// be enumerated by an observer who knows a candidate native transfer.
    pub fn commitment(&self, user: [u8; 64]) -> Result<Digest> {
        Ok(hash(&[
            b"ZARK/spark/native/plan/v1",
            &self.canonical_plan(user)?,
            &self.salt,
        ]))
    }
}
pub(crate) fn compressed(p: ProjectivePoint) -> Result<[u8; 33]> {
    ensure!(p != ProjectivePoint::IDENTITY, "native point at infinity");
    Ok(p.to_affine().to_encoded_point(true).as_bytes().try_into()?)
}
pub(crate) fn taproot(p: ProjectivePoint) -> Result<(ProjectivePoint, Scalar)> {
    let (internal, p_sign) = even(p)?;
    // Match the pinned Spark FROST tweak hook, including its scalar reduction.
    let tweak = reduce(tagged_hash("TapTweak", &[&point_bytes(internal)?[..32]]));
    let (output, q_sign) = even(internal + ProjectivePoint::GENERATOR * tweak)?;
    Ok((output, p_sign * q_sign))
}
fn bitcoin_taproot(p: ProjectivePoint) -> Result<ProjectivePoint> {
    let (internal, _) = even(p)?;
    let tweak = scalar(&tagged_hash("TapTweak", &[&point_bytes(internal)?[..32]]))?;
    Ok(even(internal + ProjectivePoint::GENERATOR * tweak)?.0)
}
fn outputs(amount: u64, key: Digest, anchor: bool) -> Vec<u8> {
    let mut out = amount.to_le_bytes().to_vec();
    out.extend_from_slice(&[34, 81, 32]);
    out.extend_from_slice(&key);
    if anchor {
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&[4, 81, 2, 78, 115]);
    }
    out
}
pub(crate) fn transaction(
    txid: Digest,
    vout: u32,
    sequence: u32,
    amount: u64,
    key: Digest,
    anchor: bool,
) -> Vec<u8> {
    let mut out = 3u32.to_le_bytes().to_vec();
    out.push(1);
    out.extend_from_slice(&txid);
    out.extend_from_slice(&vout.to_le_bytes());
    out.push(0);
    out.extend_from_slice(&sequence.to_le_bytes());
    out.push(if anchor { 2 } else { 1 });
    out.extend_from_slice(&outputs(amount, key, anchor));
    out.extend_from_slice(&0u32.to_le_bytes());
    out
}
fn sighash(
    txid: Digest,
    amount: u64,
    key: Digest,
    sequence: u32,
    payout_amount: u64,
    payout_key: Digest,
    anchor: bool,
) -> Digest {
    sighash_for_prevout(
        txid,
        0,
        amount,
        key,
        sequence,
        payout_amount,
        payout_key,
        anchor,
    )
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn sighash_for_prevout(
    txid: Digest,
    vout: u32,
    amount: u64,
    key: Digest,
    sequence: u32,
    payout_amount: u64,
    payout_key: Digest,
    anchor: bool,
) -> Digest {
    tagged_hash(
        "TapSighash",
        &[
            &[0, 0],
            &3u32.to_le_bytes(),
            &0u32.to_le_bytes(),
            &hash(&[&txid, &vout.to_le_bytes()]),
            &hash(&[&amount.to_le_bytes()]),
            &hash(&[&[34, 81, 32], &key]),
            &hash(&[&sequence.to_le_bytes()]),
            &hash(&[&outputs(payout_amount, payout_key, anchor)]),
            &[0, 0, 0, 0, 0],
        ],
    )
}
