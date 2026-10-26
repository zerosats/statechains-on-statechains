//! Versioned dual-refund blinded recovery relation for Spark-backed Zark.
//!
//! This primitive proves neither native exit-prefix validity, live backing nor
//! ownership/lineage. Its backing opening must additionally be authenticated by
//! those composed roles. It is not a replacement for ReceiverAuthorization.
use crate::{
    application_hash,
    blind_signing::{Blinding, FundingKey},
    hash, point, point_bytes, scalar, tagged_hash,
};
use anyhow::{Result, ensure};
use k256::Scalar;
use zeroize::{Zeroize, Zeroizing};
mod verifier;
mod witness;
pub use verifier::{PinnedRecoveryVerifier, VerifiedRecoveryRelation};
pub use witness::RecoveryWitness;
#[cfg(test)]
mod tests;

pub const VERSION: u32 = 1;
pub const ENCODED_LEN: usize = 620;
pub const PUBLIC_FIELDS: usize = 20;
const MAX_MONEY: u64 = 2_100_000_000_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryContext {
    pub deployment: [u8; 32],
    pub coin: [u8; 32],
    pub previous_state: [u8; 32],
    pub operation: [u8; 32],
    pub session: [u8; 32],
    /// Pre-issuance draft commitment, not the final certificate's issued state.
    /// Ownership roles bind this draft before both partials exist; their final
    /// state separately commits to the authorization and both actual responses.
    pub successor_state: [u8; 32],
    /// Public engine/CAS revision. This is not the private recovery owner slot.
    pub revision: u64,
}
impl RecoveryContext {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = VERSION.to_le_bytes().to_vec();
        for value in [
            &self.deployment,
            &self.coin,
            &self.previous_state,
            &self.operation,
            &self.session,
            &self.successor_state,
        ] {
            ensure!(*value != [0; 32], "zero Spark recovery context");
            out.extend_from_slice(value);
        }
        out.extend_from_slice(&self.revision.to_le_bytes());
        Ok(out)
    }
}

pub struct RefundOpening {
    pub txid: [u8; 32],
    pub amount: u64,
}
pub struct BackingOpening {
    pub salt: [u8; 32],
    pub refunds: [RefundOpening; 2],
}
pub struct TargetOpening {
    pub salt: [u8; 32],
    /// Even affine lift of the destination's actual P2TR output key. This is
    /// already tweaked: interpreting it as an internal key would sign a
    /// different payout script from the native recovery transaction.
    pub payout: [u8; 64],
    pub fee: u64,
    pub delay: u32,
    /// Private schedule slot; must never be copied into the public CAS revision.
    pub owner_index: u32,
    pub initial: u32,
    pub gap: u32,
    pub margin: u32,
}
pub struct NonceOpening {
    pub alpha: [u8; 32],
    pub beta: [u8; 32],
    pub salt: [u8; 32],
}
impl Drop for NonceOpening {
    fn drop(&mut self) {
        self.alpha.zeroize();
        self.beta.zeroize();
        self.salt.zeroize();
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchAuthorization {
    pub server_nonce: [u8; 64],
    pub challenge: [u8; 32],
    pub nonce_commitment: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryAuthorization {
    pub context: RecoveryContext,
    pub backing: [u8; 32],
    pub recovery: [u8; 32],
    pub policy: [u8; 32],
    pub server: [u8; 64],
    pub branches: [BranchAuthorization; 2],
}
impl RecoveryAuthorization {
    /// Rejects unknown versions and any encoding the canonical encoder changes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == ENCODED_LEN, "Spark recovery encoding length");
        let read = |offset: usize| -> [u8; 32] {
            bytes[offset..offset + 32]
                .try_into()
                .expect("checked statement size")
        };
        let context = RecoveryContext {
            deployment: read(4),
            coin: read(36),
            previous_state: read(68),
            operation: read(100),
            session: read(132),
            successor_state: read(164),
            revision: u64::from_le_bytes(bytes[292..300].try_into()?),
        };
        let value = Self {
            context,
            backing: read(196),
            recovery: read(228),
            policy: read(260),
            server: bytes[300..364].try_into()?,
            branches: std::array::from_fn(|i| {
                let offset = 364 + i * 128;
                BranchAuthorization {
                    server_nonce: bytes[offset..offset + 64]
                        .try_into()
                        .expect("checked statement size"),
                    challenge: read(offset + 64),
                    nonce_commitment: read(offset + 96),
                }
            }),
        };
        ensure!(
            value.encode()? == bytes,
            "noncanonical Spark recovery statement"
        );
        Ok(value)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let context = self.context.encode()?;
        let mut out = context[..196].to_vec();
        for value in [&self.backing, &self.recovery, &self.policy] {
            ensure!(*value != [0; 32], "zero Spark recovery commitment");
            out.extend_from_slice(value);
        }
        out.extend_from_slice(&context[196..]);
        point(&self.server)?;
        out.extend_from_slice(&self.server);
        ensure!(
            self.branches[0].server_nonce[..32] != self.branches[1].server_nonce[..32],
            "reused Spark nonce up to sign"
        );
        ensure!(
            self.branches[0].nonce_commitment != self.branches[1].nonce_commitment,
            "reused Spark blinding commitment"
        );
        for branch in &self.branches {
            point(&branch.server_nonce)?;
            scalar(&branch.challenge)?;
            ensure!(
                branch.nonce_commitment != [0; 32],
                "zero Spark nonce commitment"
            );
            out.extend_from_slice(&branch.server_nonce);
            out.extend_from_slice(&branch.challenge);
            out.extend_from_slice(&branch.nonce_commitment);
        }
        ensure!(out.len() == ENCODED_LEN, "Spark recovery encoding length");
        Ok(out)
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(application_hash::hash(&[
            b"ZARK/spark/private-recovery/signing/v1",
            &self.encode()?,
        ]))
    }
}

impl BackingOpening {
    /// Commits both refunds in fixed CPFP/direct-from-CPFP order, output index 0.
    /// Does not assert either refund was created by an authenticated native leaf.
    pub fn commitment(&self, context: &RecoveryContext, key: &FundingKey) -> Result<[u8; 32]> {
        self.commitment_keys(context, &key.xonly()?, &point_bytes(key.internal)?[..32])
    }

    /// Interim disclosed-backing observers can authenticate the opening using
    /// the aggregate public USER key, without either party's secret share.
    pub fn commitment_for_public_key(
        &self,
        context: &RecoveryContext,
        user: &[u8; 64],
    ) -> Result<[u8; 32]> {
        let (internal, _) = crate::even(point(user)?)?;
        let internal_bytes = point_bytes(internal)?;
        let tweak = scalar(&tagged_hash("TapTweak", &[&internal_bytes[..32]]))?;
        let (output, _) = crate::even(internal + k256::ProjectivePoint::GENERATOR * tweak)?;
        let output = point_bytes(output)?;
        self.commitment_keys(context, output[..32].try_into()?, &internal_bytes[..32])
    }

    fn commitment_keys(
        &self,
        context: &RecoveryContext,
        output: &[u8; 32],
        internal: &[u8],
    ) -> Result<[u8; 32]> {
        context.encode()?;
        ensure!(self.salt != [0; 32], "zero Spark backing salt");
        ensure!(
            self.refunds[0].txid != self.refunds[1].txid,
            "duplicate Spark refund"
        );
        let mut bytes = Vec::new();
        for refund in &self.refunds {
            ensure!(
                refund.txid != [0; 32] && (1..=MAX_MONEY).contains(&refund.amount),
                "Spark refund opening"
            );
            bytes.extend_from_slice(&refund.txid);
            bytes.extend_from_slice(&refund.amount.to_le_bytes());
        }
        Ok(application_hash::hash(&[
            b"ZARK/spark/private-recovery/backing/v1",
            &VERSION.to_le_bytes(),
            &context.deployment,
            &context.coin,
            &self.salt,
            &bytes,
            output,
            internal,
        ]))
    }
}
impl TargetOpening {
    pub fn policy(&self) -> Result<[u8; 32]> {
        crate::handoff::RecoverySchedule {
            initial: self.initial,
            gap: self.gap,
            margin: self.margin,
        }
        .validate()?;
        Ok(application_hash::hash(&[
            b"ZARK/spark/private-recovery/policy/v1",
            &VERSION.to_le_bytes(),
            &self.initial.to_le_bytes(),
            &self.gap.to_le_bytes(),
            &self.margin.to_le_bytes(),
            &8u32.to_le_bytes(),
        ]))
    }
    pub fn commitment(&self, context: &RecoveryContext, backing: &[u8; 32]) -> Result<[u8; 32]> {
        context.encode()?;
        self.policy()?;
        ensure!(
            (1..=8).contains(&self.owner_index),
            "Spark private owner bound"
        );
        ensure!(self.salt != [0; 32], "zero Spark recovery salt");
        let p = point(&self.payout)?;
        let p = point_bytes(p)?;
        ensure!(p[63] & 1 == 0, "Spark payout parity");
        ensure!((1..=10000).contains(&self.fee), "Spark recovery fee");
        ensure!(
            self.delay == self.initial - (self.owner_index - 1) * self.gap,
            "Spark exact recovery schedule"
        );
        Ok(application_hash::hash(&[
            b"ZARK/spark/private-recovery/target/v1",
            &context.encode()?,
            backing,
            &self.salt,
            &p[..32],
            &self.fee.to_le_bytes(),
            &self.delay.to_le_bytes(),
        ]))
    }
}
impl NonceOpening {
    pub fn commitment(
        &self,
        context: &RecoveryContext,
        backing: &[u8; 32],
        recovery: &[u8; 32],
        index: u32,
    ) -> Result<[u8; 32]> {
        ensure!(index < 2 && self.salt != [0; 32], "Spark nonce opening");
        ensure!(
            !bool::from(scalar(&self.alpha)?.is_zero())
                && !bool::from(scalar(&self.beta)?.is_zero()),
            "zero Spark blinding"
        );
        Ok(application_hash::hash(&[
            b"ZARK/spark/private-recovery/nonce/v1",
            &context.encode()?,
            backing,
            recovery,
            &index.to_le_bytes(),
            &self.alpha,
            &self.beta,
            &self.salt,
        ]))
    }
}

/// Exact BIP341 SIGHASH_DEFAULT for the fixed version-2, one-input/output spend.
/// The refund txid is consensus/wire little-endian, not displayed txid order.
pub fn recovery_sighash(
    refund: &RefundOpening,
    output: [u8; 32],
    target: &TargetOpening,
) -> Result<[u8; 32]> {
    ensure!(
        (1..=10000).contains(&target.fee) && (1..=65535).contains(&target.delay),
        "Spark recovery transaction bounds"
    );
    let destination = point_bytes(point(&target.payout)?)?;
    ensure!(destination[63] & 1 == 0, "Spark payout parity");
    ensure!(
        refund.amount <= MAX_MONEY && refund.amount > target.fee.saturating_add(330),
        "Spark recovery payout below policy"
    );
    let mut script = vec![34, 81, 32];
    script.extend_from_slice(&output);
    let mut pay = vec![34, 81, 32];
    pay.extend_from_slice(&target.payout[..32]);
    Ok(tagged_hash(
        "TapSighash",
        &[
            &[0, 0],
            &2u32.to_le_bytes(),
            &0u32.to_le_bytes(),
            &hash(&[&refund.txid, &0u32.to_le_bytes()]),
            &hash(&[&refund.amount.to_le_bytes()]),
            &hash(&[&script]),
            &hash(&[&target.delay.to_le_bytes()]),
            &hash(&[&(refund.amount - target.fee).to_le_bytes(), &pay]),
            &[0, 0, 0, 0, 0],
        ],
    ))
}

impl RecoveryWitness {
    pub fn authorize(
        self,
        context: RecoveryContext,
        server: [u8; 64],
        nonces: [[u8; 64]; 2],
    ) -> Result<(RecoveryAuthorization, Self)> {
        context.encode()?;
        let owner = Zeroizing::new(scalar(&self.user)?);
        ensure!(*owner != Scalar::ZERO, "zero Spark owner");
        let server_point = point(&server)?;
        let key = FundingKey::new(server_point, *owner)?;
        let backing = self.backing.commitment(&context, &key)?;
        let recovery = self.target.commitment(&context, &backing)?;
        let policy = self.target.policy()?;
        ensure!(
            self.nonces[0].alpha != self.nonces[1].alpha
                && self.nonces[0].beta != self.nonces[1].beta
                && self.nonces[0].salt != self.nonces[1].salt,
            "reused Spark blinding randomness"
        );
        let mut branches = Vec::new();
        for (i, server_nonce) in nonces.into_iter().enumerate() {
            let b = &self.nonces[i];
            let blinding = Blinding {
                alpha: scalar(&b.alpha)?,
                beta: scalar(&b.beta)?,
            };
            let session = blinding.bind(
                &key,
                server_point,
                point(&server_nonce)?,
                recovery_sighash(&self.backing.refunds[i], key.xonly()?, &self.target)?,
            )?;
            branches.push(BranchAuthorization {
                server_nonce,
                challenge: session.challenge.to_bytes().into(),
                nonce_commitment: b.commitment(&context, &backing, &recovery, i as u32)?,
            });
        }
        let authorization = RecoveryAuthorization {
            context,
            backing,
            recovery,
            policy,
            server,
            branches: branches
                .try_into()
                .map_err(|_| anyhow::anyhow!("Spark branch count"))?,
        };
        authorization.encode()?;
        Ok((authorization, self))
    }
}
