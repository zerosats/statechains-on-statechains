//! Wallet-local reuse of Zark's blinded Schnorr construction for Spark refunds.
//!
//! The signing transcript contains a salted context commitment, public nonces
//! and blinded challenges. Backing transactions, payouts and sighashes remain
//! local. This is cryptographic plumbing, not proof authorization: a production
//! signer must authenticate the complete two-variant relation and durably freeze
//! these challenges before consuming either nonce. Do not route this request to
//! the clear-message `user_recovery` signing API.
//! Field absence here does not establish end-to-end signer blindness: native
//! ingress services or a shared process may separately learn the aggregate USER
//! key. Their disclosure and correlation boundaries require separate review.
use crate::{
    keys::{Authority, Purpose, Share},
    wrapped_recovery::{RecoveryPlan, ValidatedRecovery},
};
use anyhow::{Result, ensure};
use k256::ProjectivePoint;
use serde::{Deserialize, Serialize};
use zark_protocol::blind_signing::{Blinding, FundingKey, SigningSession};
use zark_protocol::spark_recovery::{
    BackingOpening, NonceOpening, RecoveryAuthorization, RecoveryContext, RecoveryWitness,
    TargetOpening, recovery_sighash,
};
use zark_protocol::{hash, point, random32, scalar};
use zeroize::Zeroizing;

/// Fixed ordering matches `RecoveryPlan`: CPFP, then direct-from-CPFP refund.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefundVariant {
    Cpfp,
    DirectFromCpfp,
}
const VARIANTS: [RefundVariant; 2] = [RefundVariant::Cpfp, RefundVariant::DirectFromCpfp];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindNonce {
    pub context: [u8; 32],
    pub variant: RefundVariant,
    pub nonce_id: [u8; 32],
    /// Canonical Zark affine x || y, never a secret nonce scalar.
    pub point: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindChallenge {
    pub nonce: BlindNonce,
    pub challenge: [u8; 32],
}

/// Signer-visible data only. No ownership authority follows from this record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindRecoveryRequest {
    pub context: [u8; 32],
    pub variants: [BlindChallenge; 2],
}

impl BlindRecoveryRequest {
    pub fn digest(&self) -> Result<[u8; 32]> {
        validate_nonces(self.context, &self.variants.each_ref().map(|v| &v.nonce))?;
        for variant in &self.variants {
            scalar(&variant.challenge)?;
        }
        Ok(hash(&[
            b"ZARK/spark/blind-recovery-request/v1",
            &self.context,
            &self.variants[0].nonce.nonce_id,
            &self.variants[0].nonce.point,
            &self.variants[0].challenge,
            &self.variants[1].nonce.nonce_id,
            &self.variants[1].nonce.point,
            &self.variants[1].challenge,
        ]))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindRecoveryResponse {
    pub request: [u8; 32],
    /// Same fixed variant order as the request; both are required.
    pub partials: [[u8; 32]; 2],
}

/// Private wallet commitment opening. No Clone or serialization: a fresh binding
/// is created before requesting distinct signer nonces, then consumed once.
pub struct WalletBinding {
    context: [u8; 32],
    plan: [u8; 32],
    authority: Vec<u8>,
    _salt: Zeroizing<[u8; 32]>,
    blindings: [Blinding; 2],
    nonce_salts: Zeroizing<[[u8; 32]; 2]>,
    proof: Option<(FrozenRecovery, RecoveryWitness)>,
}

/// Public commitments frozen before the signer releases either nonce. This is
/// still not authorization: the authenticated signer state and pinned proof
/// must establish these commitments' meaning before signing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenRecovery {
    pub context: RecoveryContext,
    pub backing: [u8; 32],
    pub recovery: [u8; 32],
    pub policy: [u8; 32],
    pub server: [u8; 64],
    pub nonce_commitments: [[u8; 32]; 2],
}

impl WalletBinding {
    pub fn new(
        plan: &RecoveryPlan,
        authority: &Authority,
        owner_state: [u8; 32],
        operation: [u8; 32],
    ) -> Result<Self> {
        authority.public_package()?;
        ensure!(
            authority.members()[0].scope == *plan.scope(),
            "blind recovery authority differs from authenticated backing scope"
        );
        ensure!(
            owner_state != [0; 32] && operation != [0; 32],
            "empty recovery state or operation"
        );
        ensure!(
            authority.members()[0].scope.purpose == Purpose::LeafSigning,
            "blind recovery requires leaf USER authority"
        );
        let plan = plan.draft_digest()?;
        let authority = serde_json::to_vec(authority)?;
        let salt = Zeroizing::new(random32());
        let blindings = [Blinding::default(), Blinding::default()];
        let nonce_salts = Zeroizing::new([random32(), random32()]);
        let context = hash(&[
            b"ZARK/spark/blind-recovery-context/v1",
            &salt[..],
            &owner_state,
            &operation,
            &plan,
            &authority,
            &blindings[0].alpha.to_bytes(),
            &blindings[0].beta.to_bytes(),
            &nonce_salts[0],
            &blindings[1].alpha.to_bytes(),
            &blindings[1].beta.to_bytes(),
            &nonce_salts[1],
        ]);
        Ok(Self {
            context,
            plan,
            authority,
            _salt: salt,
            blindings,
            nonce_salts,
            proof: None,
        })
    }

    /// Construct prover material entirely inside the wallet and freeze both
    /// canonical blinding commitments before requesting signer nonces. Target
    /// payout is the actual TapTweaked destination output key (even lift), not
    /// the internal payout key accepted by `RecoveryTarget`.
    pub fn for_proof(
        plan: &RecoveryPlan,
        wallet: &Share,
        authority: &Authority,
        context: RecoveryContext,
        backing: BackingOpening,
        target: TargetOpening,
    ) -> Result<Self> {
        context.encode()?;
        ensure!(
            wallet.public().position == 1,
            "proof preparation is wallet-local"
        );
        ensure!(
            wallet.public().scope.deployment == context.deployment
                && wallet.public().scope.coin == context.coin,
            "proof context differs from USER scope"
        );
        let mut binding = Self::new(plan, authority, context.previous_state, context.operation)?;
        let user = Zeroizing::new(wallet.additive_scalar(authority)?);
        let server =
            k256::PublicKey::from_sec1_bytes(&hex::decode(&authority.members()[1].public_key)?)?
                .to_projective();
        let key = FundingKey::new(server, *user)?;
        ensure!(
            key.xonly()? == plan.output_key().serialize(),
            "proof USER output key differs"
        );
        let native_policy = hash(&[
            b"ZARK/spark/wrapped-recovery-policy/v1",
            &target.initial.to_be_bytes(),
            &target.gap.to_be_bytes(),
            &target.margin.to_be_bytes(),
        ]);
        ensure!(
            native_policy == plan.policy_digest(),
            "proof recovery policy differs from native plan"
        );
        let messages = plan.sighashes();
        for (refund, message) in backing.refunds.iter().zip(messages) {
            ensure!(
                recovery_sighash(refund, key.xonly()?, &target)? == message,
                "proof recovery differs from native plan"
            );
        }
        let backing_commitment = backing.commitment(&context, &key)?;
        let recovery = target.commitment(&context, &backing_commitment)?;
        let policy = target.policy()?;
        let nonces = std::array::from_fn(|index| NonceOpening {
            alpha: binding.blindings[index].alpha.to_bytes().into(),
            beta: binding.blindings[index].beta.to_bytes().into(),
            salt: binding.nonce_salts[index],
        });
        let frozen = FrozenRecovery {
            context: context.clone(),
            backing: backing_commitment,
            recovery,
            policy,
            server: zark_protocol::point_bytes(server)?,
            nonce_commitments: [
                nonces[0].commitment(&context, &backing_commitment, &recovery, 0)?,
                nonces[1].commitment(&context, &backing_commitment, &recovery, 1)?,
            ],
        };
        binding.proof = Some((
            frozen,
            RecoveryWitness {
                user: user.to_bytes().into(),
                backing,
                target,
                nonces,
            },
        ));
        Ok(binding)
    }

    pub fn frozen_recovery(&self) -> Result<&FrozenRecovery> {
        self.proof
            .as_ref()
            .map(|p| &p.0)
            .ok_or_else(|| anyhow::anyhow!("no canonical proof binding"))
    }

    pub fn commitment(&self) -> [u8; 32] {
        self.context
    }
}

/// Holds only wallet material. It never accepts or reconstructs a server share.
pub struct WalletSession {
    binding: WalletBinding,
    key: FundingKey,
    server: ProjectivePoint,
    nonces: [ProjectivePoint; 2],
    blindings: [Blinding; 2],
    sessions: [SigningSession; 2],
    request: BlindRecoveryRequest,
}

impl WalletSession {
    pub fn prepare(
        binding: WalletBinding,
        plan: &RecoveryPlan,
        wallet: &Share,
        authority: &Authority,
        nonces: [BlindNonce; 2],
    ) -> Result<Self> {
        ensure!(
            binding.plan == plan.draft_digest()?
                && binding.authority == serde_json::to_vec(authority)?,
            "recovery binding substituted"
        );
        ensure!(
            wallet.public().position == 1,
            "blind recovery is wallet-local"
        );
        let owner = Zeroizing::new(wallet.additive_scalar(authority)?);
        let server =
            k256::PublicKey::from_sec1_bytes(&hex::decode(&authority.members()[1].public_key)?)?
                .to_projective();
        let key = FundingKey::new(server, *owner)?;
        // FundingKey includes both internal-key and output-key parity signs and
        // the exact TapTweak. Checking only the untweaked USER x coordinate would
        // miss a different native output key.
        ensure!(
            key.xonly()? == plan.output_key().serialize(),
            "blind recovery USER output key differs"
        );
        let points = validate_nonces(binding.context, &nonces.each_ref())?;
        let blindings = [
            Blinding {
                alpha: binding.blindings[0].alpha,
                beta: binding.blindings[0].beta,
            },
            Blinding {
                alpha: binding.blindings[1].alpha,
                beta: binding.blindings[1].beta,
            },
        ];
        let messages = plan.sighashes();
        let sessions = [
            blindings[0].bind(&key, server, points[0], messages[0])?,
            blindings[1].bind(&key, server, points[1], messages[1])?,
        ];
        let variants = std::array::from_fn(|index| BlindChallenge {
            nonce: nonces[index].clone(),
            challenge: sessions[index].challenge.to_bytes().into(),
        });
        let request = BlindRecoveryRequest {
            context: binding.context,
            variants,
        };
        request.digest()?;
        Ok(Self {
            binding,
            key,
            server,
            nonces: points,
            blindings,
            sessions,
            request,
        })
    }

    /// Retain these exact bytes for retries; do not regenerate blinding for an
    /// already issued nonce. Durable wallet integration is a separate gate.
    pub fn request(&self) -> &BlindRecoveryRequest {
        &self.request
    }

    /// Take private prover material once. Save/export it only through a private
    /// wallet prover path; neither this witness nor its TOML belongs on a signer
    /// transport. The returned authorization alone is public.
    pub fn take_proof_material(&mut self) -> Result<(RecoveryAuthorization, RecoveryWitness)> {
        let (frozen, witness) = self
            .binding
            .proof
            .take()
            .ok_or_else(|| anyhow::anyhow!("missing or already taken proof witness"))?;
        let (authorization, witness) = witness.authorize(
            frozen.context.clone(),
            frozen.server,
            [
                zark_protocol::point_bytes(self.nonces[0])?,
                zark_protocol::point_bytes(self.nonces[1])?,
            ],
        )?;
        ensure!(
            authorization.backing == frozen.backing
                && authorization.recovery == frozen.recovery
                && authorization.policy == frozen.policy,
            "proof commitments changed after nonce release"
        );
        for index in 0..2 {
            ensure!(
                authorization.branches[index].challenge == self.request.variants[index].challenge
                    && authorization.branches[index].nonce_commitment
                        == frozen.nonce_commitments[index],
                "proof branch differs from frozen signing session"
            );
        }
        Ok((authorization, witness))
    }

    /// Consuming completion prevents a second message from using these local
    /// blinding witnesses. Both independently verified spends finalize together.
    pub fn finish(
        self,
        plan: &RecoveryPlan,
        response: &BlindRecoveryResponse,
    ) -> Result<ValidatedRecovery> {
        ensure!(
            self.binding.plan == plan.draft_digest()?,
            "recovery plan substituted at completion"
        );
        ensure!(
            response.request == self.request.digest()?,
            "blind recovery response transcript differs"
        );
        let mut signatures = Vec::with_capacity(2);
        for index in 0..2 {
            let partial = Zeroizing::new(scalar(&response.partials[index])?);
            signatures.push(
                self.blindings[index]
                    .finish(
                        &self.key,
                        &self.sessions[index],
                        self.server,
                        self.nonces[index],
                        *partial,
                    )?
                    .to_vec(),
            );
        }
        plan.finalize(
            signatures
                .try_into()
                .map_err(|_| anyhow::anyhow!("missing recovery variant"))?,
        )
    }
}

fn validate_nonces(context: [u8; 32], nonces: &[&BlindNonce; 2]) -> Result<[ProjectivePoint; 2]> {
    ensure!(context != [0; 32], "empty blind recovery context");
    for (index, nonce) in nonces.iter().enumerate() {
        ensure!(
            nonce.context == context
                && nonce.variant == VARIANTS[index]
                && nonce.nonce_id != [0; 32],
            "recovery nonce context, role or identity differs"
        );
    }
    ensure!(
        nonces[0].nonce_id != nonces[1].nonce_id,
        "repeated recovery nonce identity"
    );
    let points = [point(&nonces[0].point)?, point(&nonces[1].point)?];
    ensure!(
        points[0] != points[1] && points[0] != -points[1],
        "related recovery nonces"
    );
    Ok(points)
}

#[cfg(test)]
#[path = "blind_recovery_tests.rs"]
mod tests;
