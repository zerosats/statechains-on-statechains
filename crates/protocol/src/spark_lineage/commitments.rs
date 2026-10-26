//! Fresh Spark ownership commitment domains. Inputs are canonical bytes.
use super::{Digest, Intent, Issuance, domain, nonzero};
use crate::{
    application_hash, owner_auth, point, scalar,
    spark_recovery::{RecoveryContext, TargetOpening},
};
use anyhow::{Result, ensure};

fn digest(parts: &[&[u8]]) -> Digest {
    application_hash::hash(parts)
}
pub fn origin_previous_state(deployment: &Digest, coin: &Digest) -> Result<Digest> {
    Ok(digest(&[
        b"ZARK/spark/ownership/origin-predecessor/v1",
        &domain(deployment, coin)?,
    ]))
}
pub fn origin_field(deployment: &Digest, coin: &Digest, index: u32) -> Result<Digest> {
    ensure!(index < 6, "Spark origin sentinel index");
    Ok(digest(&[
        b"ZARK/spark/ownership/origin-field/v1",
        &domain(deployment, coin)?,
        &index.to_le_bytes(),
    ]))
}
pub fn public_capability_commitment(
    deployment: &Digest,
    coin: &Digest,
    key: &Digest,
) -> Result<Digest> {
    k256::schnorr::VerifyingKey::from_bytes(key)?;
    Ok(digest(&[
        b"ZARK/spark/ownership/capability/v1",
        &domain(deployment, coin)?,
        key,
    ]))
}
pub fn capability_commitment(
    deployment: &Digest,
    coin: &Digest,
    secret: &Digest,
) -> Result<Digest> {
    let key = owner_auth::normalized_key(secret)?;
    public_capability_commitment(deployment, coin, &key.verifying_key().to_bytes().into())
}
pub fn server_commitment(
    deployment: &Digest,
    coin: &Digest,
    server: &[u8; 64],
    salt: &Digest,
) -> Result<Digest> {
    point(server)?;
    nonzero(salt)?;
    Ok(digest(&[
        b"ZARK/spark/ownership/server/v1",
        &domain(deployment, coin)?,
        server,
        salt,
    ]))
}
pub fn recipient_claim_commitment(
    deployment: &Digest,
    coin: &Digest,
    operation: &Digest,
    key: &Digest,
    salt: &Digest,
) -> Result<Digest> {
    nonzero(operation)?;
    nonzero(salt)?;
    k256::schnorr::VerifyingKey::from_bytes(key)?;
    Ok(digest(&[
        b"ZARK/spark/ownership/recipient/v1",
        &domain(deployment, coin)?,
        operation,
        key,
        salt,
    ]))
}
fn hidden_scalar(
    tag: &[u8],
    binding: &[u8],
    value: &Digest,
    salt: &Digest,
    required: bool,
) -> Result<Digest> {
    scalar(value)?;
    nonzero(salt)?;
    if required {
        nonzero(value)?;
    }
    Ok(digest(&[tag, binding, value, salt]))
}
pub fn mask_commitment(intent: &Intent, value: &Digest, salt: &Digest) -> Result<Digest> {
    hidden_scalar(
        b"ZARK/spark/ownership/mask/v1",
        &intent.digest()?,
        value,
        salt,
        true,
    )
}
pub fn masked_share_commitment(intent: &Intent, value: &Digest, salt: &Digest) -> Result<Digest> {
    hidden_scalar(
        b"ZARK/spark/ownership/masked/v1",
        &intent.digest()?,
        value,
        salt,
        true,
    )
}
pub fn delta_commitment(
    context: &RecoveryContext,
    value: &Digest,
    salt: &Digest,
) -> Result<Digest> {
    hidden_scalar(
        b"ZARK/spark/ownership/delta/v1",
        &context.encode()?,
        value,
        salt,
        false,
    )
}
pub fn draft_token_commitment(intent: &Intent, token: &Digest) -> Result<Digest> {
    nonzero(token)?;
    Ok(digest(&[
        b"ZARK/spark/ownership/draft-token/v1",
        &intent.encode()?,
        token,
    ]))
}
pub fn bridge_commitment(
    intent: &Intent,
    backing: &Digest,
    delay: u32,
    policy: &Digest,
    salt: &Digest,
) -> Result<Digest> {
    for value in [backing, policy, salt] {
        nonzero(value)?;
    }
    ensure!(
        (1..=65535).contains(&delay),
        "Spark predecessor recovery delay"
    );
    Ok(digest(&[
        b"ZARK/spark/ownership/bridge/v1",
        &intent.digest()?,
        backing,
        &delay.to_le_bytes(),
        policy,
        salt,
    ]))
}
// Keep the canonical preimage components explicit beside their Noir counterpart.
#[allow(clippy::too_many_arguments)]
pub fn state_commitment(
    deployment: &Digest,
    coin: &Digest,
    backing: &Digest,
    capability: &Digest,
    recovery: &Digest,
    server: &Digest,
    policy: &Digest,
    issuance: &Digest,
) -> Result<Digest> {
    for value in [backing, capability, recovery, server, policy, issuance] {
        nonzero(value)?;
    }
    Ok(digest(&[
        b"ZARK/spark/ownership/state/v1",
        &domain(deployment, coin)?,
        backing,
        capability,
        recovery,
        server,
        policy,
        issuance,
    ]))
}
/// Pre-issuance draft commitment, distinct from the final state containing both
/// signer responses. Omitting its own field avoids a circular hash dependency.
pub fn draft_state_commitment(
    context: &RecoveryContext,
    backing: &Digest,
    next_capability: &Digest,
    server: &Digest,
    policy: &Digest,
    target: &TargetOpening,
) -> Result<Digest> {
    let ctx = context.encode()?;
    target.commitment(context, backing)?;
    for value in [backing, next_capability, server, policy] {
        nonzero(value)?;
    }
    Ok(digest(&[
        b"ZARK/spark/ownership/draft-state/v1",
        &ctx[..164],
        &context.revision.to_le_bytes(),
        backing,
        next_capability,
        server,
        policy,
        &target.salt,
        &target.payout[..32],
        &target.fee.to_le_bytes(),
        &target.delay.to_le_bytes(),
    ]))
}
/// Exact shared recovery scope without its draft field. Useful for intent links.
pub fn require_intent(issuance: &Issuance, intent: &Intent) -> Result<()> {
    let ctx = &issuance.recovery.context;
    intent.encode()?;
    ctx.encode()?;
    ensure!(
        ctx.deployment == intent.deployment
            && ctx.coin == intent.coin
            && ctx.previous_state == intent.previous_state
            && ctx.operation == intent.operation
            && ctx.revision == intent.revision
            && issuance.recipient_claim == intent.recipient_claim,
        "Spark issuance intent mismatch"
    );
    Ok(())
}

impl Intent {
    pub fn owner_reservation_message(&self, session: &Digest) -> Result<Digest> {
        k256::schnorr::VerifyingKey::from_bytes(session)?;
        Ok(crate::hash(&[
            b"ZARK/spark/ownership/reserve-intent/v1",
            &self.encode()?,
            session,
        ]))
    }
    pub fn verify_owner_reservation(
        &self,
        session: &Digest,
        expected_capability: &Digest,
        public: &Digest,
        signature: &[u8; 64],
    ) -> Result<()> {
        ensure!(
            public_capability_commitment(&self.deployment, &self.coin, public)?
                == *expected_capability,
            "Spark owner capability"
        );
        k256::schnorr::VerifyingKey::from_bytes(public)?.verify_raw(
            &self.owner_reservation_message(session)?,
            &k256::schnorr::Signature::try_from(signature.as_slice())?,
        )?;
        Ok(())
    }
}
