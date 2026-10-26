//! Actual origin-role wallet witness, with authenticated deployment pins and
//! explicit origin sentinels. Producing this input does not authorize issuance.
use super::{PrivateRecovery, witness};
use anyhow::{Result, ensure};
use zark_protocol::{
    point_bytes,
    spark_lineage::{
        Issuance, PinnedSparkVerifier, capability_commitment, origin_field, origin_previous_state,
        server_commitment,
    },
};
use zeroize::Zeroizing;

pub fn origin_issuance(
    recovery: &PrivateRecovery,
    verifier: &PinnedSparkVerifier,
) -> Result<Issuance> {
    let r = recovery.authorization()?.clone();
    let c = &r.context;
    ensure!(
        c.deployment == verifier.deployment() && r.policy == verifier.policy(),
        "private Spark origin deployment"
    );
    ensure!(
        c.previous_state == origin_previous_state(&c.deployment, &c.coin)?
            && c.revision == 1
            && recovery.witness().target.owner_index == 1,
        "private Spark origin context"
    );
    ensure!(
        recovery.intent().recipient_claim == origin_field(&c.deployment, &c.coin, 0)?,
        "private Spark origin recipient sentinel"
    );
    let value = Issuance {
        recipient_claim: origin_field(&c.deployment, &c.coin, 0)?,
        mask: origin_field(&c.deployment, &c.coin, 1)?,
        masked_share: origin_field(&c.deployment, &c.coin, 2)?,
        bridge: origin_field(&c.deployment, &c.coin, 3)?,
        delta: origin_field(&c.deployment, &c.coin, 4)?,
        previous_capability: origin_field(&c.deployment, &c.coin, 5)?,
        next_capability: recovery.next_capability(),
        server_share: server_commitment(&c.deployment, &c.coin, &r.server, recovery.server_salt())?,
        recovery: r,
        config: verifier.config().clone(),
    };
    value.encode()?;
    Ok(value)
}

pub fn origin_prover_toml(
    recovery: &PrivateRecovery,
    owner_secret: &[u8; 32],
    verifier: &PinnedSparkVerifier,
) -> Result<Zeroizing<String>> {
    let issuance = origin_issuance(recovery, verifier)?;
    let context = &issuance.recovery.context;
    ensure!(
        capability_commitment(&context.deployment, &context.coin, owner_secret)?
            == issuance.next_capability,
        "private Spark origin owner opening"
    );
    let session = k256::schnorr::VerifyingKey::from_bytes(&context.session)?;
    let mut out = witness::statement(&issuance.encode()?)?;
    recovery.witness().append_prover_fields(&mut out)?;
    witness::bytes(&mut out, "owner_secret", owner_secret)?;
    witness::bytes(&mut out, "server_salt", recovery.server_salt())?;
    witness::bytes(
        &mut out,
        "session_point",
        &point_bytes((*session.as_affine()).into())?,
    )?;
    Ok(out)
}
