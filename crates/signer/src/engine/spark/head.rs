//! Fresh head reads share the real checkpoint lock and never journal a cache.
use super::{
    Command, Engine, Request,
    state::{Coin, Phase},
};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use zark_protocol::{
    random32,
    spark_wire::{Head, HeadPhase, SignedHead},
};

impl Engine {
    pub(super) fn fresh_head(
        &self,
        coin: &Coin,
        revision: u64,
        request: &Request,
    ) -> Result<Value> {
        let Command::Head { challenge, owner } = &request.command else {
            anyhow::bail!("not a Spark head query");
        };
        ensure!(*challenge != [0; 32], "zero Spark head challenge");
        if let Some(owner) = owner {
            owner.verify(
                &request.intent,
                &request.session,
                challenge,
                &coin.capability,
            )?;
        } else {
            ensure!(
                coin.phase == Phase::Issued
                    && coin
                        .pending
                        .as_ref()
                        .is_some_and(|pending| pending.recipient == Some(request.session)
                            && pending.intent == request.intent),
                "Spark head requires current owner or exact issued recipient"
            );
        }
        let phase = if coin.single_user.is_some() {
            HeadPhase::Locked
        } else if let Some(native) = &coin.native {
            if native.completed() {
                HeadPhase::Exited
            } else {
                HeadPhase::Locked
            }
        } else {
            match coin.phase {
                Phase::Allocated | Phase::Origin => HeadPhase::Origin,
                Phase::Accepted => HeadPhase::Available,
                Phase::Exited => HeadPhase::Exited,
                Phase::Issued => HeadPhase::Issued,
                Phase::Reserved | Phase::Handover | Phase::Proposed | Phase::Prepared => {
                    HeadPhase::Locked
                }
            }
        };
        let head = Head {
            deployment: coin.deployment,
            coin: coin.coin,
            query: request.digest()?,
            challenge: *challenge,
            session: request.session,
            state: coin.state,
            capability: coin.capability,
            policy: self.policy.policy,
            revision,
            phase,
            locked_operation: coin
                .single_user
                .as_ref()
                .map(|v| v.operation())
                .or_else(|| {
                    coin.native
                        .as_ref()
                        .filter(|v| !v.completed())
                        .map(|v| v.operation())
                })
                .or_else(|| {
                    coin.pending
                        .as_ref()
                        .map(|pending| pending.intent.operation)
                }),
            share_release: self.share_release,
        };
        let signature = self
            .origin
            .sign_raw(&head.message()?, &random32())?
            .to_bytes()
            .to_vec();
        Ok(json!({"head":SignedHead { head, signature }}))
    }
}
