//! Proof-gated blind BIP-340 responses for Spark operator authentication.
//!
//! Spark also accepts identity-key Schnorr signatures for transfer and token
//! authorization, so a ticket is never a blind oracle. `AuthPrepare` freezes
//! one wallet commitment (which fixes the message and blinding) with a fresh
//! nonce under the existing current-owner identity scope. `AuthIssue` releases
//! the single response only after the pinned auth proof shows that the blinded
//! challenge belongs to a canonical Spark `Challenge` naming the coin's
//! committed joint identity key. The signer never learns that key, the Spark
//! nonce, the message or the final signature; it sees only the timestamp.
//! Auth work is auxiliary: it changes the checkpoint, not the ownership CAS.
#[cfg(test)]
mod real_proof;
#[cfg(test)]
mod tests;
mod validation;
use super::{Command, Engine, ProofRole, ProofSpec, Request, blind_issuance, state::Coin};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use zark_protocol::{
    hash, point_bytes, random32, reduce,
    spark_auth::{self, AuthHeader, AuthStatement},
    spark_lineage::{Digest, Intent},
    spark_wire::{auth_issue_intent, auth_prepare_intent},
};
use zeroize::{Zeroize, Zeroizing};

/// Joint identity work shares the 72 responses that native exit and receive
/// budgets already reserve: nine per ECDSA ticket, two per auth ticket.
const IDENTITY_RESPONSE_BUDGET: usize = 72;
const ECDSA_TICKET_RESPONSES: usize = 9;
const AUTH_TICKET_RESPONSES: usize = 2;
/// One concurrent ticket per Spark operator connection, with headroom.
const MAX_LIVE: usize = 4;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Tickets {
    key_commitment: Digest,
    tickets: BTreeMap<String, Ticket>,
}

/// Live: secret only. Issued: challenge and partial. Retired: none of them.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ticket {
    base: Intent,
    intent: Intent,
    session: Digest,
    server: Vec<u8>,
    timestamp: u64,
    commitment: Digest,
    nonce: Vec<u8>,
    secret: Option<Digest>,
    challenge: Option<Digest>,
    partial: Option<Digest>,
}
impl Drop for Ticket {
    fn drop(&mut self) {
        if let Some(secret) = &mut self.secret {
            secret.zeroize();
        }
    }
}
impl Ticket {
    fn live(&self) -> bool {
        self.secret.is_some()
    }
    fn fresh(&self, now: u64) -> bool {
        spark_auth::check_fresh(self.timestamp, now).is_ok()
    }
    fn header(&self, key_commitment: Digest) -> Result<AuthHeader> {
        Ok(AuthHeader {
            scope: spark_auth::scope_digest(&self.base)?,
            key_commitment,
            server: self.server.as_slice().try_into()?,
            timestamp: self.timestamp,
        })
    }
}

pub(super) fn is_command(command: &Command) -> bool {
    matches!(
        command,
        Command::AuthPrepare { .. } | Command::AuthIssue { .. }
    )
}

fn now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

impl Engine {
    pub(super) fn plan_auth(&self, coin: &Coin, request: &Request) -> Result<Option<ProofSpec>> {
        ensure!(self.auth_verifier.is_some(), "Spark auth signing disabled");
        let base = super::identity::scope(coin, &request.session)?;
        match &request.command {
            Command::AuthPrepare {
                key_commitment,
                timestamp,
                commitment,
            } => {
                plan_prepare(
                    coin,
                    request,
                    base,
                    key_commitment,
                    *timestamp,
                    commitment,
                    now()?,
                )?;
                Ok(None)
            }
            Command::AuthIssue {
                ticket, challenge, ..
            } => Ok(Some(plan_issue(
                coin,
                request,
                base,
                ticket,
                challenge,
                now()?,
            )?)),
            _ => anyhow::bail!("not a Spark auth command"),
        }
    }

    /// Only called after `plan_auth`, and for issue after proof verification,
    /// both repeated under the relock by `handle_guarded`.
    pub(super) fn apply_auth(
        &self,
        mut coin: Coin,
        request: &Request,
    ) -> Result<(Coin, Value, bool)> {
        let response = match &request.command {
            Command::AuthPrepare {
                key_commitment,
                timestamp,
                commitment,
            } => apply_prepare(
                &mut coin,
                request,
                key_commitment,
                *timestamp,
                commitment,
                now()?,
            )?,
            Command::AuthIssue {
                ticket, challenge, ..
            } => apply_issue(&mut coin, ticket, challenge)?,
            _ => anyhow::bail!("not a Spark auth command"),
        };
        Ok((coin, response, false))
    }
}

fn apply_prepare(
    coin: &mut Coin,
    request: &Request,
    key_commitment: &Digest,
    timestamp: u64,
    commitment: &Digest,
    now: u64,
) -> Result<Value> {
    let secret = Zeroizing::new(coin.secret);
    let server = coin.server()?;
    let base = super::identity::scope(coin, &request.session)?.clone();
    let tickets = coin.auth.get_or_insert_with(|| Tickets {
        key_commitment: *key_commitment,
        tickets: BTreeMap::new(),
    });
    ensure!(
        tickets.key_commitment == *key_commitment,
        "Spark auth key changed"
    );
    tickets.retire_stale(now);
    // Hedged: a weak RNG alone cannot repeat a nonce across tickets.
    let nonce = Zeroizing::new(reduce(hash(&[
        b"ZARK/spark/auth/nonce/v1",
        &*secret,
        &request.intent.operation,
        commitment,
        &random32(),
    ])));
    ensure!(!bool::from(nonce.is_zero()), "zero Spark auth nonce");
    let point = point_bytes(k256::ProjectivePoint::GENERATOR * *nonce)?;
    ensure!(
        tickets
            .tickets
            .values()
            .all(|t| t.nonce[..32] != point[..32]),
        "Spark auth nonce reuse"
    );
    tickets.tickets.insert(
        hex::encode(request.intent.operation),
        Ticket {
            base,
            intent: request.intent.clone(),
            session: request.session,
            server: server.to_vec(),
            timestamp,
            commitment: *commitment,
            nonce: point.to_vec(),
            secret: Some(nonce.to_bytes().into()),
            challenge: None,
            partial: None,
        },
    );
    Ok(json!({"ticket":request.intent.operation,"nonce":point.to_vec()}))
}

fn apply_issue(coin: &mut Coin, ticket: &Digest, challenge: &Digest) -> Result<Value> {
    let secret = Zeroizing::new(coin.secret);
    let t = coin
        .auth
        .as_mut()
        .and_then(|s| s.tickets.get_mut(&hex::encode(ticket)))
        .context("Spark auth ticket missing")?;
    let nonce_point = t.nonce.clone();
    let commitment = t.commitment;
    // issue() validates everything before consuming the nonce; the stored
    // response, never a recomputation, serves exact retries.
    let [partial] = blind_issuance::issue(
        &secret,
        [&mut t.secret],
        [blind_issuance::FrozenResponse {
            nonce_point: &nonce_point,
            nonce_commitment: &commitment,
            blinded_challenge: challenge,
        }],
    )?;
    t.challenge = Some(*challenge);
    t.partial = Some(partial);
    Ok(json!({"partial":partial}))
}

impl Tickets {
    /// Expired live nonces can never be issued; erase them before admitting more.
    fn retire_stale(&mut self, now: u64) {
        self.retire_where(|ticket| !ticket.fresh(now));
    }
    pub(super) fn retire_live(&mut self) {
        self.retire_where(|_| true);
    }
    fn retire_where(&mut self, retire: impl Fn(&Ticket) -> bool) {
        for ticket in self.tickets.values_mut() {
            if ticket.live() && retire(ticket) {
                if let Some(secret) = &mut ticket.secret {
                    secret.zeroize();
                }
                ticket.secret = None;
            }
        }
    }
}

fn identity_responses(coin: &Coin, auth_tickets: usize) -> usize {
    coin.identities.as_ref().map_or(0, |s| s.ticket_count()) * ECDSA_TICKET_RESPONSES
        + auth_tickets * AUTH_TICKET_RESPONSES
}

#[allow(clippy::too_many_arguments)]
fn plan_prepare(
    coin: &Coin,
    request: &Request,
    base: &Intent,
    key_commitment: &Digest,
    timestamp: u64,
    commitment: &Digest,
    now: u64,
) -> Result<()> {
    spark_auth::check_fresh(timestamp, now)?;
    ensure!(*commitment != [0; 32], "zero Spark auth commitment");
    ensure!(
        request.intent == auth_prepare_intent(base, key_commitment, timestamp, commitment)?,
        "Spark auth preparation context"
    );
    AuthHeader {
        scope: spark_auth::scope_digest(base)?,
        key_commitment: *key_commitment,
        server: coin.server()?,
        timestamp,
    }
    .encode()?;
    // Both signing paths must name one fixed wallet share for this coin.
    for fixed in [
        coin.identities.as_ref().map(|s| s.key_commitment()),
        coin.auth.as_ref().map(|s| s.key_commitment),
    ]
    .into_iter()
    .flatten()
    {
        ensure!(
            fixed == *key_commitment,
            "Spark auth names another identity key"
        );
    }
    let existing = coin.auth.as_ref().map_or(0, |s| s.tickets.len());
    ensure!(
        identity_responses(coin, existing + 1) <= IDENTITY_RESPONSE_BUDGET,
        "Spark joint identity response budget exhausted"
    );
    if let Some(tickets) = &coin.auth {
        ensure!(
            !tickets
                .tickets
                .contains_key(&hex::encode(request.intent.operation)),
            "Spark auth ticket already prepared"
        );
        let live = tickets
            .tickets
            .values()
            .filter(|t| t.live() && t.fresh(now))
            .count();
        ensure!(live < MAX_LIVE, "too many concurrent Spark auth tickets");
    }
    Ok(())
}

fn plan_issue(
    coin: &Coin,
    request: &Request,
    base: &Intent,
    ticket: &Digest,
    challenge: &Digest,
    now: u64,
) -> Result<ProofSpec> {
    let tickets = coin.auth.as_ref().context("Spark auth tickets missing")?;
    let t = tickets
        .tickets
        .get(&hex::encode(ticket))
        .context("Spark auth ticket missing")?;
    ensure!(
        t.live()
            && t.challenge.is_none()
            && t.session == request.session
            && t.base == *base
            && t.server == coin.server()?.to_vec()
            && request.intent == auth_issue_intent(&t.intent, challenge)?,
        "Spark auth ticket retired, used or out of scope"
    );
    // Checked before proof verification and again under the relock.
    spark_auth::check_fresh(t.timestamp, now)?;
    let statement = AuthStatement {
        header: t.header(tickets.key_commitment)?,
        commitment: t.commitment,
        nonce: t.nonce.as_slice().try_into()?,
        challenge: *challenge,
    };
    Ok(ProofSpec {
        role: ProofRole::Auth,
        statement: statement.encode()?,
    })
}
