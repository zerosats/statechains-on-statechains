//! Blind cb-mpc two-party ECDSA for the fresh entry identity; the signer is P2.
//!
//! Key generation replaces the allocation's random server secret with the
//! signer's cb-mpc share. The signer learns only the cb-mpc key P' = X_s + x_w'·G:
//! the wallet's identity share is x_w' + tau with a wallet-only tau, so the
//! joint key is P = P' + tau·G. Key generation is allowed only before anything
//! else uses the allocation. Tickets exist only while the coin is `Allocated`;
//! `FreezeOrigin` erases the key blob.
//!
//! Signing is blind (`scripts/cbmpc-blind-sign.patch`): the signer never sees
//! the digest m, only m'' = m + r·tau in the wallet's message 3. Two answers to
//! different m'' under one P2 nonce reveal the nonce and then x_s, so:
//! - each ticket's session lives only in memory, at most one per coin, and is
//!   consumed by its single finish; a restart or `SESSION_TIMEOUT` burns the
//!   ticket, and an expired session is never resumed;
//! - message 4 is committed with the finish response before it is released,
//!   and a retry is answered only by byte-identical replay of that response;
//! - at most `MAX_TICKETS` tickets open per allocation: entry signs one
//!   operator authentication challenge and one claim payload.
//!
//! Security assumption: with m'' chosen after R, this is ECDSA with
//! presignatures and adaptive raw digests, not Lindell17's simulated P2; the
//! secrecy of x_s against the depositor rests on that model. Cryptographic
//! sign-off is deferred because this deployment is regtest only.
//!
//! Blindness also requires that the native observer, which receives P in the
//! backing opening, is operated independently of the signer, and that every
//! signed digest carries entropy the signer cannot know (tau is fixed per coin,
//! so one digest it learns unblinds P); the wallet enforces the latter.
use super::{
    Command, Engine, Policy, ProofSpec, Request, identity,
    state::{Coin, Phase},
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};
use zark_protocol::{
    scalar,
    spark_lineage::Digest,
    spark_wire::ecdsa_2p::{self as wire, Frame},
};
use zeroize::Zeroize;

#[cfg(feature = "ecdsa-2p")]
use zark_spark_ecdsa_2p as cbmpc;

const MAX_KEYGEN_ATTEMPTS: u8 = 4;
const MAX_TICKETS: usize = 2;
/// Records written under the earlier cap of 8 still load; none can open more.
const MAX_RECORDED_TICKETS: usize = 8;
/// How long a session waits for the wallet's next message.
const SESSION_TIMEOUT: Duration = Duration::from_secs(120);

/// The pinned cb-mpc source and blind-signing patch (`scripts/build-cbmpc.sh`).
const CBMPC_COMMIT: &str = "0b716706f998633912ee2be9b9bf8909aed66088";
const CBMPC_PATCH_SHA256: &str = "c67b44f1b42834f7ad1e1255ab9b645c8465b407879fd912517888ad22ce6775";

/// Binds a new ECDSA-2P store to the blind build: a store created by an
/// unpatched or differently patched signer refuses to open. Deployments
/// without ECDSA-2P keep their config digest.
pub(super) fn config(base: &Digest) -> Digest {
    zark_protocol::hash(&[
        b"ZARK/spark/signer/ecdsa-2p-config/v2",
        base,
        format!("cb-mpc {CBMPC_COMMIT}").as_bytes(),
        format!("patch cbmpc-blind-sign.patch {CBMPC_PATCH_SHA256}").as_bytes(),
    ])
}

pub(super) fn is_command(c: &Command) -> bool {
    matches!(
        c,
        Command::EcdsaKeygen { .. }
            | Command::EcdsaKeygenFinish { .. }
            | Command::EcdsaSign { .. }
            | Command::EcdsaSignFinish { .. }
    )
}

pub(super) type Runtime = Sessions<cbmpc::Session>;

/// Live sessions with their start times. A session older than
/// `SESSION_TIMEOUT` is dead: it no longer blocks a new ticket and is dropped
/// rather than resumed, so its P2 nonce never answers a second m''.
pub(super) struct Sessions<S> {
    sessions: Mutex<Started<S>>,
}

/// Keyed by (coin, ticket operation).
type Started<S> = BTreeMap<(Digest, Digest), (Instant, S)>;

impl<S> Default for Sessions<S> {
    fn default() -> Self {
        Self {
            sessions: Mutex::new(BTreeMap::new()),
        }
    }
}

impl Runtime {
    pub fn new() -> Result<Self> {
        ensure!(
            cfg!(feature = "ecdsa-2p"),
            "signer built without the ecdsa-2p feature"
        );
        Ok(Self::default())
    }
}

impl<S> Sessions<S> {
    fn insert(&self, coin: Digest, operation: Digest, session: S) -> Result<()> {
        self.insert_started(coin, operation, session, Instant::now())
    }
    fn insert_started(
        &self,
        coin: Digest,
        operation: Digest,
        session: S,
        started: Instant,
    ) -> Result<()> {
        let mut sessions = self.lock()?;
        sessions.retain(|(c, _), _| *c != coin);
        sessions.insert((coin, operation), (started, session));
        Ok(())
    }
    fn take(&self, coin: Digest, operation: Digest) -> Result<S> {
        let (started, session) = self
            .lock()?
            .remove(&(coin, operation))
            .context("ECDSA-2P session expired or restarted; start a new attempt")?;
        ensure!(
            started.elapsed() < SESSION_TIMEOUT,
            "ECDSA-2P session expired; start a new attempt"
        );
        Ok(session)
    }
    fn live(&self, coin: Digest, operation: Digest) -> Result<bool> {
        let mut sessions = self.lock()?;
        sessions.retain(|_, (started, _)| started.elapsed() < SESSION_TIMEOUT);
        Ok(sessions.contains_key(&(coin, operation)))
    }
    fn lock(&self) -> Result<MutexGuard<'_, Started<S>>> {
        self.sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("ECDSA-2P sessions poisoned"))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TicketState {
    Started,
    Released,
    Aborted,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ticket {
    /// Present only in historical plaintext tickets, which cannot finish.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message: Option<Digest>,
    nonce: Digest,
    state: TicketState,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    attempts: u8,
    /// Operation of the newest unfinished key generation.
    keygen: Option<Digest>,
    /// The signer's cb-mpc P2 blob; its share equals `Coin::secret`.
    key: Option<Vec<u8>>,
    public: Option<Vec<u8>>,
    tickets: BTreeMap<String, Ticket>,
}

impl Drop for State {
    fn drop(&mut self) {
        if let Some(key) = &mut self.key {
            key.zeroize();
        }
    }
}

impl State {
    pub(super) fn ready(&self) -> bool {
        self.key.is_some()
    }

    /// Called when the allocation is frozen: no entry signature may follow.
    pub(super) fn retire(&mut self) {
        if let Some(key) = &mut self.key {
            key.zeroize();
        }
        self.key = None;
        self.keygen = None;
        for ticket in self.tickets.values_mut() {
            if ticket.state == TicketState::Started {
                ticket.state = TicketState::Aborted;
            }
        }
    }

    pub(super) fn validate(&self, coin: &Coin, policy: &Policy) -> Result<()> {
        ensure!(policy.ecdsa_2p, "ECDSA-2P state without its deployment");
        ensure!(
            (1..=MAX_KEYGEN_ATTEMPTS).contains(&self.attempts)
                && self.tickets.len() <= MAX_RECORDED_TICKETS
                && !(self.keygen.is_some() && self.public.is_some())
                && (self.key.is_none() || self.public.is_some())
                && (self.tickets.is_empty() || self.public.is_some()),
            "ECDSA-2P lifecycle"
        );
        ensure!(
            self.tickets
                .values()
                .filter(|t| t.state == TicketState::Started)
                .count()
                <= 1,
            "ECDSA-2P concurrent tickets"
        );
        if coin.phase == Phase::Allocated {
            ensure!(
                self.public.is_none() || self.key.is_some(),
                "ECDSA-2P key retired before the allocation froze"
            );
        } else {
            ensure!(
                self.key.is_none()
                    && self.keygen.is_none()
                    && self
                        .tickets
                        .values()
                        .all(|t| t.state != TicketState::Started),
                "ECDSA-2P key outlived the entry allocation"
            );
        }
        if let Some(raw) = &self.key {
            let key = cbmpc::KeyBlob::from_bytes(raw)?;
            ensure!(
                key.private_share()?.as_slice() == coin.secret.as_slice()
                    && self.public.as_deref() == Some(key.public_key()?.as_slice()),
                "ECDSA-2P share differs from the allocation secret"
            );
        }
        Ok(())
    }
}

impl Engine {
    /// While cb-mpc owns the entry key, every other allocation command waits
    /// for key generation, and the garbled-circuit ECDSA path stays closed.
    pub(super) fn ecdsa_gate(&self, coin: &Coin, request: &Request) -> Result<()> {
        if !self.policy.ecdsa_2p || coin.phase != Phase::Allocated {
            return Ok(());
        }
        ensure!(
            coin.ecdsa.as_ref().is_some_and(State::ready),
            "ECDSA-2P key generation must finish before using the allocation"
        );
        ensure!(
            !matches!(
                request.command,
                Command::IdentityPrepare { .. }
                    | Command::IdentityFrame { .. }
                    | Command::IdentitySign { .. }
            ),
            "entry ECDSA uses the cb-mpc tickets"
        );
        Ok(())
    }

    pub(super) fn plan_ecdsa(&self, coin: &Coin, request: &Request) -> Result<Option<ProofSpec>> {
        let runtime = self.ecdsa.as_ref().context("ECDSA-2P disabled")?;
        ensure!(
            coin.phase == Phase::Allocated,
            "ECDSA-2P requires the fresh allocation"
        );
        let base = identity::scope(coin, &request.session)?;
        let state = coin.ecdsa.as_ref();
        match &request.command {
            Command::EcdsaKeygen { frame } => {
                ensure!(
                    request.intent == wire::keygen_intent(base, frame)?
                        && coin.identities.is_none()
                        && coin.auth.is_none()
                        && coin.receive.is_none()
                        && coin.bootstrap.is_none()
                        && coin.native.is_none()
                        && coin.single_user.is_none(),
                    "ECDSA-2P key generation must precede every use of the allocation"
                );
                if let Some(state) = state {
                    ensure!(
                        state.public.is_none() && state.attempts < MAX_KEYGEN_ATTEMPTS,
                        "ECDSA-2P key already generated or attempts exhausted"
                    );
                }
            }
            Command::EcdsaKeygenFinish { keygen, frame } => {
                let state = state.context("ECDSA-2P key generation missing")?;
                let started = intent_with(base, *keygen);
                ensure!(
                    state.keygen == Some(*keygen)
                        && request.intent == wire::keygen_finish_intent(&started, frame)?,
                    "ECDSA-2P key generation context"
                );
            }
            Command::EcdsaSign { message, nonce, .. } => {
                let state = state
                    .filter(|s| s.ready())
                    .context("ECDSA-2P key missing")?;
                ensure!(
                    message.is_none(),
                    "the signer must not receive the entry ECDSA digest"
                );
                ensure!(
                    request.intent == wire::sign_intent(base, nonce)?
                        && state.tickets.len() < MAX_TICKETS
                        && !state
                            .tickets
                            .contains_key(&hex::encode(request.intent.operation)),
                    "ECDSA-2P ticket reused or exhausted"
                );
                for (id, ticket) in &state.tickets {
                    if ticket.state == TicketState::Started {
                        ensure!(
                            !runtime.live(coin.coin, decode(id)?)?,
                            "another ECDSA-2P ticket is in progress"
                        );
                    }
                }
            }
            Command::EcdsaSignFinish { ticket, frame } => {
                let state = state
                    .filter(|s| s.ready())
                    .context("ECDSA-2P key missing")?;
                let t = state
                    .tickets
                    .get(&hex::encode(ticket))
                    .context("ECDSA-2P ticket missing")?;
                let opened = wire::sign_intent(base, &t.nonce)?;
                ensure!(
                    t.state == TicketState::Started
                        && t.message.is_none()
                        && opened.operation == *ticket
                        && request.intent == wire::sign_finish_intent(&opened, frame)?,
                    "ECDSA-2P ticket context"
                );
            }
            _ => bail!("not an ECDSA-2P command"),
        }
        Ok(None)
    }

    pub(super) fn apply_ecdsa(
        &self,
        mut coin: Coin,
        request: &Request,
    ) -> Result<(Coin, Value, bool)> {
        let runtime = self.ecdsa.as_ref().context("ECDSA-2P disabled")?;
        let operation = request.intent.operation;
        let response = match &request.command {
            Command::EcdsaKeygen { frame } => {
                let mut session = cbmpc::Session::keygen(cbmpc::Role::P2, SESSION_TIMEOUT)?;
                let reply = Frame::new(session.exchange(Some(frame.as_bytes().to_vec()))?)?;
                runtime.insert(coin.coin, operation, session)?;
                let state = coin.ecdsa.get_or_insert_with(|| State {
                    attempts: 0,
                    keygen: None,
                    key: None,
                    public: None,
                    tickets: BTreeMap::new(),
                });
                state.attempts += 1;
                state.keygen = Some(operation);
                json!({ "frame": reply })
            }
            Command::EcdsaKeygenFinish { keygen, frame } => {
                let mut session = runtime.take(coin.coin, *keygen)?;
                let cbmpc::Output::Key(key) = session.finish(Some(frame.as_bytes().to_vec()))?
                else {
                    bail!("ECDSA-2P key generation produced no key")
                };
                let share = key.private_share()?;
                ensure!(
                    scalar(share.as_slice())? != k256::Scalar::ZERO,
                    "zero ECDSA-2P share"
                );
                let public = key.public_key()?;
                coin.secret.zeroize();
                coin.secret.copy_from_slice(share.as_slice());
                let state = coin
                    .ecdsa
                    .as_mut()
                    .context("ECDSA-2P key generation missing")?;
                state.keygen = None;
                state.key = Some(key.as_bytes().to_vec());
                state.public = Some(public.to_vec());
                json!({ "server": coin.server()?.to_vec(), "public": public.to_vec() })
            }
            Command::EcdsaSign { nonce, frame, .. } => {
                let state = coin.ecdsa.as_mut().context("ECDSA-2P key missing")?;
                let key = cbmpc::KeyBlob::from_bytes(
                    state.key.as_deref().context("ECDSA-2P key retired")?,
                )?;
                let sid = wire::session_id(&request.intent)?;
                let mut session = cbmpc::Session::sign_blind_signer(&key, sid, SESSION_TIMEOUT)?;
                let reply = Frame::new(session.exchange(Some(frame.as_bytes().to_vec()))?)?;
                for ticket in state.tickets.values_mut() {
                    if ticket.state == TicketState::Started {
                        ticket.state = TicketState::Aborted;
                    }
                }
                state.tickets.insert(
                    hex::encode(operation),
                    Ticket {
                        message: None,
                        nonce: *nonce,
                        state: TicketState::Started,
                    },
                );
                runtime.insert(coin.coin, operation, session)?;
                json!({ "frame": reply })
            }
            Command::EcdsaSignFinish { ticket, frame } => {
                // Taking the session consumes its nonce: no other m'' can reach it.
                let mut session = runtime.take(coin.coin, *ticket)?;
                let reply = Frame::new(session.exchange(Some(frame.as_bytes().to_vec()))?)?;
                let cbmpc::Output::Signature(None) = session.finish(None)? else {
                    bail!("ECDSA-2P signer output")
                };
                let state = coin.ecdsa.as_mut().context("ECDSA-2P key missing")?;
                state
                    .tickets
                    .get_mut(&hex::encode(ticket))
                    .context("ECDSA-2P ticket missing")?
                    .state = TicketState::Released;
                json!({ "frame": reply })
            }
            _ => bail!("not an ECDSA-2P command"),
        };
        Ok((coin, response, false))
    }
}

fn intent_with(
    base: &zark_protocol::spark_lineage::Intent,
    operation: Digest,
) -> zark_protocol::spark_lineage::Intent {
    let mut intent = base.clone();
    intent.operation = operation;
    intent
}

fn decode(id: &str) -> Result<Digest> {
    Ok(hex::decode(id)?.as_slice().try_into()?)
}

#[cfg(test)]
mod tests;

/// Builds without the native library keep the persisted shape but refuse
/// every ECDSA-2P operation.
#[cfg(not(feature = "ecdsa-2p"))]
mod cbmpc {
    use anyhow::{Result, bail};
    use std::time::Duration;
    use zeroize::Zeroizing;

    const DISABLED: &str = "signer built without the ecdsa-2p feature";
    pub enum Role {
        P2,
    }
    #[allow(dead_code)]
    pub enum Output {
        Key(KeyBlob),
        Signature(Option<Vec<u8>>),
    }
    pub struct KeyBlob;
    impl KeyBlob {
        pub fn from_bytes(_: &[u8]) -> Result<Self> {
            bail!(DISABLED)
        }
        pub fn as_bytes(&self) -> &[u8] {
            &[]
        }
        pub fn public_key(&self) -> Result<[u8; 33]> {
            bail!(DISABLED)
        }
        pub fn private_share(&self) -> Result<Zeroizing<[u8; 32]>> {
            bail!(DISABLED)
        }
    }
    pub struct Session;
    impl Session {
        pub fn keygen(_: Role, _: Duration) -> Result<Self> {
            bail!(DISABLED)
        }
        pub fn sign_blind_signer(_: &KeyBlob, _: [u8; 32], _: Duration) -> Result<Self> {
            bail!(DISABLED)
        }
        pub fn exchange(&mut self, _: Option<Vec<u8>>) -> Result<Vec<u8>> {
            bail!(DISABLED)
        }
        pub fn finish(&mut self, _: Option<Vec<u8>>) -> Result<Output> {
            bail!(DISABLED)
        }
    }
}
