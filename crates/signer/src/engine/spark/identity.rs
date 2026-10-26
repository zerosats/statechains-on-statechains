//! Scoped joint identity. Public USER and completed ECDSA signatures
//! remain wallet-local. Identity work changes the checkpoint, not ownership CAS.
mod frames;
#[cfg(test)]
mod tests;
mod validation;
use super::{
    Command, Engine, Policy, ProofSpec, Request,
    state::{Coin, Phase},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Mutex};
use zark_protocol::{
    hash, random_scalar, random32, scalar,
    spark_lineage::{Digest, Intent},
    spark_wire::{
        identity_decrypt_intent, identity_frame_intent, identity_intent, identity_message_intent,
        identity_sign_intent,
    },
};
use zark_spark_claim_mpc::identity::{IdentityCircuit, IdentityContributor, nonce_public, nonce_r};
use zeroize::{Zeroize, Zeroizing};
pub(super) struct Runtime {
    pub circuit: IdentityCircuit,
    cache: Mutex<BTreeMap<(Digest, Digest), Cache>>,
}
impl Runtime {
    pub fn new() -> Result<Self> {
        Ok(Self {
            circuit: IdentityCircuit::new()?,
            cache: Default::default(),
        })
    }
}
struct Cache {
    prefix: Digest,
    initial: Digest,
    contributor: IdentityContributor,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Secrets {
    nonce: Digest,
    seed: Digest,
}
impl Drop for Secrets {
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.seed.zeroize();
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Workflow {
    intent: Intent,
    session: Digest,
    server: Vec<u8>,
    commitment: Digest,
    wallet_nonce: Vec<u8>,
    server_nonce: Vec<u8>,
    r: Digest,
    initial: Digest,
    rounds: Vec<(Digest, Digest)>,
    secrets: Option<Secrets>,
    aborted: bool,
    masks: Option<[Digest; 2]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message: Option<Digest>,
    digest: Option<Digest>,
    partial: Option<Digest>,
}
impl Drop for Workflow {
    fn drop(&mut self) {
        if let Some(m) = &mut self.masks {
            m.zeroize();
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Sessions {
    circuit: Digest,
    commitment: Digest,
    sessions: BTreeMap<String, Workflow>,
}
/// Read-only view for the Schnorr auth path, which must name the same key and
/// share this coin's joint-identity response budget.
impl Sessions {
    pub(super) fn key_commitment(&self) -> Digest {
        self.commitment
    }
    pub(super) fn ticket_count(&self) -> usize {
        self.sessions.len()
    }
}
impl Sessions {
    pub(super) fn active(&self) -> bool {
        self.sessions.values().any(|w| w.secrets.is_some())
    }
}
impl Sessions {
    pub(super) fn retire_unused(&mut self) {
        for w in self.sessions.values_mut() {
            if w.masks.is_some() {
                if let Some(m) = &mut w.masks {
                    m.zeroize();
                }
                w.masks = None;
                w.secrets = None;
                w.aborted = true;
            }
        }
    }
}
pub(super) fn is_command(c: &Command) -> bool {
    matches!(
        c,
        Command::IdentityPrepare { .. }
            | Command::IdentityFrame { .. }
            | Command::IdentityDecrypt { .. }
            | Command::IdentitySign { .. }
    )
}
/// Identity operations may use the fresh allocation or a current-owner
/// authenticated, locked native exit. A private handover alone grants no access
/// to the preceding owner's identity tickets or session.
pub(super) fn scope<'a>(coin: &'a Coin, session: &Digest) -> Result<&'a Intent> {
    if coin.phase == Phase::Allocated {
        let pending = coin
            .pending
            .as_ref()
            .context("identity allocation missing")?;
        ensure!(
            pending.origin && coin.session == *session,
            "identity allocation session"
        );
        return Ok(&pending.intent);
    }
    ensure!(
        coin.phase == Phase::Accepted && coin.pending.is_none(),
        "identity ownership phase"
    );
    let (intent, native_session) = coin
        .native
        .as_ref()
        .and_then(|native| native.identity_scope())
        .context("identity requires an unfinished owner-authorized native exit")?;
    ensure!(
        native_session == *session && intent.previous_state == coin.state,
        "identity native session or state"
    );
    Ok(intent)
}
impl Engine {
    pub(super) fn plan_identity(
        &self,
        coin: &Coin,
        request: &Request,
    ) -> Result<Option<ProofSpec>> {
        ensure!(self.identity.is_some(), "joint identity disabled");
        let base = scope(coin, &request.session)?;
        match &request.command {
            Command::IdentityPrepare {
                commitment,
                nonce,
                message,
            } => {
                let message = message.context(
                    "unbound identity tickets are retired; freeze the message before preparation",
                )?;
                ensure!(nonce.len() == 33, "identity nonce point length");
                k256::PublicKey::from_sec1_bytes(nonce)?;
                ensure!(
                    *commitment != [0; 32]
                        && request.intent
                            == identity_message_intent(base, commitment, nonce, &message)?,
                    "identity message context"
                );
                if let Some(s) = &coin.identities {
                    ensure!(
                        s.commitment == *commitment
                            && !s.active()
                            && s.sessions.len() < 8
                            && !s
                                .sessions
                                .contains_key(&hex::encode(request.intent.operation)),
                        "identity key changed, session active or exhausted"
                    );
                }
            }
            Command::IdentityFrame {
                identity,
                step,
                frame,
            } => {
                let w = coin
                    .identities
                    .as_ref()
                    .and_then(|s| s.sessions.get(&hex::encode(identity)))
                    .context("identity session missing")?;
                ensure!(
                    w.session == request.session
                        && w.message.is_some()
                        && w.secrets.is_some()
                        && !w.aborted
                        && usize::from(*step) == w.rounds.len()
                        && *step < 7
                        && request.intent == identity_frame_intent(&w.intent, *step)?
                        && *frame != [0; 32],
                    "identity frame order/context"
                );
                // Apply reads and hashes the frame itself under the commit lock.
                self.identity_files()?
                    .check_slot(&slot(request), &request.digest()?)?;
            }
            Command::IdentityDecrypt { ephemeral } => {
                ensure!(
                    coin.phase == Phase::Allocated,
                    "identity decryption requires fresh receive allocation"
                );
                ensure!(
                    ephemeral.len() == 65 && ephemeral[0] == 4,
                    "identity ECIES point encoding"
                );
                k256::PublicKey::from_sec1_bytes(ephemeral)?;
                ensure!(
                    request.intent == identity_decrypt_intent(base, ephemeral)?,
                    "identity ECDH context"
                );
            }
            Command::IdentitySign { identity, digest } => {
                authorize_signature(coin, request, identity, digest)?;
            }
            _ => anyhow::bail!("not joint identity command"),
        }
        Ok(None)
    }
    pub(super) fn apply_identity(
        &self,
        mut coin: Coin,
        request: &Request,
    ) -> Result<(Coin, Value, bool)> {
        let runtime = self.identity.as_ref().context("identity disabled")?;
        let response = match &request.command {
            Command::IdentityPrepare {
                commitment,
                nonce,
                message,
            } => {
                let secret: Digest = random_scalar().to_bytes().into();
                let mut w = Workflow {
                    intent: request.intent.clone(),
                    session: request.session,
                    server: coin.server()?.to_vec(),
                    commitment: *commitment,
                    wallet_nonce: nonce.clone(),
                    server_nonce: nonce_public(&secret)?,
                    r: nonce_r(&secret, nonce)?,
                    initial: [0; 32],
                    rounds: Vec::new(),
                    secrets: Some(Secrets {
                        nonce: secret,
                        seed: random32(),
                    }),
                    aborted: false,
                    masks: Some(std::array::from_fn(|_| random_scalar().to_bytes().into())),
                    message: *message,
                    digest: None,
                    partial: None,
                };
                let (contributor, initial) = self.identity_contributor(&w, &coin.secret)?;
                w.initial = self.identity_files()?.write(&initial)?;
                // An uncommitted entry is harmless: a retry overwrites it, and
                // the first frame uses it only for this exact initial frame.
                self.cache_identity(&w, &w.rounds, contributor)?;
                let response = json!({"circuit":runtime.circuit.digest(),"nonce":w.server_nonce,"r":w.r,"initial":w.initial});
                let sessions = coin.identities.get_or_insert_with(|| Sessions {
                    circuit: runtime.circuit.digest(),
                    commitment: *commitment,
                    sessions: BTreeMap::new(),
                });
                sessions
                    .sessions
                    .insert(hex::encode(request.intent.operation), w);
                response
            }
            Command::IdentityFrame {
                identity, frame, ..
            } => {
                let key = hex::encode(identity);
                let input = self.identity_files()?.read(frame)?;
                let w = &coin
                    .identities
                    .as_ref()
                    .context("identity missing")?
                    .sessions[&key];
                let result = self.advance_identity(w, &coin.secret, frame, &input);
                let w = coin
                    .identities
                    .as_mut()
                    .unwrap()
                    .sessions
                    .get_mut(&key)
                    .unwrap();
                match result {
                    Ok(reply) => {
                        w.rounds.push((*frame, reply));
                        if w.rounds.len() == 7 {
                            w.secrets = None;
                        }
                        json!({"reply":reply})
                    }
                    Err(_) => {
                        w.aborted = true;
                        w.secrets = None;
                        if let Some(m) = &mut w.masks {
                            m.zeroize();
                        }
                        w.masks = None;
                        runtime
                            .cache
                            .lock()
                            .map_err(|_| anyhow::anyhow!("identity cache poisoned"))?
                            .remove(&(coin.coin, *identity));
                        json!({"aborted":true})
                    }
                }
            }
            Command::IdentityDecrypt { ephemeral } => {
                let point = k256::PublicKey::from_sec1_bytes(ephemeral)?.to_projective();
                let partial = point * scalar(&coin.secret)?;
                let proof = zark_spark_claim_mpc::identity::ecdh_prove(
                    &coin.secret,
                    ephemeral,
                    &request.digest()?,
                )?;
                use k256::elliptic_curve::sec1::ToEncodedPoint;
                json!({"partial":partial.to_affine().to_encoded_point(true).as_bytes(),"proof":proof})
            }
            Command::IdentitySign { identity, digest } => {
                let w = coin
                    .identities
                    .as_mut()
                    .unwrap()
                    .sessions
                    .get_mut(&hex::encode(identity))
                    .unwrap();
                let mut masks = Zeroizing::new(
                    w.masks
                        .take()
                        .context("identity presign already consumed")?,
                );
                let partial = zark_spark_claim_mpc::identity::online_partial(&masks, &w.r, digest)?;
                masks.zeroize();
                w.digest = Some(*digest);
                w.partial = Some(partial);
                json!({"partial":partial})
            }
            _ => anyhow::bail!("not joint identity command"),
        };
        Ok((coin, response, false))
    }
    fn identity_contributor(
        &self,
        w: &Workflow,
        secret: &Digest,
    ) -> Result<(IdentityContributor, Vec<u8>)> {
        let s = w.secrets.as_ref().context("identity nonce retired")?;
        IdentityContributor::start(
            &self.identity.as_ref().context("identity disabled")?.circuit,
            Zeroizing::new(*secret),
            Zeroizing::new(s.nonce),
            Zeroizing::new(w.masks.context("identity masks retired")?),
            w.commitment,
            Zeroizing::new(s.seed),
        )
    }
}
fn authorize_signature(
    coin: &Coin,
    request: &Request,
    identity: &Digest,
    digest: &Digest,
) -> Result<()> {
    let base = scope(coin, &request.session)?;
    let w = coin
        .identities
        .as_ref()
        .and_then(|s| s.sessions.get(&hex::encode(identity)))
        .context("identity presign missing")?;
    // The message belongs to the prepared ticket, not to a consumed flag. This
    // check therefore survives restoring the ready ticket and its checkpoint.
    // Historical unbound tickets remain readable, but cannot sign again.
    ensure!(
        w.message == Some(*digest),
        "identity message was not frozen before presigning"
    );
    ensure!(
        w.masks.is_some()
            && w.session == request.session
            && w.server == coin.server()?.to_vec()
            && w.intent == identity_message_intent(base, &w.commitment, &w.wallet_nonce, digest)?
            && w.secrets.is_none()
            && !w.aborted
            && w.rounds.len() == 7
            && w.digest.is_none()
            && request.intent == identity_sign_intent(&w.intent, digest)?,
        "identity presign incomplete, retired, or already used"
    );
    Ok(())
}
fn slot(r: &Request) -> String {
    format!(
        "{}-{}",
        hex::encode(r.intent.coin),
        hex::encode(r.intent.operation)
    )
}
