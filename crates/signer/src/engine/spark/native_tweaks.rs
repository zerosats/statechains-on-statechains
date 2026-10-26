//! Standard Spark send-key encryption. The blind signer sees only a bounded
//! template shape and opaque MPC frames, never a leaf ID or native ciphertext.
mod frames;
#[cfg(test)]
mod tests;
mod validation;
use super::{Command, Engine, Policy, ProofSpec, Request, state::Coin};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use zark_protocol::{
    hash, point_bytes, random_scalar, random32, scalar,
    spark_lineage::{Digest, Intent},
    spark_wire::{native_tweak_frame_intent, opaque_frames::FrameStore},
};
use zark_spark_claim_mpc::{CircuitSpec, ClaimCircuit, ClaimContributor, EncryptionMask};
use zeroize::{Zeroize, Zeroizing};

#[derive(Default)]
pub(super) struct Runtime {
    circuits: Mutex<BTreeMap<Digest, Arc<ClaimCircuit>>>,
    cache: Mutex<BTreeMap<(Digest, Digest, String), Cache>>,
}
struct Cache {
    prefix: Digest,
    contributor: ClaimContributor,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Secrets {
    slope: Digest,
    seed: Digest,
}
impl Drop for Secrets {
    fn drop(&mut self) {
        self.slope.zeroize();
        self.seed.zeroize();
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transcript {
    initial: Digest,
    rounds: Vec<(Digest, Digest)>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Workflow {
    circuit: Digest,
    spec: CircuitSpec,
    server: Vec<u8>,
    slope: Vec<u8>,
    secrets: Option<Secrets>,
    transcripts: BTreeMap<String, Transcript>,
    aborted: bool,
    packet: Option<Digest>,
}
impl Workflow {
    pub(super) fn sealed_packet(&self) -> Option<Digest> {
        self.packet
    }
    fn ready(&self) -> bool {
        !self.aborted
            && self.secrets.is_none()
            && self.transcripts.values().all(|t| t.rounds.len() == 7)
    }
}
pub(super) fn is_command(c: &Command) -> bool {
    matches!(
        c,
        Command::NativeTweakPrepare { .. }
            | Command::NativeTweakFrame { .. }
            | Command::NativeTweakSeal { .. }
    )
}
pub(super) fn auxiliary(c: &Command) -> bool {
    matches!(
        c,
        Command::NativeTweakPrepare { .. } | Command::NativeTweakFrame { .. }
    )
}
fn index(id: &str) -> Result<u32> {
    let bytes = hex::decode(id)?;
    ensure!(
        bytes.len() == 32 && bytes[..28] == [0; 28],
        "native tweak operator identifier profile"
    );
    let index = u32::from_be_bytes(bytes[28..].try_into()?);
    ensure!(index != 0, "zero native tweak operator identifier");
    Ok(index)
}
impl Engine {
    fn tweak_circuit(&self, spec: CircuitSpec) -> Result<Arc<ClaimCircuit>> {
        spec.validate()?;
        let key = spec.digest()?;
        let mut cache = self
            .native_tweaks
            .circuits
            .lock()
            .map_err(|_| anyhow::anyhow!("native tweak circuit cache poisoned"))?;
        if let Some(c) = cache.get(&key) {
            return Ok(c.clone());
        }
        let circuit = Arc::new(ClaimCircuit::new(spec)?);
        // Compiled shapes are a performance cache, never durable authority.
        // Bound retention when different wallets use different DER lengths.
        if cache.len() >= 8 {
            cache.pop_first();
        }
        cache.insert(key, circuit.clone());
        Ok(circuit)
    }
    pub(super) fn plan_native_tweaks(
        &self,
        coin: &Coin,
        request: &Request,
    ) -> Result<Option<ProofSpec>> {
        ensure!(
            self.native_verifier
                .as_ref()
                .is_some_and(|v| v.is_ordinary()),
            "ordinary native exit proof suite required"
        );
        let native = coin
            .native
            .as_ref()
            .context("native exit preparation missing")?;
        ensure!(
            native.intent == request.intent
                || matches!(request.command, Command::NativeTweakFrame { .. }),
            "native tweak frozen intent"
        );
        ensure!(
            native.session == request.session
                && native.statement.is_some()
                && !native.completed()
                && native.contribution.is_none(),
            "native tweak requires issued current-owner exit"
        );
        let cluster = self
            .policy
            .native_cluster
            .as_ref()
            .context("native tweak cluster missing")?;
        match &request.command {
            Command::NativeTweakPrepare {
                plaintext_bytes,
                scalar_offset,
            } => {
                ensure!(native.tweaks.is_none(), "native tweak already prepared");
                CircuitSpec {
                    plaintext_bytes: usize::from(*plaintext_bytes),
                    scalar_offset: usize::from(*scalar_offset),
                }
                .validate()?;
                for id in cluster.operators.keys() {
                    index(id)?;
                }
            }
            Command::NativeTweakFrame {
                operator,
                step,
                frame,
            } => {
                let w = native
                    .tweaks
                    .as_ref()
                    .context("native tweak preparation missing")?;
                let t = w
                    .transcripts
                    .get(operator)
                    .context("unconfigured native tweak operator")?;
                ensure!(
                    !w.aborted
                        && w.secrets.is_some()
                        && *step < 7
                        && usize::from(*step) == t.rounds.len()
                        && request.intent
                            == native_tweak_frame_intent(&native.intent, operator, *step)?
                        && *frame != [0; 32],
                    "native tweak frame order/context"
                );
                self.tweak_files()?
                    .check_slot(&slot(request), &request.digest()?)?;
                self.tweak_files()?.read(frame)?;
            }
            Command::NativeTweakSeal { packet } => {
                let w = native
                    .tweaks
                    .as_ref()
                    .context("native tweak preparation missing")?;
                ensure!(
                    w.ready() && w.packet.is_none() && *packet != [0; 32],
                    "native tweak seal phase/digest"
                );
            }
            _ => anyhow::bail!("not native tweak command"),
        }
        Ok(None)
    }
    pub(super) fn apply_native_tweaks(
        &self,
        mut coin: Coin,
        request: &Request,
    ) -> Result<(Coin, Value, bool)> {
        let response = match &request.command {
            Command::NativeTweakPrepare {
                plaintext_bytes,
                scalar_offset,
            } => {
                let spec = CircuitSpec {
                    plaintext_bytes: usize::from(*plaintext_bytes),
                    scalar_offset: usize::from(*scalar_offset),
                };
                let circuit = self.tweak_circuit(spec)?;
                let cluster = self
                    .policy
                    .native_cluster
                    .as_ref()
                    .context("native tweak cluster missing")?;
                let slope = loop {
                    let slope: Digest = random_scalar().to_bytes().into();
                    if cluster.operators.keys().all(|id| {
                        index(id).is_ok_and(|i| {
                            scalar(&coin.secret).unwrap()
                                + scalar(&slope).unwrap() * k256::Scalar::from(u64::from(i))
                                != k256::Scalar::ZERO
                        })
                    }) {
                        break slope;
                    }
                };
                let mut w = Workflow {
                    circuit: circuit.digest(),
                    spec,
                    server: coin.server()?.to_vec(),
                    slope: point_bytes(k256::ProjectivePoint::GENERATOR * scalar(&slope)?)?
                        .to_vec(),
                    secrets: Some(Secrets {
                        slope,
                        seed: random32(),
                    }),
                    transcripts: BTreeMap::new(),
                    aborted: false,
                    packet: None,
                };
                let native = coin.native.as_ref().context("native missing")?;
                let mut operators = BTreeMap::new();
                for id in cluster.operators.keys() {
                    let (mask, _, message) =
                        self.tweak_contributor(&w, &native.intent, &coin.secret, id)?;
                    let initial = self.tweak_files()?.write(&message)?;
                    w.transcripts.insert(
                        id.clone(),
                        Transcript {
                            initial,
                            rounds: Vec::new(),
                        },
                    );
                    operators.insert(
                        id.clone(),
                        json!({"header":mask.header(),"initial":initial}),
                    );
                }
                let response = json!({"circuit":w.circuit,"coefficients":[w.server,w.slope],"operators":operators});
                coin.native.as_mut().context("native missing")?.tweaks = Some(w);
                response
            }
            Command::NativeTweakFrame {
                operator, frame, ..
            } => {
                let native = coin.native.as_ref().context("native missing")?;
                let result = self.advance_tweak(
                    native.tweaks.as_ref().context("native tweaks missing")?,
                    &native.intent,
                    &coin.secret,
                    operator,
                    frame,
                );
                let native = coin.native.as_mut().context("native missing")?;
                let w = native.tweaks.as_mut().context("native tweaks missing")?;
                match result {
                    Ok(reply) => {
                        w.transcripts
                            .get_mut(operator)
                            .context("native tweak operator missing")?
                            .rounds
                            .push((*frame, reply));
                        if w.transcripts.values().all(|t| t.rounds.len() == 7) {
                            w.secrets = None;
                        }
                        json!({"reply":reply,"tweaks_ready":w.ready()})
                    }
                    Err(_) => {
                        w.secrets = None;
                        w.aborted = true;
                        self.native_tweaks
                            .cache
                            .lock()
                            .map_err(|_| anyhow::anyhow!("native tweak cache poisoned"))?
                            .retain(|(coin, operation, _), _| {
                                *coin != native.intent.coin || *operation != native.intent.operation
                            });
                        json!({"aborted":true,"native_exit_locked":true})
                    }
                }
            }
            Command::NativeTweakSeal { packet } => {
                coin.native
                    .as_mut()
                    .context("native missing")?
                    .tweaks
                    .as_mut()
                    .context("native tweaks missing")?
                    .packet = Some(*packet);
                json!({"packet":packet,"native_pending":true})
            }
            _ => anyhow::bail!("not native tweak command"),
        };
        Ok((coin, response, false))
    }
}
fn slot(request: &Request) -> String {
    format!(
        "{}-{}",
        hex::encode(request.intent.coin),
        hex::encode(request.intent.operation)
    )
}
