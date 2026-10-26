//! Funded ordinary Spark -> joint USER -> proof-gated Zark origin.
//! The trusted observer sees the disclosed backing opening, public transaction
//! columns and active anchor. Entry/exit use the interim disclosure model.
#[path = "live_receive/controller.rs"]
mod controller;
#[path = "live_receive/desktop.rs"]
mod desktop;
#[path = "live_receive/entry.rs"]
mod entry;
#[path = "live_receive/evidence.rs"]
mod evidence;
#[path = "live_receive/exit.rs"]
mod exit;
#[path = "live_receive/pipe.rs"]
mod pipe;
#[path = "live_receive/reporting.rs"]
mod reporting;
#[path = "live_receive/share_release_exit.rs"]
mod share_release_exit;
use self::{controller::Controller, pipe::Pipe};
use super::*;
use std::sync::{Arc, Mutex};
use zark_protocol::{
    handoff::TransferContext,
    spark_receive::{ClaimCluster, ClaimOperator},
};
use zark_signer::engine::Admission;
const NATIVE: &str = "/src/open-ssp/.regtest/zark-spark-acceptance/native";
/// Whole leaf values entered and moved, largest first. Smaller leaves leave
/// Spark's direct refund (value - 955) at or below the recovery proofs'
/// fee + dust floor.
const DENOMINATIONS_SAT: [u64; 3] = [10_000, 5_000, 2_000];
pub(super) struct ObservedAdmission {
    deployment: [u8; 32],
    approved: Mutex<Option<crate::native_observation::OriginPermit>>,
    completed: Mutex<Option<crate::native_observation::CompletionPermit>>,
}
impl ObservedAdmission {
    fn new(deployment: [u8; 32]) -> Self {
        Self {
            deployment,
            approved: Mutex::new(None),
            completed: Mutex::new(None),
        }
    }
}
impl Admission for ObservedAdmission {
    fn authorize(&self, c: &TransferContext) -> Result<()> {
        ensure!(
            c.deployment == self.deployment,
            "native receive admission deployment"
        );
        Ok(())
    }
    fn authorize_spark_received_origin(&self, c: &TransferContext, b: &[u8; 32]) -> Result<()> {
        self.authorize(c)?;
        self.approved
            .lock()
            .map_err(|_| anyhow::anyhow!("native observer poisoned"))?
            .as_ref()
            .context("completed native receive has not been observed")?
            .authorize(c, b)
    }
    fn authorize_spark_native_completion(
        &self,
        c: &TransferContext,
        completion: &zark_protocol::spark_wire::NativeCompletion,
        evidence: &[u8; 32],
    ) -> Result<()> {
        self.authorize(c)?;
        self.completed
            .lock()
            .map_err(|_| anyhow::anyhow!("native observer poisoned"))?
            .as_ref()
            .context("completed native exit has not been independently observed")?
            .authorize(c, completion, evidence)
    }
}
fn bytes(v: &Value, key: &str) -> Result<Vec<u8>> {
    serde_json::from_value(v[key].clone()).with_context(|| format!("native field {key}"))
}
fn bytes32(v: &Value, key: &str) -> Result<[u8; 32]> {
    Ok(bytes(v, key)?.as_slice().try_into()?)
}
fn observation_context(request: &Request) -> TransferContext {
    let i = &request.intent;
    TransferContext {
        deployment: i.deployment,
        coin: i.coin,
        previous_state: i.previous_state,
        operation: i.operation,
        recipient_claim: i.recipient_claim,
        session_auth: request.session,
        scope: zark_protocol::handoff::OperationScope::Single,
        start_revision: i.revision,
    }
}
fn uuid() -> String {
    let mut raw = random32();
    raw[6] = (raw[6] & 15) | 64;
    raw[8] = (raw[8] & 63) | 128;
    let h = hex::encode(&raw[..16]);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}
/// The acceptance operators' claim cluster, read from the retained regtest.
fn acceptance_cluster() -> Result<ClaimCluster> {
    let config_path=PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../work/zark-spark/sources/open-ssp/.regtest/zark-spark-acceptance/native/operators.json");
    let config: Value = serde_json::from_slice(&fs::read(config_path)?)?;
    let cluster = ClaimCluster {
        threshold: 2,
        operators: config
            .as_array()
            .context("native operators absent")?
            .iter()
            .map(|v| -> Result<_> {
                let index = v["id"].as_u64().context("native operator ID missing")? as u16 + 1;
                Ok((
                    format!("{index:064x}"),
                    ClaimOperator {
                        index,
                        encryption_key: hex::decode(
                            v["identity_public_key"]
                                .as_str()
                                .context("native operator identity missing")?,
                        )?,
                    },
                ))
            })
            .collect::<Result<_>>()?,
    };
    cluster.validate()?;
    Ok(cluster)
}
