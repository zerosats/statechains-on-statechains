//! Wallet-local ordinary Spark receive. Native facts and encrypted claim
//! packages never cross the blind-signing boundary. Reopening replays only
//! frozen MPC frames; no replacement randomness is generated on recovery.
mod additive;
#[cfg(test)]
mod additive_tests;
mod material;
mod mpc;
mod recovery;
mod signing;
use crate::{
    native_bridge::CurrentUserKey,
    private_transfer::persistence::OperationFile,
    standard_claim::{ClaimPlan, TweakProofs},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use zark_protocol::{
    hash,
    owner_auth::normalized_key,
    point, point_bytes, scalar,
    spark_lineage::{Config, Digest, Intent},
    spark_receive::{ClaimCluster, PinnedReceiveVerifier, ReceivePlan},
    spark_single_user::Opening,
    spark_wire::{Command, Request},
};
use zark_spark_claim_mpc::ClaimCircuit;
use zeroize::{Zeroize, Zeroizing};
const FILE: &str = "private-receive.json";
const MAX: usize = 512 * 1024;
pub struct ReceiveParameters {
    pub intent: Intent,
    pub session: Digest,
    pub user: Digest,
    pub owner: Digest,
    pub server: [u8; 64],
    pub server_salt: Digest,
    pub backing_salt: Digest,
    pub plan: ReceivePlan,
    pub claim: ClaimPlan,
}
impl Drop for ReceiveParameters {
    fn drop(&mut self) {
        self.session.zeroize();
        self.user.zeroize();
        self.owner.zeroize();
        self.backing_salt.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MpcSecrets {
    incoming: Digest,
    slope: Digest,
    seeds: BTreeMap<String, Digest>,
}
impl Drop for MpcSecrets {
    fn drop(&mut self) {
        self.incoming.zeroize();
        self.slope.zeroize();
        for s in self.seeds.values_mut() {
            s.zeroize();
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Round {
    request: Vec<u8>,
    reply: Option<Digest>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorTranscript {
    rounds: Vec<Round>,
    ciphertext: Option<Digest>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Operator {
    id: Vec<u8>,
    commitment: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    registry: Digest,
    cluster: ClaimCluster,
    circuit: Digest,
    config: Config,
    policy: Digest,
    intent: Intent,
    session: Digest,
    user: Digest,
    owner: Digest,
    server: Vec<u8>,
    server_salt: Digest,
    backing_salt: Digest,
    plan: ReceivePlan,
    claim: ClaimPlan,
    openings: [Opening; 2],
    mpc: Option<MpcSecrets>,
    prepared: Option<Value>,
    operators: Option<[Vec<Operator>; 2]>,
    proofs: Option<TweakProofs>,
    transcripts: BTreeMap<String, OperatorTranscript>,
    requests: BTreeMap<u8, Vec<u8>>,
    partials: Option<[Digest; 2]>,
    /// Pinned at creation: only an additive journal ever sends u = b - x_w.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    additive: bool,
}
impl Drop for Record {
    fn drop(&mut self) {
        self.session.zeroize();
        self.user.zeroize();
        self.owner.zeroize();
        self.backing_salt.zeroize();
    }
}
pub struct ReceiveJournal {
    file: OperationFile,
    directory: PathBuf,
    record: Record,
    circuit: ClaimCircuit,
    key: CurrentUserKey,
    cache: BTreeMap<String, (usize, zark_spark_claim_mpc::ClaimEvaluator, Vec<u8>)>,
}
impl ReceiveJournal {
    fn persist(&self) -> Result<()> {
        self.file
            .save(&Zeroizing::new(serde_json::to_vec(&self.record)?), MAX)
    }
    pub fn intent(&self) -> &Intent {
        &self.record.intent
    }
    pub fn claim_plan(&self) -> &ClaimPlan {
        &self.record.claim
    }
    pub fn user_key(&self) -> &[u8] {
        self.key.native_keys().user_key()
    }
    fn context(&self) -> Result<zark_protocol::spark_bootstrap::BootstrapContext> {
        let i = &self.record.intent;
        Ok(zark_protocol::spark_bootstrap::BootstrapContext {
            deployment: i.deployment,
            coin: i.coin,
            allocation_state: i.previous_state,
            operation: i.operation,
            session: normalized_key(&self.record.session)?
                .verifying_key()
                .to_bytes()
                .into(),
            revision: i.revision,
        })
    }
    fn raw_user(&self) -> Result<[u8; 64]> {
        point_bytes(
            point(&self.record.server)?
                + k256::ProjectivePoint::GENERATOR * scalar(&self.record.user)?,
        )
    }
    pub fn backing_commitment(&self) -> Result<Digest> {
        let c = self.context()?;
        self.record.plan.backing(
            &zark_protocol::spark_recovery::RecoveryContext {
                deployment: c.deployment,
                coin: c.coin,
                previous_state: c.allocation_state,
                operation: c.operation,
                session: c.session,
                successor_state: [1; 32],
                revision: c.revision,
            },
            self.raw_user()?,
            self.record.backing_salt,
        )
    }
    fn commitments(&self) -> Result<[Digest; 2]> {
        let c = self.context()?;
        let plan = self.record.plan.commitment(self.raw_user()?)?;
        let server = self.record.server.as_slice().try_into()?;
        Ok([
            zark_protocol::spark_receive::blinding_commitment(
                &c,
                &plan,
                &server,
                0,
                &self.record.openings[0],
            )?,
            zark_protocol::spark_receive::blinding_commitment(
                &c,
                &plan,
                &server,
                1,
                &self.record.openings[1],
            )?,
        ])
    }
    fn frozen(&self, purpose: u8) -> Result<Option<Request>> {
        self.persist()?;
        self.record
            .requests
            .get(&purpose)
            .map(|bytes| Request::decode(bytes))
            .transpose()
    }
    fn freeze(&mut self, command: Command) -> Result<Request> {
        let purpose = command.purpose();
        ensure!(
            !self.record.requests.contains_key(&purpose),
            "receive request already frozen"
        );
        let r = Request::sign(
            self.record.intent.clone(),
            command,
            &normalized_key(&self.record.session)?,
        )?;
        self.record.requests.insert(purpose, r.encode()?);
        self.persist()?;
        Ok(r)
    }
    pub fn prepare_request(&mut self) -> Result<Request> {
        if let Some(r) = self.frozen(23)? {
            return Ok(r);
        }
        let c = self.context()?;
        let plan = self.record.plan.commitment(self.raw_user()?)?;
        let backing = self.backing_commitment()?;
        let capability = zark_protocol::spark_lineage::capability_commitment(
            &c.deployment,
            &c.coin,
            &self.record.owner,
        )?;
        let nonce_commitments = self.commitments()?;
        let owner = zark_protocol::spark_wire::OwnerAuthorization::sign_receive(
            &c,
            &backing,
            &capability,
            &plan,
            &self.record.cluster.digest()?,
            &nonce_commitments,
            &normalized_key(&self.record.owner)?,
        )?;
        self.freeze(Command::ReceivePrepare {
            backing,
            capability,
            plan,
            nonce_commitments,
            owner,
        })
    }
    pub fn bind_prepare(&mut self, response: &Value) -> Result<()> {
        ensure!(
            self.record.requests.contains_key(&23),
            "receive prepare request not frozen"
        );
        if let Some(saved) = &self.record.prepared {
            ensure!(saved == response, "receive preparation retry changed");
            self.validate_prepared()?;
            return self.persist();
        }
        self.record.prepared = Some(response.clone());
        if let Err(error) = self.validate_prepared() {
            self.record.prepared = None;
            return Err(error);
        }
        if !self.record.additive {
            self.record.proofs = Some(self.proofs()?);
        }
        self.persist()
    }
    fn proofs(&self) -> Result<TweakProofs> {
        if let Some(proofs) = &self.record.proofs {
            proofs.validate(&self.record.claim)?;
            return Ok(proofs.clone());
        }
        use k256::{ProjectivePoint, elliptic_curve::sec1::ToEncodedPoint};
        let prepared = self
            .record
            .prepared
            .as_ref()
            .context("receive preparation absent")?;
        ensure!(!self.record.additive, "additive receive tweak not bound");
        let server: Vec<Vec<u8>> = serde_json::from_value(prepared["coefficients"].clone())?;
        let secrets = self
            .record
            .mpc
            .as_ref()
            .context("receive polynomial retired")?;
        let a = [
            ProjectivePoint::GENERATOR * (scalar(&secrets.incoming)? - scalar(&self.record.user)?),
            ProjectivePoint::GENERATOR * scalar(&secrets.slope)?,
        ];
        let coefficients = (0..2)
            .map(|i| -> Result<Vec<u8>> {
                let p = a[i] + point(&server[i])?;
                point_bytes(p)?;
                Ok(p.to_affine().to_encoded_point(true).as_bytes().to_vec())
            })
            .collect::<Result<_>>()?;
        let proofs = TweakProofs { coefficients };
        proofs.validate(&self.record.claim)?;
        Ok(proofs)
    }
    fn validate_prepared(&self) -> Result<()> {
        let p = self
            .record
            .prepared
            .as_ref()
            .context("receive preparation absent")?;
        for (name, expected) in [
            ("registry", self.record.registry),
            ("cluster", self.record.cluster.digest()?),
            ("circuit", self.circuit.digest()),
        ] {
            ensure!(
                serde_json::from_value::<Digest>(p[name].clone())? == expected,
                "receive {name} differs"
            );
        }
        ensure!(
            p.get("additive").is_some() == self.record.additive,
            "receive tweak mode differs from journal"
        );
        if self.record.additive {
            ensure!(
                p["additive"] == true
                    && p.get("coefficients").is_none()
                    && p.get("operators").is_none(),
                "additive receive preparation shape"
            );
            return self.validate_nonces(p);
        }
        let coefficients: Vec<Vec<u8>> = serde_json::from_value(p["coefficients"].clone())?;
        ensure!(
            coefficients.len() == 2 && point(&coefficients[0])? == -point(&self.record.server)?,
            "receive server polynomial constant differs"
        );
        point(&coefficients[1])?;
        let ops = p["operators"]
            .as_object()
            .context("receive operator headers absent")?;
        ensure!(
            ops.keys().eq(self.record.cluster.operators.keys()),
            "receive operator header coverage"
        );
        for op in ops.values() {
            let header: Vec<u8> = serde_json::from_value(op["header"].clone())?;
            ensure!(
                header.len() == 81
                    && header[0] == 4
                    && serde_json::from_value::<Digest>(op["initial"].clone())? != [0; 32],
                "receive operator encryption header"
            );
            k256::PublicKey::from_sec1_bytes(&header[..65])?;
        }
        self.validate_nonces(p)
    }
    fn validate_nonces(&self, p: &Value) -> Result<()> {
        let commitments = self.commitments()?;
        let nonces = p["nonces"].as_array().context("receive nonces absent")?;
        ensure!(nonces.len() == 2, "receive nonce count");
        for i in 0..2 {
            let nonce: Vec<u8> = serde_json::from_value(nonces[i]["point"].clone())?;
            point(&nonce)?;
            let id = hash(&[
                b"ZARK/spark/signer/receive-nonce/v1",
                zark_protocol::spark_receive::PURPOSE.as_bytes(),
                &self.record.registry,
                &self.record.cluster.digest()?,
                &self.record.circuit,
                &self.context()?.encode()?,
                &self.backing_commitment()?,
                &zark_protocol::spark_lineage::capability_commitment(
                    &self.record.intent.deployment,
                    &self.record.intent.coin,
                    &self.record.owner,
                )?,
                &self.record.plan.commitment(self.raw_user()?)?,
                &self.record.server,
                &[i as u8],
                &nonce,
                &commitments[i],
            ]);
            ensure!(
                serde_json::from_value::<Digest>(nonces[i]["id"].clone())? == id
                    && nonces[i]["index"] == i,
                "receive nonce identity differs"
            );
        }
        ensure!(
            nonces[0]["point"] != nonces[1]["point"],
            "receive original nonce reuse"
        );
        Ok(())
    }
}
