//! Wallet-local fixed joint identity. Completed keys/signatures are wallet
//! outputs; identity digests, nonce coordinates and ECIES headers still expose
//! matching handles under the interim entry/exit disclosure model. Frames use a
//! shared local transport store in the explicit single-machine fixture; private
//! inputs and final outputs always stay in separate locked party journals.
mod decrypt;
mod ecdsa;
mod entry_message;
mod signing;
#[cfg(test)]
mod tests;
use crate::{
    private_transfer::persistence::OperationFile, receive::ReceiveParameters,
    standard_claim::ClaimPlan,
};
use anyhow::{Context, Result, ensure};
pub use entry_message::EntryMessage;
#[cfg(all(test, feature = "ecdsa-2p"))]
pub(crate) use entry_message::{claim_payload, encode_challenge};
use k256::{ProjectivePoint, elliptic_curve::sec1::ToEncodedPoint};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use zark_protocol::{
    hash,
    owner_auth::normalized_key,
    point, point_bytes, random_scalar, random32, scalar,
    spark_lineage::{Digest, Intent},
    spark_receive::ReceivePlan,
    spark_wire::{
        Command, Request, identity_decrypt_intent, identity_frame_intent, identity_intent,
        identity_message_intent, identity_sign_intent, opaque_frames::FrameStore,
    },
};
use zark_spark_claim_mpc::identity::{IdentityCircuit, IdentityEvaluator, nonce_public, nonce_r};
use zeroize::{Zeroize, Zeroizing};
const FILE: &str = "private-identity.json";
const MAX: usize = 512 * 1024;
pub struct IdentityParameters {
    pub intent: Intent,
    pub session: Digest,
    pub user: Digest,
    pub owner: Digest,
}
impl Drop for IdentityParameters {
    fn drop(&mut self) {
        self.session.zeroize();
        self.user.zeroize();
        self.owner.zeroize();
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
struct Signing {
    prepare: Vec<u8>,
    nonce: Option<Digest>,
    seed: Option<Digest>,
    prepared: Option<Value>,
    rounds: Vec<Round>,
    presign: Option<Vec<u8>>,
    sign: Option<Vec<u8>>,
    signature: Option<Vec<u8>>,
    aborted: bool,
}
impl Drop for Signing {
    fn drop(&mut self) {
        if let Some(n) = &mut self.nonce {
            n.zeroize();
        }
        if let Some(s) = &mut self.seed {
            s.zeroize();
        }
        if let Some(p) = &mut self.presign {
            p.zeroize();
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    circuit: Digest,
    frames: PathBuf,
    intent: Intent,
    session: Digest,
    user: Digest,
    owner: Digest,
    key_salt: Digest,
    allocation: Vec<u8>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    native_scope: bool,
    server: Option<Vec<u8>>,
    server_salt: Option<Digest>,
    signing: BTreeMap<String, Signing>,
    decryption: BTreeMap<String, Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ecdsa: Option<ecdsa::EcdsaRecord>,
}
impl Drop for Record {
    fn drop(&mut self) {
        self.session.zeroize();
        self.user.zeroize();
        self.owner.zeroize();
        self.key_salt.zeroize();
    }
}
/// Evaluator after `usize` rounds, with the verified reply to resume it.
type ResumableEvaluator = (usize, IdentityEvaluator, Option<(Digest, Vec<u8>)>);
pub struct JointIdentityJournal {
    file: OperationFile,
    record: Record,
    circuit: IdentityCircuit,
    frames: FrameStore,
    cache: BTreeMap<String, ResumableEvaluator>,
}
impl JointIdentityJournal {
    pub fn create(directory: &Path, frames: &Path, p: &IdentityParameters) -> Result<Self> {
        Self::create_with(directory, frames, p, None)
    }
    fn create_with(
        directory: &Path,
        frames: &Path,
        p: &IdentityParameters,
        ecdsa: Option<ecdsa::EcdsaRecord>,
    ) -> Result<Self> {
        ensure!(
            frames.is_absolute() && scalar(&p.user)? != k256::Scalar::ZERO,
            "joint identity parameters"
        );
        let circuit = IdentityCircuit::new()?;
        let allocation = Request::sign(
            p.intent.clone(),
            Command::Allocate {},
            &normalized_key(&p.session)?,
        )?;
        let record = Record {
            version: 1,
            circuit: circuit.digest(),
            frames: frames.into(),
            intent: p.intent.clone(),
            session: p.session,
            user: p.user,
            owner: p.owner,
            key_salt: random32(),
            allocation: allocation.encode()?,
            native_scope: false,
            server: None,
            server_salt: None,
            signing: BTreeMap::new(),
            decryption: BTreeMap::new(),
            ecdsa,
        };
        let file = OperationFile::create(directory, FILE)?;
        let out = Self {
            file,
            record,
            circuit,
            frames: FrameStore::open(frames, 512 * 1024 * 1024)?,
            cache: BTreeMap::new(),
        };
        out.persist()?;
        Ok(out)
    }
    pub fn open(directory: &Path) -> Result<Self> {
        let (file, bytes) = OperationFile::open(directory, FILE, MAX)?;
        let record: Record = serde_json::from_slice(&bytes)?;
        ensure!(
            serde_json::to_vec(&record)? == *bytes
                && record.version == 1
                && record.frames.is_absolute(),
            "joint identity record encoding/version"
        );
        let circuit = IdentityCircuit::new()?;
        ensure!(
            circuit.digest() == record.circuit,
            "joint identity circuit changed"
        );
        let frames = FrameStore::open(&record.frames, 512 * 1024 * 1024)?;
        let out = Self {
            file,
            record,
            circuit,
            frames,
            cache: BTreeMap::new(),
        };
        out.validate()?;
        Ok(out)
    }
    fn persist(&self) -> Result<()> {
        self.file
            .save(&Zeroizing::new(serde_json::to_vec(&self.record)?), MAX)
    }
    fn signed(&self, intent: Intent, command: Command) -> Result<Request> {
        Request::sign(intent, command, &normalized_key(&self.record.session)?)
    }
    fn key_commitment(&self) -> Result<Digest> {
        zark_spark_claim_mpc::identity::key_commitment(&self.record.user, &self.record.key_salt)
    }
    pub fn allocation_request(&self) -> Result<Request> {
        self.persist()?;
        Request::decode(&self.record.allocation)
    }
    pub fn bind_allocation(&mut self, response: &Value) -> Result<()> {
        ensure!(
            !self.record.native_scope,
            "native identity is already bound to its current owner"
        );
        let server: Vec<u8> = serde_json::from_value(response["server"].clone())?;
        point(&server)?;
        let salt: Digest = serde_json::from_value(response["server_salt"].clone())?;
        ensure!(
            salt != [0; 32]
                && response["state"] == serde_json::json!(self.record.intent.previous_state)
                && response["revision"] == 1,
            "identity allocation response"
        );
        if let Some(old) = &self.record.server {
            ensure!(
                *old == server && self.record.server_salt == Some(salt),
                "identity allocation changed"
            );
        }
        self.record.server = Some(server);
        self.record.server_salt = Some(salt);
        if self.record.ecdsa.is_none() {
            self.public_key()?;
        }
        self.persist()
    }
    /// The signer's identity share: the allocation point, or its cb-mpc share
    /// once ECDSA-2P key generation replaced it.
    pub fn server(&self) -> Result<[u8; 64]> {
        let server = match &self.record.ecdsa {
            Some(ecdsa) => ecdsa.server()?,
            None => self
                .record
                .server
                .as_deref()
                .context("identity not allocated")?,
        };
        Ok(server.try_into()?)
    }
    pub fn intent(&self) -> &Intent {
        &self.record.intent
    }
    pub fn public_key(&self) -> Result<Vec<u8>> {
        let p = point(&self.server()?)? + ProjectivePoint::GENERATOR * scalar(&self.record.user)?;
        point_bytes(p)?;
        Ok(p.to_affine().to_encoded_point(true).as_bytes().to_vec())
    }
    /// Blind Schnorr login reuses this identity's wallet share and key salt, so
    /// the signer sees one fixed key commitment for both signing paths.
    pub fn auth_parameters(&self) -> Result<crate::blind_auth::AuthParameters> {
        Ok(crate::blind_auth::AuthParameters {
            intent: self.record.intent.clone(),
            session: self.record.session,
            user: self.record.user,
            key_salt: self.record.key_salt,
            server: self.server()?,
        })
    }
    pub fn receive_parameters(
        &self,
        plan: ReceivePlan,
        claim: ClaimPlan,
        backing_salt: Digest,
    ) -> Result<ReceiveParameters> {
        ensure!(
            !self.record.native_scope,
            "native exit identity cannot create a receive allocation"
        );
        ensure!(
            claim.joint_user_key == self.public_key()?
                && claim.operation == self.record.intent.operation,
            "receive must retain the fixed joint identity/USER key"
        );
        self.persist()?;
        Ok(ReceiveParameters {
            intent: self.record.intent.clone(),
            session: self.record.session,
            user: self.record.user,
            owner: self.record.owner,
            server: self.server()?,
            server_salt: self.record.server_salt.context("identity salt missing")?,
            backing_salt,
            plan,
            claim,
        })
    }
    fn validate(&self) -> Result<()> {
        let allocation = Request::decode(&self.record.allocation)?;
        ensure!(
            allocation.intent == self.record.intent
                && allocation.session[..]
                    == normalized_key(&self.record.session)?
                        .verifying_key()
                        .to_bytes()[..]
                && if self.record.native_scope {
                    matches!(allocation.command, Command::NativeExitPrepare { .. })
                        && self.record.server.is_some()
                        && self.record.decryption.is_empty()
                } else {
                    matches!(allocation.command, Command::Allocate {})
                },
            "joint identity allocation context"
        );
        if self.record.native_scope {
            let Command::NativeExitPrepare {
                plan,
                nonce_commitments,
                owner,
            } = &allocation.command
            else {
                unreachable!()
            };
            let capability = zark_protocol::spark_lineage::capability_commitment(
                &self.record.intent.deployment,
                &self.record.intent.coin,
                &self.record.owner,
            )?;
            let context = zark_protocol::spark_native::ExitContext {
                deployment: self.record.intent.deployment,
                coin: self.record.intent.coin,
                current_state: self.record.intent.previous_state,
                operation: self.record.intent.operation,
                session: allocation.session,
                revision: self.record.intent.revision,
            };
            context.verify_owner(
                plan,
                nonce_commitments,
                &capability,
                &owner.public_key,
                &owner.signature.as_slice().try_into()?,
            )?;
        }
        ensure!(
            scalar(&self.record.user)? != k256::Scalar::ZERO
                && self.record.server.is_some() == self.record.server_salt.is_some()
                && self.record.signing.len() <= 8
                && self.record.decryption.len() <= 16,
            "identity journal coverage"
        );
        if self.record.server.is_some() && self.record.ecdsa.is_none() {
            self.public_key()?;
        }
        self.validate_ecdsa()?;
        self.validate_signing()?;
        for (id, encoded) in &self.record.decryption {
            let r = Request::decode(encoded)?;
            let Command::IdentityDecrypt { ephemeral } = &r.command else {
                anyhow::bail!("identity decryption command")
            };
            ensure!(
                *id == hex::encode(hash(&[ephemeral]))
                    && r.intent == identity_decrypt_intent(&self.record.intent, ephemeral)?
                    && r.session == allocation.session,
                "identity decryption context"
            );
        }
        Ok(())
    }
}
