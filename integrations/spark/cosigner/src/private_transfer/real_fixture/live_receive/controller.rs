//! Wallet-side SDK callbacks. Native leaf facts remain here, outside Engine.
use super::*;
use crate::{
    joint_identity::{EntryMessage, IdentityParameters, JointIdentityJournal},
    receive::ReceiveJournal,
    standard_claim::{ClaimPlan, Operator},
};
use frost_secp256k1_tr as frost;
use k256::{ProjectivePoint, elliptic_curve::sec1::ToEncodedPoint};
use zark_protocol::{
    point_bytes,
    spark_receive::ReceivePlan,
    timing::{Phase, Span},
};

/// cb-mpc ECDSA-2P entry identity; only frames cross to the in-process signer.
#[cfg(feature = "ecdsa-2p")]
mod ecdsa_entry {
    use super::*;
    use crate::joint_identity::IdentityParameters;
    pub fn create(
        directory: &Path,
        frames: &Path,
        p: &IdentityParameters,
    ) -> Result<JointIdentityJournal> {
        JointIdentityJournal::create_ecdsa(directory, frames, p)
    }
    pub fn keygen(engine: &Engine, identity: &mut JointIdentityJournal) -> Result<()> {
        identity.ecdsa_keygen(&mut |r| engine.handle(r))
    }
    pub fn sign(
        engine: &Engine,
        identity: &mut JointIdentityJournal,
        message: &EntryMessage,
    ) -> Result<Vec<u8>> {
        identity.ecdsa_sign(message, &mut |r| engine.handle(r))
    }
}
#[cfg(not(feature = "ecdsa-2p"))]
mod ecdsa_entry {
    use super::*;
    use crate::joint_identity::IdentityParameters;
    const MISSING: &str = "ZARK_SPARK_ECDSA_2P requires building with the ecdsa-2p feature";
    pub fn create(_: &Path, _: &Path, _: &IdentityParameters) -> Result<JointIdentityJournal> {
        anyhow::bail!(MISSING)
    }
    pub fn keygen(_: &Engine, _: &mut JointIdentityJournal) -> Result<()> {
        anyhow::bail!(MISSING)
    }
    pub fn sign(_: &Engine, _: &mut JointIdentityJournal, _: &EntryMessage) -> Result<Vec<u8>> {
        anyhow::bail!(MISSING)
    }
}
/// `root` holds this coin's wallet files; the signer database and its shared
/// identity frame store live under the separate `network` directory.
pub(super) struct Controller<'a> {
    pub suite: &'a Suite,
    pub root: PathBuf,
    pub cluster: ClaimCluster,
    pub engine: Engine,
    pub identity: JointIdentityJournal,
    pub wallet: Option<ReceiveJournal>,
    native_prepare: Option<[u8; 32]>,
    pub admission: Arc<ObservedAdmission>,
    report: reporting::RunReport,
}
impl<'a> Controller<'a> {
    pub fn new(
        suite: &'a Suite,
        network: &Path,
        root: &Path,
        cluster: ClaimCluster,
        report: &reporting::RunReport,
    ) -> Result<Self> {
        let admission = Arc::new(ObservedAdmission::new(suite.deployment));
        let engine =
            suite.receive_engine_joint_identity(network, &cluster, false, admission.clone())?;
        let coin = random32();
        let params = IdentityParameters {
            intent: Intent {
                deployment: suite.deployment,
                coin,
                previous_state: origin_previous_state(&suite.deployment, &coin)?,
                operation: random32(),
                recipient_claim: origin_field(&suite.deployment, &coin, 0)?,
                revision: 1,
            },
            session: generate_secret(),
            user: random_scalar().to_bytes().into(),
            owner: generate_secret(),
        };
        // The local fixture shares ONLY opaque duplex frames. Key shares,
        // presigning outputs and completed signatures stay in party journals.
        let ecdsa = Suite::entry_flag("ZARK_SPARK_ECDSA_2P");
        let create = if ecdsa {
            ecdsa_entry::create
        } else {
            JointIdentityJournal::create
        };
        let mut identity = create(
            &root.join("wallets/identity"),
            &network.join("signer/state.sqlite.identity-frames"),
            &params,
        )?;
        let allocation = identity.allocation_request()?;
        identity.bind_allocation(&engine.handle(&allocation)?)?;
        if ecdsa {
            // Key generation follows allocation and precedes every entry signature.
            let started = std::time::Instant::now();
            ecdsa_entry::keygen(&engine, &mut identity)?;
            eprintln!("ECDSA-2P entry key generation: {:?}", started.elapsed());
        }
        let controller = Self {
            suite,
            root: root.into(),
            cluster: cluster.clone(),
            engine,
            identity,
            wallet: None,
            native_prepare: None,
            admission: admission.clone(),
            report: report.clone(),
        };
        // Reopen before native authentication, without preparing an unbound
        // ticket. Every ticket must include the actual challenge digest.
        drop(controller);
        let identity = JointIdentityJournal::open(&root.join("wallets/identity"))?;
        let engine =
            suite.receive_engine_joint_identity(network, &cluster, false, admission.clone())?;
        let controller = Self {
            suite,
            root: root.into(),
            cluster,
            engine,
            identity,
            wallet: None,
            native_prepare: None,
            admission,
            report: report.clone(),
        };
        Ok(controller)
    }
    pub fn call(&mut self, v: &Value) -> Result<Value> {
        match v["op"].as_str().context("SDK callback operation missing")? {
            "identity_public" => Ok(json!(self.identity.public_key()?)),
            "identity_message" => {
                let message = self.entry_message(v)?;
                Ok(json!(self.sign_identity(&message)?))
            }
            "prepare_claim" => self.prepare(v),
            "leaf_public" => {
                let w = self.wallet.as_ref().context("joint leaf not prepared")?;
                ensure!(
                    v["leaf_id"] == w.claim_plan().leaf_id,
                    "SDK leaf public key lookup differs"
                );
                Ok(json!(w.user_key()))
            }
            "claim_frost" => self.sign(v),
            _ => anyhow::bail!("SDK callback outside receive profile"),
        }
    }
    /// Entry signs only an operator challenge naming this identity or this
    /// claim's own payload; the SDK driver never supplies a digest.
    fn entry_message(&self, v: &Value) -> Result<EntryMessage> {
        let raw = bytes(v, "message")?;
        match v["kind"]
            .as_str()
            .context("identity message kind missing")?
        {
            "challenge" => EntryMessage::challenge(&raw, &self.identity.public_key()?),
            "claim" => {
                let w = self
                    .wallet
                    .as_ref()
                    .context("claim payload before claim preparation")?;
                EntryMessage::claim(&raw, &w.claim_plan().transfer_id, &w.packages()?)
            }
            _ => anyhow::bail!("identity message outside receive profile"),
        }
    }
    fn sign_identity(&mut self, message: &EntryMessage) -> Result<Vec<u8>> {
        let digest = message.digest();
        if let Some(signature) = self.identity.saved_signature(&digest)? {
            return Ok(signature);
        }
        let started = std::time::Instant::now();
        let signature = if self.identity.uses_ecdsa() {
            let _span = Span::new(Phase::IdentityMpc);
            ecdsa_entry::sign(&self.engine, &mut self.identity, message)?
        } else {
            super::exit::sign_identity(&self.engine, &mut self.identity, digest)?
        };
        eprintln!(
            "Joint identity message-bound signature: {:?}",
            started.elapsed()
        );
        Ok(signature)
    }
    fn prepare(&mut self, v: &Value) -> Result<Value> {
        let saved_path = self.root.join("native-prepare.private.json");
        if saved_path.exists() {
            let saved: Value = serde_json::from_slice(&fs::read(&saved_path)?)?;
            ensure!(saved == *v, "resumed native claim input changed");
        }
        let digest = hash(&[&serde_json::to_vec(v)?]);
        if let Some(saved) = self.native_prepare {
            ensure!(saved == digest, "native receive preparation changed");
            return Ok(json!(
                self.wallet
                    .as_ref()
                    .context("receive journal missing")?
                    .packages()?
            ));
        }
        ensure!(v["threshold"] == 2, "native receive threshold");
        let recipients = v["recipients"]
            .as_array()
            .context("native recipients missing")?;
        ensure!(
            recipients.len() == self.cluster.operators.len(),
            "native recipient count differs"
        );
        let mut observed = std::collections::BTreeSet::new();
        for r in recipients {
            let id = r["identifier"]
                .as_str()
                .context("native recipient ID missing")?;
            let pinned = self
                .cluster
                .operators
                .get(id)
                .context("unconfigured native recipient")?;
            ensure!(
                r["index"] == pinned.index
                    && bytes(r, "public_key")? == pinned.encryption_key
                    && observed.insert(id),
                "native recipient configuration differs"
            );
        }
        let leaves = v["leaves"].as_array().context("native leaves missing")?;
        ensure!(
            leaves.len() == 1,
            "ordinary receive profile supports one root"
        );
        let leaf = &leaves[0];
        let n = &leaf["node"];
        ensure!(
            n["parent_node_id"].is_null()
                && n["direct_tx"].is_null()
                && n["direct_refund_tx"].is_null(),
            "ordinary receive requires root-only native layout"
        );
        let root_tx: bitcoin::Transaction =
            bitcoin::consensus::deserialize(&bytes(leaf, "node_raw")?)?;
        let refund: bitcoin::Transaction =
            bitcoin::consensus::deserialize(&bytes(leaf, "refund_raw")?)?;
        ensure!(
            root_tx.input.len() == 1
                && root_tx.output.len() == 2
                && root_tx.input[0].sequence.0 == 1 << 30
                && refund.input.len() == 1
                && refund.input[0].previous_output.txid == root_tx.compute_txid()
                && refund.input[0].previous_output.vout == 0,
            "ordinary native root shape"
        );
        let delay = refund.input[0].sequence.0 & 0xffff;
        ensure!(
            (200..=1900).contains(&delay) && delay.is_multiple_of(100),
            "ordinary native receive window"
        );
        let amount = n["value"].as_u64().context("native leaf amount missing")?;
        ensure!(
            DENOMINATIONS_SAT.contains(&amount) && root_tx.output[0].value.to_sat() == amount,
            "funded fixture amount differs"
        );
        let parse_point = |v: &Value| -> Result<k256::ProjectivePoint> {
            Ok(k256::PublicKey::from_sec1_bytes(&hex::decode(
                v.as_str().context("native point encoding")?,
            )?)?
            .to_projective())
        };
        let combined = parse_point(&n["verifying_public_key"])?;
        let old_operator = parse_point(&n["signing_keyshare"]["public_key"])?;
        let cipher = bytes(leaf, "incoming_ciphertext")?;
        let decrypt = self.identity.decrypt_request(&cipher)?;
        let incoming = self
            .identity
            .decrypt_incoming(&cipher, &self.engine.handle(&decrypt)?)?;
        ensure!(
            old_operator + ProjectivePoint::GENERATOR * zark_protocol::scalar(&incoming[..])?
                == combined,
            "native incoming USER decomposition differs"
        );
        let intent = self.identity.intent().clone();
        let coin = intent.coin;
        let joint = k256::PublicKey::from_sec1_bytes(&self.identity.public_key()?)?.to_projective();
        let operator = point_bytes(combined - joint)?;
        let compressed =
            |p: ProjectivePoint| p.to_affine().to_encoded_point(true).as_bytes().to_vec();
        use bitcoin::hashes::Hash;
        // Reject a unilateral intermediate refund before creating any MPC or
        // signing nonce. A later claim signature cannot revoke this transaction.
        let observed: Value = serde_json::from_slice(&fs::read(
            self.root.join("native-intermediate-observation.json"),
        )?)?;
        let incoming_prefix = super::evidence::checked(v, &observed, &self.identity.public_key()?)?;
        atomic_write(
            &self.root.join("native-prepare.private.json"),
            &serde_json::to_vec(v)?,
        )?;
        let keys = crate::initial_exit::NativeLeafKeys::new(
            crate::keys::Scope {
                deployment: self.suite.deployment,
                coin,
                purpose: crate::keys::Purpose::LeafSigning,
            },
            &compressed(joint),
            &compressed(combined - joint),
            &compressed(combined),
        )?;
        let anchor = crate::initial_exit::DepositAnchor {
            outpoint: root_tx.input[0].previous_output,
            output: bitcoin::TxOut {
                value: root_tx.output[0].value,
                script_pubkey: root_tx.output[0].script_pubkey.clone(),
            },
        };
        if let Err(error) = crate::initial_exit::validate_received_root_exit_keys(
            &anchor,
            &keys,
            &incoming_prefix,
            delay,
        ) {
            self.report.save(json!({
                "status":"blocked_unsafe_receive_custody",
                "reason":"intermediate refunds must already pay the joint USER key",
                "ordinary_sdk_claim":false,"zark_admission":false,
            }))?;
            anyhow::bail!("unsafe intermediate receive custody: {error}");
        }
        let params = self.identity.receive_parameters(
            ReceivePlan {
                salt: random32(),
                anchor_txid: root_tx.input[0].previous_output.txid.to_byte_array(),
                anchor_vout: root_tx.input[0].previous_output.vout,
                amount,
                native_delay: delay,
                operator: operator.to_vec(),
                cluster: self.cluster.digest()?,
            },
            ClaimPlan {
                deployment: self.suite.deployment,
                operation: intent.operation,
                transfer_id: v["transfer_id"]
                    .as_str()
                    .context("native transfer ID missing")?
                    .into(),
                leaf_id: n["id"].as_str().context("native leaf ID missing")?.into(),
                incoming_user_key: compressed(
                    ProjectivePoint::GENERATOR * zark_protocol::scalar(&incoming[..])?,
                ),
                joint_user_key: compressed(joint),
                threshold: 2,
                operators: self
                    .cluster
                    .operators
                    .iter()
                    .map(|(id, o)| {
                        (
                            id.clone(),
                            Operator {
                                share_index: o.index,
                                encryption_key: o.encryption_key.clone(),
                            },
                        )
                    })
                    .collect(),
            },
            random32(),
        )?;
        let verifier = self.suite.receive_verifier(&self.cluster)?;
        let additive = Suite::entry_flag("ZARK_SPARK_ADDITIVE_RECEIVE");
        let create = if additive {
            ReceiveJournal::create_additive
        } else {
            ReceiveJournal::create
        };
        let mut wallet = create(
            &self.root.join("wallets/receive"),
            &params,
            incoming,
            &verifier,
            self.cluster.clone(),
        )?;
        atomic_write(
            &self.root.join("native-prepare.private.json"),
            &serde_json::to_vec(v)?,
        )?;
        let req = wallet.prepare_request()?;
        let prepared = self.engine.handle(&req)?;
        wallet.bind_prepare(&prepared)?;
        let span = Span::new(Phase::ReceiveTweak);
        if additive {
            let request = wallet.tweak_request()?;
            wallet.bind_tweak(&self.engine.handle(&request)?)?;
        } else {
            for id in self.cluster.operators.keys() {
                wallet.bind_initial_frame(id, &self.engine.receive_initial_frame(&req, id)?)?;
                for _ in 0..7 {
                    let (request, frame) = wallet.next_mpc_request(id)?;
                    let (response, reply) = self.engine.handle_receive_frame(&request, &frame)?;
                    wallet.bind_mpc_reply(
                        &request,
                        &response,
                        &reply.context("joint receive MPC aborted")?,
                    )?;
                }
                wallet.finish_operator(id)?;
            }
        }
        drop(span);
        let packages = wallet.packages()?;
        self.wallet = Some(wallet);
        self.native_prepare = Some(digest);
        Ok(json!(packages))
    }
    fn sign(&mut self, v: &Value) -> Result<Value> {
        let w = self
            .wallet
            .as_mut()
            .context("joint native claim preparation absent")?;
        let jobs = v["jobs"]
            .as_array()
            .context("native claim signing jobs missing")?;
        ensure!(jobs.len() == 2, "ordinary root requires two claim refunds");
        let (_, sighashes) = w.expected_refunds()?;
        let mut commitments = Vec::new();
        for (i, j) in jobs.iter().enumerate() {
            ensure!(
                j["leaf_id"] == w.claim_plan().leaf_id && bytes32(j, "sighash")? == sighashes[i],
                "native claim job differs from proof-bound refund"
            );
            let raw = k256::PublicKey::from_sec1_bytes(&bytes(j, "combined")?)?.to_projective();
            let node = &serde_json::from_slice::<Value>(&fs::read(
                self.root.join("native-prepare.private.json"),
            )?)?["leaves"][0]["node"];
            ensure!(
                hex::encode(raw.to_affine().to_encoded_point(true).as_bytes())
                    == node["verifying_public_key"]
                        .as_str()
                        .context("native combined key missing")?,
                "native claim combined key differs"
            );
            let mut ops = crate::leaf_signing::OperatorCommitments::new();
            for (id, c) in j["operators"]
                .as_object()
                .context("native operator commitments missing")?
            {
                ops.insert(
                    frost::Identifier::deserialize(&hex::decode(id)?)?,
                    frost::round1::SigningCommitments::new(
                        frost::round1::NonceCommitment::deserialize(&bytes(c, "hiding")?)?,
                        frost::round1::NonceCommitment::deserialize(&bytes(c, "binding")?)?,
                    ),
                );
            }
            commitments.push(ops);
        }
        w.bind_operators([commitments[0].clone(), commitments[1].clone()])?;
        let a = w.authorization()?;
        let input = w.prover_toml()?;
        let proof = self.suite.prove(
            "receive",
            &input,
            &a.encode()?,
            &self.root.join("proofs/receive"),
        )?;
        let req = w.issue_request(
            proof,
            &self.suite.receive_verifier(&self.cluster)?,
            &self.root.join("scratch"),
        )?;
        let response = self.engine.handle(&req)?;
        w.bind_partials(&response)?;
        (0..2).map(|i|->Result<Value>{let c=w.contribution(i)?;Ok(json!({"hiding":c.commitment.hiding().serialize()?,"binding":c.commitment.binding().serialize()?,"share":c.signature_share.serialize()}))}).collect::<Result<Vec<_>>>().map(|rows|json!(rows))
    }
}
