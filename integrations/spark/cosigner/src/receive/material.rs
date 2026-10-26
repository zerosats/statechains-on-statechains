//! Wallet-only material validation. No method accepts the server private share.
use super::*;
use crate::{
    initial_exit::NativeLeafKeys,
    keys::{Purpose, Scope},
};
use k256::{ProjectivePoint, elliptic_curve::sec1::ToEncodedPoint};
use zark_protocol::{
    random_scalar, random32, spark_lineage,
    spark_native::Participant,
    spark_receive::{ReceiveJob, ReceiveWitness},
    spark_single_user::Opening,
};
use zark_spark_claim_mpc::CircuitSpec;
fn compressed(p: ProjectivePoint) -> Result<Vec<u8>> {
    point_bytes(p)?;
    Ok(p.to_affine().to_encoded_point(true).as_bytes().to_vec())
}
fn key(r: &Record) -> Result<CurrentUserKey> {
    let user = point(&r.server)? + ProjectivePoint::GENERATOR * scalar(&r.user)?;
    let op = point(&r.plan.operator)?;
    CurrentUserKey::new(
        NativeLeafKeys::new(
            Scope {
                deployment: r.intent.deployment,
                coin: r.intent.coin,
                purpose: Purpose::LeafSigning,
            },
            &compressed(user)?,
            &compressed(op)?,
            &compressed(user + op)?,
        )?,
        r.server.as_slice().try_into()?,
        r.user,
    )
}
impl ReceiveJournal {
    pub fn create(
        directory: &Path,
        p: &ReceiveParameters,
        incoming: Zeroizing<Digest>,
        verifier: &PinnedReceiveVerifier,
        cluster: ClaimCluster,
    ) -> Result<Self> {
        Self::create_mode(directory, p, incoming, verifier, cluster, false)
    }
    /// The signer must be deployed with the additive receive tweak.
    pub fn create_additive(
        directory: &Path,
        p: &ReceiveParameters,
        incoming: Zeroizing<Digest>,
        verifier: &PinnedReceiveVerifier,
        cluster: ClaimCluster,
    ) -> Result<Self> {
        Self::create_mode(directory, p, incoming, verifier, cluster, true)
    }
    fn create_mode(
        directory: &Path,
        p: &ReceiveParameters,
        incoming: Zeroizing<Digest>,
        verifier: &PinnedReceiveVerifier,
        cluster: ClaimCluster,
        additive: bool,
    ) -> Result<Self> {
        cluster.validate()?;
        p.claim.validate()?;
        ensure!(
            scalar(&incoming[..])? != k256::Scalar::ZERO
                && compressed(ProjectivePoint::GENERATOR * scalar(&incoming[..])?)?
                    == p.claim.incoming_user_key,
            "receive incoming native key differs"
        );
        let (plaintext_bytes, scalar_offset) = cluster.template_shape()?;
        let circuit = ClaimCircuit::new(CircuitSpec {
            plaintext_bytes,
            scalar_offset,
        })?;
        let record = Record {
            version: 1,
            registry: verifier.registry_fingerprint(),
            cluster: cluster.clone(),
            circuit: circuit.digest(),
            config: verifier.config().clone(),
            policy: verifier.policy(),
            intent: p.intent.clone(),
            session: p.session,
            user: p.user,
            owner: p.owner,
            server: p.server.to_vec(),
            server_salt: p.server_salt,
            backing_salt: p.backing_salt,
            plan: serde_json::from_slice(&Zeroizing::new(serde_json::to_vec(&p.plan)?))?,
            claim: p.claim.clone(),
            openings: std::array::from_fn(|_| Opening {
                alpha: random_scalar().to_bytes().into(),
                beta: random_scalar().to_bytes().into(),
                binding: random_scalar().to_bytes().into(),
                salt: random32(),
            }),
            mpc: Some(MpcSecrets {
                incoming: *incoming,
                slope: random_scalar().to_bytes().into(),
                seeds: cluster
                    .operators
                    .keys()
                    .map(|id| (id.clone(), random32()))
                    .collect(),
            }),
            prepared: None,
            operators: None,
            proofs: None,
            transcripts: cluster
                .operators
                .keys()
                .map(|id| {
                    (
                        id.clone(),
                        OperatorTranscript {
                            rounds: Vec::new(),
                            ciphertext: None,
                        },
                    )
                })
                .collect(),
            requests: BTreeMap::new(),
            partials: None,
            additive,
        };
        let key = key(&record)?;
        let value = Self {
            file: OperationFile::create(directory, FILE)?,
            directory: directory.into(),
            record,
            circuit,
            key,
            cache: BTreeMap::new(),
        };
        value.validate(verifier)?;
        value.persist()?;
        Ok(value)
    }
    pub fn open(directory: &Path, verifier: &PinnedReceiveVerifier) -> Result<Self> {
        let (file, bytes) = OperationFile::open(directory, FILE, MAX)?;
        let record: Record = serde_json::from_slice(&bytes)?;
        ensure!(
            serde_json::to_vec(&record)?.as_slice() == bytes.as_slice(),
            "noncanonical receive journal"
        );
        let (plaintext_bytes, scalar_offset) = record.cluster.template_shape()?;
        let circuit = ClaimCircuit::new(CircuitSpec {
            plaintext_bytes,
            scalar_offset,
        })?;
        let key = key(&record)?;
        let value = Self {
            file,
            directory: directory.into(),
            record,
            circuit,
            key,
            cache: BTreeMap::new(),
        };
        value.validate(verifier)?;
        value.persist()?;
        Ok(value)
    }
    fn validate(&self, verifier: &PinnedReceiveVerifier) -> Result<()> {
        let r = &self.record;
        let c = self.context()?;
        c.encode()?;
        ensure!(
            r.version == 1
                && r.registry == verifier.registry_fingerprint()
                && r.config == *verifier.config()
                && r.policy == verifier.policy()
                && c.deployment == verifier.deployment()
                && r.cluster.digest()? == verifier.cluster()
                && r.plan.cluster == verifier.cluster()
                && r.circuit == self.circuit.digest(),
            "receive journal deployment/pins changed"
        );
        ensure!(
            r.intent.recipient_claim == spark_lineage::origin_field(&c.deployment, &c.coin, 0)?
                && r.backing_salt != [0; 32]
                && r.server_salt != [0; 32]
                && r.backing_salt != r.plan.salt
                && normalized_key(&r.owner)?.verifying_key().to_bytes()[..] != c.session,
            "receive fresh origin/owner material"
        );
        r.plan.bodies(self.raw_user()?)?;
        r.claim.validate()?;
        ensure!(
            r.claim.deployment == c.deployment
                && r.claim.operation == c.operation
                && r.claim.joint_user_key == self.key.native_keys().user_key()
                && r.claim.threshold == r.cluster.threshold
                && r.claim.operators.len() == r.cluster.operators.len(),
            "receive claim plan differs"
        );
        for (id, op) in &r.cluster.operators {
            let expected = r
                .claim
                .operators
                .get(id)
                .context("receive claim operator missing")?;
            ensure!(
                expected.share_index == op.index && expected.encryption_key == op.encryption_key,
                "receive claim operator configuration differs"
            );
        }
        ensure!(
            r.transcripts.keys().eq(r.cluster.operators.keys()),
            "receive transcript coverage"
        );
        let complete = r.transcripts.values().all(|t| t.ciphertext.is_some());
        ensure!(
            r.mpc.is_some() != complete,
            "receive wallet MPC secret lifecycle"
        );
        if let Some(s) = &r.mpc {
            ensure!(
                scalar(&s.incoming)? != k256::Scalar::ZERO
                    && scalar(&s.slope)? != k256::Scalar::ZERO
                    && compressed(ProjectivePoint::GENERATOR * scalar(&s.incoming)?)?
                        == r.claim.incoming_user_key
                    && s.seeds.keys().eq(r.cluster.operators.keys())
                    && s.seeds.values().all(|v| *v != [0; 32]),
                "receive private MPC input changed"
            );
        }
        for (&purpose, bytes) in &r.requests {
            let req = Request::decode(bytes)?;
            ensure!(
                req.session == c.session
                    && req.intent == r.intent
                    && req.command.purpose() == purpose
                    && (matches!(purpose, 2 | 23 | 25) || (r.additive && purpose == 43)),
                "receive frozen request scope"
            );
        }
        let bound = if r.additive {
            complete && r.requests.contains_key(&43)
        } else {
            r.prepared.is_some()
        };
        ensure!(
            r.proofs.is_some() == bound
                && (r.prepared.is_some() || !r.requests.contains_key(&43))
                && (r.prepared.is_none() || r.requests.contains_key(&23)),
            "receive preparation lifecycle"
        );
        if r.prepared.is_some() {
            self.validate_prepared()?;
        }
        if r.proofs.is_some() {
            self.proofs()?.validate(&r.claim)?;
        }
        for (id, t) in &r.transcripts {
            let rounds = if r.additive { 0 } else { 7 };
            ensure!(
                t.rounds.len() <= rounds && (t.ciphertext.is_none() || t.rounds.len() == rounds),
                "receive wallet transcript length"
            );
            for (index, round) in t.rounds.iter().enumerate() {
                let req = Request::decode(&round.request)?;
                let Command::ReceiveFrame {
                    operator,
                    step,
                    frame,
                } = &req.command
                else {
                    anyhow::bail!("invalid receive frame request");
                };
                ensure!(
                    operator == id
                        && usize::from(*step) == index
                        && req.session == c.session
                        && req.intent
                            == zark_protocol::spark_receive::frame_intent(&r.intent, id, *step)?
                        && (round.reply.is_some() || index + 1 == t.rounds.len()),
                    "receive wallet frozen frame changed"
                );
                self.read_blob(frame)?;
                if let Some(reply) = round.reply {
                    self.read_blob(&reply)?;
                }
            }
            if let Some(cipher) = t.ciphertext {
                let bytes = self.read_blob(&cipher)?;
                ensure!(
                    bytes.len() == self.circuit.spec().plaintext_bytes + 97,
                    "receive saved ciphertext shape"
                );
            }
        }
        if let Some(partials) = r.partials {
            ensure!(
                r.requests.contains_key(&25),
                "receive response before issue"
            );
            for (i, p) in partials.into_iter().enumerate() {
                self.signing_request(i)?.complete(p)?;
            }
        }
        Ok(())
    }
    pub(super) fn witness(&self) -> Result<ReceiveWitness> {
        let rows = self
            .record
            .operators
            .as_ref()
            .context("receive native operator commitments missing")?;
        let jobs = (0..2)
            .map(|i| -> Result<ReceiveJob> {
                let operators = rows[i]
                    .iter()
                    .map(|r| -> Result<Participant> {
                        let c = frost_secp256k1_tr::round1::SigningCommitments::deserialize(
                            &r.commitment,
                        )?;
                        Ok(Participant {
                            identifier: r.id.as_slice().try_into()?,
                            hiding: point_bytes(
                                k256::PublicKey::from_sec1_bytes(&c.hiding().serialize()?)?
                                    .to_projective(),
                            )?,
                            binding: point_bytes(
                                k256::PublicKey::from_sec1_bytes(&c.binding().serialize()?)?
                                    .to_projective(),
                            )?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                let b = &self.record.openings[i];
                Ok(ReceiveJob {
                    opening: Opening {
                        alpha: b.alpha,
                        beta: b.beta,
                        binding: b.binding,
                        salt: b.salt,
                    },
                    operators: operators
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("receive quorum"))?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(ReceiveWitness {
            user: self.record.user,
            owner: self.record.owner,
            backing_salt: self.record.backing_salt,
            session_point: point_bytes(ProjectivePoint::GENERATOR * scalar(&self.record.session)?)?,
            plan: serde_json::from_slice(&Zeroizing::new(serde_json::to_vec(&self.record.plan)?))?,
            jobs: jobs
                .try_into()
                .map_err(|_| anyhow::anyhow!("receive job count"))?,
        })
    }
}
