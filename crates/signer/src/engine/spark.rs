//! The actual blind Zark signer with Spark dual-refund backing.
//!
//! This is the sole authority for a fresh Spark deployment. It does not install
//! heads in the separate native interoperability application. Existing Bitcoin
//! wire records, schemas and deployments are unchanged. Native signing requires
//! its separate pinned proof suite and retains the lock through reconciliation.
mod auth;
mod bootstrap;
mod ecdsa_2p;
mod head;
mod identity;
mod mpc_exit;
mod native;
mod native_tweaks;
mod persistence;
mod planning;
mod receive;
mod share_release;
mod single_user;
mod state;
#[cfg(test)]
mod tests;
mod transitions;
mod verification;

use super::{Admission, blind_issuance};
use anyhow::{Context, Result, ensure};
use k256::schnorr::SigningKey;
use persistence::{Store, lock_guarded};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
pub use zark_protocol::spark_wire::{Command, OwnerAuthorization, Predecessor, Request};
use zark_protocol::{
    hash,
    spark_auth::PinnedAuthVerifier,
    spark_bootstrap::PinnedNativeBootstrapVerifier,
    spark_lineage::{Config, Digest, PinnedSparkVerifier, SparkRole},
    spark_mpc_exit::PinnedTransferAuthVerifier,
    spark_native::PinnedNativeExitVerifier,
    spark_native_vss::Cluster,
    spark_receive::{ClaimCluster, PinnedReceiveVerifier},
    spark_single_user::PinnedSingleUserVerifier,
};

pub struct ReceiveProtocol {
    pub verifier: PinnedReceiveVerifier,
    pub cluster: ClaimCluster,
}
struct ReceiveRuntime {
    verifier: PinnedReceiveVerifier,
    cluster: ClaimCluster,
    circuit: zark_spark_claim_mpc::ClaimCircuit,
    cache: std::sync::Mutex<
        std::collections::BTreeMap<(Digest, Digest, String), receive::ContributorCache>,
    >,
}

#[derive(Default)]
pub struct NativeProtocols {
    pub exit: Option<PinnedNativeExitVerifier>,
    pub cluster: Option<Cluster>,
    pub bootstrap: Option<PinnedNativeBootstrapVerifier>,
    pub single_user: Option<PinnedSingleUserVerifier>,
    pub receive: Option<ReceiveProtocol>,
    /// Joint identity operations for a fresh receive or owner-authorized native
    /// exit. ECDH is receive-only; completed signatures stay wallet-local.
    pub identity: bool,
    /// Proof-gated blind Schnorr for Spark authentication challenges only.
    /// Requires joint identity; claim and package digests stay ECDSA.
    pub auth: Option<PinnedAuthVerifier>,
    /// Blind BIP-340 `start_transfer_mpc` authorization for two-role native
    /// exits; requires the two-role exit verifier, its cluster and identity.
    pub transfer_auth: Option<PinnedTransferAuthVerifier>,
    /// cb-mpc two-party ECDSA owns the entry identity key and its signatures.
    /// Requires joint identity and a signer built with `ecdsa-2p`.
    pub ecdsa_2p: bool,
    /// Ordinary receive uses the additive tweak instead of garbled circuits.
    /// Requires the ordinary receive deployment.
    pub additive_receive: bool,
    /// Terminal exit by releasing the share to the current owner. Enablement is
    /// published in every origin-signed head, not in the database config
    /// digest, so existing databases open unchanged with it on or off.
    pub share_release: bool,
}

#[derive(Clone)]
struct Policy {
    deployment: Digest,
    config: Config,
    policy: Digest,
    native: Option<(Digest, Digest)>, // trusted registry fingerprint, cluster
    native_cluster: Option<Cluster>,
    bootstrap: Option<(Digest, Digest)>,
    single_user: Option<Digest>,
    receive: Option<(Digest, Digest, Digest)>,
    receive_cluster: Option<ClaimCluster>,
    identity: Option<Digest>,
    auth: Option<Digest>,
    ecdsa_2p: bool,
    additive_receive: bool,
}

#[derive(Clone, Copy)]
enum OpenMode {
    Normal,
    Repair,
    InitialiseWitness,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProofRole {
    Ownership(SparkRole),
    Native(Predecessor),
    Bootstrap,
    SingleUser(Predecessor),
    Receive,
    Auth,
    TransferAuth,
}

#[derive(Clone, PartialEq, Eq)]
struct ProofSpec {
    role: ProofRole,
    statement: Vec<u8>,
}

pub struct Engine {
    db: PathBuf,
    checkpoint: PathBuf,
    config: Digest,
    policy: Policy,
    verifier: PinnedSparkVerifier,
    admission: Arc<dyn Admission>,
    origin: SigningKey,
    native_verifier: Option<PinnedNativeExitVerifier>,
    bootstrap_verifier: Option<PinnedNativeBootstrapVerifier>,
    single_user_verifier: Option<PinnedSingleUserVerifier>,
    receive: Option<ReceiveRuntime>,
    identity: Option<identity::Runtime>,
    native_tweaks: native_tweaks::Runtime,
    auth_verifier: Option<PinnedAuthVerifier>,
    transfer_auth_verifier: Option<PinnedTransferAuthVerifier>,
    ecdsa: Option<ecdsa_2p::Runtime>,
    share_release: bool,
}

impl Engine {
    pub fn open_with_single_user(
        db: &Path,
        checkpoint: &Path,
        verifier: PinnedSparkVerifier,
        admission: Arc<dyn Admission>,
        origin: SigningKey,
        single_user: PinnedSingleUserVerifier,
    ) -> Result<Self> {
        Self::open_with_protocols(
            db,
            checkpoint,
            verifier,
            admission,
            origin,
            NativeProtocols {
                single_user: Some(single_user),
                ..Default::default()
            },
        )
    }
    pub fn open(
        db: &Path,
        checkpoint: &Path,
        verifier: PinnedSparkVerifier,
        admission: Arc<dyn Admission>,
        origin: SigningKey,
    ) -> Result<Self> {
        Self::open_inner(
            db,
            checkpoint,
            verifier,
            admission,
            origin,
            NativeProtocols::default(),
            OpenMode::Normal,
        )
    }

    pub fn open_with_native(
        db: &Path,
        checkpoint: &Path,
        verifier: PinnedSparkVerifier,
        admission: Arc<dyn Admission>,
        origin: SigningKey,
        native: PinnedNativeExitVerifier,
    ) -> Result<Self> {
        Self::open_inner(
            db,
            checkpoint,
            verifier,
            admission,
            origin,
            NativeProtocols {
                exit: Some(native),
                ..Default::default()
            },
            OpenMode::Normal,
        )
    }

    pub fn open_with_native_cluster(
        db: &Path,
        checkpoint: &Path,
        verifier: PinnedSparkVerifier,
        admission: Arc<dyn Admission>,
        origin: SigningKey,
        native: PinnedNativeExitVerifier,
        cluster: Cluster,
    ) -> Result<Self> {
        Self::open_inner(
            db,
            checkpoint,
            verifier,
            admission,
            origin,
            NativeProtocols {
                exit: Some(native),
                cluster: Some(cluster),
                ..Default::default()
            },
            OpenMode::Normal,
        )
    }

    pub fn open_with_protocols(
        db: &Path,
        checkpoint: &Path,
        verifier: PinnedSparkVerifier,
        admission: Arc<dyn Admission>,
        origin: SigningKey,
        native: NativeProtocols,
    ) -> Result<Self> {
        Self::open_inner(
            db,
            checkpoint,
            verifier,
            admission,
            origin,
            native,
            OpenMode::Normal,
        )
    }

    /// Explicit repair after inspecting one committed checkpoint publication gap.
    pub fn repair_and_open(
        db: &Path,
        checkpoint: &Path,
        verifier: PinnedSparkVerifier,
        admission: Arc<dyn Admission>,
        origin: SigningKey,
    ) -> Result<Self> {
        Self::open_inner(
            db,
            checkpoint,
            verifier,
            admission,
            origin,
            NativeProtocols::default(),
            OpenMode::Repair,
        )
    }

    pub fn repair_and_open_with_native(
        db: &Path,
        checkpoint: &Path,
        verifier: PinnedSparkVerifier,
        admission: Arc<dyn Admission>,
        origin: SigningKey,
        native: PinnedNativeExitVerifier,
    ) -> Result<Self> {
        Self::open_inner(
            db,
            checkpoint,
            verifier,
            admission,
            origin,
            NativeProtocols {
                exit: Some(native),
                ..Default::default()
            },
            OpenMode::Repair,
        )
    }

    pub fn repair_and_open_with_native_cluster(
        db: &Path,
        checkpoint: &Path,
        verifier: PinnedSparkVerifier,
        admission: Arc<dyn Admission>,
        origin: SigningKey,
        native: PinnedNativeExitVerifier,
        cluster: Cluster,
    ) -> Result<Self> {
        Self::open_inner(
            db,
            checkpoint,
            verifier,
            admission,
            origin,
            NativeProtocols {
                exit: Some(native),
                cluster: Some(cluster),
                ..Default::default()
            },
            OpenMode::Repair,
        )
    }

    pub fn repair_and_open_with_protocols(
        db: &Path,
        checkpoint: &Path,
        verifier: PinnedSparkVerifier,
        admission: Arc<dyn Admission>,
        origin: SigningKey,
        native: NativeProtocols,
    ) -> Result<Self> {
        Self::open_inner(
            db,
            checkpoint,
            verifier,
            admission,
            origin,
            native,
            OpenMode::Repair,
        )
    }

    /// Explicit operator action for a store created before the rollback
    /// witness existed (or whose witness was lost): trusts the current,
    /// published state as the newest. Never use after a restore.
    pub fn initialise_witness_and_open_with_protocols(
        db: &Path,
        checkpoint: &Path,
        verifier: PinnedSparkVerifier,
        admission: Arc<dyn Admission>,
        origin: SigningKey,
        native: NativeProtocols,
    ) -> Result<Self> {
        Self::open_inner(
            db,
            checkpoint,
            verifier,
            admission,
            origin,
            native,
            OpenMode::InitialiseWitness,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn open_inner(
        db: &Path,
        checkpoint: &Path,
        verifier: PinnedSparkVerifier,
        admission: Arc<dyn Admission>,
        origin: SigningKey,
        native: NativeProtocols,
        mode: OpenMode,
    ) -> Result<Self> {
        let receive = native
            .receive
            .map(|r| -> Result<ReceiveRuntime> {
                let (plaintext_bytes, scalar_offset) = r.cluster.template_shape()?;
                let circuit =
                    zark_spark_claim_mpc::ClaimCircuit::new(zark_spark_claim_mpc::CircuitSpec {
                        plaintext_bytes,
                        scalar_offset,
                    })?;
                ensure!(
                    r.verifier.cluster() == r.cluster.digest()?,
                    "receive cluster differs from pinned verifier"
                );
                Ok(ReceiveRuntime {
                    verifier: r.verifier,
                    cluster: r.cluster,
                    circuit,
                    cache: Default::default(),
                })
            })
            .transpose()?;
        let identity = if native.identity {
            ensure!(
                receive.is_some(),
                "joint identity requires the ordinary receive deployment"
            );
            Some(identity::Runtime::new()?)
        } else {
            None
        };
        if let Some(auth) = &native.auth {
            ensure!(
                identity.is_some(),
                "Spark auth signing requires joint identity"
            );
            ensure!(
                auth.deployment() == verifier.deployment(),
                "Spark auth verifier deployment mismatch"
            );
        }
        if let Some(transfer) = &native.transfer_auth {
            ensure!(
                identity.is_some()
                    && native.cluster.is_some()
                    && native.exit.as_ref().is_some_and(|e| !e.is_ordinary()),
                "Spark transfer auth requires joint identity and the two-role native exit"
            );
            ensure!(
                transfer.deployment() == verifier.deployment(),
                "Spark transfer auth verifier deployment mismatch"
            );
        }
        let ecdsa = if native.ecdsa_2p {
            ensure!(identity.is_some(), "ECDSA-2P requires joint identity");
            Some(ecdsa_2p::Runtime::new()?)
        } else {
            None
        };
        ensure!(
            !native.additive_receive || receive.is_some(),
            "additive receive requires the ordinary receive deployment"
        );
        let policy = Policy {
            deployment: verifier.deployment(),
            config: verifier.config().clone(),
            policy: verifier.policy(),
            native: native
                .exit
                .as_ref()
                .map(|v| (v.registry_fingerprint(), v.cluster())),
            native_cluster: native.cluster,
            bootstrap: native
                .bootstrap
                .as_ref()
                .map(|v| (v.registry_fingerprint(), v.cluster())),
            single_user: native
                .single_user
                .as_ref()
                .map(|v| v.registry_fingerprint()),
            receive: receive.as_ref().map(|r| {
                (
                    r.verifier.registry_fingerprint(),
                    r.verifier.cluster(),
                    r.circuit.digest(),
                )
            }),
            receive_cluster: receive.as_ref().map(|r| r.cluster.clone()),
            identity: identity.as_ref().map(|r| r.circuit.digest()),
            auth: native.auth.as_ref().map(|v| v.registry_fingerprint()),
            ecdsa_2p: native.ecdsa_2p,
            additive_receive: native.additive_receive,
        };
        if let Some(cluster) = &policy.native_cluster {
            let digest = cluster.digest()?;
            ensure!(
                policy.native.is_some() || policy.bootstrap.is_some(),
                "native cluster without proof suite"
            );
            for expected in [policy.native, policy.bootstrap].into_iter().flatten() {
                ensure!(
                    digest == expected.1,
                    "native cluster differs from pinned registry"
                );
            }
        }
        if let Some(native) = &native.exit {
            ensure!(
                native.deployment() == policy.deployment
                    && native.config() == &policy.config
                    && native.policy() == policy.policy,
                "native verifier ownership policy mismatch"
            );
        }
        if let Some(bootstrap) = &native.bootstrap {
            ensure!(
                bootstrap.deployment() == policy.deployment
                    && bootstrap.config() == &policy.config
                    && bootstrap.policy() == policy.policy,
                "bootstrap verifier ownership policy mismatch"
            );
        }
        if let Some(single) = &native.single_user {
            ensure!(
                single.deployment() == policy.deployment
                    && single.config() == &policy.config
                    && single.policy() == policy.policy,
                "single-USER ownership policy mismatch"
            );
        }
        if let Some(r) = &receive {
            ensure!(
                r.verifier.deployment() == policy.deployment
                    && r.verifier.config() == &policy.config
                    && r.verifier.policy() == policy.policy,
                "receive verifier ownership policy mismatch"
            );
            ensure!(
                policy.bootstrap.is_none(),
                "receive and native bootstrap are distinct deployment profiles"
            );
        }
        policy.config.encode()?;
        ensure!(
            policy.deployment != [0; 32] && policy.policy != [0; 32],
            "empty Spark signer policy"
        );
        ensure!(
            origin.verifying_key().to_bytes()[..] == policy.config.origin_key,
            "Spark origin key mismatch"
        );
        let config = hash(&[
            b"ZARK/spark/signer/config/v1",
            &policy.deployment,
            &policy.config.encode()?,
            &policy.policy,
        ]);
        let config = if let Some((registry, cluster, circuit)) = policy.receive {
            hash(&[
                b"ZARK/spark/signer/receive-config/v1",
                &config,
                &registry,
                &cluster,
                &circuit,
            ])
        } else {
            config
        };
        let config = if let Some(circuit) = policy.identity {
            hash(&[
                b"ZARK/spark/signer/joint-identity-config/v1",
                &config,
                &circuit,
            ])
        } else {
            config
        };
        let config = if let Some(registry) = policy.auth {
            hash(&[b"ZARK/spark/signer/auth-config/v1", &config, &registry])
        } else {
            config
        };
        let config = if let Some(transfer) = &native.transfer_auth {
            hash(&[
                b"ZARK/spark/signer/mpc-transfer-auth-config/v1",
                &config,
                &transfer.registry_fingerprint(),
            ])
        } else {
            config
        };
        let config = if native.ecdsa_2p {
            ecdsa_2p::config(&config)
        } else {
            config
        };
        let config = if native.additive_receive {
            hash(&[b"ZARK/spark/signer/additive-receive-config/v1", &config])
        } else {
            config
        };
        let value = Self {
            db: db.into(),
            checkpoint: checkpoint.into(),
            config,
            policy,
            verifier,
            admission,
            origin,
            native_verifier: native.exit,
            bootstrap_verifier: native.bootstrap,
            single_user_verifier: native.single_user,
            receive,
            identity,
            native_tweaks: Default::default(),
            auth_verifier: native.auth,
            transfer_auth_verifier: native.transfer_auth,
            ecdsa,
            share_release: native.share_release,
        };
        {
            let _lock = lock_guarded(db, checkpoint, &|| Ok(()))?;
            let store = Store::open(db, config)?;
            store.validate(&value.policy)?;
            match mode {
                OpenMode::Normal => {}
                OpenMode::Repair => store.repair_floor(checkpoint)?,
                OpenMode::InitialiseWitness => store.initialise_witness(checkpoint)?,
            }
            store.verify_floor(checkpoint)?;
            store.validate_receive_frames(&value)?;
        }
        Ok(value)
    }

    pub fn deployment(&self) -> Digest {
        self.policy.deployment
    }

    pub fn handle(&self, request: &Request) -> Result<Value> {
        self.handle_guarded(request, || Ok(()))
    }

    pub fn handle_guarded(
        &self,
        request: &Request,
        guard: impl Fn() -> Result<()>,
    ) -> Result<Value> {
        guard()?;
        let digest = request.authenticate()?;
        ensure!(
            request.intent.deployment == self.policy.deployment,
            "Spark request deployment"
        );
        ensure!(
            !matches!(request.command, Command::Exit { .. }),
            "Spark native exit authorization is not deployed"
        );
        let new_activity = matches!(
            request.command,
            Command::Allocate { .. }
                | Command::Reserve { .. }
                | Command::NativeExitPrepare { .. }
                | Command::SingleUserPrepare { .. }
                | Command::ReceivePrepare { .. }
                | Command::IdentityPrepare { .. }
                | Command::IdentitySign { .. }
                | Command::IdentityDecrypt { .. }
                | Command::AuthPrepare { .. }
                | Command::AuthIssue { .. }
                | Command::EcdsaKeygen { .. }
                | Command::EcdsaSign { .. }
                | Command::ShareRelease { .. }
        );
        let (revision, database, spec) = {
            let _lock = lock_guarded(&self.db, &self.checkpoint, &guard)?;
            let mut store = Store::open(&self.db, self.config)?;
            let floor = store.verify_floor(&self.checkpoint)?;
            if matches!(request.command, Command::Head { .. }) {
                let (coin, revision) = store
                    .coin(&request.intent.coin)?
                    .context("unknown Spark coin")?;
                coin.validate(&self.policy)?;
                return self.fresh_head(&coin, revision, request);
            }
            if let Some(response) = store.replay(request, &digest)? {
                return Ok(response);
            }
            // A retained, already-admitted response must remain recoverable
            // after credentials expire. Admission applies only after replay.
            if new_activity {
                self.admission.authorize(&admission_context(request))?;
            }
            if matches!(request.command, Command::Allocate { .. }) {
                ensure!(
                    store.coin(&request.intent.coin)?.is_none(),
                    "Spark coin already allocated"
                );
                let coin = self.allocate(request)?;
                coin.validate(&self.policy)?;
                let response = json!({"server":coin.server()?.to_vec(),"server_salt":coin.salt,"state":coin.state,"revision":1});
                guard()?;
                self.admission.authorize(&admission_context(request))?;
                store.commit(&coin, None, request, digest, &response, &floor, false)?;
                store.publish(&self.checkpoint)?;
                return Ok(response);
            }
            let (coin, revision) = store
                .coin(&request.intent.coin)?
                .context("unknown Spark coin")?;
            if matches!(
                request.command,
                Command::NativeBootstrapPrepare { .. } | Command::ReceivePrepare { .. }
            ) {
                ensure!(
                    revision == 1 && request.intent.revision == 1,
                    "bootstrap requires the fresh allocation CAS"
                );
            }
            if matches!(
                request.command,
                Command::Reserve { .. }
                    | Command::NativeExitPrepare { .. }
                    | Command::SingleUserPrepare { .. }
                    | Command::ShareRelease { .. }
            ) {
                ensure!(
                    request.intent.revision == revision,
                    "stale Spark reservation revision"
                );
                ensure!(
                    !store.operation_exists(&coin.coin, &request.intent.operation)?,
                    "Spark operation already used"
                );
            }
            if matches!(
                request.command,
                Command::NativeExitPrepare { .. } | Command::Reserve { .. }
            ) && self
                .native_verifier
                .as_ref()
                .is_some_and(|v| v.is_ordinary())
            {
                let operators = self
                    .policy
                    .native_cluster
                    .as_ref()
                    .context("ordinary native cluster missing")?
                    .operators
                    .len() as u64;
                // Eight one-use identity tickets cost at most 72 responses.
                // Reserve all seven tweak rounds per operator and the five
                // native transitions before permanently locking ownership.
                // A private handover must also leave its recipient this exit
                // budget after finishing the bounded ownership transition.
                let private_handover = if matches!(request.command, Command::Reserve { .. }) {
                    7
                } else {
                    0
                };
                store
                    .require_response_capacity(&coin.coin, 77 + 7 * operators + private_handover)?;
            }
            (revision, floor.database(), self.plan(&coin, request)?)
        };
        if let Some(spec) = &spec {
            self.verify(
                spec,
                request
                    .command
                    .proof()
                    .context("Spark ownership proof missing")?,
                &guard,
            )?;
        }
        guard()?;
        let _lock = lock_guarded(&self.db, &self.checkpoint, &guard)?;
        let mut store = Store::open(&self.db, self.config)?;
        let floor = store.verify_floor(&self.checkpoint)?;
        if let Some(response) = store.replay(request, &digest)? {
            return Ok(response);
        }
        let (coin, current_revision) = store
            .coin(&request.intent.coin)?
            .context("Spark coin disappeared")?;
        ensure!(
            revision == current_revision && database == floor.database(),
            "stale Spark verified revision; retry exact request"
        );
        ensure!(
            request.authenticate()? == digest,
            "Spark verified request changed"
        );
        ensure!(
            self.plan(&coin, request)? == spec,
            "Spark verified statement changed"
        );
        if new_activity {
            self.admission.authorize(&admission_context(request))?;
        }
        let (next, mut response, purge_mask) = self.apply(coin, request)?;
        next.validate(&self.policy)?;
        response["revision"] = json!(if identity::is_command(&request.command)
            || auth::is_command(&request.command)
            || ecdsa_2p::is_command(&request.command)
            || native_tweaks::auxiliary(&request.command)
            || mpc_exit::auxiliary(&request.command)
        {
            revision
        } else {
            revision
                .checked_add(1)
                .context("Spark revision exhausted")?
        });
        guard()?;
        store.commit(
            &next,
            Some(revision),
            request,
            digest,
            &response,
            &floor,
            purge_mask,
        )?;
        store.publish(&self.checkpoint)?;
        Ok(response)
    }
}

fn admission_context(request: &Request) -> zark_protocol::handoff::TransferContext {
    let intent = &request.intent;
    zark_protocol::handoff::TransferContext {
        deployment: intent.deployment,
        coin: intent.coin,
        previous_state: intent.previous_state,
        operation: intent.operation,
        recipient_claim: intent.recipient_claim,
        session_auth: request.session,
        scope: zark_protocol::handoff::OperationScope::Single,
        start_revision: intent.revision,
    }
}
