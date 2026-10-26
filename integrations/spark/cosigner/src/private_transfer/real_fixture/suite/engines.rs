//! Fixture deployment profiles, pinned before allocation and identical on reopen.
use super::*;
use std::sync::Arc;
use zark_signer::engine::spark::Engine;

impl Suite {
    /// Opt-in joint-identity entry profiles. They change the signer config
    /// hash, so a fixture must be reopened with the flags it was created with.
    pub fn entry_flag(name: &str) -> bool {
        std::env::var_os(name).is_some_and(|v| v == "1")
    }
    pub fn engine(&self, root: &Path) -> Result<Engine> {
        private_directory(&root.join("signer"))?;
        private_directory(&root.join("checkpoint"))?;
        if let Some(native) = &self.native {
            return Engine::open_with_native_cluster(
                &root.join("signer/state.sqlite"),
                &root.join("checkpoint/floor.json"),
                self.verifier()?,
                Arc::new(FixtureAdmission(self.deployment)),
                SigningKey::from_bytes(&self.origin[..])?,
                native.verifier(self.deployment, self.config.clone(), self.policy)?,
                native.cluster().clone(),
            );
        }
        Engine::open(
            &root.join("signer/state.sqlite"),
            &root.join("checkpoint/floor.json"),
            self.verifier()?,
            Arc::new(FixtureAdmission(self.deployment)),
            SigningKey::from_bytes(&self.origin[..])?,
        )
    }
    pub fn receive_verifier(
        &self,
        cluster: &zark_protocol::spark_receive::ClaimCluster,
    ) -> Result<zark_protocol::spark_receive::PinnedReceiveVerifier> {
        self.receive
            .as_ref()
            .context("set ZARK_SPARK_RECEIVE_SUITE")?
            .verifier(
                self.deployment,
                self.config.clone(),
                self.policy,
                cluster.digest()?,
            )
    }
    pub fn receive_engine(
        &self,
        root: &Path,
        cluster: &zark_protocol::spark_receive::ClaimCluster,
        repair: bool,
    ) -> Result<Engine> {
        self.receive_engine_admitted(
            root,
            cluster,
            repair,
            Arc::new(FixtureAdmission(self.deployment)),
        )
    }
    pub fn receive_engine_admitted(
        &self,
        root: &Path,
        cluster: &zark_protocol::spark_receive::ClaimCluster,
        repair: bool,
        admission: Arc<dyn Admission>,
    ) -> Result<Engine> {
        self.receive_engine_profile(root, cluster, repair, admission, false)
    }
    pub fn receive_engine_joint_identity(
        &self,
        root: &Path,
        cluster: &zark_protocol::spark_receive::ClaimCluster,
        repair: bool,
        admission: Arc<dyn Admission>,
    ) -> Result<Engine> {
        self.receive_engine_profile(root, cluster, repair, admission, true)
    }
    fn receive_engine_profile(
        &self,
        root: &Path,
        cluster: &zark_protocol::spark_receive::ClaimCluster,
        repair: bool,
        admission: Arc<dyn Admission>,
        identity: bool,
    ) -> Result<Engine> {
        private_directory(&root.join("signer"))?;
        private_directory(&root.join("checkpoint"))?;
        // A full-flow deployment pins the live cluster before allocation. It
        // cannot silently add a native signing protocol after coins are funded.
        let native_cluster =
            self.native
                .as_ref()
                .map(|_| zark_protocol::spark_native_vss::Cluster {
                    threshold: cluster.threshold,
                    operators: cluster
                        .operators
                        .iter()
                        .map(|(id, op)| (id.clone(), op.encryption_key.clone()))
                        .collect(),
                });
        let exit = native_cluster
            .as_ref()
            .map(|c| self.live_native_verifier(c))
            .transpose()?;
        let protocols = zark_signer::engine::spark::NativeProtocols {
            exit,
            cluster: native_cluster,
            receive: Some(zark_signer::engine::spark::ReceiveProtocol {
                verifier: self.receive_verifier(cluster)?,
                cluster: cluster.clone(),
            }),
            identity,
            auth: if identity {
                self.auth_verifier()?
            } else {
                None
            },
            additive_receive: identity && Self::entry_flag("ZARK_SPARK_ADDITIVE_RECEIVE"),
            ecdsa_2p: identity && Self::entry_flag("ZARK_SPARK_ECDSA_2P"),
            share_release: self.share_release,
            ..Default::default()
        };
        // Retained fixtures created before the rollback witness need the
        // explicit, one-time initialisation; it is never implied.
        let open = if repair {
            Engine::repair_and_open_with_protocols
        } else if Self::entry_flag("ZARK_SPARK_INITIALISE_WITNESS") {
            Engine::initialise_witness_and_open_with_protocols
        } else {
            Engine::open_with_protocols
        };
        open(
            &root.join("signer/state.sqlite"),
            &root.join("checkpoint/floor.json"),
            self.verifier()?,
            admission,
            SigningKey::from_bytes(&self.origin[..])?,
            protocols,
        )
    }
    pub fn live_native_verifier(
        &self,
        cluster: &zark_protocol::spark_native_vss::Cluster,
    ) -> Result<zark_protocol::spark_native::PinnedNativeExitVerifier> {
        self.native
            .as_ref()
            .context("set ZARK_SPARK_NATIVE_SUITE for the full flow")?
            .verifier_for_cluster(self.deployment, self.config.clone(), self.policy, cluster)
    }
}
