//! Real pinned Spark roles are verified outside the checkpoint lock.
use super::{Engine, Predecessor, ProofRole, ProofSpec};
use anyhow::{Result, ensure};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    time::{Duration, Instant},
};
use zark_protocol::{
    hash, random32,
    spark_lineage::{Handover, Issuance, SparkRole},
};

impl Engine {
    pub(super) fn verify(
        &self,
        spec: &ProofSpec,
        proof: &[u8],
        guard: &dyn Fn() -> Result<()>,
    ) -> Result<()> {
        let lock_path = fs::canonicalize(&self.db)?.with_extension("spark-proof.lock");
        let deadline = Instant::now() + Duration::from_secs(5);
        let _permit = crate::admission::Permit::acquire(&lock_path, deadline, guard)?;
        let _process = crate::admission::acquire_process_lock(
            &lock_path,
            deadline,
            guard,
            "Spark proof verifier busy",
        )?;
        guard()?;
        let scratch = self
            .db
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Spark database parent"))?
            .join(format!("spark-proof-{}", hex::encode(random32())));
        fs::DirBuilder::new().mode(0o700).create(&scratch)?;
        let result = (|| {
            if spec.role == ProofRole::Auth {
                let verified = self
                    .auth_verifier
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Spark auth verifier missing"))?
                    .verify(
                        &zark_protocol::spark_auth::AuthStatement::decode(&spec.statement)?,
                        proof,
                        &scratch,
                    )?;
                ensure!(
                    verified == hash(&[&spec.statement]),
                    "Spark auth verified statement changed"
                );
                guard()?;
                return Ok(());
            }
            if spec.role == ProofRole::TransferAuth {
                let verified = self
                    .transfer_auth_verifier
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Spark transfer auth verifier missing"))?
                    .verify(
                        &zark_protocol::spark_mpc_exit::TransferAuthStatement::decode(
                            &spec.statement,
                        )?,
                        proof,
                        &scratch,
                    )?;
                ensure!(
                    verified == hash(&[&spec.statement]),
                    "Spark transfer auth verified statement changed"
                );
                guard()?;
                return Ok(());
            }
            if spec.role == ProofRole::Receive {
                let verified = self
                    .receive
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("receive verifier missing"))?
                    .verifier
                    .verify(
                        &zark_protocol::spark_receive::ReceiveAuthorization::decode(
                            &spec.statement,
                        )?,
                        proof,
                        &scratch,
                    )?;
                ensure!(
                    verified == hash(&[&spec.statement]),
                    "receive verified statement changed"
                );
                guard()?;
                return Ok(());
            }
            if let ProofRole::SingleUser(predecessor) = spec.role {
                let verified = self
                    .single_user_verifier
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("single-USER verifier missing"))?
                    .verify(
                        predecessor,
                        &zark_protocol::spark_single_user::SigningAuthorization::decode(
                            &spec.statement,
                        )?,
                        proof,
                        &scratch,
                    )?;
                ensure!(
                    verified.statement_digest() == hash(&[&spec.statement]),
                    "single-USER verified statement changed"
                );
                guard()?;
                return Ok(());
            }
            if spec.role == ProofRole::Bootstrap {
                let verified = self
                    .bootstrap_verifier
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("bootstrap verifier missing"))?
                    .verify(
                        &zark_protocol::spark_bootstrap::BootstrapAuthorization::decode(
                            &spec.statement,
                        )?,
                        proof,
                        &scratch,
                    )?;
                ensure!(
                    verified.statement_digest() == hash(&[&spec.statement]),
                    "bootstrap verifier returned different statement"
                );
                guard()?;
                return Ok(());
            }
            if let ProofRole::Native(predecessor) = spec.role {
                let verified = self
                    .native_verifier
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("native verifier missing"))?
                    .verify(
                        predecessor,
                        &zark_protocol::spark_native::ExitAuthorization::decode(&spec.statement)?,
                        proof,
                        &scratch,
                    )?;
                ensure!(
                    verified.statement_digest() == hash(&[&spec.statement]),
                    "native verifier returned different statement"
                );
                guard()?;
                return Ok(());
            }
            let ProofRole::Ownership(role) = spec.role else {
                unreachable!("native handled above");
            };
            let verified = match role {
                SparkRole::Deposit | SparkRole::Receiver => self.verifier.verify_issuance(
                    role == SparkRole::Deposit,
                    &Issuance::decode(&spec.statement)?,
                    proof,
                    &scratch,
                )?,
                SparkRole::SenderFromOrigin | SparkRole::SenderFromTransfer => {
                    self.verifier.verify_handover(
                        if role == SparkRole::SenderFromOrigin {
                            Predecessor::Origin
                        } else {
                            Predecessor::Transfer
                        },
                        &Handover::decode(&spec.statement)?,
                        proof,
                        &scratch,
                    )?
                }
            };
            ensure!(
                verified.role() == role && verified.statement_digest() == hash(&[&spec.statement]),
                "Spark verifier returned different role or statement"
            );
            guard()?;
            Ok(())
        })();
        // This directory contains only this invocation's bounded proof scratch.
        let _ = fs::remove_dir_all(scratch);
        result
    }
}
