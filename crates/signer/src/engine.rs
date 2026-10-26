//! Durable blind Zark signer state for Spark deployments.
mod blind_issuance;
pub mod spark;

use anyhow::Result;
use zark_protocol::handoff::{Digest, TransferContext};

/// Trusted service admission policy; never selected by the request. This may
/// check credentials, rate limits and queue budgets before expensive proving.
/// Already-admitted continuations and recovery operations do not require an
/// unexpired credential; their frozen state, session and proofs authorize them.
pub trait Admission: Send + Sync {
    fn authorize(&self, context: &TransferContext) -> Result<()>;
    /// Ordinary receive signing alone is not backing admission. A deployed
    /// native observer must have established this exact completed claim and
    /// its active, confirmed funding anchor before an origin can be frozen.
    /// This callback checks opaque commitments. The interim observer separately
    /// opens and validates the backing, and may disclose its leaf-to-coin link
    /// to the signer. It must not approve a wallet digest without that binding.
    fn authorize_spark_received_origin(
        &self,
        _context: &TransferContext,
        _backing: &Digest,
    ) -> Result<()> {
        anyhow::bail!("native Spark receive backing observation is not deployed")
    }
    /// The configured observer must independently establish normal Spark
    /// settlement and bind it to this exact opaque plan, packet and evidence.
    /// Wallet-supplied fields never authorize retiring a native ownership head.
    fn authorize_spark_native_completion(
        &self,
        _context: &TransferContext,
        _completion: &zark_protocol::spark_wire::NativeCompletion,
        _evidence: &Digest,
    ) -> Result<()> {
        anyhow::bail!("native Spark completion observation is not deployed")
    }
}
