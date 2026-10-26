//! Public evidence for one desktop entry, written beside the coin's private state.
use super::uuid;
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use zark_protocol::storage::atomic_write;

const EXECUTION: &str = "desktop_entry";

#[derive(Clone)]
pub(super) struct RunReport {
    path: PathBuf,
    invocation: String,
}

impl RunReport {
    /// Starts the coin's `public-report.json`. A coin directory holds exactly
    /// one entry, so an existing report means the entry already ran.
    pub fn begin(root: &Path) -> Result<Self> {
        let path = root.canonicalize()?.join("public-report.json");
        ensure!(!path.exists(), "fresh report already exists");
        let result = Self {
            path,
            invocation: uuid(),
        };
        result.save(json!({"status":"running"}))?;
        Ok(result)
    }

    pub fn save(&self, mut record: Value) -> Result<()> {
        ensure!(record.is_object(), "invocation report must be an object");
        record["schema"] = json!("zark-spark-flow-evidence-v2");
        record["invocation_id"] = json!(self.invocation);
        record["execution"] = json!(EXECUTION);
        record["previous_report"] = Value::Null;
        record["run_provenance"] =
            json!({"status":"unrecorded","reason":"invoked outside the provenance runner"});
        record["evidence_status"] = json!("unrecorded_execution");
        record["security_qualified"] = json!(false);
        record["privacy_model"] = json!("interim-disclosed-entry-exit-v1");
        record["fresh_full_flow_executed"] = json!(false);
        atomic_write(&self.path, &serde_json::to_vec_pretty(&record)?)
    }
}

#[cfg(test)]
#[path = "reporting/tests.rs"]
mod tests;
