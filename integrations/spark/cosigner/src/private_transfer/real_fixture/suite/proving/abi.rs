//! Fail before freezing a new sender job against a legacy private witness ABI.
use super::super::Program;
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use zark_protocol::assets::{MAX_CIRCUIT_BYTES, read_bounded};

pub(super) fn require_sender_profile(role: &str, program: &Program) -> Result<()> {
    if !matches!(role, "sender_from_origin" | "sender_from_transfer") {
        return Ok(());
    }
    #[derive(Deserialize)]
    struct Artifact {
        abi: Abi,
    }
    #[derive(Deserialize)]
    struct Abi {
        parameters: Vec<Parameter>,
    }
    #[derive(Deserialize)]
    struct Parameter {
        name: String,
        visibility: String,
        #[serde(rename = "type")]
        kind: serde_json::Value,
    }
    let artifact: Artifact =
        serde_json::from_slice(&read_bounded(&program.artifact.path, MAX_CIRCUIT_BYTES)?)
            .context("read Spark sender private witness ABI")?;
    let keys = artifact
        .abi
        .parameters
        .iter()
        .filter(|parameter| parameter.name == "funding_output_key")
        .collect::<Vec<_>>();
    // The added output key remains private. Its authentication comes from the
    // recursively verified backing relation, never this ABI compatibility check.
    ensure!(
        keys.len() == 1
            && keys[0].visibility == "private"
            && keys[0].kind
                == serde_json::json!({
                    "kind": "array", "length": 32,
                    "type": {"kind": "integer", "sign": "unsigned", "width": 8}
                }),
        "Spark sender suite has the legacy or unsupported private witness ABI; preserve retained jobs with their original build and select a freshly authenticated candidate suite"
    );
    Ok(())
}
