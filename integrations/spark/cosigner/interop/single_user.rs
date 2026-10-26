//! Standalone driver linked to the unchanged pinned spark-frost crate.
//! Input is the public vector emitted by the focused single-USER unit test.
//! No services, wallet databases, funding, or private key material are used.
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use spark_frost::{
    proto::{
        common::SigningCommitment,
        frost::{AggregateFrostRequest, SigningScheme},
    },
    signing::aggregate_frost,
};
use std::collections::HashMap;

fn bytes(value: &Value, field: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(
        value[field]
            .as_str()
            .with_context(|| format!("missing {field}"))?,
    )?)
}

fn commitments(value: &Value) -> Result<SigningCommitment> {
    Ok(SigningCommitment {
        hiding: bytes(value, "hiding")?,
        binding: bytes(value, "binding")?,
    })
}

fn byte_map(value: &Value) -> Result<HashMap<String, Vec<u8>>> {
    value
        .as_object()
        .context("missing operator map")?
        .iter()
        .map(|(id, value)| {
            Ok((
                id.clone(),
                hex::decode(value.as_str().context("non-hex operator field")?)?,
            ))
        })
        .collect()
}

fn main() -> Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .context("expected public-vector path")?;
    let vector: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    ensure!(
        vector["schema"] == "zark-spark/single-user-signing-vector/v1",
        "wrong vector schema"
    );
    let request = AggregateFrostRequest {
        message: bytes(&vector, "message")?,
        verifying_key: bytes(&vector, "verifying_key")?,
        commitments: vector["commitments"]
            .as_object()
            .context("missing commitments")?
            .iter()
            .map(|(id, value)| Ok((id.clone(), commitments(value)?)))
            .collect::<Result<_>>()?,
        signature_shares: byte_map(&vector["signature_shares"])?,
        public_shares: byte_map(&vector["public_shares"])?,
        user_commitments: Some(commitments(&vector["user_commitments"])?),
        user_public_key: bytes(&vector, "user_public_key")?,
        user_signature_share: bytes(&vector, "user_signature_share")?,
        signing_scheme: SigningScheme::SingleUser as i32,
        ..Default::default()
    };
    ensure!(
        request.subuser_shares.is_empty(),
        "sub-user contribution escaped adapter"
    );
    let result = aggregate_frost(&request).map_err(anyhow::Error::msg)?;
    ensure!(
        result.signature == bytes(&vector, "signature")?,
        "Spark aggregate differs from vector"
    );
    let mut changed = request.clone();
    changed.message[0] ^= 1;
    ensure!(
        aggregate_frost(&changed).is_err(),
        "changed sighash accepted"
    );
    let mut changed = request.clone();
    changed.user_signature_share[0] ^= 1;
    ensure!(
        aggregate_frost(&changed).is_err(),
        "changed USER partial accepted"
    );
    let mut changed = request.clone();
    let commitment = changed.user_commitments.as_mut().unwrap();
    std::mem::swap(&mut commitment.hiding, &mut commitment.binding);
    ensure!(
        aggregate_frost(&changed).is_err(),
        "changed USER commitment accepted"
    );
    println!(
        "PASS: unchanged Spark aggregate_frost accepted one USER contribution; three mutations rejected."
    );
    Ok(())
}
