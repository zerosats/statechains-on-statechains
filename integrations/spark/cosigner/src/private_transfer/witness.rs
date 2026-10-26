//! Private prover input formatting shared by the Spark wallet roles. None of
//! these bytes belong on the blind signer wire; only final proofs do.
use anyhow::{Result, ensure};
use zeroize::Zeroizing;

pub(crate) fn bytes(output: &mut String, name: &str, value: &[u8]) -> Result<()> {
    let encoded = Zeroizing::new(serde_json::to_string(value)?);
    output.push_str(name);
    output.push_str(" = ");
    output.push_str(&encoded);
    output.push('\n');
    Ok(())
}
pub(crate) fn statement(value: &[u8]) -> Result<Zeroizing<String>> {
    let mut output = Zeroizing::new(String::new());
    bytes(&mut output, "statement", value)?;
    fields(
        &mut output,
        "packed",
        &zark_protocol::public_fields(value),
        value.len().div_ceil(31),
    )?;
    Ok(output)
}
pub(crate) fn fields(output: &mut String, name: &str, value: &[u8], count: usize) -> Result<()> {
    ensure!(
        value.len() == count * 32,
        "Spark recursive witness field shape"
    );
    output.push_str(name);
    output.push_str(" = [");
    for (i, field) in value.chunks_exact(32).enumerate() {
        if i > 0 {
            output.push(',');
        }
        output.push_str("\"0x");
        output.push_str(&hex::encode(field));
        output.push('"');
    }
    output.push_str("]\n");
    Ok(())
}
pub(crate) fn partials(output: &mut String, value: &[[u8; 32]; 2]) -> Result<()> {
    let encoded = Zeroizing::new(serde_json::to_string(value)?);
    output.push_str("partials = ");
    output.push_str(&encoded);
    output.push('\n');
    Ok(())
}
