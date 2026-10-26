//! Private combination and ordinary Spark encryption of one native claim share.
//!
//! The wallet is the sole MPC output recipient. Server inputs include its
//! evaluation and an ECIES encryption mask; neither the evaluation nor the
//! symmetric mask leaves that party. Final native ciphertexts must never be
//! returned to the blind signer, including in identity-signing requests. The
//! identity adapter must hash native signing payloads locally first.
//!
//! This primitive grants no ownership, proof admission or nonce authority.
mod boolean;
mod circuit;
mod encryption;
pub mod identity;
mod session;
pub use circuit::{CircuitSpec, ClaimCircuit};
pub use encryption::EncryptionMask;
pub use session::{ClaimContributor, ClaimEvaluator};

#[cfg(test)]
mod tests;
