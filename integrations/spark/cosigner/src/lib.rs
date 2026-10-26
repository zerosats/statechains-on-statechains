//! Spark wallet, joint-key and recovery adapters for the research prototype.
//!
//! The ordinary receive module uses private joint key-tweak computation and
//! separately pinned Zark proofs. No signing API accepts both USER shares.

pub mod blind_auth;
pub mod blind_recovery;
pub mod initial_exit;
pub mod joint_identity;
pub mod keys;
pub mod leaf_signing;
pub mod native_bridge;
pub mod native_observation;
pub mod private_transfer;
pub mod receive;
pub mod share_exit;
mod signing_session;
pub mod standard_claim;
pub mod wrapped_recovery;

// Signing primitives that only build synthetic Spark signatures in tests.
#[cfg(test)]
mod legacy_signing;
#[cfg(test)]
mod signing;
#[cfg(test)]
mod user_recovery;
