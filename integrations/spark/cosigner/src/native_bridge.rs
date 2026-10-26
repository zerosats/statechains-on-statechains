//! Wallet-local bridge between private Zark ownership and native Spark signing.
//!
//! Native outpoints, amounts, aggregate keys and FROST transcripts stay here.
//! These checked arithmetic objects do not authorize the blind signer: the
//! native proof, persisted purpose-specific nonces and live reconciliation are
//! separate requirements before any native packet can be submitted.
mod keys;
mod single_user;

pub use keys::{CurrentUserKey, WalletNonce};
pub use single_user::{
    SingleUserContribution, SingleUserNonce, SingleUserPrecommit, SingleUserRequest,
};
