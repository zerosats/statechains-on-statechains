//! Wallet-side proof-carrying Zark transfers with native Spark backing.
//!
//! The origin/sender/receiver paths use the pinned Spark lineage roles, actual
//! blinded recovery construction and durable exact-request journals. Native
//! checks alone confer no ownership. Live transport, fresh signer heads and
//! chain/recovery-window observations remain explicit bridge requirements.
mod backing;
mod certificate;
mod journal;
mod offer;
mod origin;
pub(crate) mod persistence;
mod receiver;
mod recovery;
mod sender;
pub(crate) mod witness;
pub use backing::PrivateBacking;
pub use certificate::PrivateCertificate;
pub use journal::{IssuedRecovery, RecoveryJournal};
pub use offer::PrivateOffer;
pub use origin::{origin_issuance, origin_prover_toml};
pub use receiver::{NextRecipient, PrivateReceiver};
pub use recovery::{PrivateRecovery, RecoveryParameters};
pub use sender::{PrivateSender, SenderParameters};

#[cfg(test)]
#[path = "private_transfer/backing_tests.rs"]
mod backing_tests;
#[cfg(test)]
#[path = "private_transfer/observation_tests.rs"]
mod observation_tests;

#[cfg(test)]
#[path = "private_transfer/received_root_tests.rs"]
mod received_root_tests;

#[cfg(test)]
#[path = "private_transfer/recovery_tests.rs"]
mod recovery_tests;

#[cfg(test)]
#[path = "private_transfer/journal_tests.rs"]
mod journal_tests;

#[cfg(test)]
#[path = "private_transfer/real_fixture.rs"]
mod real_fixture;
