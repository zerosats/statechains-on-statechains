//! Durable layout of one blinded desktop network.
//!
//! ```text
//! blinded-networks/<network>/
//!   network.json                 pinned flags, suite manifest hashes, cluster
//!   private-fixture-identity.json  deployment identity (Suite::save_identity)
//!   signer/ checkpoint/          the one shared in-process signer
//!   network.lock                 held for every mutating operation
//!   blocked.json                 written before a share-release journal exists
//!   profiles/<profile>/
//!     profile.lock               one window per profile
//!     profile.private.json       claim, inbox and Public-wallet secrets
//!     public.json                what other local profiles may read
//!     public-exit-tree.json      this profile's Public leaves and their parent
//!                                transactions, for a later offline exit
//!     coins/<32 hex>/coin.json   one holding; its wallet journals beside it
//!     inbox/<id>.sealed          offers addressed to this profile
//!     activity.json
//! ```
//! The network refuses to open if its pinned configuration drifts: retained
//! journals were bound to these flags and proof suites.
use super::super::{DENOMINATIONS_SAT, Suite, private_directory};
use anyhow::{Context, Result, ensure};
use k256::{elliptic_curve::sec1::ToEncodedPoint, schnorr::SigningKey};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use zark_protocol::{hash, owner_auth::generate_secret, random32, storage::atomic_write};
use zeroize::Zeroizing;

const NETWORK_SCHEMA: &str = "zark-blinded-desktop-network-v1";
const SUITES: [&str; 4] = [
    "ZARK_SPARK_REAL_SUITE",
    "ZARK_SPARK_RECEIVE_SUITE",
    "ZARK_SPARK_NATIVE_SUITE",
    "ZARK_SPARK_AUTH_SUITE",
];

pub(super) fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

pub(super) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(super) fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && meta.nlink() == 1 && meta.len() <= 1024 * 1024,
        "desktop record shape: {}",
        path.display()
    );
    Ok(serde_json::from_slice(&Zeroizing::new(fs::read(path)?))?)
}

pub(super) fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    atomic_write(path, &Zeroizing::new(serde_json::to_vec_pretty(value)?))
}

/// An advisory flock that is deliberately not a `ProcessLock`: it never
/// enters the operation-lock slot that provers inherit, so journals opened
/// while it is held keep their own strict nesting.
pub(super) struct Lock(#[allow(dead_code)] File);
impl Lock {
    pub fn try_acquire(path: &Path) -> Result<Option<Self>> {
        use std::os::fd::AsRawFd;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let meta = file.metadata()?;
        ensure!(
            meta.is_file() && meta.nlink() == 1 && meta.mode() & 0o077 == 0,
            "invalid desktop lock file"
        );
        // SAFETY: file owns a valid descriptor for the duration of the call.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(Some(Self(file)));
        }
        let error = std::io::Error::last_os_error();
        ensure!(
            error.raw_os_error() == Some(libc::EWOULDBLOCK),
            "desktop lock failed: {error}"
        );
        Ok(None)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub(super) struct NetworkConfig {
    pub schema: String,
    pub ecdsa_2p: bool,
    pub additive_receive: bool,
    pub share_release: bool,
    /// SHA-256 of each pinned suite manifest, in `SUITES` order.
    pub suites: Vec<Option<String>>,
    pub cluster: String,
}

impl NetworkConfig {
    /// The configuration this process would bind a network to. Optimized mode
    /// only: ECDSA-2P identity, additive receive and share-release exit.
    pub fn current(cluster_digest: &[u8; 32]) -> Result<Self> {
        ensure!(
            Suite::entry_flag("ZARK_SPARK_ECDSA_2P")
                && Suite::entry_flag("ZARK_SPARK_ADDITIVE_RECEIVE"),
            "blinded desktop requires ZARK_SPARK_ECDSA_2P=1 and ZARK_SPARK_ADDITIVE_RECEIVE=1"
        );
        ensure!(
            std::env::var_os("ZARK_SPARK_INITIALISE_WITNESS").is_none(),
            "the fixture-only witness switch is refused for desktop networks"
        );
        let suites = SUITES
            .iter()
            .map(|name| -> Result<Option<String>> {
                std::env::var_os(name)
                    .map(|path| Ok(hex::encode(hash(&[&fs::read(PathBuf::from(path))?]))))
                    .transpose()
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            suites[0].is_some() && suites[1].is_some(),
            "blinded desktop requires the ownership and receive proof suites"
        );
        Ok(Self {
            schema: NETWORK_SCHEMA.into(),
            ecdsa_2p: true,
            additive_receive: true,
            share_release: true,
            suites,
            cluster: hex::encode(cluster_digest),
        })
    }
}

pub(super) struct Network {
    pub name: String,
    pub root: PathBuf,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(super) struct Blocked {
    pub reason: String,
    pub operation: String,
    pub profile: String,
    pub coin: String,
    pub at: u64,
}

impl Network {
    pub fn parent() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../work/zark-spark/blinded-networks")
    }

    /// Opens or creates the network. A new network saves the suite identity;
    /// an existing one restores it and must match `config` exactly.
    pub fn open(
        parent: &Path,
        name: &str,
        suite: &mut Suite,
        config: &NetworkConfig,
    ) -> Result<Self> {
        let network = Self::open_dir(parent, name, config, &mut |staging| {
            suite.save_identity(staging)
        })?;
        suite.restore_identity(&network.root)?;
        Ok(network)
    }

    /// A new network is assembled in a staging directory (`init` writes its
    /// identity) and renamed into place, so a partial network never exists.
    pub fn open_dir(
        parent: &Path,
        name: &str,
        config: &NetworkConfig,
        init: &mut dyn FnMut(&Path) -> Result<()>,
    ) -> Result<Self> {
        ensure!(valid_name(name), "invalid network name");
        fs::create_dir_all(parent)?;
        let root = parent.join(name);
        if root.exists() {
            let saved: NetworkConfig = read_json(&root.join("network.json"))
                .context("existing directory is not a blinded desktop network")?;
            ensure!(
                saved == *config,
                "network {name} was created with another signer configuration or proof suite; use a new network name"
            );
        } else {
            let staging = parent.join(format!(".{name}-{}", hex::encode(&random32()[..8])));
            private_directory(&staging)?;
            init(&staging)?;
            write_json(&staging.join("network.json"), config)?;
            private_directory(&staging.join("profiles"))?;
            if let Err(error) = fs::rename(&staging, &root) {
                // Windows started together race to create the network. The
                // loser's staging identity was never used; it adopts the
                // winner's network, subject to the same configuration check.
                if !root.join("network.json").exists() {
                    return Err(error).context("network directory could not be created");
                }
                fs::remove_dir_all(&staging)?;
                return Self::open_dir(parent, name, config, init);
            }
        }
        Ok(Self {
            name: name.into(),
            root,
        })
    }

    pub fn lock(&self) -> Result<Option<Lock>> {
        Lock::try_acquire(&self.root.join("network.lock"))
    }

    pub fn blocked(&self) -> Result<Option<Blocked>> {
        let path = self.root.join("blocked.json");
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(read_json(&path)?))
    }

    /// Recorded before any share-release journal exists; removed only after
    /// the exit completed and replayed. A crash in between leaves it set.
    pub fn block(&self, blocked: &Blocked) -> Result<()> {
        ensure!(self.blocked()?.is_none(), "network already blocked");
        write_json(&self.root.join("blocked.json"), blocked)
    }

    /// Keeps the block and records why it can no longer clear by itself.
    pub fn fail_blocked(&self, reason: &str) -> Result<()> {
        let mut blocked = self.blocked()?.context("network is not blocked")?;
        blocked.reason = reason.into();
        write_json(&self.root.join("blocked.json"), &blocked)
    }

    pub fn unblock(&self, profile: &str, coin: &str) -> Result<()> {
        let blocked = self.blocked()?.context("network is not blocked")?;
        ensure!(
            blocked.profile == profile && blocked.coin == coin,
            "network blocked by another exit"
        );
        fs::remove_file(self.root.join("blocked.json"))?;
        Ok(())
    }

    pub fn profiles(&self) -> Result<Vec<PublicProfile>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(self.root.join("profiles"))? {
            let path = entry?.path().join("public.json");
            if path.is_file() {
                out.push(read_json(&path)?);
            }
        }
        Ok(out)
    }
}

/// Never leaves this profile's directory.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileSecrets {
    schema: String,
    claim: [u8; 32],
    inbox: [u8; 32],
    /// Named ordinary recipient in the native fixture: the Public wallet.
    public: String,
}
impl Drop for ProfileSecrets {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.claim.zeroize();
        self.inbox.zeroize();
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub(super) struct PublicProfile {
    pub schema: String,
    pub profile: String,
    /// x-only claim key: the Incognito address.
    pub claim_key: String,
    /// Compressed key that seals inbox offers to this profile.
    pub inbox_key: String,
    /// Compressed Spark identity of the Public wallet, once created.
    pub public_identity: Option<String>,
}

pub(super) struct Profile {
    pub name: String,
    pub home: PathBuf,
    secrets: ProfileSecrets,
    pub public: PublicProfile,
    _lock: Lock,
}

impl Profile {
    pub fn open(network: &Network, name: &str) -> Result<Self> {
        ensure!(valid_name(name), "invalid profile name");
        let home = network.root.join("profiles").join(name);
        private_directory(&home)?;
        let lock = Lock::try_acquire(&home.join("profile.lock"))?
            .context("this profile is already open in another window")?;
        for directory in ["coins", "inbox", "logs"] {
            private_directory(&home.join(directory))?;
        }
        let secrets_path = home.join("profile.private.json");
        if !secrets_path.exists() {
            write_json(
                &secrets_path,
                &ProfileSecrets {
                    schema: "zark-blinded-desktop-profile-v1".into(),
                    claim: generate_secret(),
                    inbox: generate_secret(),
                    public: hex::encode(random32()),
                },
            )?;
        }
        let secrets: ProfileSecrets = read_json(&secrets_path)?;
        ensure!(
            secrets.schema == "zark-blinded-desktop-profile-v1"
                && secrets.public.len() == 64
                && secrets.public.bytes().all(|b| b.is_ascii_hexdigit()),
            "profile record schema"
        );
        let claim_key: [u8; 32] = SigningKey::from_bytes(&secrets.claim)?
            .verifying_key()
            .to_bytes()
            .into();
        let inbox_key = k256::SecretKey::from_slice(&secrets.inbox)?
            .public_key()
            .to_encoded_point(true);
        let public_path = home.join("public.json");
        let derived = PublicProfile {
            schema: "zark-blinded-desktop-public-v1".into(),
            profile: name.into(),
            claim_key: hex::encode(claim_key),
            inbox_key: hex::encode(inbox_key.as_bytes()),
            public_identity: None,
        };
        let public = if public_path.exists() {
            let saved: PublicProfile = read_json(&public_path)?;
            ensure!(
                PublicProfile {
                    public_identity: None,
                    ..saved.clone()
                } == derived,
                "published profile keys differ from this profile's secrets"
            );
            saved
        } else {
            write_json(&public_path, &derived)?;
            derived
        };
        Ok(Self {
            name: name.into(),
            home,
            secrets,
            public,
            _lock: lock,
        })
    }

    pub fn claim_secret(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secrets.claim)
    }
    pub fn inbox_secret(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secrets.inbox)
    }
    pub fn public_name(&self) -> &str {
        &self.secrets.public
    }

    pub fn publish_public_identity(&mut self, identity: &[u8]) -> Result<()> {
        let identity = hex::encode(identity);
        if let Some(saved) = &self.public.public_identity {
            ensure!(*saved == identity, "Public wallet identity changed");
            return Ok(());
        }
        self.public.public_identity = Some(identity);
        write_json(&self.home.join("public.json"), &self.public)
    }

    pub fn coins(&self) -> Result<Vec<CoinRecord>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(self.home.join("coins"))? {
            let path = entry?.path().join("coin.json");
            if path.is_file() {
                out.push(read_json(&path)?);
            }
        }
        out.sort_by_key(|c: &CoinRecord| c.created_at);
        Ok(out)
    }

    pub fn coin_dir(&self, id: &str) -> Result<PathBuf> {
        ensure!(
            id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "invalid coin id"
        );
        Ok(self.home.join("coins").join(id))
    }

    pub fn new_coin(
        &self,
        origin: Origin,
        state: CoinState,
        amount_sat: u64,
    ) -> Result<CoinRecord> {
        self.new_coin_with_id(&hex::encode(&random32()[..16]), origin, state, amount_sat)
    }

    /// Creates the coin directory with the live fixture's wallet layout.
    pub fn new_coin_with_id(
        &self,
        id: &str,
        origin: Origin,
        state: CoinState,
        amount_sat: u64,
    ) -> Result<CoinRecord> {
        ensure!(DENOMINATIONS_SAT.contains(&amount_sat), "coin denomination");
        let id = id.to_owned();
        let dir = self.coin_dir(&id)?;
        ensure!(!dir.exists(), "coin already exists");
        private_directory(&dir)?;
        for name in ["wallets", "wire", "proofs", "scratch"] {
            private_directory(&dir.join(name))?;
        }
        let coin = CoinRecord {
            id,
            origin,
            state,
            amount_sat,
            leaf: None,
            revision: None,
            counterparty: None,
            created_at: now_ms(),
            attempts: 0,
        };
        self.save_coin(&coin)?;
        Ok(coin)
    }

    pub fn save_coin(&self, coin: &CoinRecord) -> Result<()> {
        write_json(&self.coin_dir(&coin.id)?.join("coin.json"), coin)
    }

    pub fn coin(&self, id: &str) -> Result<CoinRecord> {
        read_json(&self.coin_dir(id)?.join("coin.json"))
    }

    pub fn activity(&self) -> Result<Vec<Activity>> {
        let path = self.home.join("activity.json");
        if !path.exists() {
            return Ok(Vec::new());
        }
        read_json(&path)
    }

    /// Inserts or replaces the row with the same id; newest first, bounded.
    pub fn record(&self, row: Activity) -> Result<()> {
        let mut rows = self.activity()?;
        rows.retain(|r| r.id != row.id);
        rows.insert(0, row);
        rows.truncate(200);
        write_json(&self.home.join("activity.json"), &rows)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub(super) enum Origin {
    Public,
    Received,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub(super) enum CoinState {
    /// goPrivate in progress; becomes Available or Interrupted.
    Entering,
    Available,
    /// privateSend journaled; resumes automatically.
    Sending,
    /// Handed over; history only.
    Sent,
    /// Received offer being claimed; resumes automatically.
    Claiming,
    /// Share-release exit journaled; any failure blocks the network.
    Exiting,
    /// Exited into the Public wallet; history only.
    Exited,
    /// Needs manual reconciliation; never retried automatically.
    Interrupted,
    /// Entry stopped before its native transfer started; nothing moved.
    Abandoned,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(super) struct CoinRecord {
    pub id: String,
    pub origin: Origin,
    pub state: CoinState,
    pub amount_sat: u64,
    /// The native Spark leaf backing this coin.
    pub leaf: Option<String>,
    /// Signer revision of the acknowledged recovery.
    pub revision: Option<u64>,
    pub counterparty: Option<String>,
    pub created_at: u64,
    /// Prover job attempts; each attempt uses a fresh job directory.
    pub attempts: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Activity {
    pub id: String,
    pub side: String,
    pub kind: String,
    pub label: String,
    pub amount_sat: u64,
    pub state: String,
    pub at: u64,
    pub counterparty: Option<String>,
}
