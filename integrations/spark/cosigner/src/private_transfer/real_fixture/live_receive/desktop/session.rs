//! One window's process: the shared network signer is opened only while the
//! network lock is held, and every operation streams its stages.
use super::super::*;
use super::store::{Lock, Network, Profile};
use std::io::Write;

/// A refusal the UI can show verbatim; everything else is reported as a
/// generic failure and logged privately.
#[derive(Debug)]
pub(super) struct Refusal {
    pub code: &'static str,
    pub message: String,
}
impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for Refusal {}
pub(super) fn refuse(code: &'static str, message: &str) -> anyhow::Error {
    Refusal {
        code,
        message: message.into(),
    }
    .into()
}

pub(super) fn emit(value: &Value) -> Result<()> {
    let mut out = std::io::stdout().lock();
    writeln!(out, "ZARK_DESKTOP {}", serde_json::to_string(value)?)?;
    out.flush()?;
    Ok(())
}

pub(super) struct Steps {
    pub operation: &'static str,
    pub steps: &'static [(&'static str, &'static str)],
    pub expected_ms: u64,
}

pub(super) const PUBLIC_DEPOSIT: Steps = Steps {
    operation: "publicDeposit",
    steps: &[
        ("fund", "Funding from the regtest faucet"),
        ("observe", "Confirming the deposit"),
    ],
    expected_ms: 3_000,
};
pub(super) const GO_PRIVATE: Steps = Steps {
    operation: "goPrivate",
    steps: &[
        ("preflight", "Checking the Spark leaf"),
        ("swap", "Getting cash from the SSP"),
        ("identity", "Creating a joint identity"),
        ("transfer", "Moving the leaf"),
        ("claim", "Claiming with the joint key"),
        ("prove_receive", "Proving receive"),
        ("prove_origin", "Proving the new coin"),
        ("finalize", "Finalizing"),
    ],
    expected_ms: 16_000,
};
pub(super) const PUBLIC_SEND: Steps = Steps {
    operation: "publicSend",
    steps: &[
        ("swap", "Making change with the SSP"),
        ("transfer", "Sending on Spark"),
        ("deliver", "Notifying the recipient"),
    ],
    expected_ms: 2_000,
};
pub(super) const PUBLIC_CLAIM: Steps = Steps {
    operation: "publicClaim",
    steps: &[("claim", "Claiming an incoming Spark payment")],
    expected_ms: 1_000,
};
pub(super) const PRIVATE_SEND: Steps = Steps {
    operation: "privateSend",
    steps: &[
        ("reserve", "Reserving the coin"),
        ("prove_sender", "Proving ownership"),
        ("authorize", "Authorizing the handover"),
        ("deliver", "Delivering privately"),
    ],
    expected_ms: 9_000,
};
pub(super) const CLAIM: Steps = Steps {
    operation: "claim",
    steps: &[
        ("propose", "Refreshing key shares"),
        ("prepare", "Preparing recovery"),
        ("prove_receiver", "Proving receipt"),
        ("issue", "Issuing recovery"),
        ("acknowledge", "Acknowledging"),
    ],
    expected_ms: 8_000,
};
const GO_PUBLIC_STEPS: &[(&str, &str)] = &[
    ("self_handover", "Preparing the coin to leave"),
    ("head", "Checking the coin"),
    ("release", "Releasing the signer share"),
    ("chain_gate", "Checking the chain"),
    ("send", "Sending on Spark"),
    ("claim", "Claiming into Public"),
    ("finalize", "Finalizing"),
];
pub(super) const GO_PUBLIC: Steps = Steps {
    operation: "goPublic",
    steps: GO_PUBLIC_STEPS,
    expected_ms: 2_000,
};
/// A coin that entered from Public is first handed to this profile itself:
/// only a received coin carries the recipient material a share exit needs.
pub(super) const GO_PUBLIC_FROM_ENTRY: Steps = Steps {
    operation: "goPublic",
    steps: GO_PUBLIC_STEPS,
    expected_ms: 19_000,
};

impl Steps {
    /// Emits one stage event. Sub-steps from shared fixture code that this
    /// operation does not list (for example a self-handover's inner steps)
    /// keep the operation's current index.
    pub fn emit(&self, step: &str) -> Result<()> {
        let index = self.steps.iter().position(|(name, _)| *name == step);
        let label = match (step, index) {
            ("waiting", _) => "Waiting for another window…",
            (_, Some(i)) => self.steps[i].1,
            (_, None) => return Ok(()),
        };
        emit(
            &json!({"progress":label,"stage":{"operation":self.operation,"step":step,"label":label,
            "index":index.unwrap_or(0),"count":self.steps.len(),"expectedMs":self.expected_ms}}),
        )
    }
}

pub(super) struct Session {
    pub suite: Suite,
    pub cluster: ClaimCluster,
    pub docker: PathBuf,
    pub network: Network,
    pub profile: Profile,
    native: Option<Pipe>,
}

impl Session {
    pub fn new(
        suite: Suite,
        cluster: ClaimCluster,
        docker: PathBuf,
        network: Network,
        profile: Profile,
    ) -> Self {
        Self {
            suite,
            cluster,
            docker,
            network,
            profile,
            native: None,
        }
    }

    /// One long-lived native fixture per window; a failed call discards it.
    pub fn native<T>(&mut self, call: impl FnOnce(&mut Pipe) -> Result<T>) -> Result<T> {
        if self.native.is_none() {
            let log = self
                .profile
                .home
                .join("logs")
                .join(format!("native-{}.private.log", uuid()));
            self.native = Some(Pipe::native(&self.docker, &log).map_err(|_| {
                refuse(
                    "unavailable",
                    "Spark regtest is not reachable. Start it with scripts/spark-dev.sh up.",
                )
            })?);
        }
        let result = call(self.native.as_mut().context("native fixture")?);
        if result.is_err() {
            self.native = None;
        }
        result
    }

    /// Lends the pipe to code that also borrows the session; return it with
    /// `put_native` only after a successful exchange.
    pub fn take_native(&mut self) -> Result<Pipe> {
        self.native(|_| Ok(()))?;
        self.native.take().context("native fixture")
    }
    pub fn put_native(&mut self, pipe: Pipe) {
        self.native = Some(pipe);
    }

    pub fn call_native(&mut self, request: Value) -> Result<Value> {
        self.native(|pipe| pipe.call_native(&request))
    }

    /// Waits for the network lock, streaming a `waiting` stage once.
    pub fn lock(&self, steps: &Steps) -> Result<Lock> {
        let mut announced = false;
        let started = std::time::Instant::now();
        loop {
            if let Some(lock) = self.network.lock()? {
                return Ok(lock);
            }
            if !announced {
                steps.emit("waiting")?;
                announced = true;
            }
            if started.elapsed() > std::time::Duration::from_secs(600) {
                return Err(refuse(
                    "busy",
                    "Another window is still working. Try again shortly.",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }

    pub fn ensure_open(&self) -> Result<()> {
        if self.network.blocked()?.is_some() {
            return Err(refuse(
                "blocked",
                "An operation needs reconciliation. New operations are paused on this network.",
            ));
        }
        Ok(())
    }

    /// Opens the shared signer; call only while holding the network lock.
    pub fn engine(&self, admission: Arc<ObservedAdmission>) -> Result<Engine> {
        self.suite.receive_engine_joint_identity(
            &self.network.root,
            &self.cluster,
            false,
            admission,
        )
    }

    pub fn admission(&self) -> Arc<ObservedAdmission> {
        Arc::new(ObservedAdmission::new(self.suite.deployment))
    }

    pub fn log_error(&self, operation: &str, error: &anyhow::Error) {
        use std::os::unix::fs::OpenOptionsExt;
        if let Ok(mut file) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(self.profile.home.join("logs/errors.private.log"))
        {
            let _ = writeln!(file, "{} {operation}: {error:#}", super::store::now_ms());
        }
    }
}
