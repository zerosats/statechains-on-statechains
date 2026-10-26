//! Wallet (cb-mpc P1) side of blind two-party ECDSA for the fresh entry identity.
//!
//! Key generation replaces the placeholder wallet share and the allocation's
//! server point with cb-mpc shares blinded by a wallet-only tau: the identity
//! share is u = x_w' + tau, so P = X_s + u·G = P' + tau·G while the signer
//! knows only the cb-mpc key P'. Every identity path uses u; only cb-mpc uses
//! x_w', and tau = u - x_w' is never sent. The P1 blob, tau and the exact
//! finish request are saved before the signer may adopt its share. Protocol
//! sessions are memory-only; a lost one is simply restarted.
use super::*;
#[cfg(feature = "ecdsa-2p")]
use zark_protocol::spark_wire::ecdsa_2p::{self as wire, Frame};

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EcdsaRecord {
    pending: Option<PendingKeygen>,
    /// P1 blob, holding the wallet share and the Paillier secret key.
    key: Option<Vec<u8>>,
    /// The signer's cb-mpc public share, replacing the allocation server.
    server: Option<Vec<u8>>,
    signatures: BTreeMap<String, Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingKeygen {
    key: Vec<u8>,
    finish: Vec<u8>,
    /// Absent only in historical unblinded records, which cannot sign blind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tau: Option<Digest>,
}

impl Drop for EcdsaRecord {
    fn drop(&mut self) {
        if let Some(key) = &mut self.key {
            key.zeroize();
        }
    }
}

impl Drop for PendingKeygen {
    fn drop(&mut self) {
        self.key.zeroize();
        self.tau.zeroize();
    }
}

impl EcdsaRecord {
    pub(super) fn server(&self) -> Result<&[u8]> {
        self.server
            .as_deref()
            .context("ECDSA-2P key generation has not finished")
    }
    pub(super) fn signature(&self, digest: &Digest) -> Option<Vec<u8>> {
        self.signatures.get(&hex::encode(digest)).cloned()
    }
}

impl JointIdentityJournal {
    pub fn uses_ecdsa(&self) -> bool {
        self.record.ecdsa.is_some()
    }

    pub(super) fn validate_ecdsa(&self) -> Result<()> {
        let Some(state) = &self.record.ecdsa else {
            return Ok(());
        };
        ensure!(
            !self.record.native_scope
                && self.record.signing.is_empty()
                && state.key.is_some() == state.server.is_some()
                && !(state.key.is_some() && state.pending.is_some())
                && (state.signatures.is_empty() || state.key.is_some())
                && state.signatures.len() <= 8,
            "ECDSA-2P identity lifecycle"
        );
        if let Some(pending) = &state.pending {
            let finish = Request::decode(&pending.finish)?;
            ensure!(
                matches!(finish.command, Command::EcdsaKeygenFinish { .. })
                    && finish.session == Request::decode(&self.record.allocation)?.session,
                "ECDSA-2P pending key generation"
            );
        }
        if state.key.is_some() {
            check_key(state)?;
            let public = self.public_key()?;
            for (digest, der) in &state.signatures {
                use k256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
                VerifyingKey::from_sec1_bytes(&public)?
                    .verify_prehash(&hex::decode(digest)?, &Signature::from_der(der)?)?;
            }
        }
        Ok(())
    }
}

/// The blob's key must be X_s + x_w'·G.
#[cfg(feature = "ecdsa-2p")]
fn check_key(state: &EcdsaRecord) -> Result<()> {
    let key =
        zark_spark_ecdsa_2p::KeyBlob::from_bytes(state.key.as_deref().context("ECDSA-2P key")?)?;
    let cbmpc = point(state.server()?)?
        + ProjectivePoint::GENERATOR * scalar(key.private_share()?.as_slice())?;
    ensure!(
        key.public_key()?.as_slice() == cbmpc.to_affine().to_encoded_point(true).as_bytes(),
        "ECDSA-2P wallet share differs from the signer share"
    );
    Ok(())
}

#[cfg(not(feature = "ecdsa-2p"))]
fn check_key(_: &EcdsaRecord) -> Result<()> {
    anyhow::bail!("co-signer built without the ecdsa-2p feature")
}

/// tau = u - x_w', the wallet-only offset between P and the cb-mpc key.
#[cfg(feature = "ecdsa-2p")]
fn blinding(key: &zark_spark_ecdsa_2p::KeyBlob, user: &Digest) -> Result<Zeroizing<[u8; 32]>> {
    let tau = scalar(user)? - scalar(key.private_share()?.as_slice())?;
    ensure!(
        tau != k256::Scalar::ZERO,
        "unblinded ECDSA-2P key cannot sign blind"
    );
    Ok(Zeroizing::new(tau.to_bytes().into()))
}

#[cfg(feature = "ecdsa-2p")]
fn random_tau() -> Result<Digest> {
    for _ in 0..8 {
        let tau = random32();
        if scalar(&tau).is_ok_and(|t| t != k256::Scalar::ZERO) {
            return Ok(tau);
        }
    }
    anyhow::bail!("ECDSA-2P blinding sample")
}

#[cfg(feature = "ecdsa-2p")]
mod protocol {
    use super::*;
    use std::time::Duration;
    use zark_spark_ecdsa_2p::{KeyBlob, Output, Role, Session};

    const TIMEOUT: Duration = Duration::from_secs(120);

    /// Sends one signed request and returns the signer's response. Exact
    /// retries are the transport's job; protocol sessions do not survive here.
    pub type Transport<'a> = dyn FnMut(&Request) -> Result<Value> + 'a;

    impl JointIdentityJournal {
        pub fn create_ecdsa(
            directory: &Path,
            frames: &Path,
            p: &IdentityParameters,
        ) -> Result<Self> {
            Self::create_with(directory, frames, p, Some(EcdsaRecord::default()))
        }

        /// Runs after allocation and before any other use of the identity.
        pub fn ecdsa_keygen(&mut self, send: &mut Transport) -> Result<()> {
            ensure!(
                self.record.server.is_some(),
                "allocate before ECDSA-2P key generation"
            );
            let state = self
                .record
                .ecdsa
                .as_ref()
                .context("identity does not use ECDSA-2P")?;
            if state.key.is_some() {
                return self.persist();
            }
            if let Some(pending) = &state.pending {
                // The signer may already have adopted this exact finish.
                if let Ok(response) = send(&Request::decode(&pending.finish)?) {
                    return self.confirm_keygen(&response);
                }
            }
            let mut session = Session::keygen(Role::P1, TIMEOUT)?;
            let m1 = Frame::new(session.exchange(None)?)?;
            let start = self.signed(
                wire::keygen_intent(&self.record.intent, &m1)?,
                Command::EcdsaKeygen { frame: m1 },
            )?;
            // A signer that accepts a new start has no key, so a previously
            // pending wallet share can never be needed again.
            let m2 = frame(&send(&start)?)?;
            let m3 = Frame::new(session.exchange(Some(m2.as_bytes().to_vec()))?)?;
            let Output::Key(key) = session.finish(None)? else {
                anyhow::bail!("ECDSA-2P key generation produced no key")
            };
            let finish = self.signed(
                wire::keygen_finish_intent(&start.intent, &m3)?,
                Command::EcdsaKeygenFinish {
                    keygen: start.intent.operation,
                    frame: m3,
                },
            )?;
            let state = self.record.ecdsa.as_mut().context("ECDSA-2P record")?;
            state.pending = Some(PendingKeygen {
                key: key.as_bytes().to_vec(),
                finish: finish.encode()?,
                tau: Some(random_tau()?),
            });
            self.persist()?;
            let response = send(&finish)?;
            self.confirm_keygen(&response)
        }

        fn confirm_keygen(&mut self, response: &Value) -> Result<()> {
            let state = self.record.ecdsa.as_ref().context("ECDSA-2P record")?;
            let pending = state
                .pending
                .as_ref()
                .context("ECDSA-2P key generation not pending")?;
            let key = KeyBlob::from_bytes(&pending.key)?;
            let server: Vec<u8> = serde_json::from_value(response["server"].clone())?;
            let public: Vec<u8> = serde_json::from_value(response["public"].clone())?;
            let share = scalar(key.private_share()?.as_slice())?;
            let cbmpc = point(&server)? + ProjectivePoint::GENERATOR * share;
            ensure!(
                public == key.public_key()?
                    && public == cbmpc.to_affine().to_encoded_point(true).as_bytes(),
                "ECDSA-2P signer share differs from the generated key"
            );
            let tau = pending
                .tau
                .as_ref()
                .context("ECDSA-2P key generation without blinding")?;
            let user = share + scalar(tau)?;
            ensure!(user != k256::Scalar::ZERO, "ECDSA-2P blinded share");
            let state = self.record.ecdsa.as_mut().context("ECDSA-2P record")?;
            state.key = state.pending.take().map(|p| p.key.clone());
            state.server = Some(server);
            self.record.user.zeroize();
            self.record.user.copy_from_slice(&user.to_bytes());
            self.persist()
        }

        /// One fresh blind ticket per call. The signer sees neither the digest
        /// nor P; message 3 carries only m'' = m + r·tau.
        pub fn ecdsa_sign(
            &mut self,
            message: &EntryMessage,
            send: &mut Transport,
        ) -> Result<Vec<u8>> {
            use k256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
            let digest = message.digest();
            let state = self
                .record
                .ecdsa
                .as_ref()
                .context("identity does not use ECDSA-2P")?;
            if let Some(signature) = state.signature(&digest) {
                return Ok(signature);
            }
            let key = KeyBlob::from_bytes(
                state
                    .key
                    .as_deref()
                    .context("ECDSA-2P key generation pending")?,
            )?;
            let tau = blinding(&key, &self.record.user)?;
            let nonce = random32();
            let ticket = wire::sign_intent(&self.record.intent, &nonce)?;
            let sid = wire::session_id(&ticket)?;
            let mut session = Session::sign_blind_wallet(&key, digest, &tau, sid, TIMEOUT)?;
            let m1 = Frame::new(session.exchange(None)?)?;
            let open = self.signed(
                ticket.clone(),
                Command::EcdsaSign {
                    message: None,
                    nonce,
                    frame: m1,
                },
            )?;
            let m2 = frame(&send(&open)?)?;
            let m3 = Frame::new(session.exchange(Some(m2.as_bytes().to_vec()))?)?;
            let finish = self.signed(
                wire::sign_finish_intent(&ticket, &m3)?,
                Command::EcdsaSignFinish {
                    ticket: ticket.operation,
                    frame: m3,
                },
            )?;
            let m4 = frame(&send(&finish)?)?;
            let Output::Signature(Some(signature)) =
                session.finish(Some(m4.as_bytes().to_vec()))?
            else {
                anyhow::bail!("ECDSA-2P signature missing")
            };
            VerifyingKey::from_sec1_bytes(&self.public_key()?)?
                .verify_prehash(&digest, &Signature::from_der(&signature)?)?;
            let state = self.record.ecdsa.as_mut().context("ECDSA-2P record")?;
            state
                .signatures
                .insert(hex::encode(digest), signature.clone());
            self.persist()?;
            Ok(signature)
        }
    }

    fn frame(response: &Value) -> Result<Frame> {
        Ok(serde_json::from_value(response["frame"].clone())?)
    }
}
