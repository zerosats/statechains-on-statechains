//! One blocking cb-mpc protocol call per thread, driven message by message.
use super::{KeyBlob, ffi, take};
use anyhow::{Context, Result, bail, ensure};
use std::{
    ffi::{CStr, c_int, c_void},
    sync::mpsc::{self, Receiver, Sender, SyncSender, TrySendError},
    thread,
    time::Duration,
};
use zeroize::Zeroizing;

/// Both parties must use the same names; cb-mpc binds them into transcripts.
const P1_NAME: &CStr = c"zark-spark-wallet";
const P2_NAME: &CStr = c"zark-spark-signer";
const MAX_MESSAGE: usize = 128 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// Holds the Paillier key and receives the completed signature.
    P1,
    P2,
}

pub enum Output {
    Key(KeyBlob),
    /// DER, low-s. Only P1 receives it.
    Signature(Option<Vec<u8>>),
}

pub enum Step {
    Send(Vec<u8>),
    Done(Output),
}

enum Event {
    Message(Vec<u8>),
    Done(Result<Output>),
}

enum Operation {
    Keygen,
    Sign {
        key: KeyBlob,
        digest: [u8; 32],
        sid: [u8; 32],
    },
    /// `wallet` is P1's (digest, tau); P2 has neither.
    SignBlind {
        key: KeyBlob,
        wallet: Option<([u8; 32], Zeroizing<[u8; 32]>)>,
        sid: [u8; 32],
    },
}

pub struct Session {
    incoming: SyncSender<Vec<u8>>,
    events: Receiver<Event>,
    timeout: Duration,
    finished: bool,
}

impl Session {
    pub fn keygen(role: Role, timeout: Duration) -> Result<Self> {
        Self::spawn(role, Operation::Keygen, timeout)
    }

    /// `sid` must be fresh per attempt and agreed by both parties in advance.
    pub fn sign(
        role: Role,
        key: &KeyBlob,
        digest: [u8; 32],
        sid: [u8; 32],
        timeout: Duration,
    ) -> Result<Self> {
        let key = KeyBlob::from_bytes(key.as_bytes())?;
        Self::spawn(role, Operation::Sign { key, digest, sid }, timeout)
    }

    /// Blind signing as P1. The signature is valid for `digest` under
    /// Q + tau·G, where Q is the cb-mpc key; P2 sees only m'' = m + r·tau.
    pub fn sign_blind_wallet(
        key: &KeyBlob,
        digest: [u8; 32],
        tau: &[u8; 32],
        sid: [u8; 32],
        timeout: Duration,
    ) -> Result<Self> {
        let key = KeyBlob::from_bytes(key.as_bytes())?;
        let wallet = Some((digest, Zeroizing::new(*tau)));
        Self::spawn(Role::P1, Operation::SignBlind { key, wallet, sid }, timeout)
    }

    /// Blind signing as P2. Each session answers one m'' with one fresh
    /// nonce; it must never be recreated to answer another.
    pub fn sign_blind_signer(key: &KeyBlob, sid: [u8; 32], timeout: Duration) -> Result<Self> {
        let key = KeyBlob::from_bytes(key.as_bytes())?;
        Self::spawn(
            Role::P2,
            Operation::SignBlind {
                key,
                wallet: None,
                sid,
            },
            timeout,
        )
    }

    /// Delivers the peer's message, if any, then waits for this party's next
    /// message or its final output.
    pub fn next(&mut self, incoming: Option<Vec<u8>>) -> Result<Step> {
        ensure!(!self.finished, "cb-mpc session already finished");
        if let Some(message) = incoming {
            ensure!(message.len() <= MAX_MESSAGE, "cb-mpc message size");
            match self.incoming.try_send(message) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => bail!("cb-mpc message arrived out of order"),
                Err(TrySendError::Disconnected(_)) => {
                    self.finished = true;
                    while let Ok(event) = self.events.try_recv() {
                        if let Event::Done(Err(error)) = event {
                            return Err(error.context("cb-mpc session stopped"));
                        }
                    }
                    bail!("cb-mpc session stopped")
                }
            }
        }
        match self.events.recv_timeout(self.timeout) {
            Ok(Event::Message(message)) => Ok(Step::Send(message)),
            Ok(Event::Done(result)) => {
                self.finished = true;
                Ok(Step::Done(result?))
            }
            Err(_) => {
                self.finished = true;
                bail!("cb-mpc session timed out or stopped")
            }
        }
    }

    pub fn exchange(&mut self, incoming: Option<Vec<u8>>) -> Result<Vec<u8>> {
        match self.next(incoming)? {
            Step::Send(message) => Ok(message),
            Step::Done(_) => bail!("cb-mpc session finished before its message"),
        }
    }

    pub fn finish(&mut self, incoming: Option<Vec<u8>>) -> Result<Output> {
        match self.next(incoming)? {
            Step::Done(output) => Ok(output),
            Step::Send(_) => bail!("cb-mpc session sent an unexpected message"),
        }
    }

    fn spawn(role: Role, operation: Operation, timeout: Duration) -> Result<Self> {
        let (events, receiver) = mpsc::channel();
        let (incoming, inbox) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("cbmpc-ecdsa-2p".into())
            .spawn(move || {
                let channel = Channel {
                    events: events.clone(),
                    inbox,
                    timeout,
                };
                let result = run(role, &channel, operation);
                let _ = events.send(Event::Done(result));
            })
            .context("cb-mpc session thread")?;
        Ok(Self {
            incoming,
            events: receiver,
            timeout,
            finished: false,
        })
    }
}

struct Channel {
    events: Sender<Event>,
    inbox: Receiver<Vec<u8>>,
    timeout: Duration,
}

fn run(role: Role, channel: &Channel, operation: Operation) -> Result<Output> {
    let transport = ffi::Transport {
        ctx: (channel as *const Channel).cast_mut().cast(),
        send,
        receive,
        receive_all: std::ptr::null(),
        free: std::ptr::null(),
    };
    let job = ffi::Job2p {
        party: match role {
            Role::P1 => 0,
            Role::P2 => 1,
        },
        p1_name: P1_NAME.as_ptr(),
        p2_name: P2_NAME.as_ptr(),
        transport: &transport,
    };
    match operation {
        Operation::Keygen => {
            let mut out = ffi::Cmem::EMPTY;
            let rc = unsafe { ffi::cbmpc_ecdsa_2p_dkg(&job, ffi::SECP256K1, &mut out) };
            let blob = take(rc, out)?;
            Ok(Output::Key(KeyBlob::from_bytes(&blob)?))
        }
        Operation::Sign { key, digest, sid } => {
            let mut sid_out = ffi::Cmem::EMPTY;
            let mut signature = ffi::Cmem::EMPTY;
            let rc = unsafe {
                ffi::cbmpc_ecdsa_2p_sign(
                    &job,
                    key.view(),
                    ffi::Cmem::view(&digest),
                    ffi::Cmem::view(&sid),
                    &mut sid_out,
                    &mut signature,
                )
            };
            drop(take(rc, sid_out));
            let signature: Zeroizing<Vec<u8>> = take(rc, signature)?;
            Ok(Output::Signature(
                (!signature.is_empty()).then(|| signature.to_vec()),
            ))
        }
        Operation::SignBlind { key, wallet, sid } => {
            let (digest, tau): (&[u8], &[u8]) = match &wallet {
                Some((digest, tau)) => (digest, tau.as_slice()),
                None => (&[], &[]),
            };
            let mut sid_out = ffi::Cmem::EMPTY;
            let mut signature = ffi::Cmem::EMPTY;
            let rc = unsafe {
                ffi::cbmpc_ecdsa_2p_sign_blind(
                    &job,
                    key.view(),
                    ffi::Cmem::view(digest),
                    ffi::Cmem::view(tau),
                    ffi::Cmem::view(&sid),
                    &mut sid_out,
                    &mut signature,
                )
            };
            drop(take(rc, sid_out));
            let signature: Zeroizing<Vec<u8>> = take(rc, signature)?;
            Ok(Output::Signature(
                (!signature.is_empty()).then(|| signature.to_vec()),
            ))
        }
    }
}

unsafe extern "C" fn send(ctx: *mut c_void, _peer: i32, data: *const u8, size: c_int) -> c_int {
    let channel = unsafe { &*ctx.cast::<Channel>() };
    if size < 0 || size as usize > MAX_MESSAGE || (data.is_null() && size != 0) {
        return ffi::NETWORK_ERROR;
    }
    let bytes = if size == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, size as usize) }.to_vec()
    };
    match channel.events.send(Event::Message(bytes)) {
        Ok(()) => ffi::SUCCESS,
        Err(_) => ffi::NETWORK_ERROR,
    }
}

unsafe extern "C" fn receive(ctx: *mut c_void, _peer: i32, out: *mut ffi::Cmem) -> c_int {
    let channel = unsafe { &*ctx.cast::<Channel>() };
    let Ok(message) = channel.inbox.recv_timeout(channel.timeout) else {
        return ffi::NETWORK_ERROR;
    };
    let buffer = unsafe { ffi::cbmpc_malloc(message.len().max(1)) }.cast::<u8>();
    if buffer.is_null() {
        return ffi::NETWORK_ERROR;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(message.as_ptr(), buffer, message.len());
        *out = ffi::Cmem {
            data: buffer,
            size: message.len() as c_int,
        };
    }
    ffi::SUCCESS
}
