//! The Incognito side: entry from a Public leaf, private handovers and the
//! recipient's automatic claim. Every step runs under the network lock and
//! resumes from its journals with exact retained requests; prover jobs use a
//! fresh directory per attempt.
use super::super::*;
use super::{
    inbox::{self, Envelope, Kind},
    public,
    session::{CLAIM, GO_PRIVATE, PRIVATE_SEND, Session, Steps, refuse},
    store::{Activity, CoinRecord, CoinState, Origin, Profile, now_ms, read_json, write_json},
};
use crate::receive::ReceiveJournal;
use serde::{Deserialize, Serialize};

pub(super) const ADDRESS_PREFIX: &str = "zark-regtest:";
const LEAF_NODE: &str = "leaf-node.private.json";

pub(super) fn parse_address(address: &str) -> Result<[u8; 32]> {
    let key = address
        .strip_prefix(ADDRESS_PREFIX)
        .filter(|k| k.len() == 64 && k.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        .ok_or_else(|| {
            refuse(
                "invalid_address",
                "Enter an Incognito address starting with zark-regtest:",
            )
        })?;
    let raw: [u8; 32] = hex::decode(key)?
        .try_into()
        .map_err(|_| refuse("invalid_address", "This Incognito address is not valid."))?;
    k256::schnorr::VerifyingKey::from_bytes(&raw)
        .map_err(|_| refuse("invalid_address", "This Incognito address is not valid."))?;
    Ok(raw)
}

fn activity(
    row: &str,
    coin: &CoinRecord,
    kind: &str,
    label: &str,
    side: &str,
    state: &str,
) -> Activity {
    Activity {
        id: format!("{row}-{}", coin.id),
        side: side.into(),
        kind: kind.into(),
        label: label.into(),
        amount_sat: coin.amount_sat,
        state: state.into(),
        at: now_ms(),
        counterparty: coin.counterparty.clone(),
    }
}

/// Moves one whole Public bill into Incognito. The caller holds the network
/// lock and has checked the leaf's shape (`atm`). The coin is saved as
/// Entering first; entry then checks the leaf against the operators before
/// it becomes Available. `atm::go_private` and `atm::finish_swap` both call
/// this, including from background recovery.
pub(super) fn enter_leaf(s: &mut Session, leaf: &str, amount: u64) -> Result<()> {
    let mut coin = s
        .profile
        .new_coin(Origin::Public, CoinState::Entering, amount)?;
    coin.leaf = Some(leaf.into());
    s.profile.save_coin(&coin)?;
    let row = |coin: &CoinRecord, state: &str| {
        activity(
            "go-private",
            coin,
            "goPrivate",
            "Moved to Incognito",
            "transition",
            state,
        )
    };
    s.profile.record(row(&coin, "pending"))?;
    match enter(s, &coin, leaf) {
        Ok(revision) => {
            coin.revision = Some(revision);
            coin.state = CoinState::Available;
            s.profile.save_coin(&coin)?;
            s.profile.record(row(&coin, "complete"))
        }
        Err(error) => {
            let dir = s.profile.coin_dir(&coin.id)?;
            // Before the native transfer starts the leaf never left Public.
            let started = dir.join("ordinary-sender.json").exists();
            coin.state = if started {
                CoinState::Interrupted
            } else {
                CoinState::Abandoned
            };
            s.profile.save_coin(&coin)?;
            s.profile
                .record(row(&coin, if started { "interrupted" } else { "failed" }))?;
            Err(error)
        }
    }
}

fn enter(s: &mut Session, coin: &CoinRecord, leaf: &str) -> Result<u64> {
    let dir = s.profile.coin_dir(&coin.id)?;
    let report = reporting::RunReport::begin(&dir)?;
    let mut native = s.take_native()?;
    let result = (|| {
        GO_PRIVATE.emit("identity")?;
        let controller =
            Controller::new(&s.suite, &s.network.root, &dir, s.cluster.clone(), &report)?;
        let name = s.profile.public_name().to_owned();
        let mut start = |native: &mut Pipe, receiver: &[u8]| {
            native.call_native(&public::transfer_request(&name, leaf, receiver))
        };
        let entered = entry::enter(
            &s.suite,
            &s.network.root,
            &dir,
            &s.cluster,
            controller,
            &mut native,
            &s.docker,
            &mut start,
            &mut |step| GO_PRIVATE.emit(step),
        )?;
        let node = entered.claimed["leaves"][0].clone();
        ensure!(
            entered.leaf == leaf && node["id"] == leaf,
            "entered leaf differs from the selected Public leaf"
        );
        write_json(&dir.join(LEAF_NODE), &node)?;
        number(&entered.acknowledged, "revision")
    })();
    if result.is_ok() {
        s.put_native(native);
    }
    result
}

/// The open journals behind an available coin. Keep it alive while a sender
/// journal created from it is open: drops must follow lock nesting.
#[allow(clippy::large_enum_variant)]
enum Holding {
    Entered {
        wallet: ReceiveJournal,
        snapshot: Box<Snapshot>,
    },
    Received(Received),
}

impl Holding {
    fn open(s: &Session, coin: &CoinRecord) -> Result<Self> {
        let dir = s.profile.coin_dir(&coin.id)?;
        let verifier = s.suite.verifier()?;
        let revision = coin.revision.context("coin revision missing")?;
        Ok(match coin.origin {
            Origin::Public => {
                let wallet = ReceiveJournal::open(
                    &dir.join("wallets/receive"),
                    &s.suite.receive_verifier(&s.cluster)?,
                )?;
                let journal = RecoveryJournal::open(&dir.join("wallets/recovery"))?;
                let snapshot = snapshot(&journal, &verifier, &dir, revision)?;
                drop(journal);
                Self::Entered {
                    wallet,
                    snapshot: Box::new(snapshot),
                }
            }
            Origin::Received => Self::Received(open_received(s, coin)?),
        })
    }

    fn start_sender(&self, s: &Session, dir: &Path, claim_key: [u8; 32]) -> Result<PrivateSender> {
        let verifier = s.suite.verifier()?;
        let scratch = dir.join("scratch");
        let sender = dir.join("wallets/sender");
        match self {
            Self::Entered { wallet, snapshot } => wallet.start_sender(
                &sender,
                destination_key(&s.suite, snapshot, claim_key)?,
                &snapshot.backing,
                &snapshot.recovery,
                &snapshot.certificate,
                &verifier,
                &scratch,
            ),
            Self::Received(r) => r.material.start_sender(
                &sender,
                destination_key(&s.suite, &r.snapshot, claim_key)?,
                &r.snapshot.recovery,
                &r.snapshot.certificate,
                &verifier,
                &scratch,
            ),
        }
    }
}

pub(super) fn open_received(s: &Session, coin: &CoinRecord) -> Result<Received> {
    let dir = s.profile.coin_dir(&coin.id)?;
    let verifier = s.suite.verifier()?;
    let material = PrivateReceiver::open(
        &dir.join("wallets/recipient"),
        &verifier,
        &dir.join("scratch"),
    )?;
    let journal = RecoveryJournal::open(&dir.join("wallets/recovery"))?;
    let snapshot = snapshot(
        &journal,
        &verifier,
        &dir,
        coin.revision.context("coin revision missing")?,
    )?;
    drop(journal);
    Ok(Received { material, snapshot })
}

pub(super) fn leaf_node(s: &Session, coin: &CoinRecord) -> Result<Value> {
    let node: Value = read_json(&s.profile.coin_dir(&coin.id)?.join(LEAF_NODE))?;
    ensure!(
        coin.leaf.as_deref().is_some_and(|leaf| node["id"] == leaf),
        "retained SDK leaf differs from the coin's leaf"
    );
    Ok(node)
}

/// Fixed before the sender journal exists, so a resumed send reaches the same
/// recipient under the same inbox entry name.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SendPlan {
    pub to: String,
    pub claim_key: String,
    pub entry: String,
    pub quiet: bool,
}

/// The one or two different available coins the user picked, in their order.
pub(super) fn chosen_coins(profile: &Profile, ids: &[String]) -> Result<Vec<CoinRecord>> {
    if ids.is_empty() || ids.len() > 2 || (ids.len() == 2 && ids[0] == ids[1]) {
        return Err(refuse(
            "no_coins",
            "Pick one or two different Incognito coins.",
        ));
    }
    ids.iter()
        .map(|id| {
            profile
                .coin(id)
                .ok()
                .filter(|c| c.state == CoinState::Available)
                .ok_or_else(|| refuse("no_coins", "That Incognito coin is not available."))
        })
        .collect()
}

pub(super) fn send(s: &mut Session, address: &str, coins: &[String]) -> Result<()> {
    let claim_key = hex::encode(parse_address(address)?);
    let to = super::recipient(&s.network.profiles()?, &s.profile.name, |p| {
        p.claim_key == claim_key
    })?;
    s.ensure_open()?;
    let _lock = s.lock(&PRIVATE_SEND)?;
    s.ensure_open()?;
    // Each coin is its own handover; a later coin interrupted here stays
    // Sending and resumes in the background like any other send.
    for coin in chosen_coins(&s.profile, coins)? {
        start_send(s, coin, &to.profile, &to.claim_key, false, &PRIVATE_SEND)?;
    }
    Ok(())
}

pub(super) fn start_send(
    s: &mut Session,
    mut coin: CoinRecord,
    to: &str,
    claim_key: &str,
    quiet: bool,
    steps: &Steps,
) -> Result<()> {
    let dir = s.profile.coin_dir(&coin.id)?;
    write_json(
        &dir.join("send.json"),
        &SendPlan {
            to: to.into(),
            claim_key: claim_key.into(),
            entry: inbox::entry_name(),
            quiet,
        },
    )?;
    coin.state = CoinState::Sending;
    coin.counterparty = Some(to.into());
    s.profile.save_coin(&coin)?;
    if !quiet {
        s.profile.record(activity(
            "private-sent",
            &coin,
            "privateSent",
            "Sent payment",
            "incognito",
            "pending",
        ))?;
    }
    continue_send(s, coin, steps)
}

/// Caller holds the network lock. Safe to repeat after any interruption.
pub(super) fn continue_send(s: &mut Session, mut coin: CoinRecord, steps: &Steps) -> Result<()> {
    let dir = s.profile.coin_dir(&coin.id)?;
    let plan: SendPlan = read_json(&dir.join("send.json"))?;
    let to = s
        .network
        .profiles()?
        .into_iter()
        .find(|p| p.profile == plan.to && p.claim_key == plan.claim_key)
        .context("handover recipient profile changed")?;
    let claim_key: [u8; 32] = hex::decode(&plan.claim_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("claim key"))?;
    let leaf = coin.leaf.clone().context("coin leaf missing")?;
    let node = leaf_node(s, &coin)?;
    steps.emit("reserve")?;
    let fingerprint = |s: &mut Session| -> Result<Value> {
        Ok(s.call_native(json!({"op":"native_snapshot","directory":NATIVE,"leaf_id":leaf}))?
            ["public_leaf_sha256"]
            .clone())
    };
    let before = fingerprint(s)?;
    let engine = s.engine(s.admission())?;
    let verifier = s.suite.verifier()?;
    let sender_dir = dir.join("wallets/sender");
    let role = match coin.origin {
        Origin::Public => "sender_from_origin",
        Origin::Received => "sender_from_transfer",
    };
    coin.attempts += 1;
    s.profile.save_coin(&coin)?;
    // `holding` outlives the sender journal created from it.
    let mut holding = None;
    let sender = if sender_dir.join("private-sender.json").exists() {
        PrivateSender::open(&sender_dir, &verifier, &dir.join("scratch"))?
    } else {
        let opened = holding.insert(Holding::open(s, &coin)?);
        opened.start_sender(s, &dir, claim_key)?
    };
    let offer = hand_over(
        &s.suite,
        &engine,
        &dir,
        "send",
        sender,
        &sender_dir,
        role,
        &dir.join(format!("proofs/sender-{}", coin.attempts)),
        &mut |step| steps.emit(step),
    )?;
    drop(holding);
    drop(engine);
    ensure!(
        fingerprint(s)? == before,
        "native leaf changed during a private handover"
    );
    steps.emit("deliver")?;
    inbox::deliver(
        &s.network.root.join("profiles"),
        &to,
        &plan.entry,
        &Envelope {
            schema: inbox::ENVELOPE_V1.into(),
            kind: Kind::Private,
            id: coin.id.clone(),
            from: s.profile.name.clone(),
            amount_sat: coin.amount_sat,
            offer: Some(offer.to_vec()),
            leaf,
            leaf_node: Some(node),
            transfer: None,
            leaves: None,
        },
    )?;
    coin.state = CoinState::Sent;
    s.profile.save_coin(&coin)?;
    if !plan.quiet {
        s.profile.record(activity(
            "private-sent",
            &coin,
            "privateSent",
            "Sent payment",
            "incognito",
            "complete",
        ))?;
    }
    Ok(())
}

/// Each inbox entry maps to one stable coin, so a resumed claim reopens the
/// same journals.
pub(super) fn claim_coin_id(entry: &str) -> String {
    hex::encode(&hash(&[b"ZARK/desktop/claim/v1", entry.as_bytes()])[..16])
}

const CLAIM_ATTEMPTS: u32 = 3;

/// Caller holds the network lock. Returns the claimed coin's record.
pub(super) fn claim(s: &mut Session, entry: &inbox::Entry, steps: &Steps) -> Result<CoinRecord> {
    let e = &entry.envelope;
    ensure!(e.kind == Kind::Private, "not a private offer");
    let id = claim_coin_id(&entry.name);
    let dir = s.profile.coin_dir(&id)?;
    let quiet = e.from == s.profile.name;
    let mut coin = if dir.join("coin.json").exists() {
        s.profile.coin(&id)?
    } else {
        let mut coin =
            s.profile
                .new_coin_with_id(&id, Origin::Received, CoinState::Claiming, e.amount_sat)?;
        coin.leaf = Some(e.leaf.clone());
        coin.counterparty = Some(e.from.clone());
        write_json(
            &dir.join(LEAF_NODE),
            e.leaf_node.as_ref().context("offer leaf node")?,
        )?;
        s.profile.save_coin(&coin)?;
        if !quiet {
            s.profile.record(activity(
                "private-received",
                &coin,
                "privateReceived",
                "Received payment",
                "incognito",
                "pending",
            ))?;
        }
        coin
    };
    if coin.state == CoinState::Interrupted {
        return Err(refuse(
            "interrupted",
            "An incoming payment needs reconciliation.",
        ));
    }
    if coin.state == CoinState::Claiming {
        if coin.attempts >= CLAIM_ATTEMPTS {
            coin.state = CoinState::Interrupted;
            s.profile.save_coin(&coin)?;
            return Err(refuse(
                "interrupted",
                "An incoming payment could not be claimed and needs reconciliation.",
            ));
        }
        coin.attempts += 1;
        s.profile.save_coin(&coin)?;
        let verifier = s.suite.verifier()?;
        let recipient = dir.join("wallets/recipient");
        let material = if recipient.join("private-recipient.json").exists() {
            PrivateReceiver::open(&recipient, &verifier, &dir.join("scratch"))?
        } else {
            let offer = e.offer.as_ref().context("offer bytes")?;
            PrivateReceiver::create(
                &recipient,
                offer,
                *s.profile.claim_secret(),
                &verifier,
                &dir.join("scratch"),
            )?
        };
        let admission = s.admission();
        let mut engine = s.engine(admission.clone())?;
        let reopen = || s.engine(admission.clone());
        let received = claim_offer(
            &s.suite,
            &mut engine,
            &dir,
            "claim",
            material,
            &dir.join("wallets/recovery"),
            &dir.join(format!("proofs/receiver-{}", coin.attempts)),
            &reopen,
            &|_| Ok(()),
            &mut |step| steps.emit(step),
        )?;
        coin.revision = Some(received.snapshot.revision);
        // The envelope amount is the sender's word; the claimed backing is not.
        coin.amount_sat = received.snapshot.backing.anchor().output.value.to_sat();
        drop(received);
        drop(engine);
        coin.state = CoinState::Available;
        s.profile.save_coin(&coin)?;
        if !quiet {
            s.profile.record(activity(
                "private-received",
                &coin,
                "privateReceived",
                "Received payment",
                "incognito",
                "complete",
            ))?;
        }
    }
    inbox::remove(&s.profile, &entry.name)?;
    Ok(coin)
}

/// Default stage table for an automatic claim.
pub(super) fn auto_claim(s: &mut Session, entry: &inbox::Entry) -> Result<CoinRecord> {
    claim(s, entry, &CLAIM)
}
