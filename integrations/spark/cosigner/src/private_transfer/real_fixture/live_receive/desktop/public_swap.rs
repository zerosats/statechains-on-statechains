//! Public leaf swaps with the SSP: the ATM that turns Public leaves into an
//! exact amount plus change, for a Public payment or for a cash bill to move
//! into Incognito. The native fixture runs the Spark SDK's Swap V3 flow and
//! freezes each request before sending it. This journal records each step
//! before the fixture is asked to take it, so a resumed swap repeats the same
//! requests and never starts another with fresh transfer IDs.
//!
//! Privacy: the SSP sees which Public leaves it exchanged for which. On Public
//! that is ordinary Spark; at the ATM step it links Public history to the bill
//! that then enters Incognito.
use super::super::*;
use super::{
    atm, public, public_send,
    session::{Refusal, Session, Steps, refuse},
    store::{Blocked, Network, Profile, now_ms, read_json, write_json},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const SCHEMA: &str = "zark-public-swap-v1";
/// Added to a payment's expected time when it needs the SSP.
pub(super) const EXPECTED_MS: u64 = 4_000;
/// Failed claims of a counter transfer before the network pauses for
/// reconciliation, as for an incoming private payment.
const CLAIM_ATTEMPTS: u32 = 3;

/// What a Public flow needs from the window: native fixture calls and the
/// profile's records. Tests substitute a scripted fixture.
pub(super) trait Wallet {
    fn native(&mut self, request: Value) -> Result<Value>;
    fn network(&self) -> &Network;
    fn profile(&self) -> &Profile;
}

impl Wallet for Session {
    fn native(&mut self, request: Value) -> Result<Value> {
        self.call_native(request)
    }
    fn network(&self) -> &Network {
        &self.network
    }
    fn profile(&self) -> &Profile {
        &self.profile
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields, tag = "kind")]
pub(super) enum Purpose {
    /// A Public payment whose transfer ID and inbox entry are fixed up front.
    #[serde(rename_all = "camelCase")]
    Send {
        to: String,
        receiver: String,
        amount_sat: u64,
        transfer: String,
        entry: String,
    },
    /// A cash bill to move into Incognito.
    #[serde(rename_all = "camelCase")]
    GoPrivate { amount_sat: u64 },
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) enum State {
    /// Journaled; the primary transfer may not be frozen or sent yet.
    Prepared,
    /// The primary transfer of `inputs` to the SSP reached the operators.
    Initiated,
    /// The SSP answered with its counter transfer.
    Requested,
    /// The counter transfer is in Public and matches the request.
    Claimed,
    /// The purpose took the claimed leaves.
    Consumed,
    /// The primary transfer never settled; the inputs stayed on Public.
    Abandoned,
    /// The SSP settled differently from the request; what it returned is on Public.
    Failed,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Swap {
    pub schema: String,
    pub id: String,
    pub inputs: BTreeMap<String, u64>,
    pub targets: Vec<u64>,
    pub change_sat: u64,
    pub purpose: Purpose,
    pub state: State,
    /// An abandoned or failed swap's outcome has been reported.
    pub settled: bool,
    pub transfer: Option<String>,
    /// The SSP identity the primary transfer was built for (hex).
    pub ssp: Option<String>,
    pub request: Option<String>,
    pub inbound: Option<String>,
    pub received: Option<BTreeMap<String, u64>>,
    pub problem: Option<String>,
    pub attempts: u32,
    pub created_at: u64,
}

impl Swap {
    pub fn new(inputs: BTreeMap<String, u64>, targets: Vec<u64>, purpose: Purpose) -> Result<Self> {
        ensure!(
            (1..=public::MAX_TRANSFER_LEAVES).contains(&inputs.len())
                && (1..=public::MAX_TRANSFER_LEAVES).contains(&targets.len())
                && !targets.contains(&0),
            "swap shape"
        );
        let total = sum(inputs.values()).context("swap input total")?;
        let wanted = sum(targets.iter()).context("swap target total")?;
        Ok(Self {
            schema: SCHEMA.into(),
            id: uuid(),
            change_sat: total
                .checked_sub(wanted)
                .context("swap targets exceed inputs")?,
            inputs,
            targets,
            purpose,
            state: State::Prepared,
            settled: false,
            transfer: None,
            ssp: None,
            request: None,
            inbound: None,
            received: None,
            problem: None,
            attempts: 0,
            created_at: now_ms(),
        })
    }

    pub fn unsettled(&self) -> bool {
        match self.state {
            State::Consumed => false,
            State::Abandoned | State::Failed => !self.settled,
            _ => true,
        }
    }
}

fn sum<'a>(mut values: impl Iterator<Item = &'a u64>) -> Option<u64> {
    values.try_fold(0u64, |sum, value| sum.checked_add(*value))
}

/// `profile/public/<kind>`, created on first save so older profiles load as they are.
pub(super) fn journal_directory(profile: &Profile, kind: &str, create: bool) -> Result<PathBuf> {
    let directory = profile.home.join("public").join(kind);
    if create {
        private_directory(&profile.home.join("public"))?;
        private_directory(&directory)?;
    }
    Ok(directory)
}

/// Lower-case hyphenated UUID text, as the fixture and the SSP write it.
pub(super) fn canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => matches!(b, b'0'..=b'9' | b'a'..=b'f'),
        })
}

pub(super) fn save(profile: &Profile, swap: &Swap) -> Result<()> {
    ensure!(canonical_uuid(&swap.id), "swap id");
    write_json(
        &journal_directory(profile, "swaps", true)?.join(format!("{}.json", swap.id)),
        swap,
    )
}

pub(super) fn swaps(profile: &Profile) -> Result<Vec<Swap>> {
    let mut out = Vec::new();
    let directory = journal_directory(profile, "swaps", false)?;
    if !directory.exists() {
        return Ok(out);
    }
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "json") {
            let swap: Swap = read_json(&path)?;
            ensure!(
                swap.schema == SCHEMA && path.file_stem().is_some_and(|s| *s == *swap.id),
                "public swap record"
            );
            out.push(swap);
        }
    }
    out.sort_by_key(|s| s.created_at);
    Ok(out)
}

/// Whether any swap or payment still needs to finish before Public may be
/// spent again: its leaves are locked, or claimed but not yet used.
pub(super) fn unsettled(profile: &Profile) -> Result<bool> {
    Ok(swaps(profile)?.iter().any(Swap::unsettled) || public_send::unsettled(profile)?)
}

/// Recovery before acknowledgement: every Public operation and the idle loop
/// finish interrupted swaps and payments, each with its journaled IDs, before
/// anything new may select Public leaves.
pub(super) fn resume(s: &mut Session) -> Result<()> {
    for swap in swaps(&s.profile)?.into_iter().filter(Swap::unsettled) {
        let outcome = match &swap.purpose {
            Purpose::Send { .. } => advance(s, swap, false, &super::session::PUBLIC_SEND)
                .and_then(|swap| public_send::finish_swap(s, swap)),
            Purpose::GoPrivate { .. } => advance(s, swap, false, &super::session::GO_PRIVATE)
                .and_then(|swap| atm::finish_swap(s, swap)),
        };
        if let Err(error) = outcome {
            s.log_error("public swap", &error);
        }
    }
    public_send::resume(s)
}

/// `resume`, then refuses a new Public operation while anything is still
/// settling, so no leaf is selected twice.
pub(super) fn settle(s: &mut Session) -> Result<()> {
    resume(s)?;
    if unsettled(&s.profile)? {
        return Err(refuse(
            "busy",
            "A Public payment is still settling. Try again shortly.",
        ));
    }
    Ok(())
}

/// Drives a swap to `Claimed`, `Abandoned` or `Failed`, saving each state
/// before the fixture is asked for the next step. `fresh` is set only by the
/// operation that journaled the swap: a resumed `Prepared` swap whose primary
/// transfer was never frozen is abandoned rather than started late.
pub(super) fn advance(
    w: &mut impl Wallet,
    mut swap: Swap,
    fresh: bool,
    steps: &Steps,
) -> Result<Swap> {
    let name = w.profile().public_name().to_owned();
    let id = swap.id.clone();
    let request = |op: &str| json!({"op":op,"directory":NATIVE,"recipient":name,"swap_id":id});
    loop {
        swap.state = match swap.state {
            State::Prepared => {
                steps.emit("swap")?;
                if !fresh && w.native(request("public_swap_status"))?["frozen"] != true {
                    State::Abandoned
                } else {
                    let mut begin = request("public_swap_begin");
                    begin["leaf_ids"] = json!(swap.inputs.keys().collect::<Vec<_>>());
                    let begun = w.native(begin)?;
                    ensure!(
                        begun["swap_id"] == swap.id.as_str() && leaf_sats(&begun)? == swap.inputs,
                        "swap inputs differ from the journal"
                    );
                    if primary_dead(&begun)? {
                        State::Abandoned
                    } else {
                        swap.transfer = Some(text(&begun, "transfer_id")?);
                        swap.ssp = Some(hex::encode(bytes(&begun, "ssp")?));
                        State::Initiated
                    }
                }
            }
            State::Initiated => {
                let mut ask = request("public_swap_request");
                ask["targets"] = json!(swap.targets);
                let reply = w.native(ask)?;
                if reply.get("error").is_some() {
                    // The SSP did not fill. It never fills a dead primary, so
                    // an expired or returned one means the inputs are back.
                    if primary_dead(&w.native(request("public_swap_status"))?)? {
                        State::Abandoned
                    } else {
                        return Err(refuse(
                            "swap_pending",
                            "The SSP has not settled the swap yet. It is retried automatically; otherwise the leaves return to Public within minutes.",
                        ));
                    }
                } else {
                    ensure!(
                        Some(hex::encode(bytes(&reply, "ssp")?)) == swap.ssp,
                        "SSP identity changed during the swap"
                    );
                    let inbound = text(&reply, "inbound_transfer_id")?;
                    ensure!(canonical_uuid(&inbound), "counter transfer id");
                    swap.problem = reply_problem(&swap, &reply);
                    swap.request = reply["request_id"].as_str().map(str::to_owned);
                    swap.inbound = Some(inbound);
                    State::Requested
                }
            }
            State::Requested => match claim(w, &swap) {
                Ok(received) => {
                    // A wrong answer is still claimed: the primary already
                    // settled, and claiming keeps whatever the SSP sent.
                    let problem = swap
                        .problem
                        .take()
                        .or_else(|| received_problem(&swap, &received));
                    swap.received = Some(received);
                    swap.problem = problem;
                    if swap.problem.is_none() {
                        State::Claimed
                    } else {
                        State::Failed
                    }
                }
                Err(error) => {
                    if error.downcast_ref::<Refusal>().is_none() {
                        swap.attempts += 1;
                        save(w.profile(), &swap)?;
                        if swap.attempts >= CLAIM_ATTEMPTS && w.network().blocked()?.is_none() {
                            w.network().block(&Blocked {
                                reason: "An SSP swap could not be claimed into Public".into(),
                                operation: "publicSwap".into(),
                                profile: w.profile().name.clone(),
                                coin: swap.id.clone(),
                                at: now_ms(),
                            })?;
                        }
                    }
                    return Err(error);
                }
            },
            State::Claimed | State::Consumed | State::Abandoned | State::Failed => return Ok(swap),
        };
        save(w.profile(), &swap)?;
    }
}

fn text(v: &Value, key: &str) -> Result<String> {
    Ok(v[key]
        .as_str()
        .with_context(|| format!("native field {key}"))?
        .to_owned())
}

fn leaf_sats(v: &Value) -> Result<BTreeMap<String, u64>> {
    let ids: Vec<String> = serde_json::from_value(v["leaf_ids"].clone()).context("leaf ids")?;
    let sats: BTreeMap<String, u64> =
        serde_json::from_value(v["leaf_sats"].clone()).context("leaf values")?;
    ensure!(
        ids.len() == sats.len() && ids.iter().all(|id| sats.contains_key(id)),
        "leaf ids and values differ"
    );
    Ok(sats)
}

/// A primary transfer the operators never saw, or one they gave back.
fn primary_dead(v: &Value) -> Result<bool> {
    Ok(matches!(
        v["status"].as_str().context("primary transfer status")?,
        "absent" | "TRANSFER_STATUS_EXPIRED" | "TRANSFER_STATUS_RETURNED"
    ))
}

/// The SSP's own account of the fill must match the request exactly.
fn reply_problem(swap: &Swap, reply: &Value) -> Option<String> {
    let total = sum(swap.inputs.values());
    let target = sum(swap.targets.iter());
    if reply["fee_sats"] != 0 {
        Some(format!("SSP charged a fee of {}", reply["fee_sats"]))
    } else if reply["total_amount_sats"].as_u64() != total
        || reply["target_amount_sats"].as_u64() != target
    {
        Some("SSP reported different swap amounts".into())
    } else {
        None
    }
}

/// The operators' view of what Public received: one leaf of each requested
/// target, and other leaves worth exactly the change. Spark swaps fix only the
/// target leaves; the SSP pays change in whatever leaves it holds.
fn received_problem(swap: &Swap, received: &BTreeMap<String, u64>) -> Option<String> {
    let mut rest: Vec<u64> = received.values().copied().collect();
    rest.sort_unstable();
    let got = rest.clone();
    for target in &swap.targets {
        match rest.iter().position(|value| value == target) {
            Some(at) => {
                rest.remove(at);
            }
            None => return Some(format!("SSP returned {got:?} without a {target}-sat leaf")),
        }
    }
    (sum(rest.iter()) != Some(swap.change_sat)).then(|| {
        format!(
            "SSP returned {got:?}; change differs from {}",
            swap.change_sat
        )
    })
}

/// Claims the SSP's counter transfer into Public. All three operators must
/// agree that each leaf is now owned by this Public wallet.
fn claim(w: &mut impl Wallet, swap: &Swap) -> Result<BTreeMap<String, u64>> {
    let inbound = swap.inbound.clone().context("counter transfer")?;
    let ssp = hex::decode(swap.ssp.as_deref().context("swap SSP")?)?;
    let identity = w
        .profile()
        .public
        .public_identity
        .clone()
        .context("Public identity")?;
    let claimed = w.native(json!({"op":"public_claim","directory":NATIVE,
        "recipient":w.profile().public_name(),"transfer_id":inbound,"sender":ssp}))?;
    ensure!(
        claimed["operators_completed"] == 3
            && claimed["transfer_id"] == inbound.as_str()
            && hex::encode(bytes(&claimed, "owner")?) == identity
            && bytes(&claimed, "sender")? == ssp,
        "SSP counter transfer was not observed in Public"
    );
    let received = leaf_sats(&claimed)?;
    ensure!(
        sum(received.values()) == claimed["amount_sats"].as_u64(),
        "claimed amount differs from its leaves"
    );
    Ok(received)
}

/// The claimed leaf worth exactly `amount`, preferring the smallest ID.
pub(super) fn received_leaf(swap: &Swap, amount: u64) -> Result<String> {
    swap.received
        .as_ref()
        .and_then(|received| received.iter().find(|(_, sats)| **sats == amount))
        .map(|(id, _)| id.clone())
        .context("swap returned no leaf of the requested amount")
}
