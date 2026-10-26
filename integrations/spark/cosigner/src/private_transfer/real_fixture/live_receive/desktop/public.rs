//! The Public side: an ordinary Spark wallet that the native fixture holds as
//! a named recipient (stable identity and leaf key). Zark never signs here.
//! Public holds leaves of any value; only Incognito entry needs whole bills.
use super::super::*;
use super::{
    inbox::{self, Kind},
    session::{PUBLIC_CLAIM, PUBLIC_DEPOSIT, Session, refuse},
    store::{Activity, now_ms},
};
use std::collections::BTreeMap;

pub(super) const ADDRESS_PREFIX: &str = "spark-regtest:";

pub(super) struct Balance {
    pub total: u64,
    /// Available leaf IDs and their values in sats.
    pub leaves: BTreeMap<String, u64>,
}

/// The leaves a Public payment of some amount spends.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Selection {
    /// Leaves that add up to exactly the amount.
    Exact(Vec<String>),
    /// Leaves worth more than the amount; the SSP swaps them for the amount
    /// plus `change`, which returns to Public.
    Swap { inputs: Vec<String>, change: u64 },
}

/// Exact sets are searched up to this many leaves; wider searches cost more
/// than the swap they avoid.
const EXACT_LEAVES: usize = 4;
/// One Spark transfer or SSP swap takes at most this many leaves.
pub(super) const MAX_TRANSFER_LEAVES: usize = 32;

impl Balance {
    pub fn select(&self, amount: u64) -> Result<Selection> {
        select(&self.leaves, amount).ok_or_else(|| {
            refuse(
                "no_leaves",
                "Public does not hold enough to send that amount.",
            )
        })
    }
}

/// Fewest leaves, then the smallest leaf IDs, for an exact amount; otherwise
/// the covering set `cover` picks. `None` when the leaves cannot cover it.
pub(super) fn select(leaves: &BTreeMap<String, u64>, amount: u64) -> Option<Selection> {
    if amount == 0 {
        return None;
    }
    let all: Vec<(&String, u64)> = leaves.iter().map(|(id, sats)| (id, *sats)).collect();
    for size in 1..=EXACT_LEAVES.min(all.len()) {
        if let Some(set) = first_set(&all, size, &mut |sum| sum == u128::from(amount)) {
            return Some(Selection::Exact(set));
        }
    }
    let inputs = cover(leaves, amount)?;
    let total: u128 = inputs.iter().map(|id| u128::from(leaves[id])).sum();
    let change = u64::try_from(total - u128::from(amount)).ok()?;
    Some(if change == 0 {
        Selection::Exact(inputs)
    } else {
        Selection::Swap { inputs, change }
    })
}

/// Fewest leaves covering `amount`, then the least excess, then the smallest
/// IDs. Beyond `EXACT_LEAVES` leaves it takes the largest leaves first.
pub(super) fn cover(leaves: &BTreeMap<String, u64>, amount: u64) -> Option<Vec<String>> {
    let mut largest: Vec<(&String, u64)> = leaves.iter().map(|(id, sats)| (id, *sats)).collect();
    largest.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let mut sum = 0u128;
    let count = largest.iter().position(|(_, sats)| {
        sum += u128::from(*sats);
        sum >= u128::from(amount)
    })? + 1;
    if count > MAX_TRANSFER_LEAVES {
        return None;
    }
    if count > EXACT_LEAVES {
        return Some(
            largest[..count]
                .iter()
                .map(|(id, _)| (*id).clone())
                .collect(),
        );
    }
    let all: Vec<(&String, u64)> = leaves.iter().map(|(id, sats)| (id, *sats)).collect();
    let mut least: Option<u128> = None;
    first_set(&all, count, &mut |sum| {
        if sum >= u128::from(amount) && least.is_none_or(|best| sum < best) {
            least = Some(sum);
        }
        false
    });
    let least = least?;
    first_set(&all, count, &mut |sum| sum == least)
}

/// The first `size`-leaf combination, in leaf ID order, whose sum `accept`s.
fn first_set(
    all: &[(&String, u64)],
    size: usize,
    accept: &mut dyn FnMut(u128) -> bool,
) -> Option<Vec<String>> {
    let mut picks: Vec<usize> = (0..size).collect();
    loop {
        if accept(picks.iter().map(|&i| u128::from(all[i].1)).sum()) {
            return Some(picks.iter().map(|&i| all[i].0.clone()).collect());
        }
        let slot = (0..size)
            .rev()
            .find(|&slot| picks[slot] < all.len() - size + slot)?;
        picks[slot] += 1;
        for next in slot + 1..size {
            picks[next] = picks[next - 1] + 1;
        }
    }
}

/// Creates the Public wallet on first use and publishes its identity so other
/// local profiles can address it.
pub(super) fn wallet(s: &mut Session) -> Result<Value> {
    let name = s.profile.public_name().to_owned();
    let recipient =
        s.call_native(json!({"op":"exit_recipient","directory":NATIVE,"recipient":name}))?;
    s.profile
        .publish_public_identity(&bytes(&recipient, "identity")?)?;
    Ok(recipient)
}

pub(super) fn balance(s: &mut Session) -> Result<Balance> {
    let identity = match &s.profile.public.public_identity {
        Some(identity) => hex::decode(identity)?,
        None => bytes(&wallet(s)?, "identity")?,
    };
    let name = s.profile.public_name().to_owned();
    let value = s.call_native(json!({"op":"exit_balance","directory":NATIVE,"recipient":name}))?;
    ensure!(
        bytes(&value, "identity")? == identity && value["operators_agreed"] == 3,
        "Public balance identity or operator quorum"
    );
    let leaves = value["leaves"]
        .as_array()
        .context("Public leaves")?
        .iter()
        .map(|v| {
            let id = v.as_str().context("Public leaf id")?;
            let sats = value["leaf_sats"][id]
                .as_u64()
                .context("Public leaf value")?;
            Ok((id.to_owned(), sats))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    Ok(Balance {
        total: value["available_sats"].as_u64().context("Public balance")?,
        leaves,
    })
}

pub(super) fn parse_address(address: &str) -> Result<Vec<u8>> {
    let key = address
        .strip_prefix(ADDRESS_PREFIX)
        .filter(|k| k.len() == 66 && k.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        .ok_or_else(|| {
            refuse(
                "invalid_address",
                "Enter a Spark address starting with spark-regtest:",
            )
        })?;
    let raw = hex::decode(key)?;
    k256::PublicKey::from_sec1_bytes(&raw)
        .map_err(|_| refuse("invalid_address", "This Spark address is not valid."))?;
    Ok(raw)
}

/// Public payments take any positive whole-sat amount.
pub(super) fn payment_amount(amount: u64) -> Result<()> {
    if amount == 0 {
        return Err(refuse("amount", "Enter an amount of at least 1 sat."));
    }
    Ok(())
}

/// Incognito holds cash: whole bills of one of the denominations.
pub(super) fn bill_amount(amount: u64) -> Result<()> {
    if !DENOMINATIONS_SAT.contains(&amount) {
        return Err(refuse(
            "amount",
            "Incognito holds cash bills. Move 10,000, 5,000 or 2,000 sats.",
        ));
    }
    Ok(())
}

/// Starts an ordinary Spark transfer of one whole Public leaf. The fixture
/// retains the package before sending; the transfer ID is fresh.
pub(super) fn transfer_request(name: &str, leaf: &str, receiver: &[u8]) -> Value {
    json!({"op":"public_transfer","directory":NATIVE,"recipient":name,
        "receiver":receiver,"transfer_id":uuid(),"leaf_id":leaf})
}

/// The bills one test deposit creates: a single bill, or the whole set.
const DEPOSIT_SET_SAT: [u64; 4] = [10_000, 5_000, 2_000, 2_000];

pub(super) fn deposit_bills(amount: u64) -> Result<Vec<u64>> {
    if DENOMINATIONS_SAT.contains(&amount) {
        Ok(vec![amount])
    } else if amount == DEPOSIT_SET_SAT.iter().sum::<u64>() {
        Ok(DEPOSIT_SET_SAT.to_vec())
    } else {
        Err(refuse(
            "amount",
            "Deposit 10,000, 5,000 or 2,000 sats, or 19,000 for the whole set.",
        ))
    }
}

pub(super) fn deposit(s: &mut Session, amount: u64) -> Result<()> {
    let bills = deposit_bills(amount)?;
    s.ensure_open()?;
    let _lock = s.lock(&PUBLIC_DEPOSIT)?;
    s.ensure_open()?;
    wallet(s)?;
    let name = s.profile.public_name().to_owned();
    for bill in bills {
        PUBLIC_DEPOSIT.emit("fund")?;
        let funded = s.call_native(
            json!({"op":"public_fund","directory":NATIVE,"recipient":name,"amount_sats":bill}),
        )?;
        let leaf = funded["leaf_id"]
            .as_str()
            .context("funded leaf")?
            .to_owned();
        PUBLIC_DEPOSIT.emit("observe")?;
        ensure!(
            balance(s)?.leaves.get(&leaf) == Some(&bill),
            "funded leaf is not available in the Public wallet"
        );
        s.profile.record(Activity {
            id: format!("deposit-{leaf}"),
            side: "public".into(),
            kind: "deposit".into(),
            label: "Deposited to Public".into(),
            amount_sat: bill,
            state: "complete".into(),
            at: now_ms(),
            counterparty: None,
        })?;
    }
    Ok(())
}

/// Claims one incoming ordinary transfer of any leaves into the Public wallet.
/// The native claim is frozen by transfer ID, so a retry after a crash resumes
/// it. The recorded amount is what the operators report, not the envelope.
pub(super) fn claim(s: &mut Session, entry: &inbox::Entry) -> Result<()> {
    let e = &entry.envelope;
    ensure!(e.kind == Kind::Public, "not a Public transfer");
    PUBLIC_CLAIM.emit("claim")?;
    let recipient = wallet(s)?;
    let name = s.profile.public_name().to_owned();
    let transfer = e.transfer.clone().context("public transfer id")?;
    let leaves: Vec<&String> = match &e.leaves {
        Some(leaves) => leaves.keys().collect(),
        None => vec![&e.leaf],
    };
    let mut request = json!({"op":"public_claim","directory":NATIVE,
        "recipient":name,"transfer_id":transfer,"leaf_ids":leaves});
    // The sender's published Public identity, when the sender is a local profile.
    if let Some(identity) = s
        .network
        .profiles()?
        .into_iter()
        .find(|p| p.profile == e.from)
        .and_then(|p| p.public_identity)
    {
        request["sender"] = json!(hex::decode(identity)?);
    }
    let received = s.call_native(request)?;
    ensure!(
        received["operators_completed"] == 3
            && bytes(&received, "owner")? == bytes(&recipient, "identity")?,
        "incoming Spark payment was not observed"
    );
    s.profile.record(Activity {
        id: format!("public-received-{transfer}"),
        side: "public".into(),
        kind: "publicReceived".into(),
        label: "Received payment".into(),
        amount_sat: received["amount_sats"].as_u64().context("claimed amount")?,
        state: "complete".into(),
        at: now_ms(),
        counterparty: Some(e.from.clone()),
    })?;
    inbox::remove(&s.profile, &entry.name)
}
