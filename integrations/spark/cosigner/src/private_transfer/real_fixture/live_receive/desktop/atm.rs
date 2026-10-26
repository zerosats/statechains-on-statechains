//! Public → Incognito works like an ATM withdrawal. Incognito takes only whole
//! bills that are Spark root leaves: the entry and recovery proofs bind the
//! root's on-chain anchor, so a split leaf cannot enter without a proof
//! change. A Public bill of the wanted value moves as-is; otherwise the SSP
//! swaps Public leaves for one, and only a root-shaped bill it returns may
//! enter. Anything else stays on Public.
use super::super::*;
use super::{
    private, public,
    public_swap::{self, Purpose, State, Swap},
    session::{GO_PRIVATE, Session, refuse},
    store::{Activity, now_ms},
};
use anyhow::bail;

/// What a goPrivate request names.
pub(super) enum Cash {
    /// An existing Public leaf, which must already be a root bill.
    Leaf(String),
    /// A denomination; the SSP makes the bill when Public has none.
    Amount(u64),
}

/// Spark's per-transfer refund timelock decrement, in blocks.
const TRANSFER_DELAY_STEP: u32 = 100;

/// Whether Incognito entry would accept this Public leaf, from the fixture's
/// `public_leaf_shape` facts. Mirrors `Controller`'s ordinary root check
/// (one-input root at Spark's zero sequence, refund spending output 0, a
/// denomination value) and the observer's confirmed anchor, applied to the
/// refund delay the transfer into the joint identity will have.
pub(super) fn entry_shape(shape: &Value) -> bool {
    let amount = shape["amount_sats"].as_u64().unwrap_or(0);
    let delay = shape["refund_sequence"]
        .as_u64()
        .map(|s| (s & 0xffff) as u32);
    let next = delay.and_then(|d| d.checked_sub(TRANSFER_DELAY_STEP));
    shape["status"] == "AVAILABLE"
        && shape["parent"] == false
        && shape["direct"] == false
        && shape["node_inputs"] == 1
        && shape["node_outputs"] == 2
        && shape["node_sequence"] == 1u64 << 30
        && shape["refund_inputs"] == 1
        && shape["refund_spends_node"] == true
        && DENOMINATIONS_SAT.contains(&amount)
        && shape["node_output_sats"] == amount
        && shape["anchor_confirmations"]
            .as_u64()
            .is_some_and(|c| c > 0)
        && next.is_some_and(|d| (200..=1900).contains(&d) && d.is_multiple_of(100))
}

fn cash_leaf(s: &mut Session, leaf: &str) -> Result<bool> {
    let shape = s.call_native(json!({"op":"public_leaf_shape","directory":NATIVE,
        "recipient":s.profile.public_name(),"leaf_id":leaf}))?;
    ensure!(shape["leaf_id"] == leaf, "leaf shape answer differs");
    Ok(entry_shape(&shape))
}

pub(super) fn go_private(s: &mut Session, cash: Cash) -> Result<()> {
    if let Cash::Amount(amount) = cash {
        public::bill_amount(amount)?;
    }
    s.ensure_open()?;
    let _lock = s.lock(&GO_PRIVATE)?;
    s.ensure_open()?;
    public_swap::settle(s)?;
    GO_PRIVATE.emit("preflight")?;
    let balance = public::balance(s)?;
    match cash {
        Cash::Leaf(leaf) => {
            let Some(&amount) = balance.leaves.get(&leaf) else {
                return Err(refuse("no_leaves", "That Public leaf is not available."));
            };
            if !cash_leaf(s, &leaf)? {
                return Err(refuse(
                    "no_cash_leaf",
                    "That Public leaf is not a whole cash bill. Move an amount instead.",
                ));
            }
            private::enter_leaf(s, &leaf, amount)
        }
        Cash::Amount(amount) => {
            for (leaf, _) in balance.leaves.iter().filter(|(_, sats)| **sats == amount) {
                if cash_leaf(s, leaf)? {
                    return private::enter_leaf(s, leaf, amount);
                }
            }
            let inputs = public::cover(&balance.leaves, amount)
                .ok_or_else(|| refuse("no_leaves", "Public does not hold enough for that bill."))?;
            let swap = Swap::new(
                inputs
                    .into_iter()
                    .map(|id| {
                        let sats = balance.leaves[&id];
                        (id, sats)
                    })
                    .collect(),
                vec![amount],
                Purpose::GoPrivate { amount_sat: amount },
            )?;
            public_swap::save(&s.profile, &swap)?;
            let swap = public_swap::advance(s, swap, true, &GO_PRIVATE)?;
            finish_swap(s, swap)
        }
    }
}

/// Continues a move whose swap stopped. The bill is checked before the swap
/// is marked consumed; one that entry would refuse stays on Public.
pub(super) fn finish_swap(s: &mut Session, mut swap: Swap) -> Result<()> {
    let Purpose::GoPrivate { amount_sat } = swap.purpose else {
        bail!("not a goPrivate swap");
    };
    let failed = |s: &Session, swap: &Swap| {
        s.profile.record(Activity {
            id: format!("go-private-swap-{}", swap.id),
            side: "transition".into(),
            kind: "goPrivate".into(),
            label: "Moved to Incognito".into(),
            amount_sat,
            state: "failed".into(),
            at: now_ms(),
            counterparty: None,
        })
    };
    match swap.state {
        State::Claimed => {
            let leaf = public_swap::received_leaf(&swap, amount_sat)?;
            let eligible = cash_leaf(s, &leaf)?;
            swap.state = State::Consumed;
            public_swap::save(&s.profile, &swap)?;
            if !eligible {
                failed(s, &swap)?;
                return Err(refuse(
                    "no_cash_leaf",
                    "The SSP could not provide a whole cash bill, so the amount stays in Public.",
                ));
            }
            private::enter_leaf(s, &leaf, amount_sat)
        }
        State::Abandoned | State::Failed => {
            failed(s, &swap)?;
            swap.settled = true;
            public_swap::save(&s.profile, &swap)?;
            Err(if swap.state == State::Abandoned {
                refuse(
                    "swap_failed",
                    "The SSP did not provide a cash bill. Your Public balance is unchanged.",
                )
            } else {
                refuse(
                    "swap_mismatch",
                    "The SSP returned different amounts than requested. What it returned is in Public.",
                )
            })
        }
        state => bail!("goPrivate swap is still {state:?}"),
    }
}
