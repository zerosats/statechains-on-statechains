//! Public any-amount payments and SSP swaps against a scripted fixture that
//! models the operators and the SSP: selection, adversarial SSP answers, and a
//! crash before or after every fixture call followed by a resume.
use super::{
    atm,
    inbox::{self, Kind},
    public::{self, Selection},
    public_send::{self, Payment, PaymentState},
    public_swap::{self, Purpose, State, Swap, Wallet},
    session::PUBLIC_SEND,
    store::{Network, Profile},
    tests::{code, envelope, network, parent},
};
use anyhow::{Result, bail};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const ALICE: [u8; 33] = [2; 33];
const BOB: [u8; 33] = [3; 33];
const SSP: [u8; 33] = [9; 33];
const PRIMARY: &str = "01a16aab-0000-7000-8000-000000000001";
const COUNTER: &str = "c0c0c0c0-0000-4000-8000-000000000002";
const PAYMENT: &str = "11111111-2222-4333-8444-555555555555";

#[derive(Default)]
struct World {
    leaves: BTreeMap<String, u64>,
    frozen: bool,
    seen: bool,
    dead: bool,
    /// The primary expired before the operators ever saw it.
    late: bool,
    ssp_down: bool,
    /// What the SSP fills instead of targets plus change.
    fill: Option<Vec<u64>>,
    fee: u64,
    reply_ssp: Option<[u8; 33]>,
    owner: Option<[u8; 33]>,
    input_total: u64,
    counter: Option<BTreeMap<String, u64>>,
    packages: u32,
    fills: u32,
    claims: u32,
    requests: u32,
    transfers: Vec<String>,
    /// Fail this op once, after applying its effect when `true`.
    crash: Option<(&'static str, bool)>,
}

impl World {
    fn status(&self) -> &'static str {
        match (self.seen, self.dead) {
            (false, _) => "absent",
            (true, true) => "TRANSFER_STATUS_EXPIRED",
            (true, false) => "TRANSFER_STATUS_SENDER_KEY_TWEAK_PENDING",
        }
    }

    fn sats(&self, ids: &[String]) -> BTreeMap<String, u64> {
        let counter = self.counter.clone().unwrap_or_default();
        ids.iter()
            .map(|id| {
                (
                    id.clone(),
                    self.leaves
                        .get(id)
                        .or(counter.get(id))
                        .copied()
                        .unwrap_or(0),
                )
            })
            .collect()
    }

    fn answer(&mut self, r: &Value) -> Result<Value> {
        let op = r["op"].as_str().unwrap_or_default();
        let crash = self.crash.filter(|(name, _)| *name == op);
        if crash.is_some() {
            self.crash = None;
        }
        if let Some((_, false)) = crash {
            bail!("fixture stopped before {op}");
        }
        let ids: Vec<String> = serde_json::from_value(r["leaf_ids"].clone()).unwrap_or_default();
        let reply = match op {
            "public_swap_status" => {
                json!({"swap_id":r["swap_id"],"frozen":self.frozen,"status":self.status(),"transfer_id":PRIMARY})
            }
            "public_swap_begin" => {
                if !self.frozen {
                    self.frozen = true;
                    self.packages += 1;
                    self.input_total = self.sats(&ids).values().sum();
                }
                self.seen |= !self.late;
                json!({"swap_id":r["swap_id"],"transfer_id":PRIMARY,"status":self.status(),
                    "leaf_ids":ids,"leaf_sats":self.sats(&ids),"ssp":SSP.to_vec()})
            }
            "public_swap_request" => {
                self.requests += 1;
                if self.ssp_down || !self.seen || self.dead {
                    json!({"error":"SSP unavailable"})
                } else {
                    let targets: Vec<u64> = serde_json::from_value(r["targets"].clone())?;
                    if self.counter.is_none() {
                        let mut values = targets.clone();
                        let change = self.input_total - targets.iter().sum::<u64>();
                        if change > 0 {
                            values.push(change);
                        }
                        let values = self.fill.clone().unwrap_or(values);
                        self.counter = Some(
                            values
                                .iter()
                                .enumerate()
                                .map(|(i, v)| (format!("c{i}"), *v))
                                .collect(),
                        );
                        self.fills += 1;
                    }
                    json!({"swap_id":r["swap_id"],"request_id":"r1","inbound_transfer_id":COUNTER,
                        "total_amount_sats":self.input_total,"target_amount_sats":targets.iter().sum::<u64>(),
                        "fee_sats":self.fee,"ssp":self.reply_ssp.unwrap_or(SSP).to_vec()})
                }
            }
            "public_claim" => {
                assert_eq!(r["transfer_id"], COUNTER);
                assert_eq!(r["sender"], json!(SSP.to_vec()));
                self.claims += 1;
                let counter = self.counter.clone().expect("counter transfer");
                json!({"transfer_id":COUNTER,"leaf_ids":counter.keys().collect::<Vec<_>>(),
                    "leaf_sats":counter,"amount_sats":counter.values().sum::<u64>(),"operators_completed":3,
                    "owner":self.owner.unwrap_or(ALICE).to_vec(),"sender":SSP.to_vec()})
            }
            "public_transfer" => {
                let id = r["transfer_id"].as_str().unwrap_or_default().to_owned();
                if !self.transfers.contains(&id) {
                    self.transfers.push(id.clone());
                }
                let sats = self.sats(&ids);
                json!({"transfer_id":id,"leaf_ids":ids,"amount_sats":sats.values().sum::<u64>(),
                    "leaf_sats":sats,"status":"sent"})
            }
            other => bail!("unexpected fixture op {other}"),
        };
        if crash.is_some() {
            bail!("fixture stopped after {op}");
        }
        Ok(reply)
    }
}

struct Fake {
    network: Network,
    profile: Profile,
    world: World,
}

impl Wallet for Fake {
    fn native(&mut self, request: Value) -> Result<Value> {
        self.world.answer(&request)
    }
    fn network(&self) -> &Network {
        &self.network
    }
    fn profile(&self) -> &Profile {
        &self.profile
    }
}

fn leaves(values: &[(&str, u64)]) -> BTreeMap<String, u64> {
    values
        .iter()
        .map(|(id, sats)| ((*id).to_owned(), *sats))
        .collect()
}

fn fake(public: &[(&str, u64)]) -> Result<Fake> {
    let network = network(&parent()?)?;
    let mut alice = Profile::open(&network, "alice")?;
    alice.publish_public_identity(&ALICE)?;
    Profile::open(&network, "bob")?.publish_public_identity(&BOB)?;
    Ok(Fake {
        network,
        profile: alice,
        world: World {
            leaves: leaves(public),
            ..World::default()
        },
    })
}

/// Journals a payment swap exactly as `public_send::send` does.
fn pay_with_swap(f: &Fake, inputs: &[(&str, u64)], amount: u64) -> Result<Swap> {
    let swap = Swap::new(
        leaves(inputs),
        vec![amount],
        Purpose::Send {
            to: "bob".into(),
            receiver: hex::encode(BOB),
            amount_sat: amount,
            transfer: PAYMENT.into(),
            entry: "ab".repeat(32),
        },
    )?;
    public_swap::save(&f.profile, &swap)?;
    Ok(swap)
}

fn run(f: &mut Fake, swap: Swap, fresh: bool) -> Result<()> {
    let swap = public_swap::advance(f, swap, fresh, &PUBLIC_SEND)?;
    public_send::finish_swap(f, swap)
}

/// What `public_swap::resume` does, with the scripted fixture.
fn resume(f: &mut Fake) -> Result<()> {
    for swap in public_swap::swaps(&f.profile)? {
        if swap.unsettled() {
            run(f, swap, false)?;
        }
    }
    for payment in public_send::payments(&f.profile)? {
        public_send::continue_payment(f, payment)?;
    }
    Ok(())
}

fn only_swap(f: &Fake) -> Result<Swap> {
    let mut swaps = public_swap::swaps(&f.profile)?;
    assert_eq!(swaps.len(), 1);
    Ok(swaps.remove(0))
}

fn bob_inbox(f: &Fake) -> Result<Vec<inbox::Entry>> {
    let bob = Profile::open(&f.network, "bob")?;
    Ok(inbox::entries(&bob)?.0)
}

/// Exactly one package, one fill, one payment under the journaled transfer
/// ID, one delivery, and the paid leaf is the SSP's exact target.
fn assert_paid_once(f: &Fake, amount: u64) -> Result<()> {
    let w = &f.world;
    assert_eq!((w.packages, w.fills), (1, 1));
    assert_eq!(w.transfers, [PAYMENT]);
    let swap = only_swap(f)?;
    assert_eq!(swap.state, State::Consumed);
    let payments = public_send::payments(&f.profile)?;
    assert_eq!(payments.len(), 1);
    assert_eq!(payments[0].state, PaymentState::Delivered);
    assert_eq!(
        payments[0].leaves.values().copied().collect::<Vec<_>>(),
        [amount]
    );
    let entries = bob_inbox(f)?;
    assert_eq!(entries.len(), 1);
    let e = &entries[0].envelope;
    assert_eq!(
        (e.kind, e.amount_sat, e.transfer.as_deref()),
        (Kind::Public, amount, Some(PAYMENT))
    );
    assert_eq!(e.leaves.as_ref(), Some(&payments[0].leaves));
    let row = f
        .profile
        .activity()?
        .into_iter()
        .find(|r| r.id == format!("public-sent-{PAYMENT}"));
    assert_eq!(row.map(|r| r.state), Some("complete".into()));
    Ok(())
}

#[test]
fn selection_prefers_exact_fewest_leaves_then_smallest_ids() {
    let held = leaves(&[
        ("d", 5_000),
        ("a", 2_000),
        ("b", 5_000),
        ("c", 3_000),
        ("e", 10_000),
    ]);
    assert_eq!(
        public::select(&held, 5_000),
        Some(Selection::Exact(vec!["b".into()]))
    );
    assert_eq!(
        public::select(&held, 7_000),
        Some(Selection::Exact(vec!["a".into(), "b".into()]))
    );
    assert_eq!(
        public::select(&held, 20_000),
        Some(Selection::Exact(vec!["b".into(), "d".into(), "e".into()]))
    );
    // Past four leaves an exact cover is still exact, largest first.
    let all = ["e", "b", "d", "c", "a"].map(String::from).to_vec();
    assert_eq!(public::select(&held, 25_000), Some(Selection::Exact(all)));
    // The same leaves in any insertion order select the same set.
    let reordered: BTreeMap<_, _> = held.iter().rev().map(|(k, v)| (k.clone(), *v)).collect();
    assert_eq!(
        public::select(&reordered, 7_000),
        public::select(&held, 7_000)
    );
}

#[test]
fn selection_swaps_the_smallest_covering_set_for_change() {
    let held = leaves(&[("a", 2_000), ("b", 10_000), ("c", 5_000)]);
    assert_eq!(
        public::select(&held, 3_333),
        Some(Selection::Swap {
            inputs: vec!["c".into()],
            change: 1_667
        })
    );
    assert_eq!(
        public::select(&held, 16_000),
        Some(Selection::Swap {
            inputs: vec!["a".into(), "b".into(), "c".into()],
            change: 1_000
        })
    );
    // One Spark transfer takes at most 32 leaves; more is not a payment.
    let many: BTreeMap<_, _> = (0..33).map(|i| (format!("{i:02}"), 1)).collect();
    assert_eq!(public::select(&many, 33), None);
    assert_eq!(public::select(&held, 17_001), None, "insufficient");
    assert_eq!(public::select(&held, 0), None, "zero");
    assert_eq!(
        code(&public::payment_amount(0).expect_err("zero")),
        Some("amount")
    );
    let only_ten = leaves(&[("a", 10_000)]);
    assert_eq!(
        public::select(&only_ten, 7_000),
        Some(Selection::Swap {
            inputs: vec!["a".into()],
            change: 3_000
        })
    );
    // Sums never overflow, even for values no Spark leaf could hold.
    let huge = leaves(&[("a", u64::MAX), ("b", u64::MAX)]);
    assert_eq!(
        public::select(&huge, u64::MAX - 1),
        Some(Selection::Swap {
            inputs: vec!["a".into()],
            change: 1
        })
    );
    assert_eq!(public::cover(&huge, u64::MAX), Some(vec!["a".into()]));
    // Many small leaves: the greedy cover takes the largest first.
    let many: BTreeMap<String, u64> = (0..12).map(|i| (format!("l{i:02}"), 1_000 + i)).collect();
    let cover = public::cover(&many, 9_000).expect("cover");
    assert_eq!(cover.len(), 9);
    assert!(cover.iter().all(|id| many[id] >= 1_003));
}

#[test]
fn any_amount_payment_swaps_then_pays_once() -> Result<()> {
    let mut f = fake(&[("a", 10_000)])?;
    let swap = pay_with_swap(&f, &[("a", 10_000)], 7_000)?;
    assert_eq!((swap.change_sat, swap.state), (3_000, State::Prepared));
    run(&mut f, swap, true)?;
    assert_paid_once(&f, 7_000)?;
    assert_eq!(
        only_swap(&f)?.received,
        Some(leaves(&[("c0", 7_000), ("c1", 3_000)]))
    );
    // Resuming a finished payment repeats nothing.
    resume(&mut f)?;
    assert_paid_once(&f, 7_000)?;
    assert_eq!(f.world.claims, 1);
    Ok(())
}

#[test]
fn change_may_arrive_in_several_leaves() -> Result<()> {
    let mut f = fake(&[("a", 10_000)])?;
    f.world.fill = Some(vec![1_000, 7_000, 2_000]);
    let swap = pay_with_swap(&f, &[("a", 10_000)], 7_000)?;
    run(&mut f, swap, true)?;
    assert_paid_once(&f, 7_000)?;
    Ok(())
}

#[test]
fn a_crash_at_any_fixture_call_resumes_the_same_swap_and_payment() -> Result<()> {
    for op in [
        "public_swap_begin",
        "public_swap_request",
        "public_claim",
        "public_transfer",
    ] {
        for applied in [false, true] {
            let mut f = fake(&[("a", 10_000)])?;
            let swap = pay_with_swap(&f, &[("a", 10_000)], 3_333)?;
            f.world.crash = Some((op, applied));
            assert!(run(&mut f, swap, true).is_err(), "{op} {applied}");
            if op == "public_swap_begin" && !applied {
                // Nothing was frozen, so nothing can have reached Spark.
                let error = resume(&mut f).expect_err("abandoned");
                assert_eq!(code(&error), Some("swap_failed"));
                let swap = only_swap(&f)?;
                assert!(swap.state == State::Abandoned && swap.settled);
                assert_eq!((f.world.packages, f.world.requests), (0, 0));
                assert!(f.world.transfers.is_empty() && bob_inbox(&f)?.is_empty());
                resume(&mut f)?;
                continue;
            }
            resume(&mut f)?;
            assert_paid_once(&f, 3_333)?;
        }
    }
    Ok(())
}

#[test]
fn a_payment_journal_redelivers_under_its_entry_name() -> Result<()> {
    let mut f = fake(&[("a", 5_000), ("b", 2_000)])?;
    let payment = Payment {
        schema: "zark-public-send-v1".into(),
        transfer: PAYMENT.into(),
        to: "bob".into(),
        receiver: hex::encode(BOB),
        amount_sat: 7_000,
        leaves: leaves(&[("a", 5_000), ("b", 2_000)]),
        entry: "cd".repeat(32),
        state: PaymentState::Sent,
        created_at: 1,
    };
    public_send::continue_payment(&mut f, payment.clone())?;
    public_send::continue_payment(&mut f, payment)?;
    let entries = bob_inbox(&f)?;
    assert_eq!(entries.len(), 1, "redelivery replaced the entry");
    assert_eq!(entries[0].envelope.schema, inbox::ENVELOPE_V2);
    assert!(
        f.world.transfers.is_empty(),
        "a sent payment is not sent again"
    );
    Ok(())
}

#[test]
fn the_ssp_being_down_after_initiate_waits_then_settles_or_abandons() -> Result<()> {
    let mut f = fake(&[("a", 10_000)])?;
    let swap = pay_with_swap(&f, &[("a", 10_000)], 7_000)?;
    f.world.ssp_down = true;
    let error = run(&mut f, swap, true).expect_err("pending");
    assert_eq!(code(&error), Some("swap_pending"));
    assert_eq!(only_swap(&f)?.state, State::Initiated);
    f.world.ssp_down = false;
    resume(&mut f)?;
    assert_paid_once(&f, 7_000)?;

    // The primary expires while the SSP is down: the inputs are back.
    let mut f = fake(&[("a", 10_000)])?;
    let swap = pay_with_swap(&f, &[("a", 10_000)], 7_000)?;
    f.world.ssp_down = true;
    assert!(run(&mut f, swap, true).is_err());
    f.world.dead = true;
    let error = resume(&mut f).expect_err("abandoned");
    assert_eq!(code(&error), Some("swap_failed"));
    assert_eq!((f.world.fills, f.world.claims), (0, 0));
    assert!(f.world.transfers.is_empty());
    let row = f
        .profile
        .activity()?
        .into_iter()
        .find(|r| r.id == format!("public-sent-{PAYMENT}"));
    assert_eq!(row.map(|r| r.state), Some("failed".into()));
    Ok(())
}

#[test]
fn an_expired_unseen_primary_is_abandoned_without_asking_the_ssp() -> Result<()> {
    let mut f = fake(&[("a", 10_000)])?;
    f.world.late = true;
    let swap = pay_with_swap(&f, &[("a", 10_000)], 7_000)?;
    assert_eq!(
        code(&run(&mut f, swap, true).expect_err("expired")),
        Some("swap_failed")
    );
    assert_eq!((f.world.packages, f.world.requests), (1, 0));
    assert!(!public_swap::unsettled(&f.profile)?);
    Ok(())
}

#[test]
fn wrong_ssp_answers_are_claimed_but_never_paid_out() -> Result<()> {
    type Twist = fn(&mut World);
    let cases: [(&str, Twist); 6] = [
        ("wrong targets", |w| w.fill = Some(vec![6_000, 4_000])),
        ("short sum", |w| w.fill = Some(vec![7_000, 2_000])),
        ("extra leaf", |w| w.fill = Some(vec![7_000, 3_000, 1_000])),
        ("missing change", |w| w.fill = Some(vec![7_000])),
        ("target only as change", |w| {
            w.fill = Some(vec![5_000, 2_000, 3_000])
        }),
        ("fee", |w| w.fee = 5),
    ];
    for (name, twist) in cases {
        let mut f = fake(&[("a", 10_000)])?;
        twist(&mut f.world);
        let swap = pay_with_swap(&f, &[("a", 10_000)], 7_000)?;
        let error = run(&mut f, swap, true).expect_err(name);
        assert_eq!(code(&error), Some("swap_mismatch"), "{name}");
        let swap = only_swap(&f)?;
        assert!(
            swap.state == State::Failed && swap.settled && swap.problem.is_some(),
            "{name}"
        );
        assert_eq!(f.world.claims, 1, "{name}: what the SSP sent is kept");
        assert!(
            f.world.transfers.is_empty() && bob_inbox(&f)?.is_empty(),
            "{name}"
        );
        assert!(!public_swap::unsettled(&f.profile)?, "{name}");
    }
    Ok(())
}

#[test]
fn an_unobservable_counter_transfer_pauses_the_network() -> Result<()> {
    let mut f = fake(&[("a", 10_000)])?;
    f.world.owner = Some(BOB);
    let swap = pay_with_swap(&f, &[("a", 10_000)], 7_000)?;
    assert!(run(&mut f, swap, true).is_err());
    assert!(resume(&mut f).is_err());
    assert!(f.network.blocked()?.is_none());
    assert!(resume(&mut f).is_err());
    let blocked = f
        .network
        .blocked()?
        .expect("blocked after repeated failures");
    assert_eq!(
        (blocked.operation.as_str(), blocked.profile.as_str()),
        ("publicSwap", "alice")
    );
    let swap = only_swap(&f)?;
    assert_eq!((swap.state, swap.attempts), (State::Requested, 3));
    assert_eq!(f.world.fills, 1, "never refilled");
    assert!(f.world.transfers.is_empty());

    // An SSP that answers under another identity is refused before any claim.
    let mut f = fake(&[("a", 10_000)])?;
    f.world.reply_ssp = Some(BOB);
    let swap = pay_with_swap(&f, &[("a", 10_000)], 7_000)?;
    assert!(run(&mut f, swap, true).is_err());
    assert_eq!(
        (only_swap(&f)?.state, f.world.claims),
        (State::Initiated, 0)
    );
    Ok(())
}

#[test]
fn swap_journals_refuse_impossible_shapes() {
    let send = |amount| Purpose::GoPrivate { amount_sat: amount };
    assert!(Swap::new(BTreeMap::new(), vec![5_000], send(5_000)).is_err());
    assert!(Swap::new(leaves(&[("a", 2_000)]), vec![5_000], send(5_000)).is_err());
    assert!(Swap::new(leaves(&[("a", 5_000)]), vec![0], send(5_000)).is_err());
    assert!(Swap::new(leaves(&[("a", 5_000)]), vec![], send(5_000)).is_err());
    let many: BTreeMap<String, u64> = (0..33).map(|i| (format!("l{i}"), 1)).collect();
    assert!(Swap::new(many, vec![1], send(1)).is_err());
    let ok = Swap::new(leaves(&[("a", 7_000)]), vec![5_000], send(5_000)).expect("swap");
    assert_eq!(ok.change_sat, 2_000);
    assert!(public_swap::canonical_uuid(&ok.id));
    assert!(!public_swap::canonical_uuid(
        "01A16AAB-0000-7000-8000-000000000001"
    ));
}

#[test]
fn envelopes_v1_load_unchanged_and_v2_must_add_up() -> Result<()> {
    let network = network(&parent()?)?;
    let bob = Profile::open(&network, "bob")?;
    let profiles = network.root.join("profiles");
    let deliver =
        |e: &inbox::Envelope| inbox::deliver(&profiles, &bob.public, &inbox::entry_name(), e);
    deliver(&envelope(Kind::Public, "alice"))?;
    deliver(&envelope(Kind::Private, "alice"))?;
    let v2 = |kind, amount, sats: &[(&str, u64)]| {
        let mut e = envelope(kind, "alice");
        e.schema = inbox::ENVELOPE_V2.into();
        e.leaf = sats[0].0.into();
        e.amount_sat = amount;
        e.leaves = Some(leaves(sats));
        e
    };
    deliver(&v2(Kind::Public, 7_000, &[("a", 5_000), ("b", 2_000)]))?;
    deliver(&v2(Kind::Public, 9_000, &[("a", 5_000), ("b", 2_000)]))?;
    deliver(&v2(Kind::Private, 7_000, &[("a", 5_000), ("b", 2_000)]))?;
    let mut v1_with_leaves = envelope(Kind::Public, "alice");
    v1_with_leaves.leaves = Some(leaves(&[("x", 10_000)]));
    deliver(&v1_with_leaves)?;
    let (entries, unreadable) = inbox::entries(&bob)?;
    assert_eq!((entries.len(), unreadable), (3, 3));
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.envelope.leaves.is_some())
            .count(),
        1
    );
    Ok(())
}

#[test]
fn only_confirmed_root_bills_with_a_receive_window_can_enter() {
    // Facts the fixture reported for a ladder bill the SSP paid out.
    let bill = json!({"amount_sats":5000,"anchor_confirmations":121,"direct":false,"leaf_id":"x",
        "node_inputs":1,"node_output_sats":5000,"node_outputs":2,"node_sequence":1u64 << 30,"parent":false,
        "refund_inputs":1,"refund_sequence":(1u64 << 30) | 1800,"refund_spends_node":true,"status":"AVAILABLE"});
    assert!(atm::entry_shape(&bill));
    let changed = |key: &str, value: Value| {
        let mut shape = bill.clone();
        shape[key] = value;
        atm::entry_shape(&shape)
    };
    // A split child, as the SSP returns for change.
    assert!(!changed("parent", json!(true)));
    assert!(!changed("direct", json!(true)));
    // An SDK deposit root without Spark's zero-sequence flag.
    assert!(!changed("node_sequence", json!(0)));
    assert!(!changed("amount_sats", json!(7_000)));
    assert!(!changed("node_output_sats", json!(4_000)));
    assert!(!changed("anchor_confirmations", json!(0)));
    assert!(!changed("status", json!("TRANSFER_LOCKED")));
    assert!(!changed("refund_spends_node", json!(false)));
    assert!(changed("refund_sequence", json!((1u64 << 30) | 300)));
    assert!(
        !changed("refund_sequence", json!((1u64 << 30) | 200)),
        "no receive window left"
    );
    assert!(changed("refund_sequence", json!((1u64 << 30) | 2000)));
    assert!(!changed("refund_sequence", json!((1u64 << 30) | 2100)));
    assert!(!changed("refund_sequence", json!((1u64 << 30) | 1850)));
}

#[test]
fn a_profile_without_public_journals_is_settled() -> Result<()> {
    let f = fake(&[])?;
    assert!(!public_swap::unsettled(&f.profile)?);
    assert!(public_swap::swaps(&f.profile)?.is_empty());
    assert!(
        !f.profile.home.join("public").exists(),
        "listing created journal directories"
    );
    Ok(())
}
