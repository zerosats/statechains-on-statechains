//! The BlindedSnapshot the desktop UI renders. Built only from this profile's
//! records, its inbox names and the native Public balance; it never opens a
//! wallet journal or the signer.
use super::super::*;
use super::{
    inbox::{self, Kind},
    private::{self, claim_coin_id},
    public::{self, Balance},
    public_swap,
    session::Session,
    store::{CoinRecord, CoinState, Network, Origin, Profile},
};

fn coin_state(state: CoinState) -> Option<&'static str> {
    Some(match state {
        CoinState::Entering => "entering",
        CoinState::Available => "available",
        CoinState::Sending => "sending",
        CoinState::Exiting => "exiting",
        CoinState::Interrupted => "interrupted",
        CoinState::Claiming | CoinState::Sent | CoinState::Exited | CoinState::Abandoned => {
            return None;
        }
    })
}

/// A claim that never produced a coin is shown as incoming, not as a coin.
fn unclaimed(coin: &CoinRecord) -> bool {
    coin.origin == Origin::Received && coin.revision.is_none()
}

fn operation(coin: &CoinRecord) -> Option<Value> {
    let (kind, state) = match coin.state {
        CoinState::Entering => ("goPrivate", "running"),
        CoinState::Sending => ("privateSend", "running"),
        CoinState::Claiming => ("claim", "running"),
        CoinState::Exiting => ("goPublic", "interrupted"),
        CoinState::Interrupted if unclaimed(coin) => ("claim", "interrupted"),
        CoinState::Interrupted if coin.revision.is_none() => ("goPrivate", "interrupted"),
        CoinState::Interrupted => ("privateSend", "interrupted"),
        _ => return None,
    };
    Some(json!({"kind":kind,"stage":Value::Null,"coin":coin.id,"state":state}))
}

pub(super) fn snapshot(s: &mut Session) -> Result<Value> {
    let balance = public::balance(s).ok();
    build(&s.network, &s.profile, balance.as_ref())
}

pub(super) fn build(
    network: &Network,
    profile: &Profile,
    balance: Option<&Balance>,
) -> Result<Value> {
    let coins = profile.coins()?;
    let (entries, _unreadable) = inbox::entries(profile)?;
    let blocked = network.blocked()?;
    let mut visible = Vec::new();
    let mut incoming = Vec::new();
    for coin in &coins {
        if unclaimed(coin) && matches!(coin.state, CoinState::Claiming | CoinState::Interrupted) {
            let state = if coin.state == CoinState::Claiming {
                "claiming"
            } else {
                "interrupted"
            };
            incoming.push(json!({"id":coin.id,"amountSat":coin.amount_sat,"state":state}));
        } else if let Some(state) = coin_state(coin.state) {
            let available = coin.state == CoinState::Available;
            visible.push(json!({"id":coin.id,"amountSat":coin.amount_sat,"state":state,
                "origin":match coin.origin { Origin::Public => "public", Origin::Received => "received" },
                "canSend":available,"canGoPublic":available}));
        }
    }
    let mut public_incoming = Vec::new();
    for entry in &entries {
        let e = &entry.envelope;
        match e.kind {
            Kind::Private => {
                let id = claim_coin_id(&entry.name);
                if !coins.iter().any(|c| c.id == id) && e.from != profile.name {
                    incoming.push(json!({"id":id,"amountSat":e.amount_sat,"state":"pending"}));
                }
            }
            Kind::Public => public_incoming
                .push(json!({"id":e.transfer,"amountSat":e.amount_sat,"state":"pending"})),
        }
    }
    let incognito_total: u64 = coins
        .iter()
        .filter(|c| c.state == CoinState::Available)
        .map(|c| c.amount_sat)
        .sum();
    let public_total = balance.map_or(0, |b| b.total);
    let working = coins.iter().any(|c| {
        matches!(
            c.state,
            CoinState::Entering | CoinState::Sending | CoinState::Claiming | CoinState::Exiting
        )
    }) || public_swap::unsettled(profile)?;
    let status = if blocked.is_some() {
        "blocked"
    } else if working {
        "working"
    } else {
        "ready"
    };
    let activity = profile
        .activity()?
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()?;
    let blinded = json!({
        "network": network.name,
        "profile": profile.name,
        "status": status,
        "blocked": blocked.map(|b| json!({"reason":b.reason,"operation":b.operation,"profile":b.profile})),
        "operation": coins.iter().find_map(operation),
        // The smallest leaf this build moves.
        "denominationSat": DENOMINATIONS_SAT[DENOMINATIONS_SAT.len() - 1],
        "public": {
            "address": profile.public.public_identity.as_ref().map(|k| format!("{}{k}", public::ADDRESS_PREFIX)),
            "totalSat": public_total,
            "leaves": balance.map_or(Vec::new(), |b| b.leaves.iter()
                .map(|(id, sats)| json!({"id":id,"amountSat":sats,"available":true})).collect()),
            "incoming": public_incoming,
        },
        "incognito": {
            "address": format!("{}{}", private::ADDRESS_PREFIX, profile.public.claim_key),
            "totalSat": incognito_total,
            "coins": visible,
            "incoming": incoming,
        },
        "activity": activity,
    });
    Ok(json!({"connected":balance.is_some(),"blinded":blinded}))
}
