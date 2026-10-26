//! Ticket state and blinding arithmetic only. Proof verification is the pinned
//! verifier's job and is not replaced by a test oracle here.
use super::super::{
    Policy,
    state::{Pending, Phase},
};
use super::*;
use k256::{Scalar, schnorr::SigningKey};
use std::time::Instant;
use zark_protocol::{
    random_scalar,
    spark_auth::{AuthBlinding, IdentityKey, SparkChallenge},
    spark_lineage::{self as lineage, Config},
};

pub(super) struct Fixture {
    pub(super) coin: Coin,
    policy: Policy,
    key: SigningKey,
    pub(super) base: Intent,
    pub(super) wallet: IdentityKey,
}

pub(super) fn fixture() -> Result<Fixture> {
    let key = SigningKey::from_bytes(&Scalar::from(17u64).to_bytes())?;
    let base = Intent {
        deployment: [1; 32],
        coin: [2; 32],
        previous_state: lineage::origin_previous_state(&[1; 32], &[2; 32])?,
        operation: [4; 32],
        recipient_claim: lineage::origin_field(&[1; 32], &[2; 32], 0)?,
        revision: 1,
    };
    let request = Request::sign(base.clone(), Command::Allocate {}, &key)?;
    let coin = Coin {
        deployment: [1; 32],
        coin: [2; 32],
        backing: [0; 32],
        state: base.previous_state,
        capability: [0; 32],
        secret: random_scalar().to_bytes().into(),
        salt: [8; 32],
        session: request.session,
        owner: None,
        phase: Phase::Allocated,
        pending: Some(Pending::new(&request, true)),
        issuance: None,
        partials: None,
        origin_signature: None,
        native: None,
        bootstrap: None,
        single_user: None,
        receive: None,
        identities: None,
        auth: None,
        ecdsa: None,
        exit: None,
    };
    let policy = Policy {
        deployment: [1; 32],
        config: Config {
            origin_key: request.session,
            role_hashes: std::array::from_fn(|i| [i as u8 + 1; 32]),
        },
        policy: [9; 32],
        native: None,
        native_cluster: None,
        bootstrap: None,
        single_user: None,
        receive: None,
        receive_cluster: None,
        identity: Some([10; 32]),
        auth: Some([13; 32]),
        ecdsa_2p: false,
        additive_receive: false,
    };
    let wallet = IdentityKey::new(
        random_scalar().to_bytes().into(),
        random32(),
        coin.server()?,
    )?;
    Ok(Fixture {
        coin,
        policy,
        key,
        base,
        wallet,
    })
}

fn clock() -> u64 {
    now().unwrap()
}

/// Wallet-side ticket material kept between preparation and issue.
pub(super) struct Wallet {
    pub(super) challenge: SparkChallenge,
    pub(super) blinding: AuthBlinding,
    pub(super) request: Request,
}

impl Fixture {
    pub(super) fn wallet_prepare(&self, timestamp: u64) -> Result<Wallet> {
        let challenge = SparkChallenge {
            timestamp,
            nonce: random32(),
            public_key: self.wallet.compressed()?,
        };
        self.wallet.check_challenge(&challenge)?;
        let blinding = AuthBlinding::random();
        let header = self
            .wallet
            .header(spark_auth::scope_digest(&self.base)?, timestamp);
        let commitment = blinding.commitment(&header, &challenge.message()?)?;
        let key_commitment = self.wallet.commitment();
        let intent = auth_prepare_intent(&self.base, &key_commitment, timestamp, &commitment)?;
        let request = Request::sign(
            intent,
            Command::AuthPrepare {
                key_commitment,
                timestamp,
                commitment,
            },
            &self.key,
        )?;
        Ok(Wallet {
            challenge,
            blinding,
            request,
        })
    }
    pub(super) fn prepare(&mut self, wallet: &Wallet, now: u64) -> Result<[u8; 64]> {
        let Command::AuthPrepare {
            key_commitment,
            timestamp,
            commitment,
        } = &wallet.request.command
        else {
            unreachable!()
        };
        plan_prepare(
            &self.coin,
            &wallet.request,
            &self.base,
            key_commitment,
            *timestamp,
            commitment,
            now,
        )?;
        let response = apply_prepare(
            &mut self.coin,
            &wallet.request,
            key_commitment,
            *timestamp,
            commitment,
            now,
        )?;
        self.coin.validate(&self.policy)?;
        Ok(
            serde_json::from_value::<Vec<u8>>(response["nonce"].clone())?
                .as_slice()
                .try_into()?,
        )
    }
    pub(super) fn issue_request(&self, wallet: &Wallet, challenge: Digest) -> Result<Request> {
        let intent = auth_issue_intent(&wallet.request.intent, &challenge)?;
        let ticket = wallet.request.intent.operation;
        Request::sign(
            intent,
            Command::AuthIssue {
                ticket,
                challenge,
                proof: Vec::new(),
            },
            &self.key,
        )
    }
    pub(super) fn issue(&mut self, request: &Request, now: u64) -> Result<(ProofSpec, Digest)> {
        let Command::AuthIssue {
            ticket, challenge, ..
        } = &request.command
        else {
            unreachable!()
        };
        let spec = plan_issue(&self.coin, request, &self.base, ticket, challenge, now)?;
        let response = apply_issue(&mut self.coin, ticket, challenge)?;
        self.coin.validate(&self.policy)?;
        Ok((spec, serde_json::from_value(response["partial"].clone())?))
    }
}

#[test]
fn blind_auth_round_trip_yields_spark_schnorr_signature() -> Result<()> {
    let mut f = fixture()?;
    let started = Instant::now();
    let now = clock();
    let wallet = f.wallet_prepare(now)?;
    let nonce = f.prepare(&wallet, now)?;
    let message = wallet.challenge.message()?;
    let bound = wallet.blinding.bind(&f.wallet, &nonce, &message)?;
    let request = f.issue_request(&wallet, bound.challenge)?;
    let (spec, partial) = f.issue(&request, now)?;
    let signature = wallet
        .blinding
        .finish(&f.wallet, &bound, &nonce, &partial, &message)?;
    let elapsed = started.elapsed();
    // The signer's statement is exactly what the wallet proves.
    let header = f.wallet.header(spark_auth::scope_digest(&f.base)?, now);
    let expected = AuthStatement {
        commitment: wallet.blinding.commitment(&header, &message)?,
        header,
        nonce,
        challenge: bound.challenge,
    };
    assert!(spec.role == ProofRole::Auth && spec.statement == expected.encode()?);
    k256::schnorr::VerifyingKey::from_bytes(&f.wallet.compressed()?[1..])?.verify_raw(
        &message,
        &k256::schnorr::Signature::try_from(signature.as_slice())?,
    )?;
    eprintln!("local blind auth signing without proof: {elapsed:?}");
    // The nonce is gone; the same ticket cannot answer again.
    assert!(f.issue(&request, now).is_err());
    Ok(())
}

#[test]
fn restored_ticket_can_only_rerelease_the_identical_partial() -> Result<()> {
    let mut f = fixture()?;
    let now = clock();
    let wallet = f.wallet_prepare(now)?;
    let nonce = f.prepare(&wallet, now)?;
    let restored = f.coin.clone();
    let bound = wallet
        .blinding
        .bind(&f.wallet, &nonce, &wallet.challenge.message()?)?;
    let request = f.issue_request(&wallet, bound.challenge)?;
    let (_, first) = f.issue(&request, now)?;
    // A checkpoint-restored live ticket answers the proof-fixed challenge with
    // the same response; the proof admits no other challenge for this ticket.
    f.coin = restored;
    let (_, second) = f.issue(&request, now)?;
    assert_eq!(first, second);
    Ok(())
}

#[test]
fn prepare_rejects_stale_future_rebound_and_other_key() -> Result<()> {
    let mut f = fixture()?;
    let now = clock();
    for timestamp in [
        now - spark_auth::MAX_AGE_SECONDS - 1,
        now + spark_auth::MAX_FUTURE_SECONDS + 1,
    ] {
        let wallet = f.wallet_prepare(timestamp)?;
        assert!(f.prepare(&wallet, now).is_err());
    }
    // A request whose signed intent names another commitment is rejected.
    let wallet = f.wallet_prepare(now)?;
    let mut rebound = wallet.request.clone();
    let Command::AuthPrepare { commitment, .. } = &mut rebound.command else {
        unreachable!()
    };
    commitment[0] ^= 1;
    let Command::AuthPrepare {
        key_commitment,
        timestamp,
        commitment,
    } = &rebound.command
    else {
        unreachable!()
    };
    assert!(
        plan_prepare(
            &f.coin,
            &rebound,
            &f.base,
            key_commitment,
            *timestamp,
            commitment,
            now
        )
        .is_err()
    );
    f.prepare(&wallet, now)?;
    assert!(f.prepare(&wallet, now).is_err(), "duplicate ticket");
    f.wallet = IdentityKey::new(
        random_scalar().to_bytes().into(),
        random32(),
        f.coin.server()?,
    )?;
    let other = f.wallet_prepare(now)?;
    assert!(f.prepare(&other, now).is_err(), "second identity key");
    Ok(())
}

#[test]
fn issue_rejects_stale_ticket_other_session_and_changed_scope() -> Result<()> {
    let mut f = fixture()?;
    let now = clock();
    let wallet = f.wallet_prepare(now)?;
    let nonce = f.prepare(&wallet, now)?;
    let bound = wallet
        .blinding
        .bind(&f.wallet, &nonce, &wallet.challenge.message()?)?;
    let request = f.issue_request(&wallet, bound.challenge)?;
    let Command::AuthIssue {
        ticket, challenge, ..
    } = &request.command
    else {
        unreachable!()
    };
    assert!(
        plan_issue(
            &f.coin,
            &request,
            &f.base,
            ticket,
            challenge,
            now + spark_auth::MAX_AGE_SECONDS + 1
        )
        .is_err()
    );
    let stranger = SigningKey::from_bytes(&Scalar::from(29u64).to_bytes())?;
    let foreign = Request::sign(request.intent.clone(), request.command.clone(), &stranger)?;
    assert!(plan_issue(&f.coin, &foreign, &f.base, ticket, challenge, now).is_err());
    let mut other_base = f.base.clone();
    other_base.previous_state[0] ^= 1;
    assert!(plan_issue(&f.coin, &request, &other_base, ticket, challenge, now).is_err());
    let mut moved = f.coin.clone();
    moved.phase = Phase::Accepted;
    moved.pending = None;
    assert!(super::super::identity::scope(&moved, &request.session).is_err());
    // A malformed challenge is rejected before the live nonce is consumed.
    assert!(apply_issue(&mut f.coin, ticket, &[255; 32]).is_err());
    f.coin.validate(&f.policy)?;
    f.issue(&request, now)?;
    Ok(())
}

#[test]
fn concurrent_and_total_ticket_limits() -> Result<()> {
    let mut f = fixture()?;
    let now = clock();
    for _ in 0..MAX_LIVE {
        let wallet = f.wallet_prepare(now)?;
        f.prepare(&wallet, now)?;
    }
    let extra = f.wallet_prepare(now)?;
    assert!(f.prepare(&extra, now).is_err(), "concurrent live limit");
    // Expired live tickets are retired, erasing their nonce, before admission.
    let step = spark_auth::MAX_AGE_SECONDS + 1;
    let mut admitted = MAX_LIVE;
    loop {
        let at = now + step * (admitted - MAX_LIVE + 1) as u64;
        let wallet = f.wallet_prepare(at)?;
        match f.prepare(&wallet, at) {
            Ok(_) => admitted += 1,
            Err(_) => break,
        }
    }
    assert_eq!(admitted, IDENTITY_RESPONSE_BUDGET / AUTH_TICKET_RESPONSES);
    let tickets = f.coin.auth.as_ref().unwrap();
    assert!(tickets.tickets.values().filter(|t| t.live()).count() <= 1);
    Ok(())
}

#[test]
fn auth_key_commitment_is_the_ecdsa_identity_commitment() -> Result<()> {
    for _ in 0..8 {
        let (user, salt): (Digest, Digest) = (random_scalar().to_bytes().into(), random32());
        assert_eq!(
            spark_auth::key_commitment(&user, &salt)?,
            zark_spark_claim_mpc::identity::key_commitment(&user, &salt)?
        );
    }
    Ok(())
}

/// Regression: allocation-time tickets bind the allocation share's X_s, so a
/// transfer Issue that rotates the share made every later validation fail and
/// the handover could never commit.
fn issued_and_live_tickets() -> Result<(Fixture, String)> {
    let mut f = fixture()?;
    let now = clock();
    let issued = f.wallet_prepare(now)?;
    let nonce = f.prepare(&issued, now)?;
    let bound = issued
        .blinding
        .bind(&f.wallet, &nonce, &issued.challenge.message()?)?;
    f.issue(&f.issue_request(&issued, bound.challenge)?, now)?;
    let live = f.wallet_prepare(now)?;
    f.prepare(&live, now)?;
    Ok((f, hex::encode(live.request.intent.operation)))
}

#[test]
fn transfer_share_rotation_keeps_the_coin_valid() -> Result<()> {
    let (f, _) = issued_and_live_tickets()?;
    let mut rotated = f.coin.clone();
    let (origin_share, origin_salt) = (rotated.secret, rotated.salt);
    super::super::transitions::install_share(&mut rotated, &origin_share, origin_salt, true);
    rotated
        .auth
        .as_ref()
        .unwrap()
        .validate(&rotated, &f.policy)?;
    let next: [u8; 32] = random_scalar().to_bytes().into();
    super::super::transitions::install_share(&mut rotated, &next, random32(), false);
    if let Some(tickets) = &rotated.auth {
        tickets.validate(&rotated, &f.policy)?;
    }
    assert!(
        rotated.auth.is_none(),
        "the new owner inherits no earlier owner's tickets"
    );
    Ok(())
}

#[test]
fn freeze_retires_live_allocation_tickets() -> Result<()> {
    let (f, id) = issued_and_live_tickets()?;
    let mut frozen = f.coin.clone();
    super::super::transitions::retire_for_freeze(&mut frozen);
    let tickets = frozen.auth.as_ref().unwrap();
    assert!(
        tickets.tickets.values().all(|t| !t.live()),
        "no allocation nonce survives freeze"
    );
    assert!(tickets.tickets[&id].challenge.is_none());
    tickets.validate(&frozen, &f.policy)?;
    Ok(())
}

#[test]
fn validation_rejects_tampered_tickets() -> Result<()> {
    let mut f = fixture()?;
    let now = clock();
    let wallet = f.wallet_prepare(now)?;
    let nonce = f.prepare(&wallet, now)?;
    let bound = wallet
        .blinding
        .bind(&f.wallet, &nonce, &wallet.challenge.message()?)?;
    f.issue(&f.issue_request(&wallet, bound.challenge)?, now)?;
    let id = hex::encode(wallet.request.intent.operation);
    let tamper = |change: &dyn Fn(&mut Ticket)| -> bool {
        let mut coin = f.coin.clone();
        change(coin.auth.as_mut().unwrap().tickets.get_mut(&id).unwrap());
        coin.validate(&f.policy).is_err()
    };
    assert!(tamper(&|t| t.partial = Some(Scalar::ONE.to_bytes().into())));
    assert!(tamper(&|t| t.challenge = None));
    assert!(tamper(&|t| t.timestamp += 1));
    assert!(tamper(&|t| t.secret = Some(Scalar::ONE.to_bytes().into())));
    let mut disabled = f.policy.clone();
    disabled.auth = None;
    assert!(f.coin.validate(&disabled).is_err());
    Ok(())
}
