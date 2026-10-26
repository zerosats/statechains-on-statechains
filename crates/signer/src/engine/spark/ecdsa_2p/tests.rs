//! Session lifetime only; the cb-mpc protocol itself is covered by the
//! co-signer's ECDSA-2P tests.
use super::*;

fn expired() -> Instant {
    Instant::now()
        .checked_sub(SESSION_TIMEOUT + Duration::from_secs(1))
        .expect("monotonic clock older than the session timeout")
}

#[test]
fn config_tag_pins_the_blind_patch_and_differs_from_the_plaintext_build() -> Result<()> {
    use sha2::{Digest as _, Sha256};
    let patch = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/cbmpc-blind-sign.patch"
    ))?;
    assert_eq!(
        hex::encode(Sha256::digest(&patch)),
        CBMPC_PATCH_SHA256,
        "update the pinned patch digest"
    );
    let base = [3; 32];
    let unpatched = zark_protocol::hash(&[
        b"ZARK/spark/signer/ecdsa-2p-config/v1",
        &base,
        b"cb-mpc 0b716706f998633912ee2be9b9bf8909aed66088",
    ]);
    assert!(
        config(&base) != unpatched && config(&base) != base && config(&[4; 32]) != config(&base)
    );
    Ok(())
}

#[test]
fn expired_session_neither_blocks_a_new_ticket_nor_resumes() -> Result<()> {
    let sessions = Sessions::<u8>::default();
    let (coin, ticket) = ([1; 32], [2; 32]);
    sessions.insert_started(coin, ticket, 7, expired())?;
    assert!(
        !sessions.live(coin, ticket)?,
        "a dead session still blocks new tickets"
    );
    // `live` already dropped it; the finish cannot reach its nonce.
    assert!(sessions.take(coin, ticket).is_err());

    // Expired but not yet swept by `live`: `take` drops it without answering.
    sessions.insert_started(coin, ticket, 7, expired())?;
    let error = sessions
        .take(coin, ticket)
        .err()
        .context("expired session resumed")?
        .to_string();
    assert!(error.contains("expired"), "{error}");
    assert!(sessions.take(coin, ticket).is_err());
    Ok(())
}

#[test]
fn live_session_is_taken_once_and_a_new_ticket_replaces_the_coins_old_session() -> Result<()> {
    let sessions = Sessions::<u8>::default();
    let (coin, other) = ([1; 32], [9; 32]);
    sessions.insert(coin, [2; 32], 1)?;
    sessions.insert(other, [2; 32], 2)?;
    assert!(sessions.live(coin, [2; 32])?);
    sessions.insert(coin, [3; 32], 3)?;
    assert!(!sessions.live(coin, [2; 32])?, "one live session per coin");
    assert!(sessions.take(coin, [2; 32]).is_err());
    assert_eq!(sessions.take(coin, [3; 32])?, 3);
    assert!(
        sessions.take(coin, [3; 32]).is_err(),
        "a session answers one finish only"
    );
    assert_eq!(sessions.take(other, [2; 32])?, 2);
    Ok(())
}
