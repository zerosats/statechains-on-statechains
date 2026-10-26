use super::*;
use k256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(20);

fn keygen() -> (KeyBlob, KeyBlob) {
    let mut p1 = Session::keygen(Role::P1, TIMEOUT).unwrap();
    let mut p2 = Session::keygen(Role::P2, TIMEOUT).unwrap();
    let m1 = p1.exchange(None).unwrap();
    let m2 = p2.exchange(Some(m1)).unwrap();
    let m3 = p1.exchange(Some(m2)).unwrap();
    let Output::Key(k1) = p1.finish(None).unwrap() else {
        panic!("P1 key")
    };
    let Output::Key(k2) = p2.finish(Some(m3)).unwrap() else {
        panic!("P2 key")
    };
    (k1, k2)
}

fn sign(k1: &KeyBlob, k2: &KeyBlob, digest: [u8; 32], sid: [u8; 32]) -> Result<Vec<u8>> {
    let mut p1 = Session::sign(Role::P1, k1, digest, sid, TIMEOUT)?;
    let mut p2 = Session::sign(Role::P2, k2, digest, sid, TIMEOUT)?;
    let m1 = p1.exchange(None)?;
    let m2 = p2.exchange(Some(m1))?;
    let m3 = p1.exchange(Some(m2))?;
    let m4 = p2.exchange(Some(m3))?;
    let Output::Signature(None) = p2.finish(None)? else {
        anyhow::bail!("P2 received a signature")
    };
    let Output::Signature(Some(signature)) = p1.finish(Some(m4))? else {
        anyhow::bail!("P1 signature missing")
    };
    Ok(signature)
}

#[test]
fn keygen_shares_sum_to_the_joint_key_and_sign_verifies() {
    let (k1, k2) = keygen();
    let q = k1.public_key().unwrap();
    assert_eq!(q, k2.public_key().unwrap());
    let x1 = Scalar::from_repr((*k1.private_share().unwrap()).into()).unwrap();
    let x2 = Scalar::from_repr((*k2.private_share().unwrap()).into()).unwrap();
    let joint = PublicKey::from_sec1_bytes(&q).unwrap().to_projective();
    assert_eq!(ProjectivePoint::GENERATOR * (x1 + x2), joint);

    let restored = KeyBlob::from_bytes(k2.as_bytes()).unwrap();
    let digest = [7; 32];
    let der = sign(&k1, &restored, digest, [1; 32]).unwrap();
    let signature = Signature::from_der(&der).unwrap();
    assert!(signature.normalize_s().is_none(), "signature must be low-s");
    VerifyingKey::from_sec1_bytes(&q)
        .unwrap()
        .verify_prehash(&digest, &signature)
        .unwrap();
}

#[test]
fn parties_must_agree_on_digest_and_session() {
    let (k1, k2) = keygen();
    let mismatched = |d2: [u8; 32], sid2: [u8; 32]| -> Result<()> {
        let mut p1 = Session::sign(Role::P1, &k1, [3; 32], [4; 32], TIMEOUT)?;
        let mut p2 = Session::sign(Role::P2, &k2, d2, sid2, TIMEOUT)?;
        let m1 = p1.exchange(None)?;
        let m2 = p2.exchange(Some(m1))?;
        let m3 = p1.exchange(Some(m2))?;
        let m4 = p2.exchange(Some(m3))?;
        p1.finish(Some(m4)).map(|_| ())
    };
    assert!(
        mismatched([5; 32], [4; 32]).is_err(),
        "P2 must refuse another digest"
    );
    assert!(
        mismatched([3; 32], [6; 32]).is_err(),
        "P2 must refuse another session id"
    );
}

/// Runs a blind signature and returns it with every message P2 saw or sent.
fn sign_blind(
    k1: &KeyBlob,
    k2: &KeyBlob,
    digest: [u8; 32],
    tau: &[u8; 32],
    tamper: impl FnOnce(&mut Vec<u8>),
) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
    let sid = [11; 32];
    let mut p1 = Session::sign_blind_wallet(k1, digest, tau, sid, TIMEOUT)?;
    let mut p2 = Session::sign_blind_signer(k2, sid, TIMEOUT)?;
    let m1 = p1.exchange(None)?;
    let m2 = p2.exchange(Some(m1.clone()))?;
    let mut m3 = p1.exchange(Some(m2.clone()))?;
    tamper(&mut m3);
    let m4 = p2.exchange(Some(m3.clone()))?;
    let Output::Signature(None) = p2.finish(None)? else {
        anyhow::bail!("P2 received a signature")
    };
    let Output::Signature(Some(signature)) = p1.finish(Some(m4.clone()))? else {
        anyhow::bail!("P1 signature missing")
    };
    Ok((signature, vec![m1, m2, m3, m4]))
}

fn blinded(q: &[u8; 33], tau: &[u8; 32]) -> VerifyingKey {
    let tau = Scalar::from_repr((*tau).into()).unwrap();
    let point =
        PublicKey::from_sec1_bytes(q).unwrap().to_projective() + ProjectivePoint::GENERATOR * tau;
    VerifyingKey::from_affine(point.to_affine()).unwrap()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn blind_signature_verifies_under_the_tweaked_key_and_p2_sees_neither_key_nor_digest() {
    let (k1, k2) = keygen();
    let q = k1.public_key().unwrap();
    let tau = [0x42; 32];
    let digest = [0x5a; 32];
    let (der, view) = sign_blind(&k1, &k2, digest, &tau, |_| {}).unwrap();
    let signature = Signature::from_der(&der).unwrap();
    assert!(signature.normalize_s().is_none(), "signature must be low-s");
    let key = blinded(&q, &tau);
    key.verify_prehash(&digest, &signature).unwrap();
    assert!(
        VerifyingKey::from_sec1_bytes(&q)
            .unwrap()
            .verify_prehash(&digest, &signature)
            .is_err()
    );

    let encoded = key.to_encoded_point(true);
    let x = &encoded.as_bytes()[1..];
    for message in &view {
        assert!(
            !contains(message, &digest) && !contains(message, x),
            "P2 view leaks m or P"
        );
    }
}

#[test]
fn wrong_tau_or_tampered_blind_message_fails() {
    let (k1, k2) = keygen();
    let q = k1.public_key().unwrap();
    let digest = [0x33; 32];
    let (der, _) = sign_blind(&k1, &k2, digest, &[0x43; 32], |_| {}).unwrap();
    let signature = Signature::from_der(&der).unwrap();
    assert!(
        blinded(&q, &[0x42; 32])
            .verify_prehash(&digest, &signature)
            .is_err(),
        "wrong tau"
    );

    let tampered = sign_blind(&k1, &k2, digest, &[0x42; 32], |m3| {
        let last = m3.len() - 1;
        m3[last] ^= 1;
    });
    assert!(tampered.is_err(), "a changed m'' must abort");

    // A blind P1 cannot pair with an unpatched P2, which expects a message commitment.
    let mut p1 = Session::sign_blind_wallet(&k1, digest, &[0x42; 32], [12; 32], TIMEOUT).unwrap();
    let mut p2 = Session::sign(Role::P2, &k2, digest, [12; 32], TIMEOUT).unwrap();
    let m1 = p1.exchange(None).unwrap();
    let m2 = p2.exchange(Some(m1)).unwrap();
    let m3 = p1.exchange(Some(m2)).unwrap();
    assert!(
        p2.exchange(Some(m3)).is_err(),
        "mixed blind and plain signing must abort"
    );
}

#[test]
fn tampered_or_dropped_messages_abort() {
    let (k1, k2) = keygen();
    let mut p1 = Session::sign(Role::P1, &k1, [8; 32], [9; 32], TIMEOUT).unwrap();
    let mut p2 = Session::sign(Role::P2, &k2, [8; 32], [9; 32], TIMEOUT).unwrap();
    let mut m1 = p1.exchange(None).unwrap();
    let last = m1.len() - 1;
    m1[last] ^= 1;
    let m2 = p2.exchange(Some(m1)).unwrap();
    let m3 = p1.exchange(Some(m2)).unwrap();
    assert!(
        p2.exchange(Some(m3)).is_err(),
        "P2 must reject an opening of another commitment"
    );

    let mut p1 =
        Session::sign(Role::P1, &k1, [8; 32], [10; 32], Duration::from_millis(200)).unwrap();
    p1.exchange(None).unwrap();
    assert!(p1.next(None).is_err(), "a silent peer must time out");
}
