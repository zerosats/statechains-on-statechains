use super::*;
use crate::{point_bytes, random_scalar, random32};
use k256::{ProjectivePoint, Scalar};

struct Signer {
    share: Scalar,
    server: [u8; 64],
}
impl Signer {
    fn new() -> Self {
        let share = random_scalar();
        Self {
            share,
            server: point_bytes(ProjectivePoint::GENERATOR * share).unwrap(),
        }
    }
    fn nonce(&self) -> (Scalar, [u8; 64]) {
        let k = random_scalar();
        (k, point_bytes(ProjectivePoint::GENERATOR * k).unwrap())
    }
    fn respond(&self, k: Scalar, challenge: &Digest) -> Digest {
        (k + scalar(challenge).unwrap() * self.share)
            .to_bytes()
            .into()
    }
}

fn challenge_for(key: &IdentityKey, timestamp: u64) -> SparkChallenge {
    SparkChallenge {
        timestamp,
        nonce: random32(),
        public_key: key.compressed().unwrap(),
    }
}

#[test]
fn challenge_bytes_match_go_protobuf_vector() -> Result<()> {
    let mut key = [9; 33];
    key[0] = 2;
    let value = SparkChallenge {
        timestamp: 1_700_000_000,
        nonce: [7; 32],
        public_key: key,
    };
    let bytes = value.encode()?;
    assert_eq!(bytes[..10], [8, 1, 16, 128, 226, 207, 170, 6, 26, 32]);
    assert_eq!(bytes[42..45], [34, 33, 2]);
    assert_eq!(SparkChallenge::decode(&bytes)?, value);
    assert_eq!(value.message()?, hash(&[&bytes]));
    Ok(())
}

#[test]
fn challenge_rejects_other_shapes() -> Result<()> {
    let mut key = [9; 33];
    key[0] = 3;
    let bytes = SparkChallenge {
        timestamp: 1_700_000_000,
        nonce: [7; 32],
        public_key: key,
    }
    .encode()?;
    for (index, value) in [(1, 2u8), (3, 0), (7, 0), (9, 31), (43, 65), (44, 4)] {
        let mut changed = bytes;
        changed[index] = value;
        assert!(SparkChallenge::decode(&changed).is_err(), "byte {index}");
    }
    assert!(SparkChallenge::decode(&bytes[..76]).is_err());
    assert!(SparkChallenge::decode(&[&bytes[..], &[0]].concat()).is_err());
    let short = SparkChallenge {
        timestamp: (1 << 28) - 1,
        nonce: [7; 32],
        public_key: key,
    };
    assert!(short.encode().is_err());
    Ok(())
}

#[test]
fn blinded_signatures_verify_for_every_parity_combination() -> Result<()> {
    let mut seen = [false; 4];
    for _ in 0..256 {
        let signer = Signer::new();
        let key = IdentityKey::new(random_scalar().to_bytes().into(), random32(), signer.server)?;
        let challenge = challenge_for(&key, 1_760_000_000);
        key.check_challenge(&challenge)?;
        let message = challenge.message()?;
        let blinding = AuthBlinding::random();
        let (k, server_nonce) = signer.nonce();
        let bound = blinding.bind(&key, &server_nonce, &message)?;
        let partial = signer.respond(k, &bound.challenge);
        let signature = blinding.finish(&key, &bound, &server_nonce, &partial, &message)?;
        // The signer never sees R; its transcript differs from the final nonce.
        assert_ne!(signature[..32], server_nonce[..32]);
        let key_odd = key.compressed()?[0] == 3;
        assert_eq!(key_odd, bound.key_sign == -Scalar::ONE);
        let nonce_odd = bound.nonce_sign == -Scalar::ONE;
        seen[usize::from(key_odd) * 2 + usize::from(nonce_odd)] = true;
        if seen.iter().all(|s| *s) {
            return Ok(());
        }
    }
    anyhow::bail!("parity combinations not all exercised: {seen:?}")
}

#[test]
fn finish_rejects_wrong_contribution_and_message() -> Result<()> {
    let signer = Signer::new();
    let key = IdentityKey::new(random_scalar().to_bytes().into(), random32(), signer.server)?;
    let message = challenge_for(&key, 1_760_000_000).message()?;
    let blinding = AuthBlinding::random();
    let (k, server_nonce) = signer.nonce();
    let bound = blinding.bind(&key, &server_nonce, &message)?;
    let partial = signer.respond(k, &bound.challenge);
    let wrong = signer.respond(k + Scalar::ONE, &bound.challenge);
    assert!(
        blinding
            .finish(&key, &bound, &server_nonce, &wrong, &message)
            .is_err()
    );
    assert!(
        blinding
            .finish(&key, &bound, &server_nonce, &partial, &random32())
            .is_err()
    );
    Ok(())
}

#[test]
fn wallet_refuses_challenges_for_another_key() -> Result<()> {
    let signer = Signer::new();
    let key = IdentityKey::new(random_scalar().to_bytes().into(), random32(), signer.server)?;
    let mut challenge = challenge_for(&key, 1_760_000_000);
    challenge.public_key[0] ^= 1;
    assert!(key.check_challenge(&challenge).is_err());
    Ok(())
}

#[test]
fn statement_round_trip_and_commitment_binding() -> Result<()> {
    let signer = Signer::new();
    let key = IdentityKey::new(random_scalar().to_bytes().into(), random32(), signer.server)?;
    let header = key.header(random32(), 1_760_000_000);
    let blinding = AuthBlinding::random();
    let message = random32();
    let commitment = blinding.commitment(&header, &message)?;
    let mut other = header.clone();
    other.timestamp += 1;
    assert_ne!(blinding.commitment(&other, &message)?, commitment);
    assert_ne!(blinding.commitment(&header, &random32())?, commitment);
    let statement = AuthStatement {
        header,
        commitment,
        nonce: signer.nonce().1,
        challenge: random_scalar().to_bytes().into(),
    };
    let bytes = statement.encode()?;
    assert_eq!(bytes.len(), ENCODED_LEN);
    assert_eq!(AuthStatement::decode(&bytes)?, statement);
    let mut changed = bytes.clone();
    changed[0] = 2;
    assert!(AuthStatement::decode(&changed).is_err());
    let mut changed = bytes;
    changed[236..].fill(255);
    assert!(AuthStatement::decode(&changed).is_err());
    Ok(())
}

#[test]
fn freshness_bounds() {
    let now = 1_760_000_000;
    assert!(check_fresh(now, now).is_ok());
    assert!(check_fresh(now - MAX_AGE_SECONDS, now).is_ok());
    assert!(check_fresh(now - MAX_AGE_SECONDS - 1, now).is_err());
    assert!(check_fresh(now + MAX_FUTURE_SECONDS, now).is_ok());
    assert!(check_fresh(now + MAX_FUTURE_SECONDS + 1, now).is_err());
}

/// Writes one synthetic prover input for the pinned circuit, for explicit
/// proof benchmarks. Set ZARK_SPARK_AUTH_FIXTURE to a directory under work/.
#[test]
#[ignore]
fn write_synthetic_prover_input() -> Result<()> {
    let directory = std::path::PathBuf::from(std::env::var("ZARK_SPARK_AUTH_FIXTURE")?);
    let signer = Signer::new();
    let key = IdentityKey::new(random_scalar().to_bytes().into(), random32(), signer.server)?;
    let challenge = challenge_for(&key, 1_760_000_000);
    let message = challenge.message()?;
    let header = key.header(random32(), challenge.timestamp);
    let blinding = AuthBlinding::random();
    let commitment = blinding.commitment(&header, &message)?;
    let (k, nonce) = signer.nonce();
    let bound = blinding.bind(&key, &nonce, &message)?;
    let statement = AuthStatement {
        header,
        commitment,
        nonce,
        challenge: bound.challenge,
    };
    let input = AuthWitness {
        key: &key,
        challenge: &challenge,
        blinding: &blinding,
    }
    .prover_toml(&statement)?;
    std::fs::write(directory.join("Prover.toml"), input.as_bytes())?;
    std::fs::write(directory.join("statement.bin"), statement.encode()?)?;
    let signature = blinding.finish(
        &key,
        &bound,
        &nonce,
        &signer.respond(k, &bound.challenge),
        &message,
    )?;
    std::fs::write(directory.join("signature.hex"), hex::encode(signature))?;
    Ok(())
}
