use super::*;
use aes_gcm::{
    AesGcm,
    aead::{AeadInPlace, KeyInit, consts::U16},
};
use anyhow::{Result, ensure};
use hkdf::Hkdf;
use k256::{ProjectivePoint, Scalar, elliptic_curve::sec1::ToEncodedPoint};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;
use tandem::Gate;
use zeroize::Zeroizing;

fn key() -> (Scalar, Vec<u8>) {
    let secret = Scalar::from(91u64);
    (
        secret,
        (ProjectivePoint::GENERATOR * secret)
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
    )
}
fn decrypt(secret: Scalar, cipher: &[u8]) -> Result<Vec<u8>> {
    let ephemeral = k256::PublicKey::from_sec1_bytes(&cipher[..65])?;
    let shared = ephemeral.to_projective() * secret;
    let mut ikm = cipher[..65].to_vec();
    ikm.extend_from_slice(shared.to_affine().to_encoded_point(false).as_bytes());
    let mut key = [0; 32];
    Hkdf::<Sha256>::new(None, &ikm)
        .expand(&[], &mut key)
        .unwrap();
    let nonce: [u8; 16] = cipher[65..81].try_into()?;
    let tag: [u8; 16] = cipher[81..97].try_into()?;
    let mut plain = cipher[97..].to_vec();
    type NativeCipher = AesGcm<aes::Aes256, U16>;
    NativeCipher::new_from_slice(&key)
        .unwrap()
        .decrypt_in_place_detached(&nonce.into(), b"", &mut plain, &tag.into())
        .map_err(|_| anyhow::anyhow!("native GCM authentication"))?;
    Ok(plain)
}
fn evaluate(circuit: &ClaimCircuit, contributor: &[bool], evaluator: &[bool]) -> Vec<bool> {
    let mut c = contributor.iter();
    let mut e = evaluator.iter();
    let mut wires: Vec<bool> = Vec::new();
    for gate in circuit.circuit.gates() {
        let value = match *gate {
            Gate::InContrib => *c.next().unwrap(),
            Gate::InEval => *e.next().unwrap(),
            Gate::Xor(a, b) => wires[a as usize] ^ wires[b as usize],
            Gate::And(a, b) => wires[a as usize] & wires[b as usize],
            Gate::Not(a) => !wires[a as usize],
        };
        wires.push(value);
    }
    circuit
        .circuit
        .output_gates()
        .iter()
        .map(|&i| wires[i as usize])
        .collect()
}
fn sample(length: usize) -> (ClaimCircuit, EncryptionMask, Vec<u8>) {
    let (_, public) = key();
    let circuit = ClaimCircuit::new(CircuitSpec {
        plaintext_bytes: length,
        scalar_offset: 11,
    })
    .unwrap();
    let mask =
        EncryptionMask::prepare(&public, length, &mut ChaCha20Rng::from_seed([8; 32])).unwrap();
    let template = (0..length).map(|i| (i % 251) as u8).collect();
    (circuit, mask, template)
}

#[test]
fn encrypted_circuit_matches_independent_ecies_gcm_and_scalar_modulus() -> Result<()> {
    let (secret, _) = key();
    for length in [43, 64, 161, 673] {
        let (circuit, mask, template) = sample(length);
        for (a, b) in [
            (Scalar::from(7u64), Scalar::from(11u64)),
            (-Scalar::from(2u64), Scalar::from(3u64)),
        ] {
            let input = mask.input(&b.to_bytes().into());
            let mut eval = circuit::bits(&a.to_bytes());
            eval.extend(circuit::bits(&template));
            let out = evaluate(&circuit, &input, &eval);
            ensure!(out[0], "valid scalar rejected");
            let mut wire = mask.header().to_vec();
            wire.extend(circuit::bytes(&out[1..])?);
            let actual = decrypt(secret, &wire)?;
            let mut expected = template.clone();
            expected[11..43].copy_from_slice(&(a + b).to_bytes());
            assert_eq!(actual, expected);
            let mut changed = wire.clone();
            changed[81] ^= 1;
            assert!(decrypt(secret, &changed).is_err());
        }
    }
    Ok(())
}

#[test]
fn rejects_noncanonical_or_zero_sum_without_releasing_plaintext() {
    let (circuit, mask, template) = sample(64);
    for (a, b) in [
        ([255; 32], Scalar::ONE.to_bytes().into()),
        (
            Scalar::ONE.to_bytes().into(),
            (-Scalar::ONE).to_bytes().into(),
        ),
    ] {
        let c = mask.input(&b);
        let mut e = circuit::bits(&a);
        e.extend(circuit::bits(&template));
        assert!(!evaluate(&circuit, &c, &e)[0]);
    }
}

#[test]
fn actual_two_party_protocol_emits_only_native_ciphertext() -> Result<()> {
    let (circuit, mask, template) = sample(64);
    eprintln!("Joint claim circuit: {} AND gates", circuit.and_gates());
    let a = Scalar::from(7u64);
    let b = Scalar::from(11u64);
    let (mut server, mut message) = ClaimContributor::start(
        &circuit,
        Zeroizing::new(b.to_bytes().into()),
        &mask,
        Zeroizing::new([14; 32]),
    )?;
    let mut wallet = ClaimEvaluator::start(
        &circuit,
        Zeroizing::new(a.to_bytes().into()),
        Zeroizing::new(template.clone()),
        mask.header(),
        Zeroizing::new([15; 32]),
    )?;
    assert_eq!(wallet.steps(), server.steps());
    for _ in 0..wallet.steps() {
        let reply = wallet.advance(&message)?;
        message = server.advance(&reply)?;
    }
    let wire = wallet.finish(&message)?;
    let mut expected = template;
    expected[11..43].copy_from_slice(&(a + b).to_bytes());
    assert_eq!(decrypt(key().0, &wire)?, expected);
    // Contributor API never exposes a scalar, stream or plaintext result.
    assert!(server.advance(&[]).is_err());
    Ok(())
}
