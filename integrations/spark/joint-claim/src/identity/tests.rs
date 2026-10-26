//! Independent known-scalar fixtures. No production share reconstruction.
use super::*;
use crate::circuit::bytes;
use anyhow::Result;
use tandem::Gate;
fn evaluate(circuit: &Circuit, c: &[bool], e: &[bool]) -> Vec<bool> {
    let mut c = c.iter();
    let mut e = e.iter();
    let mut wires: Vec<bool> = Vec::with_capacity(circuit.gates().len());
    for gate in circuit.gates() {
        let v = match *gate {
            Gate::InContrib => *c.next().unwrap(),
            Gate::InEval => *e.next().unwrap(),
            Gate::Xor(a, b) => wires[a as usize] ^ wires[b as usize],
            Gate::And(a, b) => wires[a as usize] & wires[b as usize],
            Gate::Not(a) => !wires[a as usize],
        };
        wires.push(v);
    }
    circuit
        .output_gates()
        .iter()
        .map(|&i| wires[i as usize])
        .collect()
}
#[test]
fn montgomery_circuit_matches_independent_scalar_field_at_boundaries() -> Result<()> {
    let (mut builder, a, b) = Builder::inputs(256, 256);
    let out = arithmetic::multiply(&mut builder, &a, &b);
    let circuit = builder.finish(out);
    let values = [
        Scalar::ZERO,
        Scalar::ONE,
        Scalar::from(1234567u64),
        -Scalar::ONE,
        -Scalar::from(2u64),
    ];
    let r = factor();
    let ri = Option::<Scalar>::from(r.invert()).unwrap();
    for a in values {
        for b in values {
            let out = evaluate(
                &circuit,
                &bits(&(a * r).to_bytes()),
                &bits(&(b * r).to_bytes()),
            );
            let raw: [u8; 32] = bytes(&out)?.try_into().unwrap();
            assert_eq!(scalar(&raw)? * ri, a * b);
        }
    }
    Ok(())
}
fn presign(bytes: &[bool]) -> Result<Zeroizing<[u8; 64]>> {
    ensure!(
        bytes.len() == 513 && bytes[0],
        "presign circuit rejected input"
    );
    let raw = Zeroizing::new(crate::circuit::bytes(&bytes[1..])?);
    let ri = Option::<Scalar>::from(factor().invert()).unwrap();
    let mut out = Zeroizing::new([0; 64]);
    out[..32].copy_from_slice(&(scalar(raw[..32].try_into()?)? * ri).to_bytes());
    out[32..].copy_from_slice(&(scalar(raw[32..].try_into()?)? * ri).to_bytes());
    Ok(out)
}
#[test]
fn presign_circuit_binds_hidden_key_and_completes_independent_ecdsa() -> Result<()> {
    let circuit = IdentityCircuit::new()?;
    let reopened = IdentityCircuit::new()?;
    assert!(Arc::ptr_eq(&circuit.circuit, &reopened.circuit));
    assert_eq!(circuit.digest(), circuit.circuit.blake3_hash());
    eprintln!("Identity presign: {} AND gates", circuit.and_gates());
    let user: [u8; 32] = Scalar::from(11u64).to_bytes().into();
    let server = Scalar::from(29u64).to_bytes().into();
    let kw: [u8; 32] = Scalar::from(2u64).to_bytes().into();
    let ks: [u8; 32] = Scalar::from(3u64).to_bytes().into();
    let masks = [
        Scalar::from(61u64).to_bytes().into(),
        Scalar::from(67u64).to_bytes().into(),
    ];
    let salt = [87; 32];
    let commitment = key_commitment(&user, &salt)?;
    let c = server_input(&server, &ks, &masks, &commitment)?;
    let e = wallet_input(&user, &kw, &salt)?;
    let output = evaluate(&circuit.circuit, &c, &e);
    let p = presign(&output)?;
    let r = nonce_r(&kw, &nonce_public(&ks)?)?;
    assert_eq!(r, nonce_r(&ks, &nonce_public(&kw)?)?);
    let public = (ProjectivePoint::GENERATOR * (scalar(&user)? + scalar(&server)?))
        .to_affine()
        .to_encoded_point(true);
    for digest in [[0; 32], [41; 32], [255; 32]] {
        let partial = online_partial(&masks, &r, &digest)?;
        assert!(!complete_signature(&p, &r, &digest, &partial, public.as_bytes())?.is_empty());
        let mut changed = digest;
        changed[0] ^= 1;
        assert!(complete_signature(&p, &r, &changed, &partial, public.as_bytes()).is_err());
    }
    let mut altered = e.to_vec();
    altered[0] ^= true;
    assert!(!evaluate(&circuit.circuit, &c, &altered)[0]);
    let mut altered = e.to_vec();
    altered[512] ^= true;
    assert!(!evaluate(&circuit.circuit, &c, &altered)[0]);
    assert!(nonce_public(&[0; 32]).is_err());
    assert!(nonce_r(&kw, &[0; 33]).is_err());
    Ok(())
}
#[test]
fn ecdh_proof_binds_context_and_both_points() -> Result<()> {
    let s: [u8; 32] = Scalar::from(11u64).to_bytes().into();
    let e = Scalar::from(17u64);
    let p = (ProjectivePoint::GENERATOR * e)
        .to_affine()
        .to_encoded_point(false);
    let part = (ProjectivePoint::GENERATOR * e * scalar(&s)?)
        .to_affine()
        .to_encoded_point(true);
    let public = nonce_public(&s)?;
    let proof = ecdh_prove(&s, p.as_bytes(), &[1; 32])?;
    ecdh_verify(&public, p.as_bytes(), part.as_bytes(), &[1; 32], &proof)?;
    assert!(ecdh_verify(&public, p.as_bytes(), part.as_bytes(), &[2; 32], &proof).is_err());
    assert!(ecdh_verify(&public, p.as_bytes(), &public, &[1; 32], &proof).is_err());
    Ok(())
}
#[test]
#[ignore = "explicit resource-intensive two-party ECDSA presign qualification; no native receive"]
fn actual_identity_two_party_signature() -> Result<()> {
    let circuit = IdentityCircuit::new()?;
    let started = std::time::Instant::now();
    let user: [u8; 32] = Scalar::from(11u64).to_bytes().into();
    let server = Scalar::from(29u64).to_bytes().into();
    let kw = Scalar::from(2u64).to_bytes().into();
    let ks = Scalar::from(3u64).to_bytes().into();
    let masks = [
        Scalar::from(61u64).to_bytes().into(),
        Scalar::from(67u64).to_bytes().into(),
    ];
    let salt = [87; 32];
    let r = nonce_r(&kw, &nonce_public(&ks)?)?;
    let commitment = key_commitment(&user, &salt)?;
    let (mut c, mut message) = IdentityContributor::start(
        &circuit,
        Zeroizing::new(server),
        Zeroizing::new(ks),
        Zeroizing::new(masks),
        commitment,
        Zeroizing::new([51; 32]),
    )?;
    let mut e = IdentityEvaluator::start(
        &circuit,
        Zeroizing::new(user),
        Zeroizing::new(kw),
        Zeroizing::new(salt),
        Zeroizing::new([52; 32]),
    )?;
    for step in 0..e.steps() {
        let reply = e.advance(&message)?;
        message = c.advance(&reply)?;
        eprintln!(
            "presign round {step}: {} / {} bytes",
            reply.len(),
            message.len()
        );
    }
    let presign = e.finish(&message)?;
    eprintln!("offline presign: {:?}", started.elapsed());
    let online = std::time::Instant::now();
    let digest = [41; 32];
    let partial = online_partial(&masks, &r, &digest)?;
    let public = (ProjectivePoint::GENERATOR * (scalar(&user)? + scalar(&server)?))
        .to_affine()
        .to_encoded_point(true);
    complete_signature(&presign, &r, &digest, &partial, public.as_bytes())?;
    eprintln!("online signature: {:?}", online.elapsed());
    assert!(c.advance(&[]).is_err());
    Ok(())
}
