//! Additive receive through the real Engine and wallet journal, without Spark.
//! Inert pinned proof assets are never executed: prepare and tweak verify no
//! proofs. Synthetic operators decrypt only their own packages. Fixtures stay
//! under ignored `work/additive-receive-tests`.
use super::*;
use aes_gcm::{
    AesGcm, KeyInit,
    aead::{AeadInPlace, consts::U16},
    aes::Aes256,
};
use hkdf::Hkdf;
use k256::{ProjectivePoint, Scalar, elliptic_curve::sec1::ToEncodedPoint};
use serde_json::json;
use sha2::Sha256;
use std::{fs, os::unix::fs::DirBuilderExt, sync::Arc, time::Instant};
use zark_protocol::{
    handoff::TransferContext,
    owner_auth::generate_secret,
    proof::ArtifactPin,
    random_scalar, random32, spark_ecies,
    spark_lineage::{PinnedSparkVerifier, SparkRole, origin_field, origin_previous_state},
    spark_receive::ClaimOperator,
};
use zark_signer::engine::{
    Admission,
    spark::{Engine, NativeProtocols, ReceiveProtocol},
};

struct Allow(Digest);
impl Admission for Allow {
    fn authorize(&self, context: &TransferContext) -> Result<()> {
        ensure!(context.deployment == self.0, "test deployment");
        Ok(())
    }
}

fn compressed(p: ProjectivePoint) -> Vec<u8> {
    p.to_affine().to_encoded_point(true).as_bytes().to_vec()
}
fn operator_secret(index: u16) -> Scalar {
    Scalar::from(u64::from(index) + 80)
}

struct Fixture {
    root: PathBuf,
    deployment: Digest,
    origin: Digest,
    cluster: ClaimCluster,
}
impl Fixture {
    fn new() -> Result<Self> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../work/additive-receive-tests")
            .join(hex::encode(random32()));
        fs::create_dir_all(root.parent().context("fixture parent")?)?;
        for dir in ["", "wallet"] {
            fs::DirBuilder::new().mode(0o700).create(root.join(dir))?;
        }
        fs::write(root.join("unused-verifier"), b"never executed")?;
        fs::write(
            root.join("unused-vk"),
            vec![1u8; zark_protocol::assets::VK_BYTES],
        )?;
        let cluster = ClaimCluster {
            threshold: 2,
            operators: (1..=3u16)
                .map(|i| {
                    let operator = ClaimOperator {
                        index: i,
                        encryption_key: compressed(ProjectivePoint::GENERATOR * operator_secret(i)),
                    };
                    (
                        hex::encode(Scalar::from(u64::from(i) + 10).to_bytes()),
                        operator,
                    )
                })
                .collect(),
        };
        Ok(Self {
            root,
            deployment: random32(),
            origin: generate_secret(),
            cluster,
        })
    }
    fn pin(&self, name: &str) -> Result<ArtifactPin> {
        let path = self.root.join(name);
        Ok(ArtifactPin {
            sha256: hash(&[&fs::read(&path)?]),
            path,
        })
    }
    fn config(&self) -> Result<Config> {
        let origin = k256::schnorr::SigningKey::from_bytes(&self.origin)?;
        Ok(Config {
            origin_key: origin.verifying_key().to_bytes().into(),
            role_hashes: std::array::from_fn(|i| [i as u8 + 1; 32]),
        })
    }
    fn verifier(&self) -> Result<PinnedReceiveVerifier> {
        PinnedReceiveVerifier::new(
            self.deployment,
            self.config()?,
            [9; 32],
            self.cluster.digest()?,
            self.pin("unused-verifier")?,
            self.root.clone(),
            self.pin("unused-vk")?,
        )
    }
    fn engine(&self, additive: bool) -> Result<Engine> {
        let directory = if additive { "signer" } else { "signer-garbled" };
        self.open(
            directory,
            NativeProtocols {
                receive: Some(ReceiveProtocol {
                    verifier: self.verifier()?,
                    cluster: self.cluster.clone(),
                }),
                additive_receive: additive,
                ..Default::default()
            },
        )
    }
    fn open(&self, directory: &str, protocols: NativeProtocols) -> Result<Engine> {
        let ownership = PinnedSparkVerifier::new(
            self.deployment,
            self.config()?,
            [9; 32],
            self.pin("unused-verifier")?,
            self.root.clone(),
            [
                SparkRole::Deposit,
                SparkRole::SenderFromOrigin,
                SparkRole::SenderFromTransfer,
                SparkRole::Receiver,
            ]
            .into_iter()
            .map(|role| Ok((role, self.pin("unused-vk")?)))
            .collect::<Result<Vec<_>>>()?,
        )?;
        let checkpoint = format!("checkpoint-{directory}");
        for dir in [directory, &checkpoint] {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(self.root.join(dir))?;
        }
        Engine::open_with_protocols(
            &self.root.join(directory).join("state.sqlite"),
            &self.root.join(checkpoint).join("floor.json"),
            ownership,
            Arc::new(Allow(self.deployment)),
            k256::schnorr::SigningKey::from_bytes(&self.origin)?,
            protocols,
        )
    }
}

struct Receive {
    journal: ReceiveJournal,
    directory: PathBuf,
    incoming: Scalar,
    joint: ProjectivePoint,
    session: Digest,
    intent: Intent,
}
fn receive(f: &Fixture, engine: &Engine, name: &str, additive: bool) -> Result<Receive> {
    let coin = random32();
    let session = generate_secret();
    let intent = Intent {
        deployment: f.deployment,
        coin,
        previous_state: origin_previous_state(&f.deployment, &coin)?,
        operation: random32(),
        recipient_claim: origin_field(&f.deployment, &coin, 0)?,
        revision: 1,
    };
    let key = normalized_key(&session)?;
    let allocated = engine.handle(&Request::sign(intent.clone(), Command::Allocate {}, &key)?)?;
    let server: [u8; 64] = serde_json::from_value::<Vec<u8>>(allocated["server"].clone())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("server point length"))?;
    let user = random_scalar();
    let joint = point(&server)? + ProjectivePoint::GENERATOR * user;
    let incoming = random_scalar();
    let params = ReceiveParameters {
        intent: intent.clone(),
        session,
        user: user.to_bytes().into(),
        owner: generate_secret(),
        server,
        server_salt: random32(),
        backing_salt: random32(),
        plan: receive_plan(f)?,
        claim: claim_plan(f, &intent, incoming, joint),
    };
    let directory = f.root.join("wallet").join(name);
    let create = if additive {
        ReceiveJournal::create_additive
    } else {
        ReceiveJournal::create
    };
    let journal = create(
        &directory,
        &params,
        Zeroizing::new(incoming.to_bytes().into()),
        &f.verifier()?,
        f.cluster.clone(),
    )?;
    Ok(Receive {
        journal,
        directory,
        incoming,
        joint,
        session,
        intent,
    })
}

fn claim_plan(f: &Fixture, intent: &Intent, incoming: Scalar, joint: ProjectivePoint) -> ClaimPlan {
    ClaimPlan {
        deployment: f.deployment,
        operation: intent.operation,
        transfer_id: "00000000-0000-4000-8000-000000000001".into(),
        leaf_id: "00000000-0000-4000-8000-000000000002".into(),
        incoming_user_key: compressed(ProjectivePoint::GENERATOR * incoming),
        joint_user_key: compressed(joint),
        threshold: 2,
        operators: f
            .cluster
            .operators
            .iter()
            .map(|(id, op)| {
                (
                    id.clone(),
                    crate::standard_claim::Operator {
                        share_index: op.index,
                        encryption_key: op.encryption_key.clone(),
                    },
                )
            })
            .collect(),
    }
}

fn receive_plan(f: &Fixture) -> Result<ReceivePlan> {
    Ok(ReceivePlan {
        salt: random32(),
        anchor_txid: random32(),
        anchor_vout: 0,
        amount: 64_000,
        native_delay: 1900,
        operator: point_bytes(ProjectivePoint::GENERATOR * Scalar::from(77u64))?.to_vec(),
        cluster: f.cluster.digest()?,
    })
}

/// Lagrange interpolation at zero of the first two operators' shares.
fn reconstruct(r: &Receive, packages: &BTreeMap<String, Vec<u8>>) -> Result<Scalar> {
    let shares = packages
        .iter()
        .map(|(id, package)| {
            Ok((
                r.journal.record.cluster.operators[id].index,
                operator_share(r, id, package)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let ((i, si), (j, sj)) = (shares[0], shares[1]);
    let (xi, xj) = (Scalar::from(u64::from(i)), Scalar::from(u64::from(j)));
    Ok(si * xj * (xj - xi).invert().unwrap() + sj * xi * (xi - xj).invert().unwrap())
}

fn decrypt(secret: Scalar, wire: &[u8]) -> Result<Vec<u8>> {
    let shared = k256::PublicKey::from_sec1_bytes(&wire[..65])?.to_projective() * secret;
    let mut material = wire[..65].to_vec();
    material.extend_from_slice(shared.to_affine().to_encoded_point(false).as_bytes());
    let mut key = [0; 32];
    Hkdf::<Sha256>::new(None, &material)
        .expand(&[], &mut key)
        .map_err(|_| anyhow::anyhow!("hkdf"))?;
    let tag: [u8; 16] = wire[81..97].try_into()?;
    let mut plaintext = wire[97..].to_vec();
    AesGcm::<Aes256, U16>::new_from_slice(&key)?
        .decrypt_in_place_detached(wire[65..81].into(), b"", &mut plaintext, &tag.into())
        .map_err(|_| anyhow::anyhow!("operator ECIES authentication failed"))?;
    Ok(plaintext)
}

/// What one synthetic operator checks before staging: its package decrypts,
/// the protobuf outside the share is the wallet's template, and the share
/// satisfies Feldman against the single wallet-checked polynomial.
fn operator_share(r: &Receive, id: &str, package: &[u8]) -> Result<Scalar> {
    let op = &r.journal.record.cluster.operators[id];
    let proofs = r.journal.record.proofs.as_ref().context("proofs")?;
    let template = proofs.joint_template(&r.journal.record.claim)?;
    let (_, offset) = r.journal.record.cluster.template_shape()?;
    let mut plain = decrypt(operator_secret(op.index), package)?;
    let share = scalar(&plain[offset..offset + 32])?;
    plain[offset..offset + 32].fill(0);
    ensure!(
        plain == *template,
        "operator plaintext differs from wallet template"
    );
    let c: Vec<ProjectivePoint> = proofs
        .coefficients
        .iter()
        .map(|c| Ok(k256::PublicKey::from_sec1_bytes(c)?.to_projective()))
        .collect::<Result<_>>()?;
    ensure!(
        ProjectivePoint::GENERATOR * share == c[0] + c[1] * Scalar::from(u64::from(op.index)),
        "operator Feldman check failed"
    );
    Ok(share)
}

fn prepare(engine: &Engine, r: &mut Receive) -> Result<()> {
    let request = r.journal.prepare_request()?;
    let response = engine.handle(&request)?;
    r.journal.bind_prepare(&response)
}

#[test]
fn additive_tweak_lands_the_leaf_on_the_joint_key() -> Result<()> {
    let f = Fixture::new()?;
    let mut engine = f.engine(true)?;
    let mut r = receive(&f, &engine, "complete", true)?;
    prepare(&engine, &mut r)?;
    let request = r.journal.tweak_request()?;
    drop(r.journal);
    r.journal = ReceiveJournal::open(&r.directory, &f.verifier()?)?;
    let frozen = r.journal.tweak_request()?;
    ensure!(
        frozen.encode()? == request.encode()?,
        "frozen tweak request changed after reopen"
    );

    let started = Instant::now();
    let response = engine.handle(&request)?;
    let signer = started.elapsed();
    // Signer restart after commit: the exact retry replays the same release.
    drop(engine);
    engine = f.engine(true)?;
    ensure!(
        engine.handle(&request)? == response,
        "signer tweak replay changed after restart"
    );
    // Wallet crash between response and bind: rebinding the replay is exact.
    drop(r.journal);
    r.journal = ReceiveJournal::open(&r.directory, &f.verifier()?)?;
    let replayed = engine.handle(&r.journal.tweak_request()?)?;
    let started = Instant::now();
    r.journal.bind_tweak(&replayed)?;
    let wallet = started.elapsed();
    r.journal.bind_tweak(&response)?;
    let packages = r.journal.packages()?;
    drop(r.journal);
    r.journal = ReceiveJournal::open(&r.directory, &f.verifier()?)?;
    ensure!(
        r.journal.packages()? == packages,
        "packages changed after reopen"
    );
    ensure!(
        r.journal.record.mpc.is_none(),
        "wallet tweak inputs retained"
    );
    eprintln!("additive receive tweak: signer {signer:?}, wallet completion {wallet:?}");

    let t = reconstruct(&r, &packages)?;
    ensure!(
        ProjectivePoint::GENERATOR * (r.incoming - t) == r.joint,
        "tweaked leaf is not the joint key"
    );

    let conflicting = Request::sign(
        r.intent.clone(),
        Command::ReceiveTweak {
            tweak: random_scalar().to_bytes().into(),
        },
        &normalized_key(&r.session)?,
    )?;
    let error = engine
        .handle(&conflicting)
        .err()
        .context("conflicting tweak retry accepted")?;
    ensure!(
        error.to_string().contains("retry changed frozen request"),
        "{error}"
    );
    let mut other = r.intent.clone();
    other.operation = random32();
    let second = Request::sign(
        other,
        Command::ReceiveTweak {
            tweak: random_scalar().to_bytes().into(),
        },
        &normalized_key(&r.session)?,
    )?;
    ensure!(
        engine.handle(&second).is_err(),
        "second tweak release accepted"
    );
    fs::remove_dir_all(&f.root)?;
    Ok(())
}

#[test]
#[ignore = "requires ZARK_SPARK_ECIES_GO: a helper built from Spark's pinned github.com/ecies/go/v2"]
fn spark_operator_ecies_decrypts_completed_packages() -> Result<()> {
    let tool =
        PathBuf::from(std::env::var_os("ZARK_SPARK_ECIES_GO").context("set ZARK_SPARK_ECIES_GO")?);
    let spark_decrypt = |index: u16, wire: &[u8]| -> Result<Vec<u8>> {
        let out = std::process::Command::new(&tool)
            .arg(hex::encode(operator_secret(index).to_bytes()))
            .arg(hex::encode(wire))
            .output()?;
        ensure!(
            out.status.success(),
            "Spark ECIES rejected package: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        Ok(hex::decode(String::from_utf8(out.stdout)?.trim())?)
    };
    let f = Fixture::new()?;
    let engine = f.engine(true)?;
    let mut r = receive(&f, &engine, "spark-ecies", true)?;
    prepare(&engine, &mut r)?;
    let response = engine.handle(&r.journal.tweak_request()?)?;
    r.journal.bind_tweak(&response)?;
    let (_, offset) = f.cluster.template_shape()?;
    for (id, package) in r.journal.packages()? {
        let index = f.cluster.operators[&id].index;
        let plain = spark_decrypt(index, &package)?;
        ensure!(
            plain == decrypt(operator_secret(index), &package)?,
            "Spark and Zark plaintexts differ"
        );
        operator_share(&r, &id, &package)?;
        let mut tampered = package.clone();
        tampered[97 + offset] ^= 1;
        ensure!(
            spark_decrypt(index, &tampered).is_err(),
            "Spark accepted a flipped share byte"
        );
    }
    fs::remove_dir_all(&f.root)?;
    Ok(())
}

#[test]
fn wallet_rejects_a_wrong_tweak_and_operators_reject_tampered_shares() -> Result<()> {
    let f = Fixture::new()?;
    let engine = f.engine(true)?;
    // A wallet whose u is wrong (here: a replaced request) gets a polynomial
    // whose constant is not B - P; its own claim check refuses to bind it.
    let mut r = receive(&f, &engine, "wrong", true)?;
    prepare(&engine, &mut r)?;
    r.journal.tweak_request()?;
    let wrong = Request::sign(
        r.intent.clone(),
        Command::ReceiveTweak {
            tweak: random_scalar().to_bytes().into(),
        },
        &normalized_key(&r.session)?,
    )?;
    let response = engine.handle(&wrong)?;
    let error = r
        .journal
        .bind_tweak(&response)
        .err()
        .context("wrong tweak bound")?;
    ensure!(error.to_string().contains("USER key rotation"), "{error}");
    ensure!(
        r.journal.record.mpc.is_some() && r.journal.record.proofs.is_none(),
        "wrong tweak changed journal"
    );

    let mut r = receive(&f, &engine, "tampered", true)?;
    prepare(&engine, &mut r)?;
    let response = engine.handle(&r.journal.tweak_request()?)?;
    let ids: Vec<String> = r.journal.record.cluster.operators.keys().cloned().collect();
    let (_, offset) = f.cluster.template_shape()?;

    // A changed public coefficient fails the wallet's constant check or every
    // operator's Feldman check; a flipped share byte fails authentication.
    let mut changed = response.clone();
    changed["coefficients"][0] = json!(hex::encode(compressed(ProjectivePoint::GENERATOR)));
    ensure!(
        r.journal.bind_tweak(&changed).is_err(),
        "changed constant bound"
    );
    let mut flipped = response.clone();
    let mut sealed = hex::decode(flipped["operators"][&ids[0]]["sealed"].as_str().unwrap())?;
    sealed[97 + offset] ^= 1;
    flipped["operators"][&ids[0]]["sealed"] = json!(hex::encode(sealed));
    // A malicious signer sealing a wrong share under valid encryption.
    let op = &f.cluster.operators[&ids[1]];
    let (bad, key) = spark_ecies::seal_slot(
        &op.encryption_key,
        f.cluster.template_shape()?.0,
        offset,
        &random_scalar().to_bytes().into(),
    )?;
    flipped["operators"][&ids[1]] = json!({"sealed":hex::encode(bad),"hash_key":hex::encode(key)});
    r.journal.bind_tweak(&flipped)?;
    let packages = r.journal.packages()?;
    ensure!(
        operator_share(&r, &ids[0], &packages[&ids[0]]).is_err(),
        "flipped share authenticated"
    );
    let error = operator_share(&r, &ids[1], &packages[&ids[1]])
        .err()
        .context("wrong share accepted")?;
    ensure!(error.to_string().contains("Feldman"), "{error}");
    operator_share(&r, &ids[2], &packages[&ids[2]])?;
    ensure!(
        r.journal.bind_tweak(&response).is_err(),
        "second response bound after the first"
    );
    fs::remove_dir_all(&f.root)?;
    Ok(())
}

#[test]
fn garbled_workflows_keep_their_format_and_refuse_the_additive_path() -> Result<()> {
    let f = Fixture::new()?;
    let garbled = f.engine(false)?;
    let mut r = receive(&f, &garbled, "garbled", false)?;
    prepare(&garbled, &mut r)?;
    let bytes = fs::read(r.directory.join(FILE))?;
    ensure!(
        !String::from_utf8_lossy(&bytes).contains("additive"),
        "garbled journal format changed"
    );
    drop(r.journal);
    r.journal = ReceiveJournal::open(&r.directory, &f.verifier()?)?;
    ensure!(r.journal.tweak_request().is_err(), "garbled journal sent u");
    let tweak = Request::sign(
        r.intent.clone(),
        Command::ReceiveTweak {
            tweak: random_scalar().to_bytes().into(),
        },
        &normalized_key(&r.session)?,
    )?;
    let error = garbled
        .handle(&tweak)
        .err()
        .context("garbled signer released an additive tweak")?;
    ensure!(error.to_string().contains("not additive"), "{error}");

    // An additive journal never sends u to a garbled-circuit signer.
    let mut additive = receive(&f, &garbled, "mismatch", true)?;
    let response = garbled.handle(&additive.journal.prepare_request()?)?;
    let error = additive
        .journal
        .bind_prepare(&response)
        .err()
        .context("additive journal bound a garbled signer")?;
    ensure!(error.to_string().contains("tweak mode"), "{error}");
    ensure!(
        additive.journal.tweak_request().is_err(),
        "additive journal sent u without preparation"
    );
    fs::remove_dir_all(&f.root)?;
    Ok(())
}

/// Raw, hex and JSON-array encodings of a secret as the signer could store it.
#[cfg(feature = "ecdsa-2p")]
fn encodings(bytes: &[u8]) -> Vec<Vec<u8>> {
    let decimal = bytes
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",");
    vec![
        bytes.to_vec(),
        hex::encode(bytes).into_bytes(),
        decimal.into_bytes(),
    ]
}

/// Blind cb-mpc entry plus the additive tweak on one coin. Everything the
/// signer receives, returns or stores must omit P, B and the entry digest.
#[cfg(feature = "ecdsa-2p")]
#[test]
fn blind_entry_and_additive_tweak_hide_the_joint_key_incoming_key_and_digest() -> Result<()> {
    use crate::joint_identity::{
        EntryMessage, IdentityParameters, JointIdentityJournal, claim_payload, encode_challenge,
    };
    use k256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
    let f = Fixture::new()?;
    let engine = f.open(
        "signer-blind",
        NativeProtocols {
            receive: Some(ReceiveProtocol {
                verifier: f.verifier()?,
                cluster: f.cluster.clone(),
            }),
            additive_receive: true,
            identity: true,
            ecdsa_2p: true,
            ..Default::default()
        },
    )?;
    let mut view: Vec<Vec<u8>> = Vec::new();
    let mut send = |r: &Request| -> Result<serde_json::Value> {
        let response = engine.handle(r)?;
        view.push(r.encode()?);
        view.push(serde_json::to_vec(&response)?);
        Ok(response)
    };
    let coin = random32();
    let intent = Intent {
        deployment: f.deployment,
        coin,
        previous_state: origin_previous_state(&f.deployment, &coin)?,
        operation: random32(),
        recipient_claim: origin_field(&f.deployment, &coin, 0)?,
        revision: 1,
    };
    let params = IdentityParameters {
        intent: intent.clone(),
        session: generate_secret(),
        user: random_scalar().to_bytes().into(),
        owner: generate_secret(),
    };
    let mut identity = JointIdentityJournal::create_ecdsa(
        &f.root.join("wallet/identity"),
        &f.root.join("identity-frames"),
        &params,
    )?;
    identity.bind_allocation(&send(&identity.allocation_request()?)?)?;
    identity.ecdsa_keygen(&mut send)?;
    let joint = identity.public_key()?;
    let challenge = EntryMessage::challenge(&encode_challenge(&random32(), &joint), &joint)?;
    let signature = identity.ecdsa_sign(&challenge, &mut send)?;
    VerifyingKey::from_sec1_bytes(&joint)?
        .verify_prehash(&challenge.digest(), &Signature::from_der(&signature)?)?;

    let incoming = random_scalar();
    let joint_point = k256::PublicKey::from_sec1_bytes(&joint)?.to_projective();
    let parameters = identity.receive_parameters(
        receive_plan(&f)?,
        claim_plan(&f, &intent, incoming, joint_point),
        random32(),
    )?;
    let directory = f.root.join("wallet/blind");
    let journal = ReceiveJournal::create_additive(
        &directory,
        &parameters,
        Zeroizing::new(incoming.to_bytes().into()),
        &f.verifier()?,
        f.cluster.clone(),
    )?;
    let mut r = Receive {
        journal,
        directory,
        incoming,
        joint: joint_point,
        session: params.session,
        intent,
    };
    let response = send(&r.journal.prepare_request()?)?;
    r.journal.bind_prepare(&response)?;
    let response = send(&r.journal.tweak_request()?)?;
    r.journal.bind_tweak(&response)?;
    let packages = r.journal.packages()?;
    let t = reconstruct(&r, &packages)?;
    ensure!(
        ProjectivePoint::GENERATOR * (incoming - t) == joint_point,
        "tweaked leaf is not the joint key"
    );
    let transfer_id = r.journal.claim_plan().transfer_id.clone();
    let claim = EntryMessage::claim(
        &claim_payload(&hex::decode(transfer_id.replace('-', ""))?, &packages),
        &transfer_id,
        &packages,
    )?;
    let signature = identity.ecdsa_sign(&claim, &mut send)?;
    VerifyingKey::from_sec1_bytes(&joint)?
        .verify_prehash(&claim.digest(), &Signature::from_der(&signature)?)?;
    drop(engine);

    for dir in ["signer-blind", "checkpoint-signer-blind"] {
        for entry in fs::read_dir(f.root.join(dir))? {
            view.push(fs::read(entry?.path())?);
        }
    }
    let found = |needle: &[u8]| {
        view.iter()
            .any(|bytes| bytes.windows(needle.len()).any(|w| w == needle))
    };
    ensure!(
        encodings(&identity.server()?[..32])
            .iter()
            .any(|n| found(n)),
        "scan misses the signer share X_s it does hold"
    );
    let incoming_key = compressed(ProjectivePoint::GENERATOR * incoming);
    for (name, secret) in [
        ("P", &joint[1..]),
        ("B", &incoming_key[1..]),
        ("challenge m", &challenge.digest()[..]),
        ("claim m", &claim.digest()[..]),
    ] {
        for needle in encodings(secret) {
            ensure!(!found(&needle), "signer view contains {name}");
        }
    }
    fs::remove_dir_all(&f.root)?;
    Ok(())
}
