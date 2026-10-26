//! Record lifecycle and blinding arithmetic only. Proof verification is the
//! pinned verifier's job and is not replaced by a test oracle here.
use super::super::{
    Policy,
    native::tests::{issued, observe, unissued},
};
use super::*;
use k256::{
    ProjectivePoint, PublicKey, Scalar,
    schnorr::{Signature, SigningKey, VerifyingKey},
};
use zark_protocol::{
    random_scalar,
    spark_auth::{AuthBlinding, IdentityKey},
    spark_mpc_exit::{SECRET_CIPHER_LEN, TransferAuthWitness},
    spark_native::PlanOpening,
};

fn compressed(point: ProjectivePoint) -> [u8; 33] {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    point
        .to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap()
}

fn cluster() -> Cluster {
    Cluster {
        threshold: 2,
        operators: (1..=3u64)
            .map(|i| {
                (
                    hex::encode(Scalar::from(i).to_bytes()),
                    compressed(ProjectivePoint::GENERATOR * Scalar::from(100 + i)).to_vec(),
                )
            })
            .collect(),
    }
}

struct Fixture {
    coin: Coin,
    policy: Policy,
    key: IdentityKey,
    plan: PlanOpening,
    cipher: Vec<u8>,
    session: SigningKey,
}

fn fixture() -> Result<Fixture> {
    let (user, salt): (Digest, Digest) = (random_scalar().to_bytes().into(), random32());
    let cipher = vec![7; SECRET_CIPHER_LEN];
    let mut opened = None;
    let (mut coin, policy, workflow) = issued(&cluster(), |coin| {
        let key = IdentityKey::new(user, salt, coin.server()?)?;
        let joint = point_bytes(PublicKey::from_sec1_bytes(&key.compressed()?)?.to_projective())?;
        let plan = PlanOpening {
            salt: random32(),
            transfer_id: [3; 16],
            leaf_id: [4; 16],
            expiry: 1_900_000_000,
            cluster: cluster().digest()?,
            anchor_txid: [5; 32],
            anchor_vout: 0,
            amount: 64_000,
            native_delay: 2000,
            operator: point_bytes(ProjectivePoint::GENERATOR * Scalar::from(17u64))?,
            mask_user: point_bytes(ProjectivePoint::GENERATOR * Scalar::from(19u64))?,
            receiver_identity: compressed(ProjectivePoint::GENERATOR * Scalar::from(23u64)),
            mask_cipher_sha256: hash(&[&cipher]),
        };
        let commitment = plan.commitment(joint)?;
        opened = Some((key, plan));
        Ok(commitment)
    })?;
    coin.native = Some(workflow);
    let (key, plan) = opened.unwrap();
    let session = SigningKey::from_bytes(&random_scalar().to_bytes())?;
    Ok(Fixture {
        coin,
        policy,
        key,
        plan,
        cipher,
        session,
    })
}

impl Fixture {
    fn workflow(&self) -> &Workflow {
        self.coin.native.as_ref().unwrap()
    }
    fn request(&self, command: Command) -> Result<Request> {
        Request::sign(self.workflow().intent.clone(), command, &self.session)
    }
    fn plan(&self, command: Command) -> Result<Option<ProofSpec>> {
        plan(
            &self.coin,
            self.workflow(),
            &self.request(command)?,
            Some(&cluster()),
            true,
        )
    }
    fn step(&mut self, command: Command) -> Result<(Option<ProofSpec>, Value)> {
        let request = self.request(command)?;
        let spec = plan(
            &self.coin,
            self.workflow(),
            &request,
            Some(&cluster()),
            true,
        )?;
        let response = apply(&mut self.coin, &request, &cluster())?;
        self.validate()?;
        Ok((spec, response))
    }
    fn validate(&self) -> Result<()> {
        self.workflow().validate(&self.coin, &self.policy)
    }
    fn contribute(&mut self) -> Result<()> {
        self.step(Command::NativeMpcContribution {
            transfer_id: self.plan.transfer_id,
            leaf_id: self.plan.leaf_id,
        })?;
        Ok(())
    }
    fn header(&self) -> Result<TransferAuthHeader> {
        let mpc = self.workflow().mpc.as_ref().unwrap();
        Ok(TransferAuthHeader {
            scope: spark_auth::scope_digest(&self.workflow().intent)?,
            key_commitment: self.key.commitment(),
            server: self.coin.server()?,
            plan: self.workflow().plan(),
            transfer_id: mpc.contribution.transfer_id,
            leaf_id: mpc.contribution.leaf_id,
            signer_proofs: mpc.contribution.proof_points()?,
        })
    }
    fn witness<'a>(&'a self, blinding: &'a AuthBlinding) -> TransferAuthWitness<'a> {
        TransferAuthWitness {
            key: &self.key,
            plan: &self.plan,
            secret_cipher: &self.cipher,
            leaf_signature: &[0x30; 71],
            wallet_proofs: [
                compressed(ProjectivePoint::GENERATOR * Scalar::from(29u64)),
                compressed(ProjectivePoint::GENERATOR * Scalar::from(31u64)),
            ],
            blinding,
        }
    }
    /// Wallet commitment and the signer's frozen nonce.
    fn prepare(&mut self, blinding: &AuthBlinding) -> Result<(Digest, [u8; 64])> {
        let header = self.header()?;
        let commitment = self.witness(blinding).commitment(&header)?;
        let (_, response) = self.step(Command::NativeTransferAuthPrepare {
            key_commitment: self.key.commitment(),
            commitment,
        })?;
        let nonce: Vec<u8> = serde_json::from_value(response["nonce"].clone())?;
        Ok((commitment, nonce.as_slice().try_into()?))
    }
}

#[test]
fn blind_transfer_authorization_round_trip_and_completion_packet() -> Result<()> {
    let mut f = fixture()?;
    f.contribute()?;
    f.workflow()
        .validate_revision(f.workflow().intent.revision + 3)?;
    let blinding = AuthBlinding::random();
    let (commitment, nonce) = f.prepare(&blinding)?;
    let header = f.header()?;
    let message = f.witness(&blinding).payload(&header)?.hash()?;
    let bound = blinding.bind(&f.key, &nonce, &message)?;
    let issue = Command::NativeTransferAuthIssue {
        challenge: bound.challenge,
        proof: Vec::new(),
    };
    let restored = f.coin.clone();
    let (spec, response) = f.step(issue.clone())?;
    let expected = TransferAuthStatement {
        header,
        commitment,
        nonce,
        challenge: bound.challenge,
    };
    let spec = spec.unwrap();
    assert!(spec.role == ProofRole::TransferAuth && spec.statement == expected.encode()?);
    let partial: Digest = serde_json::from_value(response["partial"].clone())?;
    let signature = blinding.finish(&f.key, &bound, &nonce, &partial, &message)?;
    VerifyingKey::from_bytes(&f.key.compressed()?[1..])?
        .verify_raw(&message, &Signature::try_from(signature.as_slice())?)?;
    // Prepare and issue are auxiliary: the ownership CAS revision is unchanged.
    f.workflow()
        .validate_revision(f.workflow().intent.revision + 3)?;
    // The nonce is gone: only the retained response serves a retry.
    assert!(f.plan(issue.clone()).is_err());
    // A checkpoint-restored live ticket can only re-release the same partial.
    let issued_coin = std::mem::replace(&mut f.coin, restored);
    let (_, again) = f.step(issue)?;
    assert_eq!(again["partial"], response["partial"]);
    f.coin = issued_coin;
    // Completion must name exactly this authorization.
    let packet = f
        .workflow()
        .mpc
        .as_ref()
        .unwrap()
        .issued_statement(f.workflow(), &f.coin)?
        .unwrap()
        .digest()?;
    assert_eq!(packet, expected.digest()?);
    let mut other = f.coin.clone();
    observe(other.native.as_mut().unwrap(), [90; 32]);
    assert!(
        other
            .native
            .as_ref()
            .unwrap()
            .validate(&other, &f.policy)
            .is_err()
    );
    observe(f.coin.native.as_mut().unwrap(), packet);
    f.validate()?;
    Ok(())
}

/// Nothing can be collected before `NativeExitIssue` permanently locks the
/// current owner's ownership, so a later handover cannot carry it.
#[test]
fn nothing_is_released_before_issue_or_after_completion() -> Result<()> {
    let mut f = fixture()?;
    let contribution = Command::NativeMpcContribution {
        transfer_id: f.plan.transfer_id,
        leaf_id: f.plan.leaf_id,
    };
    let prepare = Command::NativeTransferAuthPrepare {
        key_commitment: f.key.commitment(),
        commitment: [9; 32],
    };
    let mut early = f.coin.clone();
    unissued(early.native.as_mut().unwrap());
    for command in [contribution.clone(), prepare.clone()] {
        assert!(
            plan(
                &early,
                early.native.as_ref().unwrap(),
                &f.request(command)?,
                Some(&cluster()),
                true
            )
            .is_err()
        );
    }
    let mut finished = f.coin.clone();
    observe(finished.native.as_mut().unwrap(), [90; 32]);
    assert!(
        plan(
            &finished,
            finished.native.as_ref().unwrap(),
            &f.request(contribution.clone())?,
            Some(&cluster()),
            true
        )
        .is_err()
    );
    // A contributed record cannot be rewound to an unissued pair.
    f.contribute()?;
    let mut rewound = f.coin.clone();
    unissued(rewound.native.as_mut().unwrap());
    assert!(
        rewound
            .native
            .as_ref()
            .unwrap()
            .validate(&rewound, &f.policy)
            .is_err()
    );
    Ok(())
}

#[test]
fn lifecycle_rejects_reordered_repeated_and_disabled_steps() -> Result<()> {
    let mut f = fixture()?;
    let blinding = AuthBlinding::random();
    let contribution = Command::NativeMpcContribution {
        transfer_id: f.plan.transfer_id,
        leaf_id: f.plan.leaf_id,
    };
    let prepare = Command::NativeTransferAuthPrepare {
        key_commitment: f.key.commitment(),
        commitment: [9; 32],
    };
    let issue = Command::NativeTransferAuthIssue {
        challenge: [1; 32],
        proof: Vec::new(),
    };
    assert!(
        f.plan(prepare.clone()).is_err(),
        "prepare before contribution"
    );
    assert!(f.plan(issue.clone()).is_err(), "issue before contribution");
    assert!(
        f.plan(Command::NativeMpcContribution {
            transfer_id: [0; 16],
            leaf_id: [4; 16]
        })
        .is_err()
    );
    let other = Cluster {
        threshold: 2,
        operators: cluster().operators.into_iter().take(2).collect(),
    };
    assert!(
        plan(
            &f.coin,
            f.workflow(),
            &f.request(contribution.clone())?,
            Some(&other),
            true
        )
        .is_err()
    );
    assert!(
        plan(
            &f.coin,
            f.workflow(),
            &f.request(contribution.clone())?,
            None,
            true
        )
        .is_err()
    );
    f.contribute()?;
    assert!(f.plan(contribution).is_err(), "second contribution");
    assert!(f.plan(issue.clone()).is_err(), "issue before prepare");
    assert!(
        plan(
            &f.coin,
            f.workflow(),
            &f.request(prepare.clone())?,
            Some(&cluster()),
            false
        )
        .is_err()
    );
    assert!(
        f.plan(Command::NativeTransferAuthPrepare {
            key_commitment: [0; 32],
            commitment: [9; 32]
        })
        .is_err()
    );
    let (_, nonce) = f.prepare(&blinding)?;
    assert!(f.plan(prepare).is_err(), "second ticket");
    assert!(
        plan(
            &f.coin,
            f.workflow(),
            &f.request(issue)?,
            Some(&cluster()),
            false
        )
        .is_err()
    );
    // A malformed challenge fails before the live nonce is consumed.
    let malformed = f.request(Command::NativeTransferAuthIssue {
        challenge: [255; 32],
        proof: Vec::new(),
    })?;
    assert!(apply(&mut f.coin, &malformed, &cluster()).is_err());
    f.validate()?;
    let message = f.witness(&blinding).payload(&f.header()?)?.hash()?;
    let bound = blinding.bind(&f.key, &nonce, &message)?;
    f.step(Command::NativeTransferAuthIssue {
        challenge: bound.challenge,
        proof: Vec::new(),
    })?;
    Ok(())
}

#[test]
fn validation_rejects_tampered_contribution_and_ticket() -> Result<()> {
    let mut f = fixture()?;
    f.contribute()?;
    let blinding = AuthBlinding::random();
    let (_, nonce) = f.prepare(&blinding)?;
    let live = f.coin.clone();
    let message = f.witness(&blinding).payload(&f.header()?)?.hash()?;
    let bound = blinding.bind(&f.key, &nonce, &message)?;
    f.step(Command::NativeTransferAuthIssue {
        challenge: bound.challenge,
        proof: Vec::new(),
    })?;
    let tamper = |base: &Coin, change: &dyn Fn(&mut MpcExit)| -> bool {
        let mut coin = base.clone();
        change(coin.native.as_mut().unwrap().mpc.as_mut().unwrap());
        coin.native
            .as_ref()
            .unwrap()
            .validate(&coin, &f.policy)
            .is_err()
    };
    assert!(tamper(&f.coin, &|m| m.ticket.as_mut().unwrap().partial =
        Some(Scalar::ONE.to_bytes().into())));
    assert!(tamper(&f.coin, &|m| m.ticket.as_mut().unwrap().challenge =
        Some([2; 32])));
    assert!(tamper(&f.coin, &|m| m.ticket.as_mut().unwrap().secret =
        Some(Scalar::ONE.to_bytes().into())));
    assert!(tamper(&live, &|m| m.ticket.as_mut().unwrap().nonce[0] ^= 1));
    assert!(tamper(&live, &|m| m.ticket.as_mut().unwrap().commitment = [0; 32]));
    assert!(tamper(&f.coin, &|m| m.contribution.proofs[0][1] ^= 1));
    assert!(tamper(&f.coin, &|m| *m
        .contribution
        .sealed_shares
        .values_mut()
        .next()
        .unwrap()
        .first_mut()
        .unwrap() ^= 1));
    assert!(tamper(&f.coin, &|m| m.contribution.transfer_id = [0; 16]));
    Ok(())
}
