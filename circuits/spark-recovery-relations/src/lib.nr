//! Spark dual-refund recovery authorization primitive, version 1.
//! Does not establish native prefix authenticity, chain state or ownership.
use bitcoin_relations::{add,challenge_scalar,join,le32,le64,normalize,part,read_point,read_scalar,tagged};
use bigcurve::{BigCurve,Secp256k1};
use bignum::{BigNum,Secp256k1_Fr};
use std::ops::Neg;

fn nonzero(bytes:[u8;32]) { assert(bitcoin_relations::is_nonzero(bytes), "zero Spark recovery field"); }
fn digest<let N:u32>(bytes:[u8;N]) -> [u8;32] { recovery::application_digest(bytes) }
fn context(statement:[u8;620]) -> [u8;204] {
    join(part::<620,196>(statement,0),part::<620,8>(statement,292))
}

/// The exact recovery relation and receiver openings checked by
/// authorize_checked. Fields are private to keep construction behind that API.
/// Pinned circuit entrypoints must obtain this value by calling
/// authorize_checked, never accept it as a prover input: type encapsulation
/// alone does not constrain an input witness.
pub struct CheckedRecovery {
    statement:[u8;620],
    user:[u8;32],
    recovery_salt:[u8;32],
    payout:[u8;64],
    fee:u64,
    delay:u32,
    owner_index:u32,
    initial:u32,
    gap:u32,
    margin:u32,
}

impl CheckedRecovery {
    /// Reuse is safe only for identical inputs to the omitted target/policy
    /// relation. The complete statement comparison also binds both refund
    /// branches, server encoding, backing, domain, session and CAS revision.
    pub fn assert_matches(self,statement:[u8;620],user:[u8;32],recovery_salt:[u8;32],
        payout:[u8;64],fee:u64,delay:u32,owner_index:u32,initial:u32,gap:u32,margin:u32,
    ) {
        assert(self.statement==statement,"checked Spark recovery statement");
        assert(self.user==user,"checked Spark recovery user");
        assert(self.recovery_salt==recovery_salt,"checked Spark recovery salt");
        assert(self.payout==payout,"checked Spark recovery payout");
        assert(self.fee==fee,"checked Spark recovery fee");
        assert(self.delay==delay,"checked Spark recovery delay");
        assert(self.owner_index==owner_index,"checked Spark recovery owner");
        assert(self.initial==initial,"checked Spark recovery initial");
        assert(self.gap==gap,"checked Spark recovery gap");
        assert(self.margin==margin,"checked Spark recovery margin");
    }
}

// Preserve the standalone and deposit callers' existing interface. Both paths
// enforce the same complete dual-refund relation below.
pub fn authorize(
    statement:[u8;620],user:[u8;32],funding_salt:[u8;32],recovery_salt:[u8;32],payout:[u8;64],
    fee:u64,delay:u32,owner_index:u32,initial:u32,gap:u32,margin:u32,
    txid_0:[u8;32],amount_0:u64,alpha_0:[u8;32],beta_0:[u8;32],nonce_salt_0:[u8;32],
    txid_1:[u8;32],amount_1:u64,alpha_1:[u8;32],beta_1:[u8;32],nonce_salt_1:[u8;32],
) {
    let _=authorize_checked(statement,user,funding_salt,recovery_salt,payout,fee,delay,owner_index,initial,gap,margin,
        txid_0,amount_0,alpha_0,beta_0,nonce_salt_0,txid_1,amount_1,alpha_1,beta_1,nonce_salt_1);
}

pub fn authorize_checked(
    statement:[u8;620],user:[u8;32],funding_salt:[u8;32],recovery_salt:[u8;32],payout:[u8;64],
    fee:u64,delay:u32,owner_index:u32,initial:u32,gap:u32,margin:u32,
    txid_0:[u8;32],amount_0:u64,alpha_0:[u8;32],beta_0:[u8;32],nonce_salt_0:[u8;32],
    txid_1:[u8;32],amount_1:u64,alpha_1:[u8;32],beta_1:[u8;32],nonce_salt_1:[u8;32],
) -> CheckedRecovery {
    assert(part::<620,4>(statement,0) == [1,0,0,0], "Spark recovery version");
    for i in 0..9 { nonzero(part::<620,32>(statement,4+32*i)); }
    let ctx = context(statement);
    // Public revision bytes identify engine/CAS state, not a recovery slot.
    // Owner index remains private, like the original Zark schedule opening.
    assert((owner_index >= 1) & (owner_index <= 8), "Spark private owner bound");
    assert((initial > 0) & (initial <= 65535), "Spark initial delay");
    assert((gap > 0) & (gap <= 65535), "Spark delay gap");
    assert((margin > 0) & (margin < gap), "Spark margin");
    assert(initial >= 7*gap+margin, "Spark eight-owner budget");
    assert(delay == initial-(owner_index-1)*gap, "Spark exact recovery schedule");
    assert((delay > 0) & (delay <= 65535), "Spark block-only delay");
    assert((fee > 0) & (fee <= 10000), "Spark recovery fee");
    assert((amount_0 <= 2_100_000_000_000_000) & (amount_1 <= 2_100_000_000_000_000), "Spark amount bound");
    // This is an executable one-output recovery primitive. Smaller off-chain
    // Spark leaves require a separate aggregation/fee-funding construction.
    assert((amount_0 > fee+330) & (amount_1 > fee+330), "Spark executable recovery payout");
    nonzero(txid_0);nonzero(txid_1);nonzero(funding_salt);nonzero(recovery_salt);
    assert(txid_0 != txid_1, "distinct Spark refund branches");
    assert((alpha_0 != alpha_1) & (beta_0 != beta_1) & (nonce_salt_0 != nonce_salt_1), "distinct Spark blinding randomness");
    let keys = recovery::derive_keys(part::<620,64>(statement,300),user);
    let internal = keys.internal(); let output = keys.output();
    let q = output.x.to_be_bytes();
    let backing = part::<620,32>(statement,196);
    let data = join(join(join(join(join(join(join(join(join(join(
        "ZARK/spark/private-recovery/backing/v1".as_bytes(),[1,0,0,0]),
        part::<620,32>(statement,4)),part::<620,32>(statement,36)),funding_salt),txid_0),le64(amount_0)),
        txid_1),le64(amount_1)),q),internal.x.to_be_bytes());
    assert(digest(data) == backing, "Spark both refund openings");
    let policy = digest(join(join(join(join(join("ZARK/spark/private-recovery/policy/v1".as_bytes(),
        [1,0,0,0]),le32(initial)),le32(gap)),le32(margin)),le32(8)));
    assert(policy == part::<620,32>(statement,260), "Spark policy opening");
    let destination = read_point(payout);
    assert(destination.y.to_be_bytes()[31] & 1 == 0, "Spark payout parity");
    let target = digest(join(join(join(join(join(join("ZARK/spark/private-recovery/target/v1".as_bytes(),
        ctx),backing),recovery_salt),destination.x.to_be_bytes()),le64(fee)),le32(delay)));
    assert(target == part::<620,32>(statement,228), "Spark shared recovery target");
    // Equal x rejects identical AND sign-negated nonce reuse under the same key.
    assert(part::<620,32>(statement,364) != part::<620,32>(statement,492), "Spark independent signer nonces");
    assert(part::<620,32>(statement,460) != part::<620,32>(statement,588), "Spark independent nonce commitments");
    let public_0 = part::<620,128>(statement,364); let public_1 = part::<620,128>(statement,492);
    open_branch(ctx,backing,target,public_0,alpha_0,beta_0,nonce_salt_0,0);
    open_branch(ctx,backing,target,public_1,alpha_1,beta_1,nonce_salt_1,1);
    let (r_0,r_1,b_0,b_1) = batch_nonces(statement,[alpha_0,beta_0,alpha_1,beta_1]);
    finish_branch(keys.negated(),q,public_0,r_0,b_0,txid_0,amount_0,payout,fee,delay);
    finish_branch(keys.negated(),q,public_1,r_1,b_1,txid_1,amount_1,payout,fee,delay);
    // Construct only after both nonce/challenge/sighash relations have been
    // constrained, as well as the shared target and exact schedule.
    CheckedRecovery {statement,user,recovery_salt,payout,fee,delay,owner_index,initial,gap,margin}
}

fn open_branch(ctx:[u8;204],backing:[u8;32],target:[u8;32],public:[u8;128],
    alpha:[u8;32],beta:[u8;32],salt:[u8;32],index:u32,
) {
    nonzero(salt);
    let commitment = digest(join(join(join(join(join(join(join("ZARK/spark/private-recovery/nonce/v1".as_bytes(),
        ctx),backing),target),le32(index)),alpha),beta),salt));
    assert(commitment == part::<128,32>(public,96), "Spark nonce opening");
}

// The statement fixes the server share and both server nonces, challenges and
// commitments; the hinted nonces and canonical blinding encodings fix every
// remaining operand. G is constant. read_point/read_scalar make each encoding
// a bijection with its value, so no operand can change after w is derived.
// Hint bytes must stay [u8;N]: Brillig byte outputs are range checked, which
// keeps the digest's byte packing injective.
fn batch_weight(statement:[u8;620],blinding:[[u8;32];4],r_0:[u8;64],r_1:[u8;64]) -> Field {
    let bytes = join(join("ZARK/spark/private-recovery/nonce-batch/v1".as_bytes(),statement),r_0);
    let bytes = join(join(join(bytes,r_1),join(blinding[0],blinding[1])),join(blinding[2],blinding[3]));
    let weights = digest(bytes);
    // A 128-bit integer, below the scalar-field modulus and the MSM short-scalar bound.
    let mut w = 0 as Field;
    for i in 0..16 { w = w*256 + weights[i] as Field; }
    w
}

// D_i = R_i - N_i - a_i G - b_i S; each branch requires D_i = 0, otherwise b_i
// is not tied to the signed nonce. This checks D_0 + w D_1 = 0, with w derived
// after every operand is fixed. If D_1 != 0, the prime-order group admits at
// most one w mod n solving it; if D_1 = 0 the check is exactly D_0 = 0. In a
// random oracle model a malicious prover thus succeeds with probability
// <= 2^-128 per weight query, scaled by the number of queries under grinding.
// As with origin_batch, application_digest output is ASSUMED to behave as a
// uniform 128-bit word; this is computational soundness, not algebraic
// equivalence. Rejecting w = 0 is defence in depth; the bound holds without it.
// Every operand is decoded here from the hashed bytes so that callers cannot
// supply values the weight does not bind; hints are arbitrary prover data.
fn verify_nonces(statement:[u8;620],blinding:[[u8;32];4],r_0_bytes:[u8;64],r_1_bytes:[u8;64],
) -> (Secp256k1,Secp256k1,Secp256k1_Fr,Secp256k1_Fr) {
    let server = read_point(part::<620,64>(statement,300));
    let n_0 = read_point(part::<620,64>(statement,364)); let n_1 = read_point(part::<620,64>(statement,492));
    let scalars = blinding.map(|encoding| read_scalar(encoding));
    for i in 0..4 { assert(!scalars[i].is_zero(), "nonzero Spark blinding"); }
    let r_0 = read_point(r_0_bytes); let r_1 = read_point(r_1_bytes);
    let w = batch_weight(statement,blinding,r_0_bytes,r_1_bytes);
    assert(w != 0, "Spark nonce batch weight");
    check_batch(w,server,scalars,n_0,n_1,r_0,r_1);
    (r_0,r_1,scalars[1],scalars[3])
}

fn batch_nonces(statement:[u8;620],blinding:[[u8;32];4]) -> (Secp256k1,Secp256k1,Secp256k1_Fr,Secp256k1_Fr) {
    // Safety: verify_nonces decodes, hashes and checks both hints before use.
    let (r_0,r_1) = unsafe { blinded_nonces(statement,blinding) };
    verify_nonces(statement,blinding,r_0,r_1)
}

unconstrained fn blinded_nonces(statement:[u8;620],blinding:[[u8;32];4]) -> ([u8;64],[u8;64]) {
    let server = read_point(part::<620,64>(statement,300));
    let r_0 = blinded_nonce(read_point(part::<620,64>(statement,364)),read_scalar(blinding[0]),read_scalar(blinding[1]),server);
    let r_1 = blinded_nonce(read_point(part::<620,64>(statement,492)),read_scalar(blinding[2]),read_scalar(blinding[3]),server);
    (r_0,r_1)
}

// Sound only for a w derived from the transcript after all operands are fixed.
fn check_batch(w:Field,server:Secp256k1,scalars:[Secp256k1_Fr;4],
    n_0:Secp256k1,n_1:Secp256k1,r_0:Secp256k1,r_1:Secp256k1,
) {
    let fw = Secp256k1_Fr::from(w);
    // R_0 = (b_0 + w b_1) S + (a_0 + w a_1) G + w (N_1 - R_1) + N_0. The MSM
    // rejects an infinite base, so R_1 = N_1 fails closed.
    let rhs = bigcurve::glv_batch::msm([server,Secp256k1::one()],
        [scalars[1]+fw*scalars[3],scalars[0]+fw*scalars[2]],[add(n_1,r_1.neg()),n_0],[w,1]);
    assert(r_0 == rhs, "Spark batched blinded nonces");
}

unconstrained fn blinded_nonce(n:Secp256k1,a:Secp256k1_Fr,b:Secp256k1_Fr,server:Secp256k1) -> [u8;64] {
    let r = add(add(n,fixed_generator::mul_generator(a.to_be_bytes())),bigcurve::glv::mul(server,b));
    join(r.x.to_be_bytes(),r.y.to_be_bytes())
}

fn finish_branch(key_negated:bool,output:[u8;32],public:[u8;128],r:Secp256k1,b:Secp256k1_Fr,
    txid:[u8;32],amount:u64,payout:[u8;64],fee:u64,delay:u32,
) {
    let submitted = read_scalar(part::<128,32>(public,64));
    let (nonce,nonce_negated) = normalize(r);
    let message = recovery::recovery_sighash(txid,0,amount,fee,output,part::<64,32>(payout,0),delay);
    let e = challenge_scalar(tagged("BIP0340/challenge".as_bytes(),join(join(nonce.x.to_be_bytes(),output),message)));
    let negate_e = key_negated != nonce_negated;
    assert(submitted == b + if negate_e { e.neg() } else { e }, "Spark blinded recovery challenge");
}

mod batch_tests;

mod checked_tests {
    use super::CheckedRecovery;

    // Synthetic private tokens test ONLY exact reuse binding. They do not
    // establish authorize_checked acceptance, signature validity or a real
    // recovery fixture; those checks require the deferred real-proof suite.
    fn fixture() -> CheckedRecovery {
        CheckedRecovery {statement:[0;620],user:[1;32],recovery_salt:[2;32],payout:[3;64],
            fee:1000,delay:90,owner_index:2,initial:100,gap:10,margin:1}
    }
    fn reuse(statement:[u8;620]) {
        fixture().assert_matches(statement,[1;32],[2;32],[3;64],1000,90,2,100,10,1);
    }
    fn change_statement(offset:u32) {
        let mut statement=[0 as u8;620];statement[offset]=1;reuse(statement);
    }

    #[test]
    fn exact_context_matches() {reuse([0;620]);}
    #[test(should_fail_with = "checked Spark recovery statement")]
    fn another_domain_rejected() {change_statement(4);}
    #[test(should_fail_with = "checked Spark recovery statement")]
    fn another_backing_rejected() {change_statement(196);}
    #[test(should_fail_with = "checked Spark recovery statement")]
    fn another_target_rejected() {change_statement(228);}
    #[test(should_fail_with = "checked Spark recovery statement")]
    fn another_policy_rejected() {change_statement(260);}
    #[test(should_fail_with = "checked Spark recovery statement")]
    fn another_revision_rejected() {change_statement(292);}
    #[test(should_fail_with = "checked Spark recovery statement")]
    fn another_server_rejected() {change_statement(300);}
    #[test(should_fail_with = "checked Spark recovery statement")]
    fn first_branch_nonce_rejected() {change_statement(364);}
    #[test(should_fail_with = "checked Spark recovery statement")]
    fn first_branch_challenge_rejected() {change_statement(428);}
    #[test(should_fail_with = "checked Spark recovery statement")]
    fn first_branch_commitment_rejected() {change_statement(460);}
    #[test(should_fail_with = "checked Spark recovery statement")]
    fn second_branch_nonce_rejected() {change_statement(492);}
    #[test(should_fail_with = "checked Spark recovery statement")]
    fn second_branch_challenge_rejected() {change_statement(556);}
    #[test(should_fail_with = "checked Spark recovery statement")]
    fn second_branch_commitment_rejected() {change_statement(588);}

    #[test(should_fail_with = "checked Spark recovery user")]
    fn another_user_rejected() {
        fixture().assert_matches([0;620],[4;32],[2;32],[3;64],1000,90,2,100,10,1);
    }
    #[test(should_fail_with = "checked Spark recovery salt")]
    fn another_salt_rejected() {
        fixture().assert_matches([0;620],[1;32],[4;32],[3;64],1000,90,2,100,10,1);
    }
    #[test(should_fail_with = "checked Spark recovery payout")]
    fn another_payout_rejected() {
        fixture().assert_matches([0;620],[1;32],[2;32],[4;64],1000,90,2,100,10,1);
    }
    #[test(should_fail_with = "checked Spark recovery fee")]
    fn another_fee_rejected() {
        fixture().assert_matches([0;620],[1;32],[2;32],[3;64],1001,90,2,100,10,1);
    }
    #[test(should_fail_with = "checked Spark recovery delay")]
    fn another_delay_rejected() {
        fixture().assert_matches([0;620],[1;32],[2;32],[3;64],1000,89,2,100,10,1);
    }
    #[test(should_fail_with = "checked Spark recovery owner")]
    fn another_owner_rejected() {
        fixture().assert_matches([0;620],[1;32],[2;32],[3;64],1000,90,3,100,10,1);
    }
    #[test(should_fail_with = "checked Spark recovery initial")]
    fn another_initial_rejected() {
        fixture().assert_matches([0;620],[1;32],[2;32],[3;64],1000,90,2,101,10,1);
    }
    #[test(should_fail_with = "checked Spark recovery gap")]
    fn another_gap_rejected() {
        fixture().assert_matches([0;620],[1;32],[2;32],[3;64],1000,90,2,100,11,1);
    }
    #[test(should_fail_with = "checked Spark recovery margin")]
    fn another_margin_rejected() {
        fixture().assert_matches([0;620],[1;32],[2;32],[3;64],1000,90,2,100,10,2);
    }
}
