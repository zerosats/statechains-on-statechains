use super::{batch_nonces,batch_weight,blinded_nonces,check_batch,verify_nonces};
use bigcurve::{BigCurve,Secp256k1};
use bignum::{BigNum,Secp256k1_Fr};
use bitcoin_relations::{add,join,read_point};
use std::ops::Neg;

// Synthetic small-scalar points exercise only the batched nonce relation. The
// statement carries the server and server-nonce encodings at their offsets;
// point(v) has discrete log k(v), so tests can solve for related bases.
fn scalar(v:u8) -> [u8;32] { let mut b=[0 as u8;32]; b[0]=v; b[31]=v; b }
fn k(v:u8) -> Secp256k1_Fr { Secp256k1_Fr::from_be_bytes(scalar(v)) }
fn encode(p:Secp256k1) -> [u8;64] { join(p.x.to_be_bytes(),p.y.to_be_bytes()) }
fn point(v:u8) -> Secp256k1 { fixed_generator::mul_generator(scalar(v)) }

struct Case { statement:[u8;620],blinding:[[u8;32];4],r_0:[u8;64],r_1:[u8;64] }

fn with(server:Secp256k1,blinding:[[u8;32];4]) -> Case {
    let mut statement=[0 as u8;620];
    let (s,a,b)=(encode(server),encode(point(5)),encode(point(7)));
    for i in 0..64 { statement[300+i]=s[i]; statement[364+i]=a[i]; statement[492+i]=b[i]; }
    // Safety: test hints, checked by verify_nonces.
    let (r_0,r_1)=unsafe { blinded_nonces(statement,blinding) };
    Case {statement,blinding,r_0,r_1}
}
fn honest() -> Case { with(point(3),[scalar(11),scalar(13),scalar(17),scalar(19)]) }

fn check(c:Case) { let _=verify_nonces(c.statement,c.blinding,c.r_0,c.r_1); }
fn shift(bytes:[u8;64],delta:Secp256k1) -> [u8;64] { encode(add(read_point(bytes),delta)) }
fn set(mut c:Case,index:u32,value:Secp256k1_Fr) -> Case { c.blinding[index]=value.to_be_bytes(); c }
fn stale(c:Case,w:Field) {
    let s=c.blinding.map(|e| Secp256k1_Fr::from_be_bytes(e));
    check_batch(w,point(3),s,point(5),point(7),read_point(c.r_0),read_point(c.r_1));
}

#[test]
fn honest_nonces_accepted() {
    let c=honest(); let (r_0,r_1,b_0,b_1)=batch_nonces(c.statement,c.blinding);
    assert((encode(r_0)==c.r_0) & (encode(r_1)==c.r_1) & (b_0==k(13)) & (b_1==k(19)));
}

#[test(should_fail_with = "Spark batched blinded nonces")]
fn substituted_first_nonce_rejected() { let mut c=honest(); c.r_0=encode(point(9)); check(c); }

#[test(should_fail_with = "Spark batched blinded nonces")]
fn substituted_second_nonce_rejected() { let mut c=honest(); c.r_1=encode(point(9)); check(c); }

#[test(should_fail_with = "Spark batched blinded nonces")]
fn changed_first_generator_blinding_rejected() { check(set(honest(),0,k(23))); }

#[test(should_fail_with = "Spark batched blinded nonces")]
fn changed_second_server_blinding_rejected() { check(set(honest(),3,k(23))); }

#[test(should_fail_with = "batch short finite base")]
fn second_nonce_equal_to_server_nonce_rejected() { let mut c=honest(); c.r_1=encode(point(7)); check(c); }

#[test(should_fail_with = "non-canonical coordinate")]
fn noncanonical_first_nonce_rejected() {
    let mut c=honest(); let p=bignum::Secp256k1_Fq::modulus().to_be_bytes();
    for i in 0..32 { c.r_0[i]=p[i]; }
    check(c);
}

// D_0 = X and D_1 = -X cancel in an unweighted sum.
#[test(should_fail_with = "Spark batched blinded nonces")]
fn cancelling_nonces_rejected() {
    let mut c=honest(); let x=point(9);
    c.r_0=shift(c.r_0,x); c.r_1=shift(c.r_1,x.neg()); check(c);
}

// a_0 + 1 and a_1 - 1 leave a_0 + a_1 unchanged: D_0 = -G and D_1 = G.
#[test(should_fail_with = "Spark batched blinded nonces")]
fn cancelling_blindings_rejected() {
    let c=set(honest(),0,k(11)+Secp256k1_Fr::one()); check(set(c,2,k(17)-Secp256k1_Fr::one()));
}

// A prover who knows w for the honest transcript can choose D_0 = -w D_1, by
// moving R_1 (kind 0), a_1 (kind 1) or b_1 (kind 2).
fn forged(kind:u8) -> (Case,Field) {
    let mut c=honest(); let w=batch_weight(c.statement,c.blinding,c.r_0,c.r_1);
    let fw=Secp256k1_Fr::from(w); let delta=k(9);
    if kind==0 {
        c.r_1=shift(c.r_1,point(9));
        c.r_0=shift(c.r_0,bigcurve::glv::mul(point(9),fw).neg());
    } else if kind==1 {
        c=set(c,2,k(17)+delta);
        c.r_0=shift(c.r_0,fixed_generator::mul_generator((fw*delta).to_be_bytes()));
    } else {
        c=set(c,3,k(19)+delta);
        c.r_0=shift(c.r_0,bigcurve::glv::mul(point(3),fw*delta));
    }
    (c,w)
}

// Controls: each forgery satisfies the equation under the stale weight.
#[test]
fn forged_nonce_satisfies_stale_weight() { let (c,w)=forged(0); stale(c,w); }
#[test]
fn forged_generator_blinding_satisfies_stale_weight() { let (c,w)=forged(1); stale(c,w); }
#[test]
fn forged_server_blinding_satisfies_stale_weight() { let (c,w)=forged(2); stale(c,w); }

// Rebinding the weight to the forged transcript invalidates each forgery.
#[test(should_fail_with = "Spark batched blinded nonces")]
fn forged_nonce_rejected() { let (c,_)=forged(0); check(c); }
#[test(should_fail_with = "Spark batched blinded nonces")]
fn forged_generator_blinding_rejected() { let (c,_)=forged(1); check(c); }
#[test(should_fail_with = "Spark batched blinded nonces")]
fn forged_server_blinding_rejected() { let (c,_)=forged(2); check(c); }

// Control for the w != 0 gate: a zero weight would ignore a wrong D_1.
#[test]
fn zero_weight_ignores_second_branch() { let mut c=honest(); c.r_1=encode(point(9)); stale(c,0); }

// Spot checks of hash sensitivity, not a proof of transcript coverage.
#[test]
fn weight_covers_every_operand() {
    let c=honest(); let w=batch_weight(c.statement,c.blinding,c.r_0,c.r_1);
    // Server, both server nonces, challenges and commitments, and the target.
    for offset in [300,363,364,427,428,459,460,491,492,555,556,587,588,619,228] {
        let mut s=c.statement; s[offset]^=1;
        assert(batch_weight(s,c.blinding,c.r_0,c.r_1)!=w);
    }
    for i in 0..4 {
        let mut b=c.blinding; b[i][31]^=1;
        assert(batch_weight(c.statement,b,c.r_0,c.r_1)!=w);
    }
    let mut r=c.r_0; r[63]^=1; assert(batch_weight(c.statement,c.blinding,r,c.r_1)!=w);
    let mut r=c.r_1; r[0]^=1; assert(batch_weight(c.statement,c.blinding,c.r_0,r)!=w);
}

// Honest completeness with related MSM bases. S = k(3)G, N_0 = k(5)G and
// N_1 = k(7)G; choosing a_1 fixes R_1 - N_1 = (a_1 + k(3) b_1) G.
fn related(a_1:Secp256k1_Fr) {
    let c=with(point(3),[scalar(11),scalar(13),a_1.to_be_bytes(),scalar(19)]);
    let _=batch_nonces(c.statement,c.blinding);
}
#[test]
fn generator_server_accepted() {
    let c=with(Secp256k1::one(),[scalar(11),scalar(13),scalar(17),scalar(19)]);
    let _=batch_nonces(c.statement,c.blinding);
}
// R_1 = -N_1, so N_1 - R_1 doubles N_1.
#[test]
fn negated_second_nonce_accepted() { related((k(7)+k(7)+k(19)*k(3)).neg()); }
// N_1 - R_1 = N_0.
#[test]
fn short_bases_equal_accepted() { related((k(5)+k(19)*k(3)).neg()); }
// N_1 - R_1 = -S.
#[test]
fn short_base_negates_server_accepted() { related(k(3)-k(19)*k(3)); }
