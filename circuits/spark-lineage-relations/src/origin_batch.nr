//! Spark origin's two issued responses and trusted attestation share one MSM.
//! This follows Bitcoin's computational batching model; it does not establish
//! three independently checked equations against arbitrary malicious witnesses.
use bitcoin_relations::{add,challenge_scalar,join,part,read_point,read_scalar,tagged};
use bigcurve::BigCurve;
use bignum::{BigNum,Secp256k1_Fr};
use crate::digest;

// Fixed-width encodings bind the complete certificate, authorization and role
// configuration, not merely their curve operands. auth contains the server,
// both nonce points, both challenge scalars and operation/revision context.
// The explicit points, partials, signature and raw BIP340 challenge cover every
// remaining input to the equations. Salt also binds the issued-state opening.
fn transcript_digest(
    current:[u8;324],auth:[u8;1036],partials:[[u8;32];2],salt:[u8;32],
    key:[u8;64],nonce:[u8;64],signature:[u8;64],cfg:[u8;160],challenge:[u8;32],
) -> [u8;32] {
    let bytes=join("ZARK/spark/ownership/origin-batch/v1".as_bytes(),current);
    let bytes=join(bytes,auth);
    let bytes=join(bytes,cfg);
    let bytes=join(bytes,salt);
    let bytes=join(bytes,partials[0]);
    let bytes=join(bytes,partials[1]);
    let bytes=join(bytes,key);
    let bytes=join(bytes,nonce);
    let bytes=join(bytes,signature);
    digest(join(bytes,challenge))
}

// Each half is an integer in [0, 2^128), below both scalar-field moduli.
fn weight(bytes:[u8;32],offset:u32) -> Field {
    let mut value=0 as Field;
    for i in 0..16 { value=value*256+bytes[offset+i] as Field; }
    value
}

// Only verify_origin calls this internal relation, after recursive role-0
// verification and issued_state_binding. Those checks cannot be replaced by
// hashing their bytes here: hashing gives context binding, not authorization.
pub(crate) fn verify(
    current:[u8;324],auth:[u8;1036],partials:[[u8;32];2],salt:[u8;32],
    key:[u8;64],nonce:[u8;64],signature:[u8;64],cfg:[u8;160],
) {
    let server=read_point(part::<1036,64>(auth,300));
    let nonce_0=read_point(part::<1036,64>(auth,364));
    let nonce_1=read_point(part::<1036,64>(auth,492));
    let c0=read_scalar(part::<1036,32>(auth,428));
    let c1=read_scalar(part::<1036,32>(auth,556));
    let z0=read_scalar(partials[0]);let z1=read_scalar(partials[1]);
    let p=read_point(key);let r=read_point(nonce);
    let s=read_scalar(part::<64,32>(signature,32));
    assert(p.x.to_be_bytes()==part::<160,32>(cfg,0),"Spark origin key lift");
    assert((p.y.to_be_bytes()[31]&1)==0,"Spark origin key parity");
    assert(r.x.to_be_bytes()==part::<64,32>(signature,0),"Spark origin nonce lift");
    assert((r.y.to_be_bytes()[31]&1)==0,"Spark origin nonce parity");
    let message=digest(join("ZARK/spark/ownership/origin/v1".as_bytes(),current));
    let challenge=tagged("BIP0340/challenge".as_bytes(),join(join(r.x.to_be_bytes(),p.x.to_be_bytes()),message));
    let e=challenge_scalar(challenge);
    let weights=transcript_digest(current,auth,partials,salt,key,nonce,signature,cfg,challenge);
    let w1=weight(weights,0);let w2=weight(weights,16);
    let fw1=Secp256k1_Fr::from(w1);let fw2=Secp256k1_Fr::from(w2);
    // D0 = z0 G - R0 - c0 X; D1 = z1 G - R1 - c1 X;
    // Ds = s G - R - e P. Check D0 + w1 D1 + w2 Ds = 0.
    // For any fixed nonzero residual tuple in the prime-order group, at most
    // 2^128 of the 2^256 uniform weight pairs solve this equation. In a random
    // oracle model that is <= 2^-128 success per transcript hash query; adaptive
    // grinding scales that bound by the number of queries. The argument assumes
    // every residual input is transcript-bound, canonical decoding, constrained
    // MSM replay and sound recursive proofs. Like Bitcoin, weights use the
    // existing application_digest sponge, whose two outputs are ASSUMED to
    // behave as independent uniform 128-bit words; its custom Poseidon2
    // construction is unaudited. This is a computational assumption, not exact
    // algebraic equivalence or an unconditional 128-bit soundness guarantee.
    // Zero weights are allowed and included in the same per-query bound.
    let lhs=fixed_generator::mul_generator((z0+fw1*z1+fw2*s).to_be_bytes());
    let rhs=add(nonce_0,bigcurve::glv_batch::msm([server,p],[c0+fw1*c1,fw2*e],[nonce_1,r],[w1,w2]));
    assert(lhs==rhs,"Spark batched origin responses and attestation");
}

mod tests;
