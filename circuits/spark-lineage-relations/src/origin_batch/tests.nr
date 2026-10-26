//! Source-only synthetic cases. These have not been executed or compiled.
//! Recursive-role/real-proof rejection belongs to the later artifact gate;
//! these unit cases isolate the post-issuance batch and public helper contract.
use super::{transcript_digest,verify,weight};
use bitcoin_relations::{challenge_scalar,join,part,read_point,tagged};
use bigcurve::BigCurve;
use bignum::{BigNum,Secp256k1_Fq,Secp256k1_Fr};
use crate::{authorized_state,digest,server_commit,state_commit};
use std::ops::Neg;

struct Fixture {
    current:[u8;324],auth:[u8;1036],partials:[[u8;32];2],salt:[u8;32],
    key:[u8;64],nonce:[u8;64],signature:[u8;64],cfg:[u8;160],
}

fn write<let N:u32,let M:u32>(bytes:[u8;N],offset:u32,value:[u8;M])->[u8;N] {
    let mut out=bytes;for i in 0..M {out[offset+i]=value[i];}out
}
fn scalar(value:Field)->[u8;32] {Secp256k1_Fr::from(value).to_be_bytes()}
fn point(value:Field)->[u8;64] {
    let p=fixed_generator::mul_generator(scalar(value));
    join(p.x.to_be_bytes(),p.y.to_be_bytes())
}
fn negate(bytes:[u8;64])->[u8;64] {
    let p=read_point(bytes).neg();join(p.x.to_be_bytes(),p.y.to_be_bytes())
}
fn challenge(f:Fixture)->[u8;32] {
    let message=digest(join("ZARK/spark/ownership/origin/v1".as_bytes(),f.current));
    tagged("BIP0340/challenge".as_bytes(),join(join(part::<64,32>(f.nonce,0),part::<64,32>(f.key,0)),message))
}
fn weights(f:Fixture)->[u8;32] {
    transcript_digest(f.current,f.auth,f.partials,f.salt,f.key,f.nonce,f.signature,f.cfg,challenge(f))
}
fn check(f:Fixture) {
    verify(f.current,f.auth,f.partials,f.salt,f.key,f.nonce,f.signature,f.cfg);
}

// Recommit and resign after changing partials, so invalid-response tests cannot
// pass merely because a stale certificate or signature rejected first.
fn complete(value:Fixture)->Fixture {
    let mut f=value;
    let domain=part::<1036,68>(f.auth,0);
    let server=server_commit(domain,part::<1036,64>(f.auth,300),f.salt);
    f.auth=write(f.auth,844,server);
    let authorization=digest(join("ZARK/spark/ownership/authorization/v1".as_bytes(),f.auth));
    let issued=digest(join(join(join("ZARK/spark/ownership/issuance/v1".as_bytes(),authorization),f.partials[0]),f.partials[1]));
    let state=state_commit(domain,part::<1036,32>(f.auth,196),part::<1036,32>(f.auth,812),part::<1036,32>(f.auth,228),server,part::<1036,32>(f.auth,260),issued);
    f.current=write(f.current,100,state);
    // Synthetic origin key and nonce both equal G (secret scalar one).
    f.signature=join(part::<64,32>(f.nonce,0),(Secp256k1_Fr::one()+challenge_scalar(challenge(f))).to_be_bytes());
    f
}
fn fixture()->Fixture {
    let key=point(1);let nonce=point(1);
    let mut cfg=[0 as u8;160];cfg=write(cfg,0,part::<64,32>(key,0));
    for i in 0..4 {cfg=write(cfg,32+32*i,scalar((i+1) as Field));}
    let mut current=[0 as u8;324];current[0]=1;
    current=write(current,4,scalar(11));current=write(current,36,scalar(12));
    current=write(current,68,scalar(13));current=write(current,132,scalar(14));
    current=write(current,164,cfg);
    let mut auth=[0 as u8;1036];auth=write(auth,0,part::<324,68>(current,0));
    auth=write(auth,196,part::<324,32>(current,68));auth=write(auth,228,scalar(15));
    auth=write(auth,260,part::<324,32>(current,132));auth[292]=1;
    auth=write(auth,300,point(1));auth=write(auth,364,point(2));auth=write(auth,428,scalar(3));
    auth=write(auth,492,point(3));auth=write(auth,556,scalar(5));
    for i in 0..8 {auth=write(auth,620+32*i,scalar((i+20) as Field));}
    auth=write(auth,876,cfg);
    complete(Fixture {current,auth,partials:[scalar(5),scalar(8)],salt:scalar(31),key,nonce,signature:[0;64],cfg})
}

#[test]
fn valid_responses_match_separate_equations_and_batch() {
    let f=fixture();authorized_state(f.current,f.auth,f.partials,f.salt);check(f);
}
#[test(should_fail_with = "Spark batched origin responses and attestation")]
fn rejects_first_issued_response() {
    let mut f=fixture();f.partials[0]=scalar(6);check(complete(f));
}
#[test(should_fail_with = "Spark batched origin responses and attestation")]
fn rejects_second_issued_response() {
    let mut f=fixture();f.partials[1]=scalar(9);check(complete(f));
}
#[test(should_fail_with = "Spark batched origin responses and attestation")]
fn rejects_placeholder_second_response() {
    let mut f=fixture();f.partials[1]=[0;32];check(complete(f));
}
#[test(should_fail_with = "Spark batched origin responses and attestation")]
fn rejects_origin_signature_scalar() {
    let mut f=fixture();
    let s=bitcoin_relations::read_scalar(part::<64,32>(f.signature,32));
    f.signature=write(f.signature,32,(s+Secp256k1_Fr::one()).to_be_bytes());check(f);
}
#[test(should_fail_with = "Spark batched origin responses and attestation")]
fn opposite_response_errors_cannot_cancel_an_unweighted_sum() {
    let mut f=fixture();f.partials=[scalar(6),scalar(7)];check(complete(f));
}
#[test(should_fail_with = "signer partial equation")]
fn public_authorized_state_still_rejects_first_response() {
    let mut f=fixture();f.partials[0]=scalar(6);let f=complete(f);
    authorized_state(f.current,f.auth,f.partials,f.salt);
}
#[test(should_fail_with = "signer partial equation")]
fn public_authorized_state_still_rejects_second_response() {
    let mut f=fixture();f.partials[1]=scalar(9);let f=complete(f);
    authorized_state(f.current,f.auth,f.partials,f.salt);
}
#[test(should_fail_with = "non-canonical scalar")]
fn rejects_noncanonical_first_response() {
    let mut f=fixture();f.partials[0]=Secp256k1_Fr::modulus().to_be_bytes();check(f);
}
#[test(should_fail_with = "non-canonical scalar")]
fn rejects_noncanonical_second_response() {
    let mut f=fixture();f.partials[1]=Secp256k1_Fr::modulus().to_be_bytes();check(f);
}
#[test(should_fail_with = "non-canonical scalar")]
fn rejects_noncanonical_signature_scalar() {
    let mut f=fixture();f.signature=write(f.signature,32,Secp256k1_Fr::modulus().to_be_bytes());check(f);
}
#[test(should_fail_with = "non-canonical scalar")]
fn rejects_noncanonical_challenge() {
    let mut f=fixture();f.auth=write(f.auth,556,Secp256k1_Fr::modulus().to_be_bytes());check(f);
}
#[test(should_fail_with = "non-canonical coordinate")]
fn rejects_noncanonical_server_coordinate() {
    let mut f=fixture();f.auth=write(f.auth,300,Secp256k1_Fq::modulus().to_be_bytes());check(f);
}
#[test(should_fail)]
fn rejects_off_curve_second_nonce() {
    let mut f=fixture();f.auth=write(f.auth,492,[0 as u8;64]);check(f);
}
#[test(should_fail_with = "Spark origin key parity")]
fn rejects_negated_origin_key() {let mut f=fixture();f.key=negate(f.key);check(f);}
#[test(should_fail_with = "Spark origin nonce parity")]
fn rejects_negated_origin_nonce() {let mut f=fixture();f.nonce=negate(f.nonce);check(f);}
#[test(should_fail_with = "Spark origin key lift")]
fn rejects_substituted_origin_key() {let mut f=fixture();f.key=point(2);check(f);}
#[test(should_fail_with = "Spark origin nonce lift")]
fn rejects_substituted_origin_nonce() {let mut f=fixture();f.nonce=point(2);check(f);}
#[test(should_fail_with = "Spark batched origin responses and attestation")]
fn rejects_certificate_from_another_context() {
    let mut f=fixture();f.current[35]=f.current[35]^1;check(f);
}
#[test(should_fail_with = "Spark issued config")]
fn public_binding_rejects_authorization_from_another_role_configuration() {
    let mut f=fixture();f.auth[939]=9;authorized_state(f.current,f.auth,f.partials,f.salt);
}
#[test(should_fail_with = "Spark issued domain")]
fn public_binding_rejects_authorization_from_another_context() {
    let mut f=fixture();f.auth[35]=f.auth[35]^1;authorized_state(f.current,f.auth,f.partials,f.salt);
}

// These are transcript-binding assertions, not assertions that hashing alone
// rejects context changes. Exact valid equations hold under any weights;
// recursive verification and issued_state_binding authenticate the context.
#[test]
fn transcript_binds_certificate_authorization_and_role_fields() {
    let f=fixture();let expected=weights(f);
    for index in [0,4,36,68,100,132,164,196,228,260,292,300,364,428,460,492,556,588,620,652,684,716,748,780,812,844,876,908,940,972,1004,1035] {
        let mut changed=f;changed.auth[index]=changed.auth[index]^1;
        assert(weights(changed)!=expected,"Spark batch authorization field bound");
    }
    for index in [0,4,36,68,100,132,164,196,228,260,292,323] {
        let mut changed=f;changed.current[index]=changed.current[index]^1;
        assert(weights(changed)!=expected,"Spark batch certificate field bound");
    }
    for index in [0,31,32,63,64,95,96,127,128,159] {
        let mut changed=f;changed.cfg[index]=changed.cfg[index]^1;
        assert(weights(changed)!=expected,"Spark batch configuration field bound");
    }
}
#[test]
fn transcript_binds_partials_salt_and_attestation_operands() {
    let f=fixture();let expected=weights(f);
    for branch in 0..2 {
        let mut changed=f;changed.partials[branch][31]=changed.partials[branch][31]^1;
        assert(weights(changed)!=expected);
    }
    let mut changed=f;changed.salt[31]=changed.salt[31]^1;assert(weights(changed)!=expected);
    for index in [0,31,32,63] {
        let mut changed=f;changed.key[index]=changed.key[index]^1;assert(weights(changed)!=expected);
        let mut changed=f;changed.nonce[index]=changed.nonce[index]^1;assert(weights(changed)!=expected);
        let mut changed=f;changed.signature[index]=changed.signature[index]^1;assert(weights(changed)!=expected);
    }
    let mut c=challenge(f);c[31]=c[31]^1;
    assert(transcript_digest(f.current,f.auth,f.partials,f.salt,f.key,f.nonce,f.signature,f.cfg,c)!=expected);
}
#[test]
fn weight_halves_are_big_endian_128_bit_integers() {
    let mut bytes=[0 as u8;32];bytes[0]=1;bytes[15]=2;bytes[16]=3;bytes[31]=4;
    assert(weight(bytes,0)==0x01000000000000000000000000000002);
    assert(weight(bytes,16)==0x03000000000000000000000000000004);
    assert(weight([255;32],0)==340282366920938463463374607431768211455);
}
