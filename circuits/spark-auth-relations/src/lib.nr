//! Spark operator authentication for the joint identity key P = X_wallet + X_server.
//!
//! The signer must never act as a blind Schnorr oracle: Spark also accepts
//! identity-key BIP-340 signatures for transfer and token authorization. This
//! relation therefore proves that the one blinded challenge is over the SHA-256
//! of the canonical `spark_authn.Challenge` protobuf, version 1, naming exactly
//! the coin's committed identity key in compressed SEC1 form. The key, the
//! Spark nonce, the message and the final signature stay wallet-private.
//!
//! Statement (268 bytes, signer-assembled; the signer independently checks the
//! public timestamp for freshness and supplies every other field itself):
//!   0 version [1,0,0,0] | 4 identity scope | 36 identity key commitment
//!   68 server share x||y | 132 challenge timestamp le64
//!   140 blinding commitment | 172 server nonce x||y | 236 blinded challenge
use bitcoin_relations::{add,application_digest,challenge_scalar,digest,is_nonzero,join,normalize,part,read_point,read_scalar};
use bigcurve::BigCurve;
use bignum::BigNum;
use std::ops::Neg;

// SHA256("ZARK/spark/joint-identity/key-commit/v1"): the garbled-circuit
// identity key commitment, so both signing paths name one fixed wallet share.
global KEY_DOMAIN:[u8;32]=[114,205,121,195,81,83,72,113,255,146,62,97,125,7,86,18,54,253,186,99,130,70,20,46,50,247,117,4,161,121,207,164];
// 2^256 mod n. The commitment hashes the share in this scaled representation.
global KEY_FACTOR:[u8;32]=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,69,81,35,25,80,183,95,196,64,45,161,115,47,201,190,191];
// SHA256("BIP0340/challenge").
global CHALLENGE_TAG:[u8;32]=[123,181,45,122,159,239,88,50,62,177,191,122,64,125,179,130,210,243,242,216,27,177,34,79,73,254,81,143,109,72,211,124];

pub fn key_commitment(user:[u8;32],key_salt:[u8;32])->[u8;32] {
    let scaled=read_scalar(user)*read_scalar(KEY_FACTOR);
    digest(join(join(scaled.to_be_bytes(),key_salt),KEY_DOMAIN))
}

fn read_le64(bytes:[u8;8])->u64 {
    let mut value:u64=0;
    for i in 0..8 {value=value|((bytes[i] as u64)<<(8*i as u64));}
    value
}

/// Canonical proto3 encoding with fields in number order. The timestamp bound
/// fixes a five-byte varint (years 1978-3058), so the preimage is exactly 77 bytes.
pub fn challenge_bytes(timestamp:u64,nonce:[u8;32],key_odd:bool,key_x:[u8;32])->[u8;77] {
    assert((timestamp>=(1 as u64)<<28)&(timestamp<(1 as u64)<<35),"challenge timestamp varint width");
    let mut varint=[0 as u8;5];
    for i in 0..4 {varint[i]=(((timestamp>>(7*i as u64))&127) as u8)|128;}
    varint[4]=(timestamp>>28) as u8;
    let head=join(join([8,1,16],varint),[26,32]);
    join(join(join(head,nonce),[34,33,2+key_odd as u8]),key_x)
}

pub fn authorize(statement:[u8;268],user:[u8;32],key_salt:[u8;32],challenge_nonce:[u8;32],
    alpha:[u8;32],beta:[u8;32],salt:[u8;32],
) {
    assert(part::<268,4>(statement,0)==[1,0,0,0],"auth statement version");
    for offset in [4,36,140] {assert(is_nonzero(part::<268,32>(statement,offset)),"zero auth binding");}
    assert(is_nonzero(key_salt)&is_nonzero(salt)&is_nonzero(challenge_nonce),"zero auth salt or nonce");
    assert(key_commitment(user,key_salt)==part::<268,32>(statement,36),"identity key opening");

    let u=read_scalar(user);assert(!u.is_zero(),"zero wallet identity share");
    let server=read_point(part::<268,64>(statement,68));
    let (key,key_negated)=normalize(add(server,fixed_generator::mul_generator(user)));
    let key_x=key.x.to_be_bytes();
    let timestamp=read_le64(part::<268,8>(statement,132));
    let message=digest(challenge_bytes(timestamp,challenge_nonce,key_negated,key_x));

    // The commitment was frozen before the server nonce existed and fixes the
    // message, so neither blinding nor challenge can be chosen after seeing R_s.
    let data=join(join(join(join(join("ZARK/spark/auth/blinding/v1".as_bytes(),part::<268,140>(statement,0)),message),alpha),beta),salt);
    assert(application_digest(data)==part::<268,32>(statement,140),"auth blinding opening");

    let a=read_scalar(alpha);let b=read_scalar(beta);
    assert(!a.is_zero()&!b.is_zero(),"zero auth blinding scalar");
    let server_nonce=read_point(part::<268,64>(statement,172));
    let (nonce,nonce_negated)=normalize(add(add(server_nonce,fixed_generator::mul_generator(alpha)),bigcurve::glv::mul(server,b)));
    let e=challenge_scalar(digest(join(join(join(join(CHALLENGE_TAG,CHALLENGE_TAG),nonce.x.to_be_bytes()),key_x),message)));
    let c=b+if key_negated!=nonce_negated {e.neg()} else {e};
    assert(c==read_scalar(part::<268,32>(statement,236)),"blinded auth challenge");
}

#[test]
fn challenge_encoding_matches_go_protobuf() {
    // proto.Marshal(&Challenge{Version:1,Timestamp:1700000000,Nonce:[7;32],PublicKey:02||[9;32]})
    let encoded=challenge_bytes(1700000000,[7;32],false,[9;32]);
    assert(part::<77,8>(encoded,0)==[8,1,16,128,226,207,170,6]);
    assert(part::<77,2>(encoded,8)==[26,32]);
    assert(part::<77,3>(encoded,42)==[34,33,2]);
    assert(challenge_bytes(1700000000,[7;32],true,[9;32])[44]==3);
}

#[test(should_fail_with="challenge timestamp varint width")]
fn challenge_rejects_short_varint() {let _=challenge_bytes(((1 as u64)<<28)-1,[7;32],false,[9;32]);}

#[test]
fn key_domain_and_tag_constants() {
    assert(digest("ZARK/spark/joint-identity/key-commit/v1".as_bytes())==KEY_DOMAIN);
    assert(digest("BIP0340/challenge".as_bytes())==CHALLENGE_TAG);
}
