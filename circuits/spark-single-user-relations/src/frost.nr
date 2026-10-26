//! Canonical identifier sorting and untagged ordinary FROST binding factors.
use bitcoin_relations::{add,join,part,read_point,read_scalar,challenge_scalar,normalize,tagged};
use bigcurve::{BigCurve,Secp256k1};
use bignum::{BigNum,Secp256k1_Fr};
use std::ops::Neg;
use native::plan::compressed;
fn h1(preimage:[u8;129])->Secp256k1_Fr {
    let dst="FROST-secp256k1-SHA256-TR-v1rho".as_bytes();
    let input:[u8;228]=join(join(join(join([0;64],preimage),[0,48,0]),dst),[31]);
    let b0:[u8;32]=recovery::digest(input);
    let b1:[u8;32]=recovery::digest(join(join(join(b0,[1]),dst),[31]));
    let mut xor=[0 as u8;32];for i in 0..32 {xor[i]=b0[i]^b1[i];}
    let b2:[u8;32]=recovery::digest(join(join(join(xor,[2]),dst),[31]));
    let uniform:[u8;48]=join(b1,part::<32,16>(b2,0));
    let high=read_scalar(join([0;8],part::<48,24>(uniform,0)));let low=read_scalar(join([0;8],part::<48,24>(uniform,24)));
    let mut power=[0 as u8;32];power[7]=1;high*read_scalar(power)+low
}
fn item(id:[u8;32],h:Secp256k1,b:Secp256k1)->[u8;98] {join(join(id,compressed(h)),compressed(b))}
fn rho(id:[u8;32],output:Secp256k1,h4:[u8;32],h5:[u8;32])->Secp256k1_Fr {h1(join(join(join(compressed(output),h4),h5),id))}
pub fn authorize(ctx:[u8;172],plan:[u8;32],server:Secp256k1,server_bytes:[u8;64],public:[u8;128],message:[u8;32],output:Secp256k1,key_negated:bool,
    alpha:[u8;32],beta:[u8;32],tau:[u8;32],salt:[u8;32],ids:[[u8;32];2],hs:[[u8;64];2],bs:[[u8;64];2],
) {
    let a=read_scalar(alpha);let b=read_scalar(beta);let t=read_scalar(tau);
    assert(!a.is_zero()&!b.is_zero()&!t.is_zero(),"single-USER blinding scalar zero");lineage::nonzero(salt);
    let data=join(join(join(join(join(join(join("ZARK/spark/single-user/blinding/v1".as_bytes(),ctx),plan),server_bytes),alpha),beta),tau),salt);
    assert(recovery::application_digest(data)==part::<128,32>(public,96),"single-USER frozen opening");
    let user_id:[u8;32]=[104,125,166,77,82,161,108,111,199,146,198,252,131,30,193,175,167,151,169,31,119,84,150,104,166,181,66,31,18,193,172,119];
    let i0=read_scalar(ids[0]);let i1=read_scalar(ids[1]);let iu=read_scalar(user_id);
    assert(!i0.is_zero()&!i1.is_zero()&(i0<i1)&(i0!=iu)&(i1!=iu),"single-USER selected operator IDs");
    let h0=read_point(hs[0]);let h1p=read_point(hs[1]);let b0=read_point(bs[0]);let b1=read_point(bs[1]);
    let user_h=add(add(read_point(part::<128,64>(public,0)),fixed_generator::mul_generator(alpha)),bigcurve::glv::mul(server,b));
    let user_b=fixed_generator::mul_generator(tau);
    let op0=item(ids[0],h0,b0);let op1=item(ids[1],h1p,b1);let user=item(user_id,user_h,user_b);
    let list:[u8;294]=if iu<i0 {join(join(user,op0),op1)}else if iu<i1 {join(join(op0,user),op1)}else{join(join(op0,op1),user)};
    let h4:[u8;32]=recovery::digest(join("FROST-secp256k1-SHA256-TR-v1msg".as_bytes(),message));
    let h5:[u8;32]=recovery::digest(join("FROST-secp256k1-SHA256-TR-v1com".as_bytes(),list));
    let r0=rho(ids[0],output,h4,h5);let r1=rho(ids[1],output,h4,h5);let ru=rho(user_id,output,h4,h5);
    let operators=add(add(h0,bigcurve::glv::mul(b0,r0)),add(h1p,bigcurve::glv::mul(b1,r1)));
    let (nonce,nonce_negated)=normalize(add(add(operators,user_h),fixed_generator::mul_generator((ru*t).to_be_bytes())));
    let e=challenge_scalar(tagged("BIP0340/challenge".as_bytes(),join(join(nonce.x.to_be_bytes(),output.x.to_be_bytes()),message)));
    assert(read_scalar(part::<128,32>(public,64))==b+if key_negated!=nonce_negated {e.neg()}else{e},"single-USER blinded challenge");
}
