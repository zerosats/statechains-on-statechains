//! Pinned Spark two-group FROST transcript. All commitment points, participant
//! identifiers and binding factors are constrained; no opaque transcript hash
//! or caller challenge substitutes for this relation.
use bitcoin_relations::{add,challenge_scalar,join,normalize,part,read_point,read_scalar,tagged};
use bigcurve::{BigCurve,Secp256k1};
use bignum::{BigNum,Secp256k1_Fr};
use std::ops::Neg;
use crate::plan::compressed;

pub struct JobWitness {
    pub alpha:[u8;32],pub beta:[u8;32],pub tau:[u8;32],pub salt:[u8;32],
    pub operator_ids:[[u8;32];2],pub operator_hiding:[[u8;64];2],pub operator_binding:[[u8;64];2],
    pub wallet_hiding:[u8;32],pub wallet_binding:[u8;32],
}
// RFC9380 expand_message_xmd(SHA256), ell=2, L=48, followed by the pinned
// secp256k1 FromOkm reduction. SHA256 alone is not FROST H1.
fn h1(preimage:[u8;130])->Secp256k1_Fr {
    let dst="FROST-secp256k1-SHA256-TR-v1rho".as_bytes();
    let b0_input:[u8;229]=join(join(join(join([0;64],preimage),[0,48,0]),dst),[31]);
    let b0:[u8;32]=recovery::digest(b0_input);
    let b1_input:[u8;65]=join(join(join(b0,[1]),dst),[31]);
    let b1:[u8;32]=recovery::digest(b1_input);
    let mut xor=[0 as u8;32];for i in 0..32 {xor[i]=b0[i]^b1[i];}
    let b2_input:[u8;65]=join(join(join(xor,[2]),dst),[31]);
    let b2:[u8;32]=recovery::digest(b2_input);
    let uniform:[u8;48]=join(b1,part::<32,16>(b2,0));
    let high=read_scalar(join([0;8],part::<48,24>(uniform,0)));
    let low=read_scalar(join([0;8],part::<48,24>(uniform,24)));
    let mut power=[0 as u8;32];power[7]=1;
    high*read_scalar(power)+low
}
fn item(group:u8,id:[u8;32],h:Secp256k1,b:Secp256k1)->[u8;99] {
    join(join(join([group],id),compressed(h)),compressed(b))
}
fn rho(group:u8,id:[u8;32],output:Secp256k1,h4:[u8;32],h5:[u8;32])->Secp256k1_Fr {
    h1(join(join(join(join([group],compressed(output)),h4),h5),id))
}
pub fn authorize(ctx:[u8;172],plan:[u8;32],server:Secp256k1,server_bytes:[u8;64],
    public:[u8;128],index:u32,message:[u8;32],output:Secp256k1,key_negated:bool,w:JobWitness,
) {
    let a=read_scalar(w.alpha);let b=read_scalar(w.beta);let t=read_scalar(w.tau);
    let d=read_scalar(w.wallet_hiding);let e_wallet=read_scalar(w.wallet_binding);
    assert(!a.is_zero()&!b.is_zero()&!t.is_zero()&!d.is_zero()&!e_wallet.is_zero(),"native nonce scalar zero");
    lineage::nonzero(w.salt);
    let data:[u8;208]=join("ZARK/spark/native/wallet-blinding/v1".as_bytes(),ctx);
    let data:[u8;240]=join(data,plan);
    let data:[u8;304]=join(data,server_bytes);
    let data:[u8;308]=join(data,bitcoin_relations::le32(index));
    let data:[u8;340]=join(data,w.alpha);
    let data:[u8;372]=join(data,w.beta);
    let data:[u8;404]=join(data,w.tau);
    let data:[u8;436]=join(data,w.salt);
    assert(recovery::application_digest(data)==part::<128,32>(public,96),"native frozen blinding opening");
    let id0=read_scalar(w.operator_ids[0]);let id1=read_scalar(w.operator_ids[1]);
    assert(!id0.is_zero()&!id1.is_zero()&(id0<id1),"native selected operator identifiers");
    let h0=read_point(w.operator_hiding[0]);let h1p=read_point(w.operator_hiding[1]);
    let b0=read_point(w.operator_binding[0]);let b1=read_point(w.operator_binding[1]);
    let beta_server=bigcurve::glv::mul(server,b);
    let server_h=add(add(read_point(part::<128,64>(public,0)),fixed_generator::mul_generator(a.to_be_bytes())),beta_server);
    let server_b=fixed_generator::mul_generator(t.to_be_bytes());
    let wallet_h=fixed_generator::mul_generator(d.to_be_bytes());
    let wallet_b=fixed_generator::mul_generator(e_wallet.to_be_bytes());
    let mut wallet_id=[0 as u8;32];wallet_id[31]=1;
    let mut server_id=[0 as u8;32];server_id[31]=2;
    let list:[u8;198]=join(item(0,w.operator_ids[0],h0,b0),item(0,w.operator_ids[1],h1p,b1));
    let list:[u8;297]=join(list,item(1,wallet_id,wallet_h,wallet_b));
    let list:[u8;396]=join(list,item(1,server_id,server_h,server_b));
    let h4_input:[u8;63]=join("FROST-secp256k1-SHA256-TR-v1msg".as_bytes(),message);
    let h5_input:[u8;427]=join("FROST-secp256k1-SHA256-TR-v1com".as_bytes(),list);
    let h4:[u8;32]=recovery::digest(h4_input);
    let h5:[u8;32]=recovery::digest(h5_input);
    let r0=rho(0,w.operator_ids[0],output,h4,h5);let r1=rho(0,w.operator_ids[1],output,h4,h5);
    let rw=rho(1,wallet_id,output,h4,h5);let rs=rho(1,server_id,output,h4,h5);
    let operators=add(add(h0,bigcurve::glv::mul(b0,r0)),add(h1p,bigcurve::glv::mul(b1,r1)));
    // Known wallet/server binding scalars may be combined algebraically; the
    // exact same four point encodings remain individually bound in H5 above.
    let known=d+rw*e_wallet+rs*t;
    let (nonce,nonce_negated)=normalize(add(add(operators,server_h),fixed_generator::mul_generator(known.to_be_bytes())));
    let challenge=challenge_scalar(tagged("BIP0340/challenge".as_bytes(),join(join(nonce.x.to_be_bytes(),output.x.to_be_bytes()),message)));
    let expected=b+if key_negated!=nonce_negated {challenge.neg()}else{challenge};
    assert(read_scalar(part::<128,32>(public,64))==expected,"native blinded FROST challenge");
}
