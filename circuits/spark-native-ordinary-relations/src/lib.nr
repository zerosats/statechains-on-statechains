//! Ordinary single-USER two-refund exit. Separately pinned from legacy native exits.
//! Wrappers authenticate current issuance before this relation constrains the
//! private native plan and complete FROST transcript. Chain freshness, ECIES and
//! durable native VSS/commit reconciliation remain separate native boundaries.
use bitcoin_relations::{add,join,le64,normalize,part,read_point,read_scalar};
use bigcurve::BigCurve;
use bignum::BigNum;
use native::plan;

pub fn authorize(statement:[u8;812],current:[u8;324],current_authorization:[u8;1036],
    user:[u8;32],owner_secret:[u8;32],backing_salt:[u8;32],session_point:[u8;64],
    plan_salt:[u8;32],transfer_id:[u8;16],leaf_id:[u8;16],expiry:u64,anchor_txid:[u8;32],anchor_vout:u32,amount:u64,native_delay:u32,
    operator:[u8;64],mask_user:[u8;64],receiver_identity:[u8;64],mask_cipher_sha256:[u8;32],jobs:[native::frost::JobWitness;2],
) {
    assert(part::<812,4>(statement,0)==[1,0,0,0],"native exit version");
    for i in 0..5 {lineage::nonzero(part::<812,32>(statement,4+32*i));}
    assert(part::<812,8>(statement,164)!=[0;8],"native frozen starting revision");
    for i in 0..5 {lineage::nonzero(part::<812,32>(statement,172+32*i));}
    let domain=part::<812,68>(statement,0);let cfg=part::<812,160>(statement,396);lineage::config(cfg);
    assert(part::<324,68>(current,0)==domain,"native current domain");
    assert(part::<324,32>(current,68)==part::<812,32>(statement,172),"native current backing");
    assert(part::<324,32>(current,100)==part::<812,32>(statement,68),"native current state");
    assert(part::<324,32>(current,132)==part::<812,32>(statement,204),"native current policy");
    assert(part::<324,160>(current,164)==cfg,"native current role registry");
    assert(part::<1036,64>(current_authorization,300)==part::<812,64>(statement,332),"native current server share");
    let capability=part::<812,32>(statement,236);
    assert(part::<1036,32>(current_authorization,812)==capability,"native current capability");
    assert(lineage::capability(domain,owner_secret)==capability,"native private owner opening");
    let session=read_point(session_point);
    assert((session.x.to_be_bytes()==part::<812,32>(statement,132))&((session.y.to_be_bytes()[31]&1)==0),"native session lift");
    let u=read_scalar(user);assert(!u.is_zero(),"native current user share zero");
    let server_bytes=part::<812,64>(statement,332);let server=read_point(server_bytes);
    let raw_user=add(server,fixed_generator::mul_generator(u.to_be_bytes()));
    let (internal,_)=normalize(raw_user);let user_output=plan::bitcoin_key(raw_user);
    let derived=plan::derive(raw_user,user_output,read_point(operator),read_point(mask_user),read_point(receiver_identity),
        anchor_txid,anchor_vout,amount,native_delay,transfer_id,leaf_id,expiry,part::<812,32>(statement,300),mask_cipher_sha256,plan_salt);
    lineage::nonzero(backing_salt);
    let data:[u8;106]=join("ZARK/spark/private-recovery/backing/v1".as_bytes(),domain);
    let data:[u8;138]=join(data,backing_salt);
    let data:[u8;170]=join(data,derived.old_txids[0]);
    let data:[u8;178]=join(data,le64(derived.old_amounts[0]));
    let data:[u8;210]=join(data,derived.old_txids[1]);
    let data:[u8;218]=join(data,le64(derived.old_amounts[1]));
    let data:[u8;250]=join(data,user_output.x.to_be_bytes());
    let data:[u8;282]=join(data,internal.x.to_be_bytes());
    assert(recovery::application_digest(data)==part::<812,32>(statement,172),"native exact authenticated old refunds");
    assert(derived.commitment==part::<812,32>(statement,268),"native salted plan opening");
    assert(part::<812,32>(statement,556)!=part::<812,32>(statement,684),"native signer nonce reuse up to sign");
    assert(part::<812,32>(statement,652)!=part::<812,32>(statement,780),"native blinding commitment reuse");
    assert((jobs[0].alpha!=jobs[1].alpha)&(jobs[0].beta!=jobs[1].beta)&(jobs[0].tau!=jobs[1].tau)&(jobs[0].salt!=jobs[1].salt),"native branch randomness reuse");
    for i in 0..2 {
        let branch=recovery::digest(join(join("ZARK/spark/native/ordinary-branch/v1".as_bytes(),derived.commitment),[i as u8]));
        ordinary::frost::authorize(part::<812,172>(statement,0),branch,server,server_bytes,part::<812,128>(statement,556+128*i),
            derived.sighashes[i],derived.output,derived.key_negated,
            jobs[i].alpha,jobs[i].beta,jobs[i].tau,jobs[i].salt,jobs[i].operator_ids,jobs[i].operator_hiding,jobs[i].operator_binding);
    }
}
