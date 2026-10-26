//! Fresh-allocation receive role; no old native or issued ownership proof can
//! stand in for this relation. Both ordinary USER claims pay the same key.
use bitcoin_relations::{add,join,le32,le64,normalize,part,read_point,read_scalar};
use bigcurve::BigCurve;
use bignum::BigNum;
pub struct Job {
    pub alpha:[u8;32],pub beta:[u8;32],pub tau:[u8;32],pub salt:[u8;32],
    pub operator_ids:[[u8;32];2],pub operator_hiding:[[u8;64];2],pub operator_binding:[[u8;64];2],
}
pub fn authorize(statement:[u8;812],user:[u8;32],owner_secret:[u8;32],backing_salt:[u8;32],session_point:[u8;64],
    plan_salt:[u8;32],anchor_txid:[u8;32],anchor_vout:u32,amount:u64,native_delay:u32,operator:[u8;64],jobs:[Job;2],
) {
    assert(part::<812,4>(statement,0)==[1,0,0,0],"receive version");
    for i in 0..5 {lineage::nonzero(part::<812,32>(statement,4+32*i));lineage::nonzero(part::<812,32>(statement,172+32*i));}
    assert(part::<812,8>(statement,164)==[1,0,0,0,0,0,0,0],"receive fresh allocation revision");
    let domain=part::<812,68>(statement,0);
    let predecessor=lineage::digest(join("ZARK/spark/ownership/origin-predecessor/v1".as_bytes(),domain));
    assert(part::<812,32>(statement,68)==predecessor,"receive origin predecessor");
    lineage::config(part::<812,160>(statement,396));
    assert(lineage::capability(domain,owner_secret)==part::<812,32>(statement,236),"receive initial owner capability");
    let session=read_point(session_point);
    assert((session.x.to_be_bytes()==part::<812,32>(statement,132))&((session.y.to_be_bytes()[31]&1)==0),"receive session lift");
    let u=read_scalar(user);assert(!u.is_zero(),"receive zero wallet share");
    let server_bytes=part::<812,64>(statement,332);let server=read_point(server_bytes);
    let raw_user=add(server,fixed_generator::mul_generator(u.to_be_bytes()));
    let (internal,_)=normalize(raw_user);let user_output=native::plan::bitcoin_key(raw_user);
    assert((amount>0)&(amount<=2_100_000_000_000_000),"receive amount bound");
    assert((native_delay>=200)&(native_delay<=1900)&(native_delay%100==0),"receive root refund window");
    lineage::nonzero(anchor_txid);lineage::nonzero(plan_salt);lineage::nonzero(backing_salt);
    assert(plan_salt!=backing_salt,"receive distinct private salts");
    let op=read_point(operator);let (output,negated)=native::plan::combined_key(add(raw_user,op));
    let root=native::plan::txid(native::plan::transaction(anchor_txid,anchor_vout,1<<30,2,native::plan::anchored_outputs(amount,output.x.to_be_bytes())));
    let direct=if amount>955 {amount-955}else{amount};
    let tx0=native::plan::txid(native::plan::transaction(root,0,(1<<30)|native_delay,2,native::plan::anchored_outputs(amount,user_output.x.to_be_bytes())));
    let tx1=native::plan::txid(native::plan::transaction(root,0,(1<<30)|(native_delay+50),1,native::plan::outputs(direct,user_output.x.to_be_bytes())));
    let m0=native::plan::sighash(root,amount,output.x.to_be_bytes(),(1<<30)|native_delay,native::plan::anchored_outputs(amount,user_output.x.to_be_bytes()));
    let m1=native::plan::sighash(root,amount,output.x.to_be_bytes(),(1<<30)|(native_delay+50),native::plan::outputs(direct,user_output.x.to_be_bytes()));
    let data=join("ZARK/spark/private-recovery/backing/v1".as_bytes(),domain);
    let data=join(join(join(join(join(join(join(data,backing_salt),tx0),le64(amount)),tx1),le64(direct)),user_output.x.to_be_bytes()),internal.x.to_be_bytes());
    assert(recovery::application_digest(data)==part::<812,32>(statement,172),"receive exact future backing");
    let plan=join("ZARK/spark/receive/plan/v1".as_bytes(),root);
    let plan=join(join(join(join(join(join(join(join(plan,le64(amount)),le32(native_delay)),bitcoin_relations::join(raw_user.x.to_be_bytes(),raw_user.y.to_be_bytes())),operator),part::<812,32>(statement,300)),tx0),tx1),plan_salt);
    let plan=recovery::digest(plan);assert(plan==part::<812,32>(statement,268),"receive salted native plan");
    assert(part::<812,32>(statement,556)!=part::<812,32>(statement,684),"receive original nonce sign reuse");
    assert(part::<812,32>(statement,652)!=part::<812,32>(statement,780),"receive branch commitment reuse");
    for i in 0..2 {
        if i==1 {assert((jobs[0].alpha!=jobs[1].alpha)&(jobs[0].beta!=jobs[1].beta)&(jobs[0].tau!=jobs[1].tau)&(jobs[0].salt!=jobs[1].salt),"receive independent branch blinding");}
        let branch=recovery::digest(join(join("ZARK/spark/receive/branch/v1".as_bytes(),plan),[i as u8]));
        ordinary::frost::authorize(part::<812,172>(statement,0),branch,server,server_bytes,part::<812,128>(statement,556+128*i),if i==0 {m0}else{m1},output,negated,
            jobs[i].alpha,jobs[i].beta,jobs[i].tau,jobs[i].salt,jobs[i].operator_ids,jobs[i].operator_hiding,jobs[i].operator_binding);
    }
}
