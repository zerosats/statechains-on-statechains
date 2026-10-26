//! One ordinary USER contribution; no group tags or sub-user positions.
use bitcoin_relations::{add,join,le32,le64,normalize,part,read_point,read_scalar};
use bigcurve::BigCurve;
use bignum::BigNum;
pub mod frost;

pub fn authorize(statement:[u8;652],current:[u8;324],authorization:[u8;1036],
    user:[u8;32],owner_secret:[u8;32],backing_salt:[u8;32],session_point:[u8;64],
    plan_salt:[u8;32],anchor_txid:[u8;32],anchor_vout:u32,amount:u64,native_delay:u32,operator:[u8;64],receiver:[u8;64],variant:u8,
    alpha:[u8;32],beta:[u8;32],tau:[u8;32],salt:[u8;32],operator_ids:[[u8;32];2],operator_hiding:[[u8;64];2],operator_binding:[[u8;64];2],
) {
    assert(part::<652,4>(statement,0)==[1,0,0,0],"single-USER version");
    for i in 0..5 {lineage::nonzero(part::<652,32>(statement,4+32*i));}
    assert(part::<652,8>(statement,164)!=[0;8],"single-USER starting revision");
    for i in 0..4 {lineage::nonzero(part::<652,32>(statement,172+32*i));}
    let domain=part::<652,68>(statement,0);let cfg=part::<652,160>(statement,364);lineage::config(cfg);
    assert(part::<324,68>(current,0)==domain,"single-USER current domain");
    assert(part::<324,32>(current,68)==part::<652,32>(statement,172),"single-USER backing");
    assert(part::<324,32>(current,100)==part::<652,32>(statement,68),"single-USER current state");
    assert(part::<324,32>(current,132)==part::<652,32>(statement,204),"single-USER policy");
    assert(part::<324,160>(current,164)==cfg,"single-USER ownership registry");
    let server_bytes=part::<652,64>(statement,300);let server=read_point(server_bytes);
    assert(part::<1036,64>(authorization,300)==server_bytes,"single-USER current server");
    let capability=part::<652,32>(statement,236);
    assert(part::<1036,32>(authorization,812)==capability,"single-USER current capability");
    assert(lineage::capability(domain,owner_secret)==capability,"single-USER owner opening");
    let session=read_point(session_point);
    assert((session.x.to_be_bytes()==part::<652,32>(statement,132))&((session.y.to_be_bytes()[31]&1)==0),"single-USER session lift");
    let u=read_scalar(user);assert(!u.is_zero(),"single-USER zero wallet share");
    let raw_user=add(server,fixed_generator::mul_generator(u.to_be_bytes()));
    let (internal,_)=normalize(raw_user);let user_output=native::plan::bitcoin_key(raw_user);
    assert((amount>0)&(amount<=2_100_000_000_000_000),"single-USER amount");
    assert((native_delay>=200)&(native_delay<=2000)&(native_delay%100==0)&(variant<2),"single-USER profile");
    lineage::nonzero(anchor_txid);lineage::nonzero(plan_salt);lineage::nonzero(backing_salt);
    let operator=read_point(operator);let receiver=read_point(receiver);
    let (output,negated)=native::plan::combined_key(add(raw_user,operator));
    let root=native::plan::txid(native::plan::transaction(anchor_txid,anchor_vout,1<<30,2,native::plan::anchored_outputs(amount,output.x.to_be_bytes())));
    let direct=if amount>955 {amount-955}else{amount};
    let old0=native::plan::txid(native::plan::transaction(root,0,(1<<30)|native_delay,2,native::plan::anchored_outputs(amount,user_output.x.to_be_bytes())));
    let old1=native::plan::txid(native::plan::transaction(root,0,(1<<30)|(native_delay+50),1,native::plan::outputs(direct,user_output.x.to_be_bytes())));
    let data:[u8;106]=join("ZARK/spark/private-recovery/backing/v1".as_bytes(),domain);
    let data:[u8;138]=join(data,backing_salt);let data:[u8;170]=join(data,old0);
    let data:[u8;178]=join(data,le64(amount));let data:[u8;210]=join(data,old1);
    let data:[u8;218]=join(data,le64(direct));let data:[u8;250]=join(data,user_output.x.to_be_bytes());
    let data:[u8;282]=join(data,internal.x.to_be_bytes());
    assert(recovery::application_digest(data)==part::<652,32>(statement,172),"single-USER exact authenticated backing");
    let destination=native::plan::bitcoin_key(receiver).x.to_be_bytes();
    let next=native_delay-100;
    let txid0=native::plan::txid(native::plan::transaction(root,0,(1<<30)|next,2,native::plan::anchored_outputs(amount,destination)));
    let txid1=native::plan::txid(native::plan::transaction(root,0,(1<<30)|(next+50),1,native::plan::outputs(direct,destination)));
    let message0=native::plan::sighash(root,amount,output.x.to_be_bytes(),(1<<30)|next,native::plan::anchored_outputs(amount,destination));
    let message1=native::plan::sighash(root,amount,output.x.to_be_bytes(),(1<<30)|(next+50),native::plan::outputs(direct,destination));
    let new_txid=if variant==0 {txid0}else{txid1};let message=if variant==0 {message0}else{message1};
    let plan=join("ZARK/spark/single-user/plan/v1".as_bytes(),root);
    let plan=join(join(plan,le64(amount)),le32(native_delay));
    let plan=join(join(join(plan,native::plan::compressed(raw_user)),native::plan::compressed(operator)),native::plan::compressed(receiver));
    let plan=join(join(join(plan,[variant]),new_txid),plan_salt);
    let plan=recovery::digest(plan);
    assert(plan==part::<652,32>(statement,268),"single-USER salted signing plan");
    frost::authorize(part::<652,172>(statement,0),plan,server,server_bytes,part::<652,128>(statement,524),message,output,negated,
        alpha,beta,tau,salt,operator_ids,operator_hiding,operator_binding);
}
