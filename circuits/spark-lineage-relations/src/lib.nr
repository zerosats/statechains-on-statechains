//! Four-role Spark ownership suite. Native exits are deliberately absent.
//! Native signed-prefix validity and live-chain observations remain receiver
//! checks; a private refund opening alone does not establish those facts.
use bitcoin_relations::{join,le32,part,read_point,read_scalar};
use bigcurve::BigCurve;
use bignum::BigNum;
pub mod openings;
pub mod sender;
pub mod receiver;
mod origin_batch;

pub fn nonzero(value:[u8;32]) { assert(bitcoin_relations::is_nonzero(value),"zero Spark ownership field"); }
pub fn digest<let N:u32>(bytes:[u8;N])->[u8;32] {recovery::application_digest(bytes)}
pub fn field(bytes:[u8;32])->Field {
    nonzero(bytes);let mut value=0 as Field;
    for byte in bytes {value=value*256+byte as Field;}
    assert(value.to_be_bytes::<32>()==bytes,"noncanonical Spark role hash");value
}
pub fn config(cfg:[u8;160]) {
    nonzero(part::<160,32>(cfg,0));
    for i in 0..4 {let _=field(part::<160,32>(cfg,32+32*i));for j in 0..4 {if i<j {assert(part::<160,32>(cfg,32+32*i)!=part::<160,32>(cfg,32+32*j),"duplicate Spark role");}}}
}
pub fn role(cfg:[u8;160],index:u32)->[u8;32] {part(cfg,32+32*index)}
pub fn certificate(bytes:[u8;324]) {
    assert(part::<324,4>(bytes,0)==[1,0,0,0],"Spark certificate version");
    for i in 0..5 {nonzero(part::<324,32>(bytes,4+32*i));}config(part::<324,160>(bytes,164));
}
pub fn handover(bytes:[u8;588]) {
    assert(part::<588,4>(bytes,0)==[1,0,0,0],"Spark handover version");
    for i in 0..5 {nonzero(part::<588,32>(bytes,4+32*i));}
    assert(part::<588,8>(bytes,164)!=[0;8],"Spark handover starting revision");
    for i in 0..8 {nonzero(part::<588,32>(bytes,172+32*i));}config(part::<588,160>(bytes,428));
}
pub fn issuance(bytes:[u8;1036]) {
    assert(part::<1036,4>(bytes,0)==[1,0,0,0],"Spark issuance version");
    for i in 0..8 {nonzero(part::<1036,32>(bytes,620+32*i));}
    assert(part::<1036,32>(bytes,780)!=part::<1036,32>(bytes,812),"Spark capability rotation");
    config(part::<1036,160>(bytes,876));
}
pub fn context(auth:[u8;1036])->[u8;204] {join(part::<1036,196>(auth,0),part::<1036,8>(auth,292))}
pub fn intent(auth:[u8;1036])->[u8;172] {join(join(part::<1036,132>(auth,0),part::<1036,32>(auth,620)),part::<1036,8>(auth,292))}
pub fn intent_digest(intent:[u8;172])->[u8;32] {digest(join("ZARK/spark/ownership/intent/v1".as_bytes(),intent))}
pub fn origin_field(domain:[u8;68],index:u32)->[u8;32] {digest(join(join("ZARK/spark/ownership/origin-field/v1".as_bytes(),domain),le32(index)))}
pub fn capability(domain:[u8;68],secret:[u8;32])->[u8;32] {
    let s=read_scalar(secret);assert(!s.is_zero(),"zero Spark owner secret");
    let p=fixed_generator::mul_generator(s.to_be_bytes());assert(!p.is_infinity);
    assert((p.y.to_be_bytes()[31]&1)==0,"normalized Spark owner secret");
    digest(join(join("ZARK/spark/ownership/capability/v1".as_bytes(),domain),p.x.to_be_bytes()))
}
pub fn server_commit(domain:[u8;68],server:[u8;64],salt:[u8;32])->[u8;32] {
    nonzero(salt);let _=read_point(server);digest(join(join(join("ZARK/spark/ownership/server/v1".as_bytes(),domain),server),salt))
}
pub fn state_commit(domain:[u8;68],backing:[u8;32],cap:[u8;32],recovery:[u8;32],server:[u8;32],policy:[u8;32],issued:[u8;32])->[u8;32] {
    digest(join(join(join(join(join(join(join("ZARK/spark/ownership/state/v1".as_bytes(),domain),backing),cap),recovery),server),policy),issued))
}
pub fn verify<let N:u32,let K:u32>(vk:[Field;115],proof:[Field;458],bytes:[u8;N],allowed:[u8;32]) {
    let approved=field(allowed);common::verify_zk(vk,proof,packing::pack::<N,K>(bytes),approved,approved);
}
pub fn verify_sender(statement:[u8;588],vk:[Field;115],proof:[Field;458],cfg:[u8;160]) {
    handover(statement);assert(part::<588,160>(statement,428)==cfg,"Spark sender config");
    let actual=common::hash(vk);assert((actual==field(role(cfg,1)))|(actual==field(role(cfg,2))),"Spark sender role");
    std::verify_proof_with_type(vk,proof,packing::pack::<588,19>(statement),actual,6);
}
// Commitment binding only: the caller must also verify BOTH issued responses.
// Keep this private so callers cannot mistake a committed response for a valid
// signer response. Origin checks them in its batch; authorized_state checks
// each equation separately and retains its existing public contract.
fn issued_state_binding(current:[u8;324],auth:[u8;1036],partials:[[u8;32];2],salt:[u8;32]) {
    certificate(current);issuance(auth);
    assert(part::<324,68>(current,0)==part::<1036,68>(auth,0),"Spark issued domain");
    assert(part::<324,32>(current,68)==part::<1036,32>(auth,196),"Spark issued backing");
    assert(part::<324,32>(current,132)==part::<1036,32>(auth,260),"Spark issued policy");
    assert(part::<324,160>(current,164)==part::<1036,160>(auth,876),"Spark issued config");
    let domain=part::<1036,68>(auth,0);
    let server=server_commit(domain,part::<1036,64>(auth,300),salt);
    assert(server==part::<1036,32>(auth,844),"Spark issued server opening");
    let authorization=digest(join("ZARK/spark/ownership/authorization/v1".as_bytes(),auth));
    let issued=digest(join(join(join("ZARK/spark/ownership/issuance/v1".as_bytes(),authorization),partials[0]),partials[1]));
    assert(state_commit(domain,part::<1036,32>(auth,196),part::<1036,32>(auth,812),part::<1036,32>(auth,228),server,part::<1036,32>(auth,260),issued)==part::<324,32>(current,100),"Spark exact issued state");
}
// An actual post-issuance state requires BOTH responses, never a placeholder.
// This public helper continues to establish both exact partial equations.
pub fn authorized_state(current:[u8;324],auth:[u8;1036],partials:[[u8;32];2],salt:[u8;32]) {
    issued_state_binding(current,auth,partials,salt);
    recovery::verify_partial(read_point(part::<1036,64>(auth,300)),read_point(part::<1036,64>(auth,364)),read_scalar(part::<1036,32>(auth,428)),partials[0]);
    recovery::verify_partial(read_point(part::<1036,64>(auth,300)),read_point(part::<1036,64>(auth,492)),read_scalar(part::<1036,32>(auth,556)),partials[1]);
}
pub fn verify_origin(current:[u8;324],auth:[u8;1036],vk:[Field;115],proof:[Field;458],partials:[[u8;32];2],salt:[u8;32],origin_key:[u8;64],origin_nonce:[u8;64],signature:[u8;64],cfg:[u8;160]) {
    assert(part::<324,160>(current,164)==cfg,"Spark origin config");
    // The prior proof authenticates pre-issuance authorization bytes only. The
    // exact completed-state binding and both post-proof signer responses below
    // remain necessary, as does the trusted post-issuance origin attestation.
    verify::<1036,34>(vk,proof,auth,role(cfg,0));
    issued_state_binding(current,auth,partials,salt);
    origin_batch::verify(current,auth,partials,salt,origin_key,origin_nonce,signature,cfg);
}
pub fn verify_transfer(current:[u8;324],auth:[u8;1036],vk:[Field;115],proof:[Field;458],partials:[[u8;32];2],salt:[u8;32],cfg:[u8;160]) {
    assert(part::<324,160>(current,164)==cfg,"Spark predecessor config");
    verify::<1036,34>(vk,proof,auth,role(cfg,3));authorized_state(current,auth,partials,salt);
}
