//! Private openings shared by sender, deposit and receiver roles.
use bitcoin_relations::{add,join,le32,le64,normalize,part,read_point,read_scalar};
use bigcurve::BigCurve;
use bignum::BigNum;
use crate::{context,digest,nonzero};

pub fn policy(initial:u32,gap:u32,margin:u32)->[u8;32] {
    assert((initial>0)&(initial<=65535),"Spark initial delay");
    assert((gap>0)&(gap<=65535),"Spark delay gap");
    assert((margin>0)&(margin<gap),"Spark safety margin");
    assert(initial>=7*gap+margin,"Spark owner schedule budget");
    digest(join(join(join(join(join("ZARK/spark/private-recovery/policy/v1".as_bytes(),[1,0,0,0]),le32(initial)),le32(gap)),le32(margin)),le32(8)))
}
pub fn backing(auth:[u8;1036],user:[u8;32],salt:[u8;32],txid_0:[u8;32],amount_0:u64,txid_1:[u8;32],amount_1:u64) {
    backing_fields(salt,txid_0,amount_0,txid_1,amount_1);
    let keys=recovery::derive_keys(part::<1036,64>(auth,300),user);
    backing_key_opening(auth,salt,txid_0,amount_0,txid_1,amount_1,
        keys.output().x.to_be_bytes(),keys.internal().x.to_be_bytes());
}

// Only use after recursively authenticating a deposit/receiver predecessor and
// binding its deployment, coin, backing commitment and role configuration. The
// predecessor established TapTweak; opening that exact commitment reuses its
// output x while still proving knowledge of this owner's nonzero additive share.
// This helper alone does not establish that an arbitrary output x is TapTweaked.
pub fn backing_with_authenticated_output_key(
    auth:[u8;1036],user:[u8;32],salt:[u8;32],funding_output_key:[u8;32],
    txid_0:[u8;32],amount_0:u64,txid_1:[u8;32],amount_1:u64,
) {
    backing_fields(salt,txid_0,amount_0,txid_1,amount_1);
    let server=read_point(part::<1036,64>(auth,300));
    let u=read_scalar(user);assert(!u.is_zero(),"nonzero Spark sender user share");
    let (internal,_)=normalize(add(server,fixed_generator::mul_generator(u.to_be_bytes())));
    backing_key_opening(auth,salt,txid_0,amount_0,txid_1,amount_1,
        funding_output_key,internal.x.to_be_bytes());
}

fn backing_fields(salt:[u8;32],txid_0:[u8;32],amount_0:u64,txid_1:[u8;32],amount_1:u64) {
    nonzero(salt);nonzero(txid_0);nonzero(txid_1);assert(txid_0!=txid_1,"Spark refund distinction");
    assert((amount_0>0)&(amount_0<=2_100_000_000_000_000),"Spark first refund amount");
    assert((amount_1>0)&(amount_1<=2_100_000_000_000_000),"Spark second refund amount");
}

// Both the full derivation and authenticated reuse must open identical bytes,
// including the fixed CPFP/direct-from-CPFP refund order and both key x values.
fn backing_key_opening(
    auth:[u8;1036],salt:[u8;32],txid_0:[u8;32],amount_0:u64,txid_1:[u8;32],amount_1:u64,
    output:[u8;32],internal:[u8;32],
) {
    let bytes=join("ZARK/spark/private-recovery/backing/v1".as_bytes(),[1,0,0,0]);
    let bytes=join(bytes,part::<1036,32>(auth,4));
    let bytes=join(bytes,part::<1036,32>(auth,36));
    let bytes=join(bytes,salt);
    let bytes=join(bytes,txid_0);
    let bytes=join(bytes,le64(amount_0));
    let bytes=join(bytes,txid_1);
    let bytes=join(bytes,le64(amount_1));
    let bytes=join(bytes,output);
    let bytes=join(bytes,internal);
    assert(digest(bytes)==part::<1036,32>(auth,196),"Spark private backing opening");
}
pub fn target(auth:[u8;1036],payout:[u8;64],fee:u64,delay:u32,owner_index:u32,salt:[u8;32],initial:u32,gap:u32,margin:u32) {
    nonzero(salt);assert((fee>0)&(fee<=10000),"Spark recovery fee");
    assert((owner_index>=1)&(owner_index<=8),"Spark private owner index");
    assert(policy(initial,gap,margin)==part::<1036,32>(auth,260),"Spark policy opening");
    assert(delay==initial-(owner_index-1)*gap,"Spark recovery schedule opening");
    let p=read_point(payout);assert((p.y.to_be_bytes()[31]&1)==0,"Spark payout parity");
    let bytes=join("ZARK/spark/private-recovery/target/v1".as_bytes(),context(auth));
    let bytes=join(bytes,part::<1036,32>(auth,196));
    let bytes=join(bytes,salt);
    let bytes=join(bytes,p.x.to_be_bytes());
    let bytes=join(bytes,le64(fee));
    let opened=digest(join(bytes,le32(delay)));
    assert(opened==part::<1036,32>(auth,228),"Spark private recovery opening");
}
pub fn draft(auth:[u8;1036],payout:[u8;64],fee:u64,delay:u32,salt:[u8;32]) {
    let bytes=join("ZARK/spark/ownership/draft-state/v1".as_bytes(),part::<1036,164>(auth,0));
    let bytes=join(bytes,part::<1036,8>(auth,292));
    let bytes=join(bytes,part::<1036,32>(auth,196));
    let bytes=join(bytes,part::<1036,32>(auth,812));
    let bytes=join(bytes,part::<1036,32>(auth,844));
    let bytes=join(bytes,part::<1036,32>(auth,260));
    let bytes=join(bytes,salt);
    let bytes=join(bytes,part::<64,32>(payout,0));
    let bytes=join(bytes,le64(fee));
    let draft=digest(join(bytes,le32(delay)));
    assert(draft==part::<1036,32>(auth,164),"Spark exact preissuance draft");
}

global TEST_SERVER:[u8;64]=[121,190,102,126,249,220,187,172,85,160,98,149,206,135,11,7,2,155,252,219,45,206,40,217,89,242,129,91,22,248,23,152,72,58,218,119,38,163,196,101,93,164,251,252,14,17,8,168,253,23,180,72,166,133,84,25,156,71,208,143,251,16,212,184];

fn test_user(value:u8)->[u8;32] {let mut user=[0 as u8;32];user[31]=value;user}

// Synthetic opening authenticated by the original full derivation. The fixture
// serializes the pre-optimization backing bytes independently of the reuse path.
fn test_backing()->([u8;1036],[u8;32]) {
    let mut auth=[0 as u8;1036];auth[0]=1;
    for i in 0..32 {auth[4+i]=1;auth[36+i]=2;}
    for i in 0..64 {auth[300+i]=TEST_SERVER[i];}
    let keys=recovery::derive_keys(TEST_SERVER,test_user(5));
    let output=keys.output().x.to_be_bytes();
    let bytes=join("ZARK/spark/private-recovery/backing/v1".as_bytes(),[1,0,0,0]);
    let bytes=join(join(join(bytes,[1 as u8;32]),[2 as u8;32]),[3 as u8;32]);
    let bytes=join(join(join(join(bytes,[4 as u8;32]),le64(100000)),[5 as u8;32]),le64(200000));
    let commitment=digest(join(join(bytes,output),keys.internal().x.to_be_bytes()));
    for i in 0..32 {auth[196+i]=commitment[i];}
    backing(auth,test_user(5),[3;32],[4;32],100000,[5;32],200000);
    (auth,output)
}

#[test]
fn authenticated_output_matches_full_backing() {
    let (auth,output)=test_backing();
    backing_with_authenticated_output_key(auth,test_user(5),[3;32],output,[4;32],100000,[5;32],200000);
}

#[test(should_fail_with="Spark private backing opening")]
fn authenticated_output_rejects_another_output() {
    let (auth,output)=test_backing();let mut output=output;output[31]=output[31]^1;
    backing_with_authenticated_output_key(auth,test_user(5),[3;32],output,[4;32],100000,[5;32],200000);
}

#[test(should_fail_with="Spark private backing opening")]
fn authenticated_output_rejects_another_user_share() {
    let (auth,output)=test_backing();
    backing_with_authenticated_output_key(auth,test_user(6),[3;32],output,[4;32],100000,[5;32],200000);
}

#[test(should_fail_with="Spark private backing opening")]
fn authenticated_output_rejects_another_server_share() {
    let (auth,output)=test_backing();let mut auth=auth;
    let server=fixed_generator::mul_generator(test_user(2));
    let bytes=join(server.x.to_be_bytes(),server.y.to_be_bytes());
    for i in 0..64 {auth[300+i]=bytes[i];}
    backing_with_authenticated_output_key(auth,test_user(5),[3;32],output,[4;32],100000,[5;32],200000);
}

#[test(should_fail_with="nonzero Spark sender user share")]
fn authenticated_output_rejects_zero_user() {
    let (auth,output)=test_backing();
    backing_with_authenticated_output_key(auth,[0;32],[3;32],output,[4;32],100000,[5;32],200000);
}

#[test(should_fail_with="non-canonical scalar")]
fn authenticated_output_rejects_noncanonical_user() {
    let (auth,output)=test_backing();
    let order:[u8;32]=[255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,254,186,174,220,230,175,72,160,59,191,210,94,140,208,54,65,65];
    backing_with_authenticated_output_key(auth,order,[3;32],output,[4;32],100000,[5;32],200000);
}

#[test(should_fail_with="non-canonical coordinate")]
fn authenticated_output_rejects_noncanonical_server() {
    let (auth,output)=test_backing();let mut auth=auth;
    let modulus:[u8;32]=[255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,254,255,255,252,47];
    for i in 0..32 {auth[300+i]=modulus[i];}
    backing_with_authenticated_output_key(auth,test_user(5),[3;32],output,[4;32],100000,[5;32],200000);
}

#[test(should_fail_with="Spark private backing opening")]
fn authenticated_output_rejects_swapped_refunds() {
    let (auth,output)=test_backing();
    backing_with_authenticated_output_key(auth,test_user(5),[3;32],output,[5;32],200000,[4;32],100000);
}

#[test(should_fail_with="Spark private backing opening")]
fn authenticated_output_rejects_changed_second_amount() {
    let (auth,output)=test_backing();
    backing_with_authenticated_output_key(auth,test_user(5),[3;32],output,[4;32],100000,[5;32],200001);
}

#[test(should_fail_with="Spark private backing opening")]
fn authenticated_output_rejects_another_deployment() {
    let (auth,output)=test_backing();let mut auth=auth;auth[4]=6;
    backing_with_authenticated_output_key(auth,test_user(5),[3;32],output,[4;32],100000,[5;32],200000);
}

#[test(should_fail_with="Spark private backing opening")]
fn authenticated_output_rejects_another_coin() {
    let (auth,output)=test_backing();let mut auth=auth;auth[36]=6;
    backing_with_authenticated_output_key(auth,test_user(5),[3;32],output,[4;32],100000,[5;32],200000);
}
