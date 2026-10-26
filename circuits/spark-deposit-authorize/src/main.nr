//! Origin dual recovery issuance; signed Spark prefix and live backing are
//! privately checked by clients. Trusted post-issuance origin attestation plus
//! one durable allocation per coin prevent peers from inventing origin lineage.
use bitcoin_relations::{join,part,read_point};
use bigcurve::BigCurve;
use bignum::BigNum;
fn main(
    packed:pub [Field;34],statement:[u8;1036],user:[u8;32],funding_salt:[u8;32],recovery_salt:[u8;32],
    payout:[u8;64],fee:u64,delay:u32,owner_index:u32,initial:u32,gap:u32,margin:u32,
    txid_0:[u8;32],amount_0:u64,alpha_0:[u8;32],beta_0:[u8;32],nonce_salt_0:[u8;32],
    txid_1:[u8;32],amount_1:u64,alpha_1:[u8;32],beta_1:[u8;32],nonce_salt_1:[u8;32],
    owner_secret:[u8;32],server_salt:[u8;32],session_point:[u8;64],
) {
    packing::bind::<1036,34>(statement,packed);lineage::issuance(statement);
    spark::authorize(part::<1036,620>(statement,0),user,funding_salt,recovery_salt,payout,fee,delay,owner_index,initial,gap,margin,
        txid_0,amount_0,alpha_0,beta_0,nonce_salt_0,txid_1,amount_1,alpha_1,beta_1,nonce_salt_1);
    let domain=part::<1036,68>(statement,0);
    assert(part::<1036,32>(statement,68)==lineage::digest(join("ZARK/spark/ownership/origin-predecessor/v1".as_bytes(),domain)),"Spark fresh origin predecessor");
    assert(part::<1036,8>(statement,292)==[1,0,0,0,0,0,0,0],"Spark origin starting CAS revision");
    assert(owner_index==1,"Spark initial owner slot");
    for i in 0..6 {assert(part::<1036,32>(statement,620+32*i)==lineage::origin_field(domain,i),"Spark origin sentinel");}
    assert(lineage::capability(domain,owner_secret)==part::<1036,32>(statement,812),"Spark origin owner capability");
    assert(lineage::server_commit(domain,part::<1036,64>(statement,300),server_salt)==part::<1036,32>(statement,844),"Spark allocated origin server opening");
    let session=read_point(session_point);assert((session.y.to_be_bytes()[31]&1)==0,"Spark origin session parity");
    assert(session.x.to_be_bytes()==part::<1036,32>(statement,132),"Spark origin session lift");
    lineage::openings::draft(statement,payout,fee,delay,recovery_salt);
}
