//! Sender ownership relation, composed with an authenticated predecessor role.
use bitcoin_relations::{join,le32,part,read_scalar};
use bignum::BigNum;
use crate::{capability,digest,intent_digest,nonzero,openings};

// The entrypoint must first recursively authenticate the predecessor. Its exact
// backing/configuration bindings below are what permit reusing the output key;
// an unauthenticated backing opening cannot replace the TapTweak relation.
pub fn authorize(
    statement:[u8;588],token:[u8;32],previous:[u8;324],previous_authorization:[u8;1036],
    server:[u8;64],server_salt:[u8;32],user:[u8;32],owner_secret:[u8;32],
    mask:[u8;32],mask_salt:[u8;32],masked:[u8;32],masked_salt:[u8;32],
    funding_salt:[u8;32],funding_output_key:[u8;32],txid_0:[u8;32],amount_0:u64,txid_1:[u8;32],amount_1:u64,
    payout:[u8;64],fee:u64,delay:u32,owner_index:u32,recovery_salt:[u8;32],bridge_salt:[u8;32],
    initial:u32,gap:u32,margin:u32,
) {
    crate::handover(statement);crate::certificate(previous);crate::issuance(previous_authorization);
    assert(part::<588,68>(statement,0)==part::<324,68>(previous,0),"Spark predecessor domain");
    assert(part::<588,32>(statement,68)==part::<324,32>(previous,100),"Spark predecessor state");
    assert(part::<588,32>(statement,172)==part::<324,32>(previous,68),"Spark predecessor backing");
    assert(part::<588,32>(statement,364)==part::<324,32>(previous,132),"Spark predecessor policy");
    assert(part::<588,160>(statement,428)==part::<324,160>(previous,164),"Spark predecessor role config");
    assert(server==part::<1036,64>(previous_authorization,300),"Spark current private server share");
    assert(crate::server_commit(part::<588,68>(statement,0),server,server_salt)==part::<588,32>(statement,332),"Spark sender server opening");
    assert(part::<588,32>(statement,332)==part::<1036,32>(previous_authorization,844),"Spark predecessor server commitment");
    let cap=capability(part::<588,68>(statement,0),owner_secret);
    assert(cap==part::<588,32>(statement,300),"Spark current capability opening");
    assert(cap==part::<1036,32>(previous_authorization,812),"Spark predecessor capability");
    openings::backing_with_authenticated_output_key(previous_authorization,user,funding_salt,
        funding_output_key,txid_0,amount_0,txid_1,amount_1);
    openings::target(previous_authorization,payout,fee,delay,owner_index,recovery_salt,initial,gap,margin);
    assert(owner_index<8,"Spark final owner cannot transfer");
    let u=read_scalar(user);let m=read_scalar(mask);let z=read_scalar(masked);
    assert(!u.is_zero()&!m.is_zero()&!z.is_zero(),"nonzero Spark sender shares");
    assert(z==u+m,"Spark masked sender conservation");
    nonzero(token);nonzero(mask_salt);nonzero(masked_salt);nonzero(bridge_salt);
    let intent=part::<588,172>(statement,0);let intent_hash=intent_digest(intent);
    assert(digest(join(join("ZARK/spark/ownership/draft-token/v1".as_bytes(),intent),token))==part::<588,32>(statement,396),"Spark draft token opening");
    assert(digest(join(join(join("ZARK/spark/ownership/mask/v1".as_bytes(),intent_hash),mask),mask_salt))==part::<588,32>(statement,204),"Spark sender mask opening");
    assert(digest(join(join(join("ZARK/spark/ownership/masked/v1".as_bytes(),intent_hash),masked),masked_salt))==part::<588,32>(statement,236),"Spark masked share opening");
    let bridge=digest(join(join(join(join(join("ZARK/spark/ownership/bridge/v1".as_bytes(),intent_hash),
        part::<588,32>(statement,172)),le32(delay)),part::<588,32>(statement,364)),bridge_salt));
    assert(bridge==part::<588,32>(statement,268),"Spark common predecessor bridge");
}
