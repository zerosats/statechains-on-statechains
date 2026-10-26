//! Receiver claim ownership, sender provenance and exact recovery decrement.
use bitcoin_relations::{join,le32,part,read_point,read_scalar};
use bigcurve::BigCurve;
use bignum::BigNum;
use crate::{capability,context,digest,intent,intent_digest,nonzero};

pub fn authorize(
    auth:[u8;1036],handover:[u8;588],handover_vk:[Field;115],handover_proof:[Field;458],
    claim_secret:[u8;32],claim_salt:[u8;32],session_point:[u8;64],next_owner_secret:[u8;32],
    masked:[u8;32],masked_salt:[u8;32],user:[u8;32],delta:[u8;32],delta_salt:[u8;32],
    server_salt:[u8;32],payout:[u8;64],fee:u64,delay:u32,owner_index:u32,
    recovery_salt:[u8;32],old_delay:u32,bridge_salt:[u8;32],initial:u32,gap:u32,margin:u32,
) {
    crate::openings::target(auth,payout,fee,delay,owner_index,recovery_salt,initial,gap,margin);
    authorize_claim(auth,handover,handover_vk,handover_proof,claim_secret,claim_salt,session_point,next_owner_secret,
        masked,masked_salt,user,delta,delta_salt,server_salt,payout,fee,delay,owner_index,recovery_salt,old_delay,bridge_salt,initial,gap);
}

/// Reuse the exact target, payout and schedule openings already constrained by
/// the complete dual-refund recovery relation. Keep the standalone entrypoint
/// above for callers that have not established that relation themselves.
pub fn authorize_with_recovery(
    auth:[u8;1036],handover:[u8;588],handover_vk:[Field;115],handover_proof:[Field;458],
    claim_secret:[u8;32],claim_salt:[u8;32],session_point:[u8;64],next_owner_secret:[u8;32],
    masked:[u8;32],masked_salt:[u8;32],user:[u8;32],delta:[u8;32],delta_salt:[u8;32],
    server_salt:[u8;32],payout:[u8;64],fee:u64,delay:u32,owner_index:u32,
    recovery_salt:[u8;32],old_delay:u32,bridge_salt:[u8;32],initial:u32,gap:u32,margin:u32,
    checked:spark::CheckedRecovery,
) {
    checked.assert_matches(part::<1036,620>(auth,0),user,recovery_salt,payout,fee,delay,owner_index,initial,gap,margin);
    authorize_claim(auth,handover,handover_vk,handover_proof,claim_secret,claim_salt,session_point,next_owner_secret,
        masked,masked_salt,user,delta,delta_salt,server_salt,payout,fee,delay,owner_index,recovery_salt,old_delay,bridge_salt,initial,gap);
}

fn authorize_claim(
    auth:[u8;1036],handover:[u8;588],handover_vk:[Field;115],handover_proof:[Field;458],
    claim_secret:[u8;32],claim_salt:[u8;32],session_point:[u8;64],next_owner_secret:[u8;32],
    masked:[u8;32],masked_salt:[u8;32],user:[u8;32],delta:[u8;32],delta_salt:[u8;32],
    server_salt:[u8;32],payout:[u8;64],fee:u64,delay:u32,owner_index:u32,
    recovery_salt:[u8;32],old_delay:u32,bridge_salt:[u8;32],initial:u32,gap:u32,
) {
    crate::issuance(auth);
    let cfg=part::<1036,160>(auth,876);crate::verify_sender(handover,handover_vk,handover_proof,cfg);
    assert(intent(auth)==part::<588,172>(handover,0),"Spark exact sender intent");
    assert(part::<1036,32>(auth,196)==part::<588,32>(handover,172),"Spark unchanged backing");
    assert(part::<1036,32>(auth,260)==part::<588,32>(handover,364),"Spark shared policy");
    assert(part::<1036,32>(auth,652)==part::<588,32>(handover,204),"Spark shared mask commitment");
    assert(part::<1036,32>(auth,684)==part::<588,32>(handover,236),"Spark shared masked commitment");
    assert(part::<1036,32>(auth,716)==part::<588,32>(handover,268),"Spark shared bridge commitment");
    assert(part::<1036,32>(auth,780)==part::<588,32>(handover,300),"Spark shared predecessor capability");
    let s=read_point(session_point);assert((s.y.to_be_bytes()[31]&1)==0,"Spark session parity");
    assert(s.x.to_be_bytes()==part::<1036,32>(auth,132),"Spark session lift");
    nonzero(claim_salt);nonzero(masked_salt);nonzero(delta_salt);nonzero(bridge_salt);
    let claim=read_scalar(claim_secret);assert(!claim.is_zero(),"Spark nonzero claim secret");
    let claim_point=fixed_generator::mul_generator(claim.to_be_bytes());assert(!claim_point.is_infinity);
    assert((claim_point.y.to_be_bytes()[31]&1)==0,"Spark normalized claim secret");
    let domain=part::<1036,68>(auth,0);
    let recipient=digest(join(join(join(join("ZARK/spark/ownership/recipient/v1".as_bytes(),domain),
        part::<1036,32>(auth,100)),claim_point.x.to_be_bytes()),claim_salt));
    assert(recipient==part::<1036,32>(auth,620),"Spark recipient claim ownership");
    assert(capability(domain,next_owner_secret)==part::<1036,32>(auth,812),"Spark next capability ownership");
    let z=read_scalar(masked);let u=read_scalar(user);let d=read_scalar(delta);
    assert(!z.is_zero()&!u.is_zero(),"Spark recipient shares");assert(z==u+d,"Spark recipient share conservation");
    let intent_hash=intent_digest(intent(auth));
    assert(digest(join(join(join("ZARK/spark/ownership/masked/v1".as_bytes(),intent_hash),masked),masked_salt))==part::<1036,32>(auth,684),"Spark recipient masked opening");
    assert(digest(join(join(join("ZARK/spark/ownership/delta/v1".as_bytes(),context(auth)),delta),delta_salt))==part::<1036,32>(auth,748),"Spark recipient delta opening");
    assert(crate::server_commit(domain,part::<1036,64>(auth,300),server_salt)==part::<1036,32>(auth,844),"Spark successor server opening");
    crate::openings::draft(auth,payout,fee,delay,recovery_salt);
    assert(owner_index>1,"Spark receiver follows a predecessor");
    assert(old_delay==delay+gap,"Spark exact predecessor decrement");
    assert(old_delay<=initial,"Spark predecessor delay bound");
    let bridge=digest(join(join(join(join(join("ZARK/spark/ownership/bridge/v1".as_bytes(),intent_hash),
        part::<1036,32>(auth,196)),le32(old_delay)),part::<1036,32>(auth,260)),bridge_salt));
    assert(bridge==part::<1036,32>(auth,716),"Spark authenticated predecessor delay");
}
