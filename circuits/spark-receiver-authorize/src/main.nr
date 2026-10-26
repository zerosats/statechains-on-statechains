//! Real receiver claim + recursively authenticated sender + both blind recoveries.
use bitcoin_relations::part;
fn main(
    packed:pub [Field;34],statement:[u8;1036],user:[u8;32],funding_salt:[u8;32],recovery_salt:[u8;32],
    payout:[u8;64],fee:u64,delay:u32,owner_index:u32,initial:u32,gap:u32,margin:u32,
    txid_0:[u8;32],amount_0:u64,alpha_0:[u8;32],beta_0:[u8;32],nonce_salt_0:[u8;32],
    txid_1:[u8;32],amount_1:u64,alpha_1:[u8;32],beta_1:[u8;32],nonce_salt_1:[u8;32],
    handover:[u8;588],handover_vk:[Field;115],handover_proof:[Field;458],
    claim_secret:[u8;32],claim_salt:[u8;32],session_point:[u8;64],next_owner_secret:[u8;32],
    masked:[u8;32],masked_salt:[u8;32],delta:[u8;32],delta_salt:[u8;32],server_salt:[u8;32],old_delay:u32,bridge_salt:[u8;32],
) {
    packing::bind::<1036,34>(statement,packed);
    let checked_recovery=spark::authorize_checked(part::<1036,620>(statement,0),user,funding_salt,recovery_salt,payout,fee,delay,owner_index,initial,gap,margin,
        txid_0,amount_0,alpha_0,beta_0,nonce_salt_0,txid_1,amount_1,alpha_1,beta_1,nonce_salt_1);
    lineage::receiver::authorize_with_recovery(statement,handover,handover_vk,handover_proof,claim_secret,claim_salt,session_point,next_owner_secret,
        masked,masked_salt,user,delta,delta_salt,server_salt,payout,fee,delay,owner_index,recovery_salt,old_delay,bridge_salt,initial,gap,margin,checked_recovery);
}
