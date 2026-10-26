//! Sender from an authenticated, actually issued initial Spark-backed state.
fn main(
    packed:pub [Field;19],statement:[u8;588],token:[u8;32],
    previous:[u8;324],previous_authorization:[u8;1036],previous_vk:[Field;115],previous_proof:[Field;458],partials:[[u8;32];2],
    origin_key:[u8;64],origin_nonce:[u8;64],origin_signature:[u8;64],
    server:[u8;64],server_salt:[u8;32],user:[u8;32],owner_secret:[u8;32],
    mask:[u8;32],mask_salt:[u8;32],masked:[u8;32],masked_salt:[u8;32],
    funding_salt:[u8;32],funding_output_key:[u8;32],txid_0:[u8;32],amount_0:u64,txid_1:[u8;32],amount_1:u64,
    payout:[u8;64],fee:u64,delay:u32,owner_index:u32,recovery_salt:[u8;32],bridge_salt:[u8;32],initial:u32,gap:u32,margin:u32,
) {
    packing::bind::<588,19>(statement,packed);
    let cfg=bitcoin_relations::part::<588,160>(statement,428);
    // Authenticate the full backing relation before the sender reuses its key.
    lineage::verify_origin(previous,previous_authorization,previous_vk,previous_proof,partials,server_salt,origin_key,origin_nonce,origin_signature,cfg);
    lineage::sender::authorize(statement,token,previous,previous_authorization,server,server_salt,user,owner_secret,mask,mask_salt,masked,masked_salt,
        funding_salt,funding_output_key,txid_0,amount_0,txid_1,amount_1,payout,fee,delay,owner_index,recovery_salt,bridge_salt,initial,gap,margin);
    assert(owner_index==1,"Spark typed origin predecessor");
}
