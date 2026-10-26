//! Authenticated native initial-root two-refund exit from recursive transfer state.
fn main(
    packed:pub [Field;27],statement:[u8;812],
    current:[u8;324],current_authorization:[u8;1036],current_vk:[Field;115],current_proof:[Field;458],partials:[[u8;32];2],server_salt:[u8;32],
    user:[u8;32],owner_secret:[u8;32],backing_salt:[u8;32],session_point:[u8;64],
    plan_salt:[u8;32],transfer_id:[u8;16],leaf_id:[u8;16],expiry:u64,anchor_txid:[u8;32],anchor_vout:u32,amount:u64,native_delay:u32,
    operator:[u8;64],mask_user:[u8;64],receiver_identity:[u8;64],mask_cipher_sha256:[u8;32],jobs:[native::frost::JobWitness;2],
) {
    packing::bind::<812,27>(statement,packed);
    let cfg=bitcoin_relations::part::<812,160>(statement,396);
    lineage::verify_transfer(current,current_authorization,current_vk,current_proof,partials,server_salt,cfg);
    ordinary_native::authorize(statement,current,current_authorization,user,owner_secret,backing_salt,session_point,
        plan_salt,transfer_id,leaf_id,expiry,anchor_txid,anchor_vout,amount,native_delay,
        operator,mask_user,receiver_identity,mask_cipher_sha256,jobs);
}

