//! Ordinary USER native claim before the first ownership certificate exists.
fn main(packed:pub [Field;27],statement:[u8;812],user:[u8;32],owner_secret:[u8;32],backing_salt:[u8;32],session_point:[u8;64],
    plan_salt:[u8;32],anchor_txid:[u8;32],anchor_vout:u32,amount:u64,native_delay:u32,operator:[u8;64],jobs:[receive::Job;2],
) {
    packing::bind::<812,27>(statement,packed);
    receive::authorize(statement,user,owner_secret,backing_salt,session_point,plan_salt,anchor_txid,anchor_vout,amount,native_delay,operator,jobs);
}
