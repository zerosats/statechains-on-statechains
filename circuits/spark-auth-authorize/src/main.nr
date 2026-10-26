//! One blinded BIP-340 response for a Spark operator authentication challenge.
fn main(packed:pub [Field;9],statement:[u8;268],user:[u8;32],key_salt:[u8;32],challenge_nonce:[u8;32],
    alpha:[u8;32],beta:[u8;32],salt:[u8;32],
) {
    packing::bind::<268,9>(statement,packed);
    auth::authorize(statement,user,key_salt,challenge_nonce,alpha,beta,salt);
}
