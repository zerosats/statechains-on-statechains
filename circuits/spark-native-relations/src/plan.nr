//! Exact initial-root native transaction profile. The old refund txids open
//! the existing private backing; no caller-provided transaction digest grants
//! signing authority. Ordinary direct-history leaves need a distinct profile.
use bitcoin_relations::{add,challenge_scalar,join,le32,le64,normalize,read_scalar,tagged};
use bigcurve::{BigCurve,Secp256k1};
use bignum::BigNum;

pub fn compressed(p:Secp256k1)->[u8;33] {
    assert(!p.is_infinity,"native compressed infinity");
    join([2+(p.y.to_be_bytes()[31]&1)],p.x.to_be_bytes())
}
// Spark's FROST combined signing key reduces TapTweak; ordinary Bitcoin USER
// and receiver scripts reject noncanonical tweaks, as the ownership relation.
pub fn combined_key(raw:Secp256k1)->(Secp256k1,bool) {
    let (internal,first)=normalize(raw);
    let tweak=challenge_scalar(tagged("TapTweak".as_bytes(),internal.x.to_be_bytes()));
    let (output,second)=normalize(add(internal,fixed_generator::mul_generator(tweak.to_be_bytes())));
    (output,first!=second)
}
pub fn bitcoin_key(raw:Secp256k1)->Secp256k1 {
    let (internal,_)=normalize(raw);
    let tweak=read_scalar(tagged("TapTweak".as_bytes(),internal.x.to_be_bytes()));
    let (output,_)=normalize(add(internal,fixed_generator::mul_generator(tweak.to_be_bytes())));output
}
pub fn outputs(amount:u64,key:[u8;32])->[u8;43] {
    join(join(le64(amount),[34,81,32]),key)
}
pub fn anchored_outputs(amount:u64,key:[u8;32])->[u8;56] {
    join(outputs(amount,key),[0,0,0,0,0,0,0,0,4,81,2,78,115])
}
pub fn transaction<let N:u32>(txid:[u8;32],vout:u32,sequence:u32,count:u8,outs:[u8;N])->[u8;51+N] {
    let bytes=join(join(join(join(join(join(le32(3),[1]),txid),le32(vout)),[0]),le32(sequence)),[count]);
    join(join(bytes,outs),le32(0))
}
pub fn txid<let N:u32>(tx:[u8;N])->[u8;32] {recovery::digest(recovery::digest(tx))}
pub fn sighash<let N:u32>(root:[u8;32],amount:u64,key:[u8;32],sequence:u32,outs:[u8;N])->[u8;32] {
    let header=join(join([0,0],le32(3)),le32(0));
    let hashes=join(recovery::digest(join(root,le32(0))),recovery::digest(le64(amount)));
    let hashes=join(hashes,recovery::digest(join([34,81,32],key)));
    let hashes=join(join(hashes,recovery::digest(le32(sequence))),recovery::digest(outs));
    tagged("TapSighash".as_bytes(),join(join(header,hashes),[0,0,0,0,0]))
}
pub struct Derived {
    pub old_txids:[[u8;32];2],pub old_amounts:[u64;2],
    pub sighashes:[[u8;32];2],pub commitment:[u8;32],pub output:Secp256k1,pub key_negated:bool,
}
pub fn derive(raw_user:Secp256k1,user_output:Secp256k1,operator:Secp256k1,mask_user:Secp256k1,receiver:Secp256k1,
    anchor_txid:[u8;32],anchor_vout:u32,amount:u64,native_delay:u32,transfer_id:[u8;16],leaf_id:[u8;16],expiry:u64,
    cluster:[u8;32],cipher:[u8;32],salt:[u8;32],
)->Derived {
    assert((amount>0)&(amount<=2_100_000_000_000_000),"native amount bound");
    assert((native_delay>=200)&(native_delay<=2000)&(native_delay%100==0),"native initial-root delay");
    assert((transfer_id!=[0;16])&(leaf_id!=[0;16])&(expiry>0),"native transfer metadata");
    lineage::nonzero(anchor_txid);lineage::nonzero(cluster);lineage::nonzero(cipher);lineage::nonzero(salt);
    let (output,key_negated)=combined_key(add(raw_user,operator));
    let destination=bitcoin_key(receiver).x.to_be_bytes();
    let root=txid(transaction(anchor_txid,anchor_vout,1<<30,2,anchored_outputs(amount,output.x.to_be_bytes())));
    let user=user_output.x.to_be_bytes();
    let direct_amount=if amount>955 {amount-955}else{amount};
    let old_0=txid(transaction(root,0,(1<<30)|native_delay,2,anchored_outputs(amount,user)));
    let old_1=txid(transaction(root,0,(1<<30)|(native_delay+50),1,outputs(direct_amount,user)));
    let next=native_delay-100;
    let outs_0=anchored_outputs(amount,destination);let outs_1=outputs(direct_amount,destination);
    let new_0=txid(transaction(root,0,(1<<30)|next,2,outs_0));
    let new_1=txid(transaction(root,0,(1<<30)|(next+50),1,outs_1));
    // Explicit lengths keep the compiler's generic type-expression expansion
    // bounded. These offsets are the Rust canonical_plan352 contract.
    let canonical:[u8;24]=join([1,0,0,0,1,0,0,0],transfer_id);
    let canonical:[u8;40]=join(canonical,leaf_id);
    let canonical:[u8;48]=join(canonical,le64(expiry));
    let canonical:[u8;80]=join(canonical,root);
    let canonical:[u8;88]=join(canonical,le64(amount));
    let canonical:[u8;92]=join(canonical,le32(native_delay));
    let canonical:[u8;125]=join(canonical,compressed(raw_user));
    let canonical:[u8;158]=join(canonical,compressed(operator));
    let canonical:[u8;191]=join(canonical,compressed(mask_user));
    let canonical:[u8;224]=join(canonical,compressed(receiver));
    let canonical:[u8;256]=join(canonical,cipher);
    let canonical:[u8;288]=join(canonical,cluster);
    let canonical:[u8;320]=join(canonical,new_0);
    let canonical:[u8;352]=join(canonical,new_1);
    let data:[u8;377]=join("ZARK/spark/native/plan/v1".as_bytes(),canonical);
    let data:[u8;409]=join(data,salt);
    let commitment=recovery::digest(data);
    Derived {old_txids:[old_0,old_1],old_amounts:[amount,direct_amount],
        sighashes:[sighash(root,amount,output.x.to_be_bytes(),(1<<30)|next,outs_0),sighash(root,amount,output.x.to_be_bytes(),(1<<30)|(next+50),outs_1)],
        commitment,output,key_negated}
}
