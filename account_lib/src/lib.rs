extern crate serde;
#[macro_use]
extern crate serde_derive;

use ethereum_types::{
    H160,
    H256,
    U256
};
use num_traits::int;
use rlp::RlpStream;
use secp256k1::{
    key::SecretKey,
    Message,
    Secp256k1,
};
use tiny_keccak::{
    Keccak,
    Hasher,
};
use hex;
use web3;

#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
pub struct Account{
    pub address:String,
    pub secret:String,
    pub public:String,
    pub nonce:String,
}
impl Account{
}
/// Description of a Transaction, pending or in the chain.
#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
pub struct RawTransaction {
    /// Nonce
    pub nonce: U256,
    /// Recipient (None when contract creation)
    pub to: Option<H160>,
    /// Transfered value
    pub value: U256,
    /// Gas Price
    #[serde(rename = "gasPrice")]
    pub gas_price: U256,
    /// Gas amount
    pub gas: U256,
    /// Input data
    pub data: Vec<u8>,
}

impl RawTransaction {

    /// Signs and returns the RLP-encoded transaction
    pub fn sign<T: int::PrimInt>(&self, private_key: &H256, chain_id: &T) -> Vec<u8> {
        let chain_id_u64: u64 = chain_id.to_u64().unwrap();
        let hash = self.hash(chain_id_u64);
        let sig = ecdsa_sign(&hash, &private_key.0, &chain_id_u64);
        let mut r_n = sig.r;
        let mut s_n = sig.s;
        while r_n[0] == 0 {
            r_n.remove(0);
        }
        while s_n[0] == 0 {
            s_n.remove(0);
        }
        let mut tx = RlpStream::new();
        tx.begin_unbounded_list();
        self.encode(&mut tx);
        tx.append(&sig.v);
        tx.append(&r_n);
        tx.append(&s_n);
        tx.finalize_unbounded_list();
        tx.out()
    }

    fn hash(&self, chain_id: u64) -> Vec<u8> {
        let mut hash = RlpStream::new();
        hash.begin_unbounded_list();
        self.encode(&mut hash);
        hash.append(&chain_id.clone());
        hash.append(&U256::zero());
        hash.append(&U256::zero());
        hash.finalize_unbounded_list();
        keccak256_hash(&hash.out())
    }

    fn encode(&self, s: &mut RlpStream) {
        s.append(&self.nonce);
        s.append(&self.gas_price);
        s.append(&self.gas);
        if let Some(ref t) = self.to {
            s.append(t);
        } else {
            s.append(&vec![]);
        }
        s.append(&self.value);
        s.append(&self.data);
    }
}

pub fn keccak256_hash(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut resp: [u8; 32] = Default::default();
    hasher.finalize(&mut resp);
    resp.iter().cloned().collect()
}

pub fn ecdsa_sign(hash: &[u8], private_key: &[u8], chain_id: &u64) -> EcdsaSig {
    let s = Secp256k1::signing_only();
    let msg = Message::from_slice(hash).unwrap();
    let key = SecretKey::from_slice(private_key).unwrap();
    let (v, sig_bytes) = s.sign_recoverable(&msg, &key).serialize_compact();

    EcdsaSig {
        v: v.to_i32() as u64 + chain_id * 2 + 35,
        r: sig_bytes[0..32].to_vec(),
        s: sig_bytes[32..64].to_vec(),
    }
}

pub struct EcdsaSig {
    v: u64,
    r: Vec<u8>,
    s: Vec<u8>,
}

pub fn pre_sign_tx<'a>(sender:&'a mut Account, receiver : &Account) ->String{
    let add= sender.nonce.parse::<i32>().unwrap()+1;
    sender.nonce=add.to_string();
    sign_tx(&sender.nonce.to_string(),
            &receiver.address.to_string(),
            &"0".to_string(),
            &"10000".to_string(),
            &"21240".to_string(),
            &"7f7465737432000000000000000000000000000000000000000000000000000000600057".to_string(),
            &sender.secret.to_string(),
            &"3".to_string())

}
pub fn sign_tx<'a>(nonce:&'a String,to:&'a String,value:&'a String,gas_price:&'a String,
                   gas:&'a String,data:&'a String,private_key:&'a String,chain_id:&'a String) ->String{
    let nonce=nonce.to_string().parse::<u128>().unwrap();
    let to=to.to_string();
    let mut to_t: [u8; 20] = Default::default();
    to_t.copy_from_slice(&hex::decode(
        to
    ).unwrap());
    let value=value.to_string().parse::<u128>().unwrap();
    let gas_price=gas_price.to_string().parse::<u128>().unwrap();
    let gas=gas.to_string().parse::<u128>().unwrap();
    let data=data.to_string();
    let private_key=private_key.to_string();
    let chain_id=chain_id.to_string().parse::<u32>().unwrap();
    let tx =RawTransaction {
        nonce: web3::types::U256::from(nonce),
        to: Some(web3::types::H160 (to_t)),
        value: web3::types::U256::from(value),
        gas_price: web3::types::U256::from(gas_price),
        gas: web3::types::U256::from(gas),
        data: hex::decode(
            data
        ).unwrap(),
    };
    let mut data: [u8; 32] = Default::default();
    data.copy_from_slice(&hex::decode(
        private_key
    ).unwrap());
    let private_key = web3::types::H256(data);
    let raw_rlp_bytes = tx.sign(&private_key, &chain_id);
    let r=hex::encode(raw_rlp_bytes);
    //println!("{:?}",raw_rlp_bytes);
    r
}