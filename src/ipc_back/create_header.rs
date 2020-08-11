use ethereum_types::{H256,U256,Address};
use parity_bytes::Bytes;
use rlp::{Rlp, RlpStream, Decodable, DecoderError, Encodable};
use rlp_derive::{RlpEncodable, RlpDecodable};

use crate::transaction::{UnverifiedTransaction};
use crate::header::Header;

#[derive(Default, Debug, Clone, PartialEq,RlpEncodable, RlpDecodable)]
pub struct CreateHeaderReq {
    pub parent_block_hash: H256,
    pub author: Address,
    pub extra_data: Bytes,
    pub gas_limit: U256,
    pub difficulty: U256,
    pub transactions: Vec<UnverifiedTransaction>,
}

impl CreateHeaderReq {
    pub fn new(parent_block_hash: H256,
               author: Address,
               extra_data: Bytes,
               gas_limit: U256,
               difficulty: U256,
               transactions: Vec<UnverifiedTransaction>) -> Self{
        CreateHeaderReq {
            parent_block_hash,
            author,
            extra_data,
            gas_limit,
            difficulty,
            transactions,
        }
    }
}


#[derive(Default, Debug, Clone, PartialEq,RlpEncodable, RlpDecodable)]
pub struct CreateHeaderResp(Header);




#[cfg(test)]
mod tests {
    use super::*;
    use rustc_hex::FromHex;
    use std::str::FromStr;

    use crate::transaction::*;
    use crate::header::*;
    #[test]
    fn req_test(){
        let bytes: Vec<u8> = FromHex::from_hex("f85f800182520894095e7baea6a6c7c4c2dfeb977efac326af552d870a801ba048b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353a0efffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804").unwrap();
        let t: UnverifiedTransaction = rlp::decode(&bytes).expect("decoding UnverifiedTransaction failed");
        let parent_hash = H256::from_str("40eb088232727a64c88d5e98d25e7b16ee7e9acc267c25c0088c7d1432745896").unwrap();
        let author = Address::from_str("095e7baea6a6c7c4c2dfeb977efac326af552d87").unwrap();
        let extra_data = b"12bb".to_vec();
        let gas_limit = U256::from(1000);
        let difficulty = U256::from(2020);
        let req = CreateHeaderReq::new(parent_hash.clone(),author.clone(),extra_data.clone(),gas_limit.clone(),difficulty.clone(),vec![t.clone()]);
        let rlp_datas = req.rlp_bytes();

        let other: CreateHeaderReq = rlp::decode(rlp_datas.as_slice()).unwrap();
        assert_eq!(req,other);

    }

    #[test]
    fn resp_test() {

        let mut header = Header::default();


        let parent_hash = "e4505deee005a3c3dc4aa696ab429562e51a08190861b81a09c652487426ac72";
        let parent_hash = H256::from_str(parent_hash).unwrap();
        header.set_parent_hash(parent_hash);


        let author = "5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c";
        let author = Address::from_str(author).unwrap();
        header.set_author(author);

        let state_root = "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347";
        let state_root = H256::from_str(state_root).unwrap();
        header.set_state_root(state_root);

        let tx_root = "e4505deee005a3c3dc4aa696ab429562e51a08190861b81a09c652487426ac72";
        let tx_root = H256::from_str(tx_root).unwrap();
        header.set_transactions_root(tx_root);

        let difficulty = U256::zero();
        header.set_difficulty(difficulty);

        header.set_number(100 as u64);
        header.set_gas_limit(U256::zero());
        header.set_gas_used(U256::zero());
        header.set_timestamp(13000000 as u64);

        let data = b"hello".to_vec();
        header.set_extra_data(data);

        let resp = CreateHeaderResp(header);

        let rlp_data = rlp::encode(&resp);
        let other: CreateHeaderResp = rlp::decode(rlp_data.as_slice()).unwrap();
        assert_eq!(header,other.0);
    }

}


