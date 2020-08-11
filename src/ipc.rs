
use hex_literal::hex;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use ethereum_types::{H256,U256,Address};
use parity_bytes::Bytes;
use rlp_derive::{RlpEncodable, RlpDecodable};

use crate::transaction::{UnverifiedTransaction};
use crate::header::Header;

/// RLP-Encode( method(string), id(number), param(rlp-encoded-list) );
#[derive(Default, Debug, Clone, PartialEq)]
pub struct IpcRequest {
    pub method: String,
    pub id: u64,
    pub params: Vec<u8>,
}

#[derive(Default, Debug, Clone, PartialEq)]
pub struct IpcReply {
    pub id: u64,
    pub result: Vec<u8>,
}

impl Encodable for IpcRequest {
    fn rlp_append(&self, s: &mut RlpStream){
        s.begin_list(3);
        s.append(&self.method);
        s.append(&self.id);
        s.append(&self.params);
    }
}

impl Decodable for IpcRequest {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.as_raw().len() != rlp.payload_info()?.total() {
            return Err(DecoderError::RlpIsTooBig);
        }
        if rlp.item_count()? != 3 {
            return Err(DecoderError::RlpIncorrectListLen);
        }
        Ok(IpcRequest {
            method: rlp.val_at(0)?,
            id: rlp.val_at(1)?,
            params: rlp.val_at(2)?,
        })
    }
}

impl Encodable for IpcReply {
    fn rlp_append(&self, s: &mut RlpStream){
        s.begin_list(2);
        s.append(&self.id);
        s.append(&self.result);
    }
}

impl Decodable for IpcReply {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.as_raw().len() != rlp.payload_info()?.total() {
            return Err(DecoderError::RlpIsTooBig);
        }
        if rlp.item_count()? != 2 {
            return Err(DecoderError::RlpIncorrectListLen);
        }
        Ok(IpcReply {
            id: rlp.val_at(0)?,
            result: rlp.val_at(1)?,
        })
    }
}

/// method: CreateHeader, Request
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

/// method: CreateHeader, Response
#[derive(Default, Debug, Clone, PartialEq,RlpEncodable, RlpDecodable)]
pub struct CreateHeaderResp(pub Header);

/// method: LatestBlocks, Request
#[derive(Default, Debug, Clone, PartialEq,RlpEncodable, RlpDecodable)]
pub struct LatestBlocksReq(pub u64);
/// method: LatestBlocks, Response
#[derive(Default, Debug, Clone, PartialEq,RlpEncodable, RlpDecodable)]
pub struct LatestBlocksResp(pub Vec<Header>);

/// method: ApplyBlock, Request
#[derive(Default, Debug, Clone, PartialEq,RlpEncodable, RlpDecodable)]
pub struct ApplyBlockReq(pub Header,pub Vec<UnverifiedTransaction>);
/// method: ApplyBlock, Response
#[derive(Default, Debug, Clone, PartialEq,RlpEncodable, RlpDecodable)]
pub struct ApplyBlockResp(pub bool);


#[cfg(test)]
mod tests {
    use super::*;
    use ethereum_types::{H256, H160, Address, U256, BigEndianHash};
    use crate::transaction::{UnverifiedTransaction, Action};
    use parity_crypto::publickey::{Signature, Secret, Public, recover, public_to_address};
    use std::str::FromStr;
    use rustc_hex::FromHex;


    #[test]
    fn test_match_request() {

        let mut stream = RlpStream::new_list(1);
        stream.append(&15u32);
        let out = stream.out();

        let rlp = Rlp::new(&out);
        println!("{}", rlp);
        // ["0x636174", "0x646f67"]
        let ipc_request = IpcRequest {
            method: "LatestBlocks".to_string(),
            id: 123,
            params: out,
        };


        match ipc_request.method.as_str() {
            "LatestBlocks" => {}, // get_latest_blocks
            "BlocksAfterN" => {}, // get_blocks_after_number
            "BlocksN" => {},
            "AccountsInfo" => {}, // get_accounts_info
            "SendToTxPool" => {},
            _ => {}
        };
    }

    #[test]
    fn test_req() {
        let data = hex!("f85f800182520894095e7baea6a6c7c4c2dfeb977efac326af552d870a801ba048b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353a0efffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804");
        //let data = hex!("778899");
        let ipc_request = IpcRequest {
            method: "hello".to_string(),
            id: 123,
            params: data.to_vec(),
        };
        // rlp::encode();
        let req_bytes = ipc_request.rlp_bytes();
        println!("ipc_request hex-string: {}", hex::encode(req_bytes));
        let recovered_request : IpcRequest = rlp::decode(&ipc_request.rlp_bytes()).unwrap();
        println!("recovered_request: {:x?}", recovered_request);

        let bytes = recovered_request.params;

        let t: UnverifiedTransaction = rlp::decode(&bytes).expect("decoding UnverifiedTransaction failed");
        assert_eq!(t.data, b"");
        assert_eq!(t.gas, U256::from(0x5208u64));
        assert_eq!(t.gas_price, U256::from(0x01u64));
        assert_eq!(t.nonce, U256::from(0x00u64));
        if let Action::Call(ref to) = t.action {
            assert_eq!(*to, Address::from_str("095e7baea6a6c7c4c2dfeb977efac326af552d87").unwrap());
        } else { panic!(); }
        assert_eq!(t.value, U256::from(0x0au64));
        assert_eq!(public_to_address(&t.recover_public().unwrap()), Address::from_str("0f65fe9276bc9a24ae7083ae28e2660ef72df99e").unwrap());
        assert_eq!(t.chain_id(), None);
    }

    #[test]
    fn creader_req_test(){
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
    fn create_header_resp_test() {

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

        let resp = CreateHeaderResp(header.clone());

        let rlp_data = rlp::encode(&resp);
        let other: CreateHeaderResp = rlp::decode(rlp_data.as_slice()).unwrap();
        assert_eq!(header,other.0);
    }


    #[test]
    fn test_latest_blocks(){
        let req = LatestBlocksReq(10);
        let rlp_bytes = rlp::encode(&req);
        let req1: LatestBlocksReq = rlp::decode(rlp_bytes.as_slice()).unwrap();
        assert_eq!(req.0,req1.0);


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

        let mut header1 = header.clone();
        header1.set_extra_data(b"jack".to_vec());
        let resp = LatestBlocksResp(vec![header.clone(),header1.clone()]);
        let rlp_bytes = rlp::encode(&resp);
        let resp1:LatestBlocksResp = rlp::decode(rlp_bytes.as_slice()).unwrap();
        assert_eq!(resp,resp1);

    }



    #[test]
    fn test_apply_block(){

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

        let bytes: Vec<u8> = FromHex::from_hex("f85f800182520894095e7baea6a6c7c4c2dfeb977efac326af552d870a801ba048b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353a0efffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804").unwrap();
        let t: UnverifiedTransaction = rlp::decode(&bytes).expect("decoding UnverifiedTransaction failed");

        let req = ApplyBlockReq(header,vec![t]);
        let rlp_bytes = rlp::encode(&req);
        let req1: ApplyBlockReq = rlp::decode(rlp_bytes.as_slice()).unwrap();
        assert_eq!(req,req1);

        let resp = ApplyBlockResp(true);
        let rlp_bytes = rlp::encode(&resp);
        let resp1: ApplyBlockResp = rlp::decode(rlp_bytes.as_slice()).unwrap();
        assert_eq!(resp1.0,true);

    }
}



