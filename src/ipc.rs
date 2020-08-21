extern crate account_lib;
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

/// method: AccountInfo, Request
#[derive(Default, Debug, Clone, PartialEq,RlpEncodable, RlpDecodable)]
pub struct AccountInfoReq(pub Address);
/// method: ApplyBlock, Response
#[derive(Default, Debug, Clone, PartialEq,RlpEncodable, RlpDecodable)]
pub struct AccountInfoResp(pub U256, pub U256);


#[cfg(test)]
mod tests {
    use super::*;
    use ethereum_types::{H256, H160, Address, U256, BigEndianHash};
    use crate::transaction::{UnverifiedTransaction, Action};
    use parity_crypto::publickey::{Signature, Secret, Public, recover, public_to_address};
    use std::str::FromStr;
    use rustc_hex::FromHex;
    use super::account_lib::pre_sign_tx;


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


    #[test]
    fn main1() {
        use zmq::{Context, DEALER, ROUTER, DONTWAIT};
        use std::time::Duration;
        use hex_literal::hex;
        println!("xxxx");
        let context = Context::new();
        let socket = context.socket(DEALER).unwrap();
        socket.set_identity( &hex!("1234567890").to_vec() ).unwrap();
        println!("yyy");

        socket.connect("tcp://192.168.1.49:7050").unwrap();
        println!("zzz");

        socket.send("hello", 0).unwrap();
        println!("aaa");
        let mut rmp = socket.recv_multipart(DONTWAIT).unwrap();
        println!("client thread, received from server, #received_parts: {:?}", rmp);
    }

    #[test]
    fn main2() {
        use zmq::{Context, DEALER, ROUTER, DONTWAIT};
        use std::time::Duration;
        use hex_literal::hex;
        use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

        let tx1 = "f864808504a817c800825208943535353535353535353535353535353535353535808025a0044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116da0044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d";
        let tx2 = "f864808504a817c800825208943535353535353535353535353535353535353535808025a0044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116da0044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d";
        let tx3 = "f864018504a817c80182a410943535353535353535353535353535353535353535018025a0489efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bcaa0489efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6";
        let tx4 = "f864028504a817c80282f618943535353535353535353535353535353535353535088025a02d7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5a02d7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5";
        let tx5 = "f865038504a817c803830148209435353535353535353535353535353535353535351b8025a02a80e1ef1d7842f27f2e6be0972bb708b9a135c38860dbe73c27c3486c34f4e0a02a80e1ef1d7842f27f2e6be0972bb708b9a135c38860dbe73c27c3486c34f4de";
        let tx6 = "f865048504a817c80483019a28943535353535353535353535353535353535353535408025a013600b294191fc92924bb3ce4b969c1e7e2bab8f4c93c3fc6d0a51733df3c063a013600b294191fc92924bb3ce4b969c1e7e2bab8f4c93c3fc6d0a51733df3c060";
        let tx7 = "f865058504a817c8058301ec309435353535353535353535353535353535353535357d8025a04eebf77a833b30520287ddd9478ff51abbdffa30aa90a8d655dba0e8a79ce0c1a04eebf77a833b30520287ddd9478ff51abbdffa30aa90a8d655dba0e8a79ce0c1";
        let tx8 = "f866068504a817c80683023e3894353535353535353535353535353535353535353581d88025a06455bf8ea6e7463a1046a0b52804526e119b4bf5136279614e0b1e8e296a4e2fa06455bf8ea6e7463a1046a0b52804526e119b4bf5136279614e0b1e8e296a4e2d";
        let tx9 = "f867078504a817c807830290409435353535353535353535353535353535353535358201578025a052f1a9b320cab38e5da8a8f97989383aab0a49165fc91c737310e4f7e9821021a052f1a9b320cab38e5da8a8f97989383aab0a49165fc91c737310e4f7e9821021";
        let txa = "f867088504a817c8088302e2489435353535353535353535353535353535353535358202008025a064b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c12a064b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c10";
        let txb = "f867098504a817c809830334509435353535353535353535353535353535353535358202d98025a052f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afba052f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb";

        let mut stream = RlpStream::new_list(2);
        //stream.append(&hex::decode(tx1).unwrap()).append(&hex::decode(tx2).unwrap());
        stream.append(&hex::decode(tx1).unwrap()).append(&hex::decode(tx2).unwrap());
        let out = stream.out();

        let ipc_request = IpcRequest {
            method: "SendToTxPool".to_string(),
            id: 123,
            params: out,
        };
        let recovered_request : IpcRequest = rlp::decode(&ipc_request.rlp_bytes()).unwrap();
        println!("recovered_request: {:x?}", recovered_request);

        // let x : Vec<UnverifiedTransaction> = rlp::decode_list(&ipc_request.params);
        let x : Vec<Vec<u8>> = rlp::decode_list(&ipc_request.params);
        let y : UnverifiedTransaction = rlp::decode(&x[0]).unwrap();
        println!("####{:?}", y);
    }


    #[test]
    fn main3() {
        use zmq::{Context, DEALER, ROUTER, DONTWAIT};
        use std::time::Duration;
        use hex_literal::hex;
        use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

        let tx1 = "f864808504a817c800825208943535353535353535353535353535353535353535808025a0044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116da0044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d";
        let tx2 = "f864808504a817c800825208943535353535353535353535353535353535353535808025a0044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116da0044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d";
        let tx3 = "f864018504a817c80182a410943535353535353535353535353535353535353535018025a0489efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bcaa0489efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6";
        let tx4 = "f864028504a817c80282f618943535353535353535353535353535353535353535088025a02d7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5a02d7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5";
        let tx5 = "f865038504a817c803830148209435353535353535353535353535353535353535351b8025a02a80e1ef1d7842f27f2e6be0972bb708b9a135c38860dbe73c27c3486c34f4e0a02a80e1ef1d7842f27f2e6be0972bb708b9a135c38860dbe73c27c3486c34f4de";
        let tx6 = "f865048504a817c80483019a28943535353535353535353535353535353535353535408025a013600b294191fc92924bb3ce4b969c1e7e2bab8f4c93c3fc6d0a51733df3c063a013600b294191fc92924bb3ce4b969c1e7e2bab8f4c93c3fc6d0a51733df3c060";
        let tx7 = "f865058504a817c8058301ec309435353535353535353535353535353535353535357d8025a04eebf77a833b30520287ddd9478ff51abbdffa30aa90a8d655dba0e8a79ce0c1a04eebf77a833b30520287ddd9478ff51abbdffa30aa90a8d655dba0e8a79ce0c1";
        let tx8 = "f866068504a817c80683023e3894353535353535353535353535353535353535353581d88025a06455bf8ea6e7463a1046a0b52804526e119b4bf5136279614e0b1e8e296a4e2fa06455bf8ea6e7463a1046a0b52804526e119b4bf5136279614e0b1e8e296a4e2d";
        let tx9 = "f867078504a817c807830290409435353535353535353535353535353535353535358201578025a052f1a9b320cab38e5da8a8f97989383aab0a49165fc91c737310e4f7e9821021a052f1a9b320cab38e5da8a8f97989383aab0a49165fc91c737310e4f7e9821021";
        let txa = "f867088504a817c8088302e2489435353535353535353535353535353535353535358202008025a064b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c12a064b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c10";
        let txb = "f867098504a817c809830334509435353535353535353535353535353535353535358202d98025a052f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afba052f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb";
        let txc = "f8ad830dd98a8502540be40083026739947c2af3a86b4bf47e6ee63ad9bde7b3b0ba7f95da80b844a9059cbb000000000000000000000000b34938746d316e995aa81f9b3f94419a0a41e14300000000000000000000000000000000000000000000026faff2dfe5c524000025a0167bf6ce1f7ecee1e5a414e3622baa14daf6caaf90f498b4fb94b1a91bc79491a0362191d3956065a0e14276dd4810b523e93a786091d27388a2b00b6955f93161";

        let foo : UnverifiedTransaction = rlp::decode(&hex::decode(txa).unwrap()).unwrap();
        let bar : UnverifiedTransaction = rlp::decode(&hex::decode(txc).unwrap()).unwrap();
        let fb_vec = vec![foo, bar];
        let fb_bytes = rlp::encode_list(&fb_vec);

        let ipc_request = IpcRequest {
            method: "SendToTxPool".to_string(),
            id: 666,
            params: fb_bytes,
        };
        let recovered_request : IpcRequest = rlp::decode(&ipc_request.rlp_bytes()).unwrap();
        println!("Recovered request: {:x?}", recovered_request);

        //let socket = Context::new().socket(DEALER).unwrap();
        let context = Context::new();
        let socket = context.socket(DEALER).unwrap();
        socket.set_identity( &hex!("1234").to_vec() ).unwrap();
        socket.connect("tcp://192.168.1.49:7050").unwrap();
        socket.send(ipc_request.rlp_bytes(), 0).unwrap();
        std::thread::sleep(std::time::Duration::from_secs(3));
        let result_rmp = socket.recv_multipart(DONTWAIT);
        if let Ok(mut rmp) = result_rmp {
            println!("Client received from server, Received multiparts: {:?}", rmp);
            let foo : IpcReply = rlp::decode(&rmp.pop().unwrap()).unwrap();
            println!("Client received from server, IpcReply decoded: {:?}", foo);
            let bar : String = rlp::decode(&foo.result).unwrap();
            println!("Client received from server,  Result decoded: {:?}", bar);
        } else {
            println!("Error: Reply Timeout");
        }

    }


    #[test]
    fn main4() {
        use zmq::{Context, DEALER, ROUTER, DONTWAIT};
        use std::time::Duration;
        use hex_literal::hex;
        use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

        let txfoo = "f86e808227108252d094fff7e25dff2aa60f61f9d98130c8646a01f3164989055de6a779bbac00008455aa66cc25a0d42ff575cc734cabc779536c97160592d46c3518583f55823858b49a226d5a24a054b1c00c57421428f256d765b1d1e9739a6343d82e4a7800591338223d238e3d";
        let txbar = "f86a018227108252d09400cf3711cbd3a1512570639280758118ba0b2bcb8904563918244f4000008025a0b387e98ea78f840f04c6298db3322cc2db192a3fe2d6b0d267ef504ace3e566ea07101dcba98875d024d3a3f266465220205c8e3c4364e3386f642c8c562d07ddf";

        let foo : UnverifiedTransaction = rlp::decode(&hex::decode(txfoo).unwrap()).unwrap();
        let bar : UnverifiedTransaction = rlp::decode(&hex::decode(txbar).unwrap()).unwrap();
        let foobar_vec = vec![foo, bar];
        let foobar_bytes = rlp::encode_list(&foobar_vec);

        let ipc_request = IpcRequest {
            method: "SendToTxPool".to_string(),
            id: 666,
            params: foobar_bytes,
        };
        let recovered_request : IpcRequest = rlp::decode(&ipc_request.rlp_bytes()).unwrap();
        println!("Recovered request: {:x?}", recovered_request);

        //let socket = Context::new().socket(DEALER).unwrap();
        let context = Context::new();
        let socket = context.socket(DEALER).unwrap();
        socket.set_identity( &hex!("1234").to_vec() ).unwrap();
        socket.connect("tcp://192.168.1.118:7050").unwrap();
        socket.send(ipc_request.rlp_bytes(), 0).unwrap();
        std::thread::sleep(std::time::Duration::from_secs(2));
        let result_rmp = socket.recv_multipart(DONTWAIT);
        if let Ok(mut rmp) = result_rmp {
            println!("Client received from server, Received multiparts: {:?}", rmp);
            let foo : IpcReply = rlp::decode(&rmp.pop().unwrap()).unwrap();
            println!("Client received from server, IpcReply decoded: {:?}", foo);
            let bar : String = rlp::decode(&foo.result).unwrap();
            println!("Client received from server,  Result decoded: {:?}", bar);
        } else {
            println!("Error: Reply Timeout");
        }

    }
    #[test]
    fn main5() {

        use zmq::{Context, DEALER, ROUTER, DONTWAIT};
        use std::time::Duration;
        use hex_literal::hex;
        use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
        use account_lib::Account;
        use rand::prelude::*;

        let mut a0=Account{
            address:"81da5eef9cbe6ccbcbe43a26756a0cac4e0930c3".to_string(),
            secret:"007b475108be23ad5005ac3e53f8aac3d828d6538cc6e004605d0903644fd058".to_string(),
            public:"11759748a63fe811c67d15fb03649e1e8d8a90c198ebcc3eecf21064ba535e03912ef2e774fd61f5d5b3d81070c52efc977ff6ba891af27d2cdf31af914212e0".to_string(),
            nonce:"0".to_string(),
        };
        let mut a1=Account{
            address:"b6c37e040893fe6b4829f525316c88f816798b9b".to_string(),
            secret:"007b475108be23ad5005ac3e53f8aac3d828d6538cc6e004605d0903644fd058".to_string(),
            public:"11759748a63fe811c67d15fb03649e1e8d8a90c198ebcc3eecf21064ba535e03912ef2e774fd61f5d5b3d81070c52efc977ff6ba891af27d2cdf31af914212e0".to_string(),
            nonce:"0".to_string(),
        };
        let mut a2=Account{
            address:"4e453da8e9344049daafb4c7c57eb99982916974".to_string(),
            secret:"4d21bc3885f597bb3dd2c5c690c6dd461a7807bad4d41bc949f7eb3c2b0d08c6".to_string(),
            public:"85b15a424addee8caf4ebbe4a70b61759804c75c54922886b472a2eedefa3db7e1a948e11db6cb68882c3c7de163177560d2175ceccd9b37381d188d975403fa".to_string(),
            nonce:"0".to_string(),
        };
        let mut a3=Account{
            address:"32c51b238170c2788ab179099ac70afa9f51351b".to_string(),
            secret:"291dd826cf4a0a95317e2061437128c881268e814847a325847eddde6968c38f".to_string(),
            public:"535c6abc6e20a4b71b7a695004fa50dde32c023d876469340026f91b7dd7f0cb8eafc8d9083a9ab34b303d0b6bf172816615a15a52222c339cfdfc7f9e002558".to_string(),
            nonce:"0".to_string(),
        };
        let mut a4=Account{
            address:"1bf672b787263f0639baba61532e1baedd6bcd56".to_string(),
            secret:"b0dcf619c22af722140c515df0f7ac86fe15e65921a0f8f404d876b652be45c6".to_string(),
            public:"f61d5f430c059fda164dd5541e39d1c4e014056ce9123d30bcdfe4fcd025bfd4e6e265e424488de5f17b47578123221bdf134519b1b7fe813bd84891849bdfa7".to_string(),
            nonce:"0".to_string(),
        };
        let mut a5=Account{
            address:"3b4942e717358d07b6a8300099ddeb5c137d7192".to_string(),
            secret:"5957687117732f73a378fb6aacabd620d30013577e6270223943cd70a6a95360".to_string(),
            public:"6bfb77cb5d5a3b224ef9cd6f371f53db5e3c334459ea810ef5e8d2e659ff719c6e083c89f89989a5427c56895c0cbd89bab361625587cc48bfbc1073c8950dab".to_string(),
            nonce:"0".to_string(),
        };
        let mut a6=Account{
            address:"0acc41d732f605910db67da194f8c4c19dc8775e".to_string(),
            secret:"b4179cc97245d04215434670cca3a8730426afbfd611314eb7a7e4b90e6a6722".to_string(),
            public:"ed638a53820470d0517a06daee45e66a08fbb1102bb9d47f7a66417a3c8241cf241c10a861f7c1a7b70ec8578e8d93a4f7241e3521e7bd03a229c30bdb08c89d".to_string(),
            nonce:"0".to_string(),
        };
        let mut a7=Account{
            address:"20cd8edc9ac16876b021b4fa2bafea7afb7895d9".to_string(),
            secret:"446d875997814062f0e49fb33e8d04e41bfa7bd5a535d619f82cd11550fd201a".to_string(),
            public:"01e087edffbbe9ecf60809be7f2f19cbbc6e8a9f9ff5c9f16762bb5d657497cf4bcfc36f8e47dd78ef7ffceb366910c312ab89bc09a742ab3a1c08f6f40cdb22".to_string(),
            nonce:"0".to_string(),
        };
        let mut a8=Account{
            address:"7dd58708a7434d6b219c4f37b5e2126043596afa".to_string(),
            secret:"01b8148f6a6d0a2f21bc9aa91fd9a6016fa76f4899cedb8458626612bc13d4a2".to_string(),
            public:"d6acdea97145ac2017e39ca15800b90831ca6294845230096716bfd0cf0e5d51993d01d500e2b10c870400322cd77007ca4a769aefee8f09b617d8e6af03c88c".to_string(),
            nonce:"0".to_string(),
        };
        let mut a9=Account{
            address:"5e2d5b34ae700a932314d30d9c0b99d703389aeb".to_string(),
            secret:"1a12a12aa194958bc2f0cbd2131f0f585e265dec9ffcddd85993f71104cf8e0f".to_string(),
            public:"df03baba0d8f1925824502be72bf95435dea30dc68866a857babbadbc04eac26773038777f7ecf61096ecb8f4df0d46d7ba10385a482260c8df27c5bb3cee3bb".to_string(),
            nonce:"0".to_string(),
        };

        let accounts = vec![&mut a0, &mut a1, &mut a2, &mut a3, &mut a4,
                                              &mut a5, &mut a6, &mut a7, &mut a8, &mut a9];

        // 获取两个不相等的 0-10 随机下标
        let mut rng = rand::thread_rng();
        let i: usize = rng.gen();
        let mut j:usize = rng.gen();
        while (i == j) {  // 最后保证 i 和 j 不相等
            j = rng.gen();
        }
        let x = i % 10;
        let y = j % 10;

        // 获取发送方和接收方
        let sender = accounts[x];
        let receiver = accounts[y];

        // 生成交易
        let tx = pre_sign_tx(sender, receiver);

        let foo : UnverifiedTransaction = rlp::decode(&hex::decode(tx.as_str()).unwrap()).unwrap();
        let foobar_vec = vec![foo];
        let foobar_bytes = rlp::encode_list(&foobar_vec);

        let ipc_request = IpcRequest {
            method: "SendToTxPool".to_string(),
            id: 666,
            params: foobar_bytes,
        };
        let recovered_request : IpcRequest = rlp::decode(&ipc_request.rlp_bytes()).unwrap();
        println!("Recovered request: {:x?}", recovered_request);

        //let socket = Context::new().socket(DEALER).unwrap();
        let context = Context::new();
        let socket = context.socket(DEALER).unwrap();
        socket.set_identity( &hex!("1234").to_vec() ).unwrap();
        socket.connect("tcp://192.168.1.118:7050").unwrap();
        socket.send(ipc_request.rlp_bytes(), 0).unwrap();
        std::thread::sleep(std::time::Duration::from_secs(2));
        let result_rmp = socket.recv_multipart(DONTWAIT);
        if let Ok(mut rmp) = result_rmp {
            println!("Client received from server, Received multiparts: {:?}", rmp);
            let foo : IpcReply = rlp::decode(&rmp.pop().unwrap()).unwrap();
            println!("Client received from server, IpcReply decoded: {:?}", foo);
            let bar : String = rlp::decode(&foo.result).unwrap();
            println!("Client received from server,  Result decoded: {:?}", bar);
        } else {
            println!("Error: Reply Timeout");
        }
    }


}



