
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



}



