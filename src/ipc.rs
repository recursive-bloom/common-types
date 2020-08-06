
use hex_literal::hex;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

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
        s.append_list(&self.params);
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
            params: rlp.list_at(2)?,
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

#[test]
fn test_req() {
    use ethereum_types::{H256, H160, Address, U256, BigEndianHash};
    use super::transaction::{UnverifiedTransaction, Action};
    use parity_crypto::publickey::{Signature, Secret, Public, recover, public_to_address};
    use std::str::FromStr;

    let data = hex!("f85f800182520894095e7baea6a6c7c4c2dfeb977efac326af552d870a801ba048b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353a0efffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804");
    //let data = hex!("778899");
    let ipc_request = IpcRequest {
        method: "hello".to_string(),
        id: 123,
        params: data.to_vec(),
    };

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



