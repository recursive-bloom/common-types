
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

/// RLP-Encode( method(string), id(number), param(rlp-encoded-list) );
#[derive(Default, Debug, Clone, PartialEq)]
pub struct IpcRequest {
    pub method: String,
    pub id: u64,
    pub params: om<u8>,
}

#[derive(Default, Debug, Clone, PartialEq)]
pub struct IpcReply {
    pub id: u64,
    pub result: Vec<u8>,
}

impl IpcRequest {
    pub fn new(method : String, id : u64, params : Vec<u8>) -> Self {
        IpcRequest{
            method,
            id,
            params
        }
    }
}

impl IpcReply {
    pub fn new(method : String, id : u64, result : Vec<u8>) -> Self {
        IpcReply{
            id,
            result,
        }
    }
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

#[test]
fn xx() {
    println!("hello");
}



