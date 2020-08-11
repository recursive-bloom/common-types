
pub mod create_header;

use rlp::{self,Encodable,Decodable,DecoderError,RlpStream,Rlp};


#[derive(Debug, Clone, PartialEq)]
pub enum MethodName {
    CreateHeader,
    Unknown
}

impl<'a> From<&'a str> for MethodName {
    fn from(s: &'a str) -> Self {
        match s {
            "CreateHeader" => {
                MethodName::CreateHeader
            },
            _ => {
                MethodName::Unknown
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum  Request{
    CreateHeader(create_header::CreateHeaderReq),
}


/// RLP-Encode( method(string), id(number), param(rlp-encoded-list) );
#[derive(Debug, Clone, PartialEq)]
pub struct IpcRequest {
    pub method: String,
    pub id: u64,
    pub req: Request,
}

impl IpcRequest {
    pub fn new(method: String, id: u64, req: Request) -> Self{
        IpcRequest{
            method,
            id,
            req,
        }
    }
}

impl rlp::Encodable for IpcRequest {

    fn rlp_append(&self, s: &mut RlpStream){
        s.begin_list(3);
        s.append(&self.method);
        s.append(&self.id);
        match &self.req {
            Request::CreateHeader(req) => {
                s.append(req);
            }
        }
    }
}

impl rlp::Decodable for IpcRequest {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.as_raw().len() != rlp.payload_info()?.total() {
            return Err(DecoderError::RlpIsTooBig);
        }
        if rlp.item_count()? != 3 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        let method: String = rlp.val_at(0)?;
        let id:u64 = rlp.val_at(1)?;
        let method_name = MethodName::from(method.as_str());
        let req = match method_name {
            MethodName::CreateHeader => {
                let req: create_header::CreateHeaderReq = rlp.val_at(2)?;
                Request::CreateHeader(req)
            }
            MethodName::Unknown => {
                return Err(DecoderError::RlpInvalidLength);
            }
        };

        Ok(IpcRequest {
            method,
            id,
            req,
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use rustc_hex::FromHex;
    use std::str::FromStr;
    use ethereum_types::{Address,U256,H256};

    use crate::transaction::*;
    use crate::header::*;
    use super::create_header::*;

    #[test]
    fn ipcreq_test(){
        let bytes: Vec<u8> = FromHex::from_hex("f85f800182520894095e7baea6a6c7c4c2dfeb977efac326af552d870a801ba048b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353a0efffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804").unwrap();
        let t: UnverifiedTransaction = rlp::decode(&bytes).expect("decoding UnverifiedTransaction failed");
        let parent_hash = H256::from_str("40eb088232727a64c88d5e98d25e7b16ee7e9acc267c25c0088c7d1432745896").unwrap();
        let author = Address::from_str("095e7baea6a6c7c4c2dfeb977efac326af552d87").unwrap();
        let extra_data = b"12bb".to_vec();
        let gas_limit = U256::from(1000);
        let difficulty = U256::from(2020);
        let req = CreateHeaderReq::new(parent_hash.clone(),author.clone(),extra_data.clone(),gas_limit.clone(),difficulty.clone(),vec![t.clone()]);

        let i_req = Request::CreateHeader(req.clone());
        let ipc_req = IpcRequest::new("CreateHeader".to_string(),10,i_req);
        let bytes = ipc_req.rlp_bytes();
        let ipc_req2:IpcRequest = rlp::decode(bytes.as_slice()).unwrap();
        assert_eq!(ipc_req,ipc_req2);
        let req2 = match ipc_req2.req {
            Request::CreateHeader(req) => {
                req
            }
        };

        assert_eq!(req2.difficulty,difficulty);
        assert_eq!(req2.extra_data,extra_data);
        assert_eq!(req2.gas_limit,gas_limit);
        assert_eq!(req2.author,author);
        assert_eq!(req2.parent_block_hash,parent_hash);

    }

    #[test]
    fn ipcresp_test() {

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

        let rlp_data = rlp::encode(&header);
        let other: Header = rlp::decode(rlp_data.as_slice()).unwrap();
        assert_eq!(header,other);
    }

}


