
use crate::{
	header::Header,
	transaction::{UnverifiedTransaction},
};
use parity_bytes::Bytes;
use rlp::{self,Rlp, RlpStream, Decodable, DecoderError};
use ethereum_types::H256;


/// A block, encoded as it is on the block chain.
#[derive(Default, Debug, Clone, PartialEq)]
pub struct Block {
	/// The header of this block.
	pub header: Header,
	/// The transactions in this block.
	pub transactions: Vec<UnverifiedTransaction>,
}

impl Block {

	pub fn new(header: Header, transactions: Vec<UnverifiedTransaction>) -> Self {
		Block{
			header,
			transactions,
		}
	}

	/// Get the RLP-encoding of the block with the seal.
	pub fn rlp_bytes(&self) -> Bytes {
		let mut block_rlp = RlpStream::new_list(2);
		block_rlp.append(&self.header);
		block_rlp.append_list(&self.transactions);
		block_rlp.out()
	}
}

impl Decodable for Block {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		if rlp.as_raw().len() != rlp.payload_info()?.total() {
			return Err(DecoderError::RlpIsTooBig);
		}
		if rlp.item_count()? != 2 {
			return Err(DecoderError::RlpIncorrectListLen);
		}
		Ok(Block {
			header: rlp.val_at(0)?,
			transactions: rlp.list_at(1)?,
		})
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockHashListError {
	DuplicateHash,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BlockHashList(Vec<H256>);

impl Default for BlockHashList {
	fn default() -> Self {
		BlockHashList(vec![])
	}
}

impl BlockHashList {

	pub fn push(&mut self,block_hash: H256) -> Result<(),BlockHashListError> {
		match self.0.iter().filter(|h| **h == block_hash).count() {
			0 => {
				self.0.push(block_hash);
				Ok(())
			}

			_ => {
				Err(BlockHashListError::DuplicateHash)
			}
		}
	}

	pub fn rlp_bytes(&self) -> Bytes {
		let mut list_rlp = RlpStream::new_list(1);
		list_rlp.append_list(&self.0);
		list_rlp.out()
	}

	pub fn push_main_block_hash(&mut self, main_block_hash: H256) {
		self.0.retain(|h| h != &main_block_hash);
		self.0.insert(0,main_block_hash);
	}

	pub fn block_hashes(&self) -> &Vec<H256> {
		&self.0
	}
}

impl Decodable for BlockHashList {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		if rlp.as_raw().len() != rlp.payload_info()?.total() {
			return Err(DecoderError::RlpIsTooBig);
		}
		if rlp.item_count()? != 1 {
			return Err(DecoderError::RlpIncorrectListLen);
		}
		Ok(BlockHashList(rlp.list_at(0)?))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::str::FromStr;

	#[test]
	fn block_hash_list_test() {
		let block_hash1 = H256::from_str("40eb088232727a64c88d5e98d25e7b16ee7e9acc267c25c0088c7d1432745896").unwrap();
		let block_hash2 = H256::from_str("30eb088232727a64c88d5e98d25e7b16ee7e9acc267c25c0088c7d1432745896").unwrap();

		let mut list = BlockHashList::default();
		list.push(block_hash1.clone()).unwrap();
		list.push(block_hash2.clone()).unwrap();

		let list_bytes = list.rlp_bytes();
		let list2: BlockHashList = rlp::decode(list_bytes.as_slice()).unwrap();
		assert_eq!(list,list2);
	}

	#[test]
	fn block_hash_list_push_main_hash_test() {
		let block_hash1 = H256::from_str("40eb088232727a64c88d5e98d25e7b16ee7e9acc267c25c0088c7d1432745896").unwrap();
		let block_hash2 = H256::from_str("30eb088232727a64c88d5e98d25e7b16ee7e9acc267c25c0088c7d1432745896").unwrap();
		let block_hash3 = H256::from_str("20eb088232727a64c88d5e98d25e7b16ee7e9acc267c25c0088c7d1432745896").unwrap();

		let mut list = BlockHashList::default();
		list.push(block_hash1.clone()).unwrap();
		list.push(block_hash2.clone()).unwrap();

		list.push_main_block_hash(block_hash3);
		assert_eq!(list.block_hashes(),&vec![block_hash3,block_hash1,block_hash2]);
	}

}



