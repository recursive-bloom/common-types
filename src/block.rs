
use crate::{
	header::Header,
	transaction::{UnverifiedTransaction},
};
use parity_bytes::Bytes;
use rlp::{Rlp, RlpStream, Decodable, DecoderError};

/// A block, encoded as it is on the block chain.
#[derive(Default, Debug, Clone, PartialEq)]
pub struct Block {
	/// The header of this block.
	pub header: Header,
	/// The transactions in this block.
	pub transactions: Vec<UnverifiedTransaction>,
}

impl Block {
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
