
use crate::BlockNumber;
use ethereum_types::{H256, U256, Address};
use parity_bytes::Bytes;
use keccak_hash::{KECCAK_NULL_RLP, KECCAK_EMPTY_LIST_RLP, keccak};
use rlp::{Rlp, RlpStream, Encodable, DecoderError, Decodable};


#[derive(Debug, Clone, Eq)]
pub struct Header {
    /// Parent hash.
    parent_hash: H256,
    /// Block timestamp.
    timestamp: u64,
    /// Block number.
    number: BlockNumber,
    /// Block author.
    author: Address,

    /// Transactions root.
    transactions_root: H256,

    /// Block extra data.
    extra_data: Bytes,

    /// State root.
    state_root: H256,

    /// Gas used for contracts execution.
    gas_used: U256,
    /// Block gas limit.
    gas_limit: U256,

    /// Block difficulty.
    difficulty: U256,

    /// Memoized hash of that header and the seal.
    hash: Option<H256>,
}

impl PartialEq for Header {
    fn eq(&self, c: &Header) -> bool {
        if let (&Some(ref h1), &Some(ref h2)) = (&self.hash, &c.hash) {
            if h1 == h2 {
                return true
            }
        }

        self.parent_hash == c.parent_hash &&
            self.timestamp == c.timestamp &&
            self.number == c.number &&
            self.author == c.author &&
            self.transactions_root == c.transactions_root &&
            self.extra_data == c.extra_data &&
            self.state_root == c.state_root &&
            self.gas_used == c.gas_used &&
            self.gas_limit == c.gas_limit &&
            self.difficulty == c.difficulty
    }
}

impl Default for Header {
    fn default() -> Self {
        Header {
            parent_hash: H256::zero(),
            timestamp: 0,
            number: 0,
            author: Address::zero(),

            transactions_root: KECCAK_NULL_RLP,
            extra_data: vec![],

            state_root: KECCAK_NULL_RLP,
            gas_used: U256::default(),
            gas_limit: U256::default(),

            difficulty: U256::default(),
            hash: None,
        }
    }
}

impl Header {
    fn genesis(&self) -> Self {
        Header {
            parent_hash: H256::zero(),
            timestamp: 0,
            number: 0,
            author: Address::zero(),

            transactions_root: KECCAK_NULL_RLP,
            extra_data: vec![],

            state_root: KECCAK_NULL_RLP,
            gas_used: U256::default(),
            gas_limit: U256::default(),

            difficulty: U256::default(),
            hash: None,
        }
    }

    /// Create a new, default-valued, header.
    pub fn new() -> Self { Self::default() }

    /// Get the parent_hash field of the header.
    pub fn parent_hash(&self) -> &H256 { &self.parent_hash }

    /// Get the timestamp field of the header.
    pub fn timestamp(&self) -> u64 { self.timestamp }

    /// Get the number field of the header.
    pub fn number(&self) -> BlockNumber { self.number }

    /// Get the author field of the header.
    pub fn author(&self) -> &Address { &self.author }

    /// Get the extra data field of the header.
    pub fn extra_data(&self) -> &Bytes { &self.extra_data }

    /// Get the state root field of the header.
    pub fn state_root(&self) -> &H256 { &self.state_root }

    /// Get the transactions root field of the header.
    pub fn transactions_root(&self) -> &H256 { &self.transactions_root }

    /// Get the gas used field of the header.
    pub fn gas_used(&self) -> &U256 { &self.gas_used }

    /// Get the gas limit field of the header.
    pub fn gas_limit(&self) -> &U256 { &self.gas_limit }

    /// Get the difficulty field of the header.
    pub fn difficulty(&self) -> &U256 { &self.difficulty }

    /// Set the number field of the header.
    pub fn set_parent_hash(&mut self, a: H256) {
        change_field(&mut self.hash, &mut self.parent_hash, a);
    }

    /// Set the state root field of the header.
    pub fn set_state_root(&mut self, a: H256) {
        change_field(&mut self.hash, &mut self.state_root, a);
    }

    /// Set the transactions root field of the header.
    pub fn set_transactions_root(&mut self, a: H256) {
        change_field(&mut self.hash, &mut self.transactions_root, a);
    }

    /// Set the timestamp field of the header.
    pub fn set_timestamp(&mut self, a: u64) {
        change_field(&mut self.hash, &mut self.timestamp, a);
    }

    /// Set the number field of the header.
    pub fn set_number(&mut self, a: BlockNumber) {
        change_field(&mut self.hash, &mut self.number, a);
    }

    /// Set the author field of the header.
    pub fn set_author(&mut self, a: Address) {
        change_field(&mut self.hash, &mut self.author, a);
    }

    /// Set the extra data field of the header.
    pub fn set_extra_data(&mut self, a: Bytes) {
        change_field(&mut self.hash, &mut self.extra_data, a);
    }

    /// Set the gas used field of the header.
    pub fn set_gas_used(&mut self, a: U256) {
        change_field(&mut self.hash, &mut self.gas_used, a);
    }

    /// Set the gas limit field of the header.
    pub fn set_gas_limit(&mut self, a: U256) {
        change_field(&mut self.hash, &mut self.gas_limit, a);
    }

    /// Set the difficulty field of the header.
    pub fn set_difficulty(&mut self, a: U256) {
        change_field(&mut self.hash, &mut self.difficulty, a);
    }

    /// Get & memoize the hash of this header (keccak of the RLP with seal).
    pub fn compute_hash(&mut self) -> H256 {
        let hash = self.hash();
        self.hash = Some(hash);
        hash
    }

    /// Get the hash of this header (keccak of the RLP with seal).
    pub fn hash(&self) -> H256 {
        self.hash.unwrap_or_else(|| keccak(self.rlp()))
    }

    /// Get the hash of the header excluding the seal
    pub fn bare_hash(&self) -> H256 {
        keccak(self.rlp())
    }

    /// Encode the header, getting a type-safe wrapper around the RLP.
    pub fn encoded(&self) -> Bytes {
        self.rlp()
    }

    /// Get the RLP representation of this Header.
    fn rlp(&self) -> Bytes {
        let mut s = RlpStream::new();
        self.stream_rlp(&mut s);
        s.out()
    }

    /// Place this header into an RLP stream `s`.
    fn stream_rlp(&self, s: &mut RlpStream) {

        s.begin_list(10);

        s.append(&self.parent_hash);
        s.append(&self.author);
        s.append(&self.state_root);
        s.append(&self.transactions_root);
        s.append(&self.difficulty);
        s.append(&self.number);
        s.append(&self.gas_limit);
        s.append(&self.gas_used);
        s.append(&self.timestamp);
        s.append(&self.extra_data);
    }
}

/// Alter value of given field, reset memoised hash if changed.
fn change_field<T>(hash: &mut Option<H256>, field: &mut T, value: T) where T: PartialEq<T> {
    if field != &value {
        *field = value;
        *hash = None;
    }
}

impl Decodable for Header {
    fn decode(r: &Rlp) -> Result<Self, DecoderError> {
        let mut blockheader = Header {
            parent_hash: r.val_at(0)?,
            author: r.val_at(1)?,
            state_root: r.val_at(2)?,
            transactions_root: r.val_at(3)?,
            difficulty: r.val_at(4)?,
            number: r.val_at(5)?,
            gas_limit: r.val_at(6)?,
            gas_used: r.val_at(7)?,
            timestamp: r.val_at(8)?,
            extra_data: r.val_at(9)?,
            hash: keccak(r.as_raw()).into(),
        };

        Ok(blockheader)
    }
}

impl Encodable for Header {
    fn rlp_append(&self, s: &mut RlpStream) {
        self.stream_rlp(s);
    }
}

#[cfg(test)]
mod tests {
    use rustc_hex::{FromHex,ToHex};
    use rlp;
    use super::Header;
    use ethereum_types::{H256, U256, Address};
    use std::str::FromStr;
    use parity_bytes::ToPretty;


    #[test]
    fn test_header() {
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

        println!("{:?}",header.hash());

        let r = header.rlp();
        let r = r.as_slice();
        let r: String = r.to_hex();
        println!("{:}",r);
    }


    #[test]
    fn decode_and_encode_header() {
        // that's rlp of block header created with ethash engine.
        let header_rlp: Vec<u8> = "f886a0e4505deee005a3c3dc4aa696ab429562e51a08190861b81a09c652487426ac72945a0b54d5dc17e0aadc383d2db43b0a0d3e029c4ca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347a0e4505deee005a3c3dc4aa696ab429562e51a08190861b81a09c652487426ac728064808083c65d408568656c6c6f".from_hex().unwrap();

        let header: Header = rlp::decode(&header_rlp).expect("error decoding header");
        let encoded_header = rlp::encode(&header);

        assert_eq!(header_rlp, encoded_header);
    }

    #[test]
    fn decode_and_check_hash() {
        let header_rlp: Vec<u8> = "f886a0e4505deee005a3c3dc4aa696ab429562e51a08190861b81a09c652487426ac72945a0b54d5dc17e0aadc383d2db43b0a0d3e029c4ca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347a0e4505deee005a3c3dc4aa696ab429562e51a08190861b81a09c652487426ac728064808083c65d408568656c6c6f".from_hex().unwrap();

        let header: Header = rlp::decode(&header_rlp).expect("error decoding header");
        let encoded_header = rlp::encode(&header);

        let hash = H256::from_str("bec39f12045bf5e5caff2383b0715fe758c9174554f023eef7a46eee08551c63").unwrap();
        assert_eq!(hash, header.hash());
    }
}