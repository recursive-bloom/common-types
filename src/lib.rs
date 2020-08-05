pub mod header;
pub mod transaction;
pub mod block;

/// Type for block number.
pub type BlockNumber = u64;
pub type TransactionIndex = u64;


use std::{fmt, error};

use ethereum_types::U256;
use parity_crypto::publickey::{Error as EthPublicKeyCryptoError};


#[derive(Debug, PartialEq, Eq, Clone, Copy)]
/// Error indicating value found is outside of a valid range.
pub struct OutOfBounds<T> {
    /// Minimum allowed value.
    pub min: Option<T>,
    /// Maximum allowed value.
    pub max: Option<T>,
    /// Value found.
    pub found: T,
}

impl<T> OutOfBounds<T> {
    pub fn map<F, U>(self, map: F) -> OutOfBounds<U>
        where F: Fn(T) -> U
    {
        OutOfBounds {
            min: self.min.map(&map),
            max: self.max.map(&map),
            found: map(self.found),
        }
    }
}

impl<T: fmt::Display> fmt::Display for OutOfBounds<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match (self.min.as_ref(), self.max.as_ref()) {
            (Some(min), Some(max)) => format!("Min={}, Max={}", min, max),
            (Some(min), _) => format!("Min={}", min),
            (_, Some(max)) => format!("Max={}", max),
            (None, None) => "".into(),
        };

        f.write_fmt(format_args!("Value {} out of bounds. {}", self.found, msg))
    }
}


#[derive(Debug, PartialEq, Clone)]
/// Errors concerning transaction processing.
pub enum Error {
    /// Transaction is already imported to the queue
    AlreadyImported,
    /// Transaction is not valid anymore (state already has higher nonce)
    Old,
    /// Transaction was not imported to the queue because limit has been reached.
    LimitReached,
    /// Transaction's gas price is below threshold.
    InsufficientGasPrice {
        /// Minimal expected gas price
        minimal: U256,
        /// Transaction gas price
        got: U256,
    },
    /// Transaction has too low fee
    /// (there is already a transaction with the same sender-nonce but higher gas price)
    TooCheapToReplace {
        /// previous transaction's gas price
        prev: Option<U256>,
        /// new transaction's gas price
        new: Option<U256>,
    },
    /// Transaction's gas is below currently set minimal gas requirement.
    InsufficientGas {
        /// Minimal expected gas
        minimal: U256,
        /// Transaction gas
        got: U256,
    },
    /// Sender doesn't have enough funds to pay for this transaction
    InsufficientBalance {
        /// Senders balance
        balance: U256,
        /// Transaction cost
        cost: U256,
    },
    /// Transactions gas is higher then current gas limit
    GasLimitExceeded {
        /// Current gas limit
        limit: U256,
        /// Declared transaction gas
        got: U256,
    },
    /// Transaction's gas limit (aka gas) is invalid.
    InvalidGasLimit(OutOfBounds<U256>),
    /// Transaction sender is banned.
    SenderBanned,
    /// Transaction receipient is banned.
    RecipientBanned,
    /// Contract creation code is banned.
    CodeBanned,
    /// Invalid chain ID given.
    InvalidChainId,
    /// Not enough permissions given by permission contract.
    NotAllowed,
    /// Signature error
    InvalidSignature(String),
    /// Transaction too big
    TooBig,
    /// Invalid RLP encoding
    InvalidRlp(String),
}

impl From<EthPublicKeyCryptoError> for Error {
    fn from(err: EthPublicKeyCryptoError) -> Self {
        Error::InvalidSignature(format!("{}", err))
    }
}

impl From<rlp::DecoderError> for Error {
    fn from(err: rlp::DecoderError) -> Self {
        Error::InvalidRlp(format!("{}", err))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;
        let msg = match *self {
            AlreadyImported => "Already imported".into(),
            Old => "No longer valid".into(),
            TooCheapToReplace { prev, new } =>
                format!("Gas price too low to replace, previous tx gas: {:?}, new tx gas: {:?}",
                        prev, new
                ),
            LimitReached => "Transaction limit reached".into(),
            InsufficientGasPrice { minimal, got } =>
                format!("Insufficient gas price. Min={}, Given={}", minimal, got),
            InsufficientGas { minimal, got } =>
                format!("Insufficient gas. Min={}, Given={}", minimal, got),
            InsufficientBalance { balance, cost } =>
                format!("Insufficient balance for transaction. Balance={}, Cost={}",
                        balance, cost),
            GasLimitExceeded { limit, got } =>
                format!("Gas limit exceeded. Limit={}, Given={}", limit, got),
            InvalidGasLimit(ref err) => format!("Invalid gas limit. {}", err),
            SenderBanned => "Sender is temporarily banned.".into(),
            RecipientBanned => "Recipient is temporarily banned.".into(),
            CodeBanned => "Contract code is temporarily banned.".into(),
            InvalidChainId => "Transaction of this chain ID is not allowed on this chain.".into(),
            InvalidSignature(ref err) => format!("Transaction has invalid signature: {}.", err),
            NotAllowed => "Sender does not have permissions to execute this type of transaction".into(),
            TooBig => "Transaction too big".into(),
            InvalidRlp(ref err) => format!("Transaction has invalid RLP structure: {}.", err),
        };

        f.write_fmt(format_args!("Transaction error ({})", msg))
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "Transaction error"
    }
}


