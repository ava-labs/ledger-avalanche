use arrayvec::CapacityError;
use nom::error::ErrorKind;

#[repr(u32)]
#[derive(Copy, Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub enum ParserError {
    // Generic errors
    NoData,
    DisplayIdxOutOfRange,
    DisplayPageOutOfRange,
    UnexpectedError,
    // Required fields
    // Coin specific
    InvalidHashMode,
    InvalidSignature,
    InvalidPubkeyEncoding,
    InvalidAddressVersion,
    InvalidAddressLength,
    InvalidTypeId,
    InvalidCodec,
    InvalidThreshold,
    InvalidNetworkId,
    InvalidChainId,
    InvalidAsciiValue,
    InvalidTimestamp,
    InvalidStakingAmount,
    UnexpectedType,
    InvalidTransactionType,
    OperationOverflows,
    UnexpectedBufferEnd,
    UnexpectedNumberItems,
    UnexpectedField,
    ValueOutOfRange,
    InvalidAddress,
    InvalidPath,
    TooManyOutputs,
    InvalidAvaxMessage,
    InvalidEthMessage,
}

impl From<ErrorKind> for ParserError {
    fn from(err: ErrorKind) -> Self {
        match err {
            ErrorKind::Eof => ParserError::UnexpectedBufferEnd,
            ErrorKind::Permutation => ParserError::UnexpectedType,
            ErrorKind::TooLarge => ParserError::ValueOutOfRange,
            ErrorKind::Tag => ParserError::InvalidTypeId,
            _ => ParserError::UnexpectedError,
        }
    }
}

impl<I> nom::error::ParseError<I> for ParserError {
    fn from_error_kind(_input: I, kind: ErrorKind) -> Self {
        Self::from(kind)
    }

    // We don't have enough memory resources to use here an array with the last
    // N errors to be used as a backtrace, so that, we just propagate here the latest
    // reported error
    fn append(_input: I, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}
impl From<ParserError> for nom::Err<ParserError> {
    fn from(error: ParserError) -> Self {
        nom::Err::Error(error)
    }
}

impl From<CapacityError> for ParserError {
    fn from(error: CapacityError) -> Self {
        ParserError::UnexpectedBufferEnd
    }
}

impl From<nom::Err<Self>> for ParserError {
    fn from(e: nom::Err<Self>) -> Self {
        match e {
            nom::Err::Error(e) => e,
            nom::Err::Failure(e) => e,
            nom::Err::Incomplete(_) => Self::UnexpectedBufferEnd,
        }
    }
}
