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
    InvalidThreshold,
    InvalidNetworkId,
    InvalidChainId,
    UnexpectedType,
    UnexpectedBufferEnd,
    UnexpectedNumberItems,
    UnexpectedField,
    ValueOutOfRange,
    InvalidAddress,
}

impl From<ErrorKind> for ParserError {
    fn from(err: ErrorKind) -> Self {
        match err {
            ErrorKind::Eof => ParserError::UnexpectedBufferEnd,
            ErrorKind::Permutation => ParserError::UnexpectedType,
            ErrorKind::TooLarge => ParserError::ValueOutOfRange,
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
