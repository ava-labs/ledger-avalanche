use arrayvec::CapacityError;
use nom::error::ErrorKind;

#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
// #[cfg_attr(test, derive(Debug))]
pub enum ParserError {
    ParserOk = 0,
    // Generic errors
    NoData,
    DisplayIdxOutOfRange,
    DisplayPageOutOfRange,
    UnexpectedError,
    ParserInitContextEmpty,
    ParserContextMismatch,
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
    TooManyAddresses,
    InvalidAvaxMessage,
    UnexpectedData,
    InvalidEthMessage,
    InvalidEthSelector,
    InvalidAssetCall,
    NftInfoNotProvided,
    InvalidContractAddress,
    InvalidMessageSize,
    InvalidCodecId,
    InvalidLength,
    InvalidSourceAddressSize,
    // Pinned discriminant: the C side (parser_common.h: parser_blind_sign_not_enabled)
    // compares against this exact value to decide whether to show the blind-sign
    // warning screen, and the FFI passes it through verbatim (dispatcher.rs: `e as
    // u32`). Keep the two in lockstep. Pinning also turns inserting a variant above
    // this line into a hard compile error (duplicate discriminant) instead of a
    // silent drift that breaks the warning screen.
    BlindSignNotEnabled = 42,
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
    fn from(_error: CapacityError) -> Self {
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
