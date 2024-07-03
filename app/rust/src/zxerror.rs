/// Compatible error definition with ledger-zxlib error
#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub enum ZxError {
    Unknown = 0b00000000,
    Ok = 0b00000011,
    NoData = 0b00000101,
    BufferTooSmall = 0b00000110,
    OutOfBounds = 0b00001001,
    EncodingFailed = 0b00001010,
    InvalidCryptoSettings = 0b00001100,
    LedgerApiError = 0b00001111,
}
