/*******************************************************************************
*   (c) 2022 Zondax AG
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
use core::{mem::MaybeUninit, ptr::addr_of_mut};

use nom::bytes::complete::take;
use zemu_sys::ViewError;

use crate::{
    handlers::{eth::u256, handle_ui_message},
    parser::{
        intstr_to_fpstr_inplace, DisplayableItem, FromBytes, ParserError, EIP1559_TX, EIP2930_TX,
        U64_SIZE,
    },
};

mod legacy;
pub use legacy::Legacy;
mod base;
pub use base::BaseLegacy;

mod eip1559;
pub use eip1559::Eip1559;
mod eip2930;
pub use eip2930::Eip2930;

/// Renders an u256 in bytes.
/// `input`: The big-indian bytes of the number to
/// be rendered
#[inline(never)]
pub fn render_u256(
    num: &[u8],
    decimal_point: usize,
    message: &mut [u8],
    page: u8,
) -> Result<u8, ViewError> {
    let mut u256_str = [0; u256::FORMATTED_SIZE_DECIMAL + 2];

    let amount = u256::from_big_endian(num);
    amount.to_lexical(&mut u256_str);

    let out =
        intstr_to_fpstr_inplace(&mut u256_str, decimal_point).map_err(|_| ViewError::Unknown)?;

    handle_ui_message(out, message, page)
}

/// Returns the remaining bytes from data along with the bytes
/// representation of the found item
pub fn parse_rlp_item(data: &[u8]) -> Result<(&[u8], &[u8]), nom::Err<ParserError>> {
    let read = 0;

    let marker = *data.first().ok_or(ParserError::UnexpectedBufferEnd)?;

    let (read, to_read) = match marker {
        _num @ 0..=0x7F => return Ok((&data[1..], &data[0..1])),
        sstring @ 0x80..=0xB7 => (1, sstring as u64 - 0x80),
        string @ 0xB8..=0xBF => {
            // For strings longer than 55 bytes the length is encoded
            // differently.
            // The number of bytes that compose the length is encoded
            // in the marker
            // And then the length is just the number BE encoded
            let num_bytes = string as usize - 0xB7;
            let num = data
                .get(1..)
                .ok_or(ParserError::UnexpectedBufferEnd)?
                .get(..num_bytes)
                .ok_or(ParserError::UnexpectedBufferEnd)?;

            let mut array = [0; U64_SIZE];
            array[U64_SIZE - num_bytes..].copy_from_slice(num);

            let num = u64::from_be_bytes(array);
            (1 + num_bytes, num)
        }
        slist @ 0xC0..=0xF7 => (read + 1, slist as u64 - 0xC0),
        list @ 0xF8.. => {
            // For lists longer than 55 bytes the length is encoded
            // differently.
            // The number of bytes that compose the length is encoded
            // in the marker
            // And then the length is just the number BE encoded

            let num_bytes = list as usize - 0xF7;
            let num = data
                .get(1..)
                .ok_or(ParserError::UnexpectedBufferEnd)?
                .get(..num_bytes)
                .ok_or(ParserError::UnexpectedBufferEnd)?;

            let mut array = [0; U64_SIZE];
            array[U64_SIZE - num_bytes..].copy_from_slice(num);

            let num = u64::from_be_bytes(array);
            (1 + num_bytes, num)
        }
    };

    take(to_read as usize)(&data[read..])
}

// Important: do not change the repr attribute,
// as this type is use as the tag field
// for the Transaction enum which has the same representation
#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
#[repr(u8)]
pub enum EthTxType {
    Legacy,
    EIP1559,
    EIP2930,
}

impl From<u8> for EthTxType {
    fn from(value: u8) -> Self {
        match value {
            EIP1559_TX => Self::EIP1559,
            EIP2930_TX => Self::EIP2930,
            // legacy is constructed
            _ => Self::Legacy,
        }
    }
}

impl EthTxType {
    fn from_bytes(input: &[u8]) -> Result<(&[u8], Self), ParserError> {
        if input.is_empty() {
            return Err(ParserError::UnexpectedBufferEnd);
        }

        let tx_type = input.get(0).ok_or(ParserError::UnexpectedBufferEnd)?;

        match *tx_type {
            EIP1559_TX => Ok((&input[1..], Self::EIP1559)),
            EIP2930_TX => Ok((&input[1..], Self::EIP2930)),
            // legacy transaction does not have a version so just parse
            // it, if it is not valid, the parser will error anyways
            _ => Ok((input, Self::Legacy)),
        }
    }
}

#[repr(C)]
struct LegacyVariant<'b>(EthTxType, Legacy<'b>);

#[repr(C)]
struct Eip1559Variant<'b>(EthTxType, Eip1559<'b>);

#[repr(C)]
struct Eip2930Variant<'b>(EthTxType, Eip2930<'b>);

#[derive(Clone, Copy, PartialEq)]
// DO not change the representation
// as it would cause unalignment issues
// with the OutputType tag
#[repr(u8)]
#[cfg_attr(test, derive(Debug))]
pub enum EthTransaction<'b> {
    Legacy(Legacy<'b>),
    Eip1559(Eip1559<'b>),
    Eip2930(Eip2930<'b>),
}

impl<'b> EthTransaction<'b> {
    #[cfg(test)]
    pub fn new(input: &'b [u8]) -> Result<Self, ParserError> {
        let mut variant = MaybeUninit::uninit();
        Self::new_into(input, &mut variant)?;
        // Safe as parsing initializes it
        Ok(unsafe { variant.assume_init() })
    }

    pub fn new_into(
        input: &'b [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<(), ParserError> {
        _ = Self::from_bytes_into(input, out)?;
        Ok(())
    }
    pub fn chain_id_low_byte(&self) -> u8 {
        match self {
            Self::Legacy(t) => t.chain_id_low_byte(),
            Self::Eip1559(t) => t.chain_id_low_byte(),
            Self::Eip2930(t) => t.chain_id_low_byte(),
        }
    }
}

impl<'b> FromBytes<'b> for EthTransaction<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        // get transaction data as the eip2718 defines transactions structure as follow:
        // version || rlp[tx_fields]
        // version for eip1559 = 2,
        // for eip2930 = 1,
        // for legacy it does not have a version
        let (rem, tx_type) = EthTxType::from_bytes(input)?;

        // parse rlp[] part in order to get the transaction bytes
        let (rem, tx_bytes) = parse_rlp_item(rem)?;
        if tx_bytes.is_empty() {
            return Err(ParserError::UnexpectedBufferEnd.into());
        }
        match tx_type {
            EthTxType::Legacy => {
                let out = out.as_mut_ptr() as *mut LegacyVariant;

                let legacy = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                // read all the data as the contract deployment
                // we do not have a way to verify this data. in the worst scenario
                // the transaction would be rejected, and for this reason
                // It is shown on the screen(partially) for the user to review.
                _ = Legacy::from_bytes_into(tx_bytes, legacy)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(EthTxType::Legacy);
                }
            }
            EthTxType::EIP1559 => {
                let out = out.as_mut_ptr() as *mut Eip1559Variant;

                let eip = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                // read all the data as the contract deployment
                // we do not have a way to verify this data. in the worst scenario
                // the transaction would be rejected, and for this reason
                // It is shown on the screen(partially) for the user to review.
                _ = Eip1559::from_bytes_into(tx_bytes, eip)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(EthTxType::EIP1559);
                }
            }
            EthTxType::EIP2930 => {
                let out = out.as_mut_ptr() as *mut Eip2930Variant;

                let eip = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                // read all the data as the contract deployment
                // we do not have a way to verify this data. in the worst scenario
                // the transaction would be rejected, and for this reason
                // It is shown on the screen(partially) for the user to review.
                _ = Eip2930::from_bytes_into(tx_bytes, eip)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(EthTxType::EIP2930);
                }
            }
        }
        Ok(rem)
    }
}

impl<'b> DisplayableItem for EthTransaction<'b> {
    fn num_items(&self) -> usize {
        match self {
            Self::Legacy(t) => t.num_items(),
            Self::Eip1559(t) => t.num_items(),
            Self::Eip2930(t) => t.num_items(),
        }
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        match self {
            Self::Legacy(t) => t.render_item(item_n, title, message, page),
            Self::Eip1559(t) => t.render_item(item_n, title, message, page),
            Self::Eip2930(t) => t.render_item(item_n, title, message, page),
        }
    }
}
