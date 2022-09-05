/*******************************************************************************
*   (c) 2021 Zondax GmbH
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
use nom::bytes::complete::{tag, take};
use nom::number::complete::{be_u16, be_u32, be_u8};
use zemu_sys::ViewError;

use crate::parser::{nano_avax_to_fp_str, ChainId};
use crate::{
    handlers::handle_ui_message,
    parser::{
        u8_to_str, AvmOutput, BaseTxFields, DisplayableItem, FromBytes, Header, InitialState,
        ObjectList, ParserError, AVM_CREATE_ASSET_TX,
    },
};

const MAX_NAME_LEN: usize = 128;
const MAX_SYMBOL_LEN: usize = 4;

#[derive(Clone, Copy, PartialEq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct CreateAssetTx<'b> {
    pub tx_header: Header<'b>,
    pub base_tx: BaseTxFields<'b, AvmOutput<'b>>,
    pub name: &'b [u8],
    pub sym: &'b [u8],
    pub denomination: u8,
    pub initial_states: ObjectList<'b, InitialState<'b>>,
}

impl<'b> CreateAssetTx<'b> {
    fn fee(&'b self) -> Result<u64, ParserError> {
        let sum_inputs = self.base_tx.sum_inputs_amount()?;

        let base_outputs = self.base_tx.sum_outputs_amount()?;

        let fee = sum_inputs
            .checked_sub(base_outputs)
            .ok_or(ParserError::OperationOverflows)?;
        Ok(fee)
    }
}

impl<'b> FromBytes<'b> for CreateAssetTx<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("CreateAssetTx::from_bytes_into\x00");

        let (rem, _) = tag(AVM_CREATE_ASSET_TX.to_be_bytes())(input)?;

        let out = out.as_mut_ptr();

        // tx header
        let tx_header = unsafe { &mut *addr_of_mut!((*out).tx_header).cast() };
        let rem = Header::from_bytes_into(rem, tx_header)?;

        // This transaction is only valid if comes from XChain
        let chain_id = unsafe { (&*tx_header.as_ptr()).chain_id()? };
        if !matches!(chain_id, ChainId::XChain) {
            return Err(ParserError::InvalidChainId.into());
        }

        // base_tx
        let base_tx = unsafe { &mut *addr_of_mut!((*out).base_tx).cast() };
        let rem = BaseTxFields::<AvmOutput>::from_bytes_into(rem, base_tx)?;

        // name
        let (rem, name_len) = be_u16(rem)?;
        if name_len > MAX_NAME_LEN as _ {
            return Err(ParserError::ValueOutOfRange.into());
        }
        let (rem, name) = take(name_len as usize)(rem)?;
        if !name.is_ascii() {
            return Err(ParserError::InvalidAsciiValue.into());
        }

        // symbol
        let (rem, sym_len) = be_u16(rem)?;
        if sym_len > MAX_SYMBOL_LEN as _ {
            return Err(ParserError::ValueOutOfRange.into());
        }
        let (rem, sym) = take(sym_len as usize)(rem)?;
        if !sym.is_ascii() {
            return Err(ParserError::InvalidAsciiValue.into());
        }

        let (rem, denomination) = be_u8(rem)?;

        // initial_states
        let states = unsafe { &mut *addr_of_mut!((*out).initial_states).cast() };
        let rem = ObjectList::<InitialState>::new_into(rem, states)?;

        unsafe {
            // by default all outputs are renderable
            addr_of_mut!((*out).name).write(name);
            addr_of_mut!((*out).sym).write(sym);
            addr_of_mut!((*out).denomination).write(denomination);
        }
        Ok(rem)
    }
}

impl<'b> DisplayableItem for CreateAssetTx<'b> {
    fn num_items(&self) -> usize {
        // description + asset_name + asset_symbol + denomination + fee
        1 + 1 + 1 + 1 + 1
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        use bolos::{pic_str, PIC};
        use lexical_core::Number;

        let mut buffer = [0; u64::FORMATTED_SIZE_DECIMAL + 2];

        match item_n {
            0 => {
                let label = pic_str!(b"CreateAsset");
                title[..label.len()].copy_from_slice(label);
                let content = pic_str!(b"Transaction");
                handle_ui_message(content, message, page)
            }
            1 => {
                let label = pic_str!(b"Asset Name");
                title[..label.len()].copy_from_slice(label);
                handle_ui_message(self.name, message, page)
            }
            2 => {
                let label = pic_str!(b"Asset symbol");
                title[..label.len()].copy_from_slice(label);
                handle_ui_message(self.sym, message, page)
            }
            3 => {
                let label = pic_str!(b"Denomination");
                title[..label.len()].copy_from_slice(label);

                let mut buffer = [0; u8::FORMATTED_SIZE + 2];
                let num = u8_to_str(self.denomination, &mut buffer[..])
                    .map_err(|_| ViewError::Unknown)?;

                handle_ui_message(num, message, page)
            }

            4 => {
                let label = pic_str!(b"Fee(AVAX)");
                title[..label.len()].copy_from_slice(label);

                let fee = self.fee().map_err(|_| ViewError::Unknown)?;
                let fee_buff =
                    nano_avax_to_fp_str(fee, &mut buffer[..]).map_err(|_| ViewError::Unknown)?;

                handle_ui_message(fee_buff, message, page)
            }

            _ => Err(ViewError::NoData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &[u8] = &[
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0xab, 0x68, 0xeb, 0x1e, 0xe1, 0x42, 0xa0,
        0x5c, 0xfe, 0x76, 0x8c, 0x36, 0xe1, 0x1f, 0x0b, 0x59, 0x6d, 0xb5, 0xa3, 0xc6, 0xc7, 0x7a,
        0xab, 0xe6, 0x65, 0xda, 0xd9, 0xe6, 0x38, 0xca, 0x94, 0xf7, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xd4, 0x31, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x51,
        0x02, 0x5c, 0x61, 0xfb, 0xcf, 0xc0, 0x78, 0xf6, 0x93, 0x34, 0xf8, 0x34, 0xbe, 0x6d, 0xd2,
        0x6d, 0x55, 0xa9, 0x55, 0xc3, 0x34, 0x41, 0x28, 0xe0, 0x60, 0x12, 0x8e, 0xde, 0x35, 0x23,
        0xa2, 0x4a, 0x46, 0x1c, 0x89, 0x43, 0xab, 0x08, 0x59, 0x00, 0x00, 0x00, 0x01, 0xf1, 0xe1,
        0xd1, 0xc1, 0xb1, 0xa1, 0x91, 0x81, 0x71, 0x61, 0x51, 0x41, 0x31, 0x21, 0x11, 0x01, 0xf0,
        0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x07,
        0x5b, 0xcd, 0x15, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x02, 0x03, 0x00, 0x10, 0x56, 0x6f, 0x6c, 0x61, 0x74,
        0x69, 0x6c, 0x69, 0x74, 0x79, 0x20, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x00, 0x03, 0x56, 0x49,
        0x58, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xd4, 0x31, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x51, 0x02, 0x5c,
        0x61, 0xfb, 0xcf, 0xc0, 0x78, 0xf6, 0x93, 0x34, 0xf8, 0x34, 0xbe, 0x6d, 0xd2, 0x6d, 0x55,
        0xa9, 0x55, 0xc3, 0x34, 0x41, 0x28, 0xe0, 0x60, 0x12, 0x8e, 0xde, 0x35, 0x23, 0xa2, 0x4a,
        0x46, 0x1c, 0x89, 0x43, 0xab, 0x08, 0x59,
    ];

    #[test]
    fn parse_create_asset() {
        let (_, tx) = CreateAssetTx::from_bytes(DATA).unwrap();
        let name = core::str::from_utf8(tx.name).unwrap();
        let symbol = core::str::from_utf8(tx.sym).unwrap();
        assert_eq!(name, "Volatility Index");
        assert_eq!(symbol, "VIX");
        assert_eq!(tx.denomination, 2);
    }
}
