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

        // initial_states
        let states = unsafe { &mut *addr_of_mut!((*out).initial_states).cast() };
        let rem = ObjectList::<InitialState>::new_into(rem, states)?;

        unsafe {
            // by default all outputs are renderable
            addr_of_mut!((*out).name).write(name);
            addr_of_mut!((*out).sym).write(sym);
        }
        Ok(rem)
    }
}

impl<'b> DisplayableItem for CreateAssetTx<'b> {
    fn num_items(&self) -> usize {
        // description + asset_name + asset_symbol + denomination
        1 + 1 + 1 + 1
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        use bolos::{PIC,pic_str};
        use lexical_core::Number;

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

            _ => Err(ViewError::NoData),
        }
    }
}
