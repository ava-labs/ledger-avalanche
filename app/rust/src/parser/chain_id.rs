/*******************************************************************************
*   (c) 2018-2024 Zondax AG
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
use crate::handlers::handle_ui_message;
use crate::sys::ViewError;
use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::bytes::complete::take;

use crate::parser::{DisplayableItem, FromBytes, ParserError};
use crate::utils::hex_encode;

pub const CHAIN_ID_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct ChainId<'b>(&'b [u8; CHAIN_ID_LEN]);

impl<'b> ChainId<'b> {
    pub fn new(id: &'b [u8; CHAIN_ID_LEN]) -> Self {
        Self(id)
    }
}

impl<'b> FromBytes<'b> for ChainId<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("ChainId::from_bytes_into\x00");

        let (rem, chain_id) = take(CHAIN_ID_LEN)(input)?;
        // This would not fail as previous line ensures we take
        // the right amount of bytes, also the alignemnt is correct
        let chain_id = arrayref::array_ref!(chain_id, 0, CHAIN_ID_LEN);

        //good ptr and no uninit reads
        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).0).write(chain_id);
        }

        Ok(rem)
    }
}

impl<'b> DisplayableItem for ChainId<'b> {
    fn num_items(&self) -> Result<u8, ViewError> {
        Ok(1)
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::{pic_str, PIC};

        if item_n != 0 {
            return Err(ViewError::NoData);
        }
        let prefix = pic_str!(b"0x"!);
        let label = pic_str!(b"Chain ID");
        title[..label.len()].copy_from_slice(label);

        // prefix
        let mut out = [0; CHAIN_ID_LEN * 2 + 2];
        let mut sz = prefix.len();
        out[..prefix.len()].copy_from_slice(&prefix[..]);

        sz += hex_encode(self.0, &mut out[prefix.len()..]).map_err(|_| ViewError::Unknown)?;

        handle_ui_message(&out[..sz], message, page)
    }
}
