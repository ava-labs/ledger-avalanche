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
use nom::{
    bytes::complete::take,
    number::complete::{be_u32, be_u64},
    sequence::tuple,
};
use zemu_sys::ViewError;

use crate::{
    handlers::handle_ui_message,
    parser::{DisplayableItem, ParserError},
};

const U32_SIZE: usize = std::mem::size_of::<u32>();

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct SECPTransferInput<'b> {
    pub amount: u64,
    // list of address indices, the indices are u32
    // but we represent them as a slice of U32_SIZE byte-arrays
    // instead of casting it directly to &[u32] because of the
    // endianness
    pub address_indices: &'b [[u8; U32_SIZE]],
}

impl<'b> SECPTransferInput<'b> {
    pub const TYPE_ID: u32 = 0x00000005;

    #[cfg(test)]
    pub fn from_bytes(input: &'b [u8]) -> Result<(&'b [u8], Self), nom::Err<ParserError>> {
        let mut out = MaybeUninit::uninit();
        let rem = Self::from_bytes_into(input, &mut out)?;
        unsafe { Ok((rem, out.assume_init())) }
    }

    #[inline(never)]
    pub fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("SECPTransferInput::from_bytes_into\x00");

        let (rem, (amount, num_indices)) = tuple((be_u64, be_u32))(input)?;

        let (rem, indices) = take(num_indices as usize * U32_SIZE)(rem)?;
        let indices =
            bytemuck::try_cast_slice(indices).map_err(|_| ParserError::InvalidAddressLength)?;

        //good ptr and no uninit reads
        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).amount).write(amount);
            addr_of_mut!((*out).address_indices).write(indices);
        }

        Ok(rem)
    }

    fn parse_index(&self, index_n: usize) -> Result<(&'b [u8], u32), nom::Err<ParserError>> {
        if let Some(slice) = self.address_indices.get(index_n) {
            let (rem, index) = be_u32(&slice[..])?;
            Ok((rem, index))
        } else {
            Err(ParserError::UnexpectedBufferEnd.into())
        }
    }
}

impl<'a> DisplayableItem for SECPTransferInput<'a> {
    fn num_items(&self) -> usize {
        // output-type, amount, indices
        1 + 1 + self.address_indices.len()
    }

    #[inline(never)]
    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::{pic_str, PIC};
        use lexical_core::{write as itoa, Number};

        let mut buffer = [0; usize::FORMATTED_SIZE];

        let num_indices = self.address_indices.len();

        match item_n as usize {
            0 => {
                let title_content = pic_str!(b"Output");
                title[..title_content.len()].copy_from_slice(title_content);

                handle_ui_message(pic_str!(b"SECPTransferInput"), message, page)
            }
            1 => {
                let title_content = pic_str!(b"Amount");
                title[..title_content.len()].copy_from_slice(title_content);
                let buffer = itoa(self.amount, &mut buffer);

                handle_ui_message(buffer, message, page)
            }
            i @ 2.. if i < num_indices + 2 => {
                // normalize the index into something between 0 and num_indices
                let item_n = i - 2;

                let title_content = pic_str!(b"Indices");
                title[..title_content.len()].copy_from_slice(title_content);

                let (_, index) = self.parse_index(item_n).map_err(|_| ViewError::Unknown)?;

                let buffer = itoa(index, &mut buffer);

                handle_ui_message(buffer, message, page)
            }

            _ => Err(ViewError::NoData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // SECP256K1TransferInput { type_id: 5, amount: 186, address_indices: [4, 5, 58, 1, 79, 65, 87, 94, 125, 378] }
    const DATA: &[u8] = &[
        0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 186, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 58, 0,
        0, 0, 1, 0, 0, 0, 79, 0, 0, 0, 65, 0, 0, 0, 87, 0, 0, 0, 94, 0, 0, 0, 125, 0, 0, 1, 122,
    ];

    #[test]
    fn parse_secp256k1_input() {
        let input = SECPTransferInput::from_bytes(&DATA[4..]).unwrap().1;
        assert_eq!(input.address_indices.len(), 10);
        assert_eq!(input.amount, 186);
    }
}
