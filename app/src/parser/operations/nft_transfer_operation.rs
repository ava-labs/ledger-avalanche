/*******************************************************************************
*   (c) 2018 - 2022 Zondax AG
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

use crate::parser::NFTTransferOutput;

use crate::{
    parser::{DisplayableItem, FromBytes, ParserError, U32_SIZE},
    utils::ApduPanic,
};

use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::{
    bytes::complete::{tag, take},
    number::complete::be_u32,
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
#[repr(C)]
pub struct NFTTransferOperation<'b> {
    pub address_indices: &'b [[u8; U32_SIZE]],
    // The documentation states
    // This output doesn’t have the TypeId,
    // because the type is known by the context of being in this operation
    // so we need to bypass the type_id when parsing it.
    // The simplest way is adding a helper method to
    // nft_transfer_output that omits this check.
    pub nft_transfer_output: NFTTransferOutput<'b>,
}

impl<'b> NFTTransferOperation<'b> {
    pub const TYPE_ID: u32 = 0x0d;
}

impl<'b> FromBytes<'b> for NFTTransferOperation<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("NFTTransferOperation::from_bytes_into\x00");

        // // double check the type
        let (rem, _) = tag(Self::TYPE_ID.to_be_bytes())(input)?;

        let (rem, num_indices) = be_u32(rem)?;
        let (rem, indices) = take(num_indices as usize * U32_SIZE)(rem)?;
        let indices = bytemuck::try_cast_slice(indices).apdu_unwrap();

        let out = out.as_mut_ptr();
        let nft_transfer_output = unsafe { &mut *addr_of_mut!((*out).nft_transfer_output).cast() };
        // parse without type checking
        let rem = NFTTransferOutput::into_without_type(rem, nft_transfer_output)?;

        //good ptr and no uninit reads
        unsafe {
            addr_of_mut!((*out).address_indices).write(indices);
        }

        Ok(rem)
    }
}

impl<'b> DisplayableItem for NFTTransferOperation<'b> {
    fn num_items(&self) -> usize {
        self.nft_transfer_output.num_items()
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        self.nft_transfer_output
            .render_item(item_n, title, message, page)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nft_transfer_operation() {
        let raw_input = [
            // Type ID
            0x00, 0x00, 0x00, 0x0d, // number of address indices:
            0x00, 0x00, 0x00, 0x02, // address index 0:
            0x00, 0x00, 0x00, 0x07, // address index 1:
            0x00, 0x00, 0x00, 0x03, // groupID:
            0x00, 0x00, 0x30, 0x39, // length of payload:
            0x00, 0x00, 0x00, 0x03, // payload:
            0x43, 0x11, 0x00, // locktime:
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd4, 0x31, // threshold:
            0x00, 0x00, 0x00, 0x01, // number of addresses:
            0x00, 0x00, 0x00, 0x02, // addrs[0]:
            0x51, 0x02, 0x5c, 0x61, 0xfb, 0xcf, 0xc0, 0x78, 0xf6, 0x93, 0x34, 0xf8, 0x34, 0xbe,
            0x6d, 0xd2, 0x6d, 0x55, 0xa9, 0x55, // addrs[1]:
            0xc3, 0x34, 0x41, 0x28, 0xe0, 0x60, 0x12, 0x8e, 0xde, 0x35, 0x23, 0xa2, 0x4a, 0x46,
            0x1c, 0x89, 0x43, 0xab, 0x08, 0x59,
        ];

        let nft_transfer_operation = NFTTransferOperation::from_bytes(&raw_input).unwrap().1;

        let address_bytes: &[[u8; 4]] = &[7_u32.to_be_bytes(), 3_u32.to_be_bytes()];

        assert_eq!(nft_transfer_operation.address_indices, address_bytes);
    }
}
