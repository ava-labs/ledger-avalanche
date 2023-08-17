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
use crate::{
    parser::{DisplayableItem, FromBytes, NFTTransferOutput, ParserError, U32_SIZE},
    utils::ApduPanic,
};

use zemu_sys::ViewError;

use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::{
    bytes::complete::{tag, take},
    number::complete::be_u32,
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
#[repr(C)]
pub struct NFTMintOperation<'b> {
    pub address_indices: &'b [[u8; U32_SIZE]],
    // It turns out that the fields this operation contains
    // are the same as the ones in the NFTTransferOutput
    // type, which makes sense considering the notion
    // of inheritance the avax design follows.
    // This makes this, type very similar to the NFTTransferOperation, for
    // which the documentations says that it "extends" an untyped
    // nft_transfer_output.
    nft_output: NFTTransferOutput<'b>,
}

impl<'b> NFTMintOperation<'b> {
    pub const TYPE_ID: u32 = 0x0c;
}

impl<'b> FromBytes<'b> for NFTMintOperation<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("NFTMintOperation::from_bytes_into\x00");

        // // double check the type
        let (rem, _) = tag(Self::TYPE_ID.to_be_bytes())(input)?;

        let (rem, num_indices) = be_u32(rem)?;
        let (rem, indices) = take(num_indices as usize * U32_SIZE)(rem)?;
        let indices = bytemuck::try_cast_slice(indices).apdu_unwrap();

        let out = out.as_mut_ptr();

        let output = unsafe { &mut *addr_of_mut!((*out).nft_output).cast() };
        // parse without type checking
        let rem = NFTTransferOutput::into_without_type(rem, output)?;

        //good ptr and no uninit reads
        unsafe {
            addr_of_mut!((*out).address_indices).write(indices);
        }

        Ok(rem)
    }
}

impl<'a> DisplayableItem for NFTMintOperation<'a> {
    fn num_items(&self) -> Result<u8, ViewError> {
        self.nft_output.num_items()
    }

    #[inline(never)]
    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        self.nft_output.render_item(item_n, title, message, page)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nft_mint_operation() {
        let raw_input = [
            // Type ID
            0x00, 0x00, 0x00, 0x0c, // number of address indices:
            0x00, 0x00, 0x00, 0x02, // address index 0:
            0x00, 0x00, 0x00, 0x03, // address index 1:
            0x00, 0x00, 0x00, 0x07, // groupID:
            0x00, 0x00, 0x30, 0x39, // length of payload:
            0x00, 0x00, 0x00, 0x03, // payload:
            0x43, 0x11, 0x00, // transferable output:
            0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 0, 0, 0, 0, 1, 22, 54, 119, 75, 103, 131, 141, 236,
            22, 225, 106, 182, 207, 172, 178, 27, 136, 195, 168, 97,
        ];

        let nft_mint_operation = NFTMintOperation::from_bytes(&raw_input).unwrap().1;

        let address_bytes: &[[u8; 4]] = &[3_u32.to_be_bytes(), 7_u32.to_be_bytes()];

        assert_eq!(nft_mint_operation.address_indices, address_bytes);
    }
}
