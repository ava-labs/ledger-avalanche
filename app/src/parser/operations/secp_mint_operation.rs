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

use crate::parser::{SECPMintOutput, SECPTransferOutput};

use crate::{
    parser::{FromBytes, ParserError},
    utils::{hex_encode, ApduPanic},
};

use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::{
    bytes::complete::{tag, take},
    number::complete::be_u32,
    sequence::tuple,
};

const U32_SIZE: usize = std::mem::size_of::<u32>();

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct SECPMintOperation<'b> {
    pub address_indices: &'b [[u8; U32_SIZE]],
    pub mint_output: SECPMintOutput<'b>,
    pub transfer_output: SECPTransferOutput<'b>,
}
impl<'b> SECPMintOperation<'b> {
    pub const TYPE_ID: u32 = 8;
}

impl<'b> FromBytes<'b> for SECPMintOperation<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("SECPMintOperation::from_bytes_into\x00");

        // // double check the type
        let (rem, _) = tag(Self::TYPE_ID.to_be_bytes())(input)?;

        let (rem, num_indices) = be_u32(rem)?;

        let (rem, indices) = take(num_indices as usize * U32_SIZE)(rem)?;
        let indices = bytemuck::try_cast_slice(indices).apdu_unwrap();

        let out = out.as_mut_ptr();
        let mint_output = unsafe { &mut *addr_of_mut!((*out).mint_output).cast() };
        let rem = SECPMintOutput::from_bytes_into(rem, mint_output)?;

        let transfer_output = unsafe { &mut *addr_of_mut!((*out).transfer_output).cast() };
        let rem = SECPTransferOutput::from_bytes_into(rem, transfer_output)?;

        //good ptr and no uninit reads
        unsafe {
            addr_of_mut!((*out).address_indices).write(indices);
        }

        Ok(rem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_secp256k1_mint_operation() {
        let raw_input = [
            0, 0, 0, 8, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 64, 0, 0, 0, 8, 0, 0, 0, 6, 0,
            0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 2, 157, 31, 52, 188, 58, 111, 35, 6, 202, 7,
            144, 22, 174, 248, 92, 19, 23, 103, 242, 56, 22, 54, 119, 75, 103, 131, 141, 236, 22,
            225, 106, 182, 207, 172, 178, 27, 136, 195, 168, 97, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 39,
            16, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 1, 157, 31, 52, 188, 58, 111, 35, 6,
            202, 7, 144, 22, 174, 248, 92, 19, 23, 103, 242, 56,
        ];

        let secp_mint_operation = SECPMintOperation::from_bytes(&raw_input).unwrap().1;

        let address_bytes: &[[u8; 4]] = &[
            1_u32.to_be_bytes(),
            5_u32.to_be_bytes(),
            64_u32.to_be_bytes(),
            8_u32.to_be_bytes(),
        ];

        assert_eq!(secp_mint_operation.address_indices, address_bytes);
    }
}
