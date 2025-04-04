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
use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::{
    bytes::complete::{tag, take},
    number::complete::be_u32,
};

use crate::{
    parser::{FromBytes, ParserError},
    utils::ApduPanic,
};

const U32_SIZE: usize = std::mem::size_of::<u32>();

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct SubnetAuth<'b> {
    // list of validator's signature indices, the indices are u32
    // but we represent them as a slice of U32_SIZE byte-arrays
    // instead of casting it directly to &[u32] because of the
    // endianness
    pub sig_indices: &'b [[u8; U32_SIZE]],
}

impl SubnetAuth<'_> {
    pub const TYPE_ID: u32 = 0x0000000a;
}

impl<'b> FromBytes<'b> for SubnetAuth<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("SubnetAuth::from_bytes_into\x00");

        // double check
        let (rem, _) = tag(Self::TYPE_ID.to_be_bytes())(input)?;
        let (rem, num_indices) = be_u32(rem)?;

        let (rem, indices) = take(num_indices as usize * U32_SIZE)(rem)?;
        // This would not fail as previous line ensures we take
        // the right amount of bytes, also the alignemnt is correct
        let indices = bytemuck::try_cast_slice(indices).apdu_unwrap();

        //good ptr and no uninit reads
        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).sig_indices).write(indices);
        }

        Ok(rem)
    }
}
