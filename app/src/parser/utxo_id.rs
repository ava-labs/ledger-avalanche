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
use nom::bytes::complete::take;
use nom::number::complete::be_u32;

use crate::parser::{FromBytes, ParserError};

pub const TX_ID_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct UtxoId<'b> {
    tx_id: &'b [u8; TX_ID_LEN],
    out_idx: u32,
}

impl<'b> FromBytes<'b> for UtxoId<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("UtxoId::from_bytes_into\x00");

        let (rem, tx_id) = take(TX_ID_LEN)(input)?;
        // This would not fail as previous line ensures we take
        // the right amount of bytes, also the alignemnt is correct
        let tx_id = arrayref::array_ref!(tx_id, 0, TX_ID_LEN);

        // output index
        let (rem, out_idx) = be_u32(rem)?;

        //good ptr and no uninit reads
        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).tx_id).write(tx_id);
            addr_of_mut!((*out).out_idx).write(out_idx);
        }

        Ok(rem)
    }
}
