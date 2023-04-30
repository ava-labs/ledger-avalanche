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
use crate::handlers::handle_ui_message;
use crate::parser::{nano_avax_to_fp_str, DisplayableItem, FromBytes, NodeId, ParserError};
use crate::sys::{ViewError, PIC};

use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::{
    number::complete::{be_i64, be_u64},
    sequence::tuple,
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct Validator<'b> {
    pub node_id: NodeId<'b>,
    pub start_time: i64,
    pub endtime: i64,
    pub weight: u64,
}

impl<'b> FromBytes<'b> for Validator<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("Validator::from_bytes_into\x00");

        let node_id = unsafe { &mut *addr_of_mut!((*out).node_id).cast() };
        let rem = NodeId::from_bytes_into(input, node_id)?;

        let (rem, (start_time, endtime, weight)) = tuple((be_i64, be_i64, be_u64))(rem)?;

        // check for appropiate timestamps
        if endtime <= start_time {
            return Err(ParserError::InvalidTimestamp.into());
        }

        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).start_time).write(start_time);
            addr_of_mut!((*out).endtime).write(endtime);
            addr_of_mut!((*out).weight).write(weight);
        }

        Ok(rem)
    }
}

impl<'b> DisplayableItem for Validator<'b> {
    fn num_items(&self) -> usize {
        // node_id(1), start_time, endtime and total_stake
        self.node_id.num_items() + 3
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        use crate::parser::timestamp_to_str_date;
        use bolos::pic_str;
        use lexical_core::Number;

        match item_n {
            0 => self.node_id.render_item(0, title, message, page),
            1 => {
                let label = pic_str!(b"Start time");
                title[..label.len()].copy_from_slice(label);
                let time =
                    timestamp_to_str_date(self.start_time).map_err(|_| ViewError::Unknown)?;
                handle_ui_message(time.as_slice(), message, page)
            }
            2 => {
                let label = pic_str!(b"End time");
                title[..label.len()].copy_from_slice(label);
                let time = timestamp_to_str_date(self.endtime).map_err(|_| ViewError::Unknown)?;
                handle_ui_message(time.as_slice(), message, page)
            }
            3 => {
                let label = pic_str!(b"Total stake(AVAX)");
                title[..label.len()].copy_from_slice(label);

                let mut buffer = [0; u64::FORMATTED_SIZE + 2];
                let num = nano_avax_to_fp_str(self.weight, &mut buffer[..])
                    .map_err(|_| ViewError::Unknown)?;

                handle_ui_message(num, message, page)
            }

            _ => Err(ViewError::NoData),
        }
    }
}
