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
use crate::checked_add;
use crate::handlers::handle_ui_message;
use crate::parser::{DisplayableItem, FromBytes, NodeId, ParserError};
use crate::sys::{ViewError, PIC};

use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::{number::complete::be_i64, sequence::tuple};

mod weight_type;
pub use weight_type::{Stake, Weight};
use weight_type::{StakeTrait, WeightTrait};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct Validator<'b, W = Stake> {
    pub node_id: NodeId<'b>,
    pub start_time: i64,
    pub endtime: i64,
    pub weight: W,
}

impl<'b, W: StakeTrait> Validator<'b, W> {
    pub fn stake(&self) -> u64 {
        self.weight.stake()
    }
}

impl<'b, W: WeightTrait> Validator<'b, W> {
    pub fn weight(&self) -> u64 {
        self.weight.weight()
    }
}

impl<'b, W: FromBytes<'b>> FromBytes<'b> for Validator<'b, W> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("Validator::from_bytes_into\x00");

        let out = out.as_mut_ptr();

        let node_id = unsafe { &mut *addr_of_mut!((*out).node_id).cast() };
        let rem = NodeId::from_bytes_into(input, node_id)?;

        let (rem, (start_time, endtime)) = tuple((be_i64, be_i64))(rem)?;

        let weight = unsafe { &mut *addr_of_mut!((*out).weight).cast() };
        let rem = W::from_bytes_into(rem, weight)?;

        // check for appropiate timestamps
        if endtime <= start_time {
            return Err(ParserError::InvalidTimestamp.into());
        }

        unsafe {
            addr_of_mut!((*out).start_time).write(start_time);
            addr_of_mut!((*out).endtime).write(endtime);
        }

        Ok(rem)
    }
}

impl<'b, W: DisplayableItem> DisplayableItem for Validator<'b, W> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // node_id(1), start_time, endtime and weight(1)
        let items = self.node_id.num_items()?;
        let weight = self.weight.num_items()?;

        checked_add!(ViewError::Unknown, items, 2, weight)
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
            3 => self.weight.render_item(0, title, message, page),
            _ => Err(ViewError::NoData),
        }
    }
}
