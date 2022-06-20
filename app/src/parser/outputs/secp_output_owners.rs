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
    parser::{Address, DisplayableItem, FromBytes, ParserError, ADDRESS_LEN},
};

#[derive(Clone, Copy, PartialEq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct SECPOutputOwners<'b> {
    pub locktime: u64,
    pub threshold: u32,
    pub addresses: &'b [[u8; ADDRESS_LEN]],
}

impl<'b> SECPOutputOwners<'b> {
    pub const TYPE_ID: u32 = 0x0000000b;
}
impl<'b> FromBytes<'b> for SECPOutputOwners<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("SECPOutputOwners::from_bytes_into\x00");
        // get owners type and check
        let (rem, owner_type_id) = be_u32(input)?;
        if owner_type_id != SECPOutputOwners::TYPE_ID {
            return Err(ParserError::UnexpectedType.into());
        }

        let (rem, (locktime, threshold, addr_len)) = tuple((be_u64, be_u32, be_u32))(rem)?;

        let (rem, addresses) = take(addr_len as usize * ADDRESS_LEN)(rem)?;
        if addr_len == 0 {
            return Err(ParserError::InvalidAddressLength.into());
        }

        let addresses =
            bytemuck::try_cast_slice(addresses).map_err(|_| ParserError::InvalidAddressLength)?;

        if (threshold as usize > addresses.len()) || (addresses.is_empty() && threshold != 0) {
            return Err(ParserError::InvalidThreshold.into());
        }

        //good ptr and no uninit reads
        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).locktime).write(locktime);
            addr_of_mut!((*out).threshold).write(threshold);
            addr_of_mut!((*out).addresses).write(addresses);
        }

        Ok(rem)
    }
}

impl<'a> DisplayableItem for SECPOutputOwners<'a> {
    fn num_items(&self) -> usize {
        // output-type and addresses
        let items = 1 + self.addresses.len();
        // do not show locktime if it is 0
        items + (self.locktime > 0) as usize
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

        let mut buffer = [0; usize::FORMATTED_SIZE + 2];
        let addr_item_n = self.num_items() - self.addresses.len();

        match item_n as usize {
            0 if self.locktime > 0 => {
                let title_content = pic_str!(b"Locktime");
                title[..title_content.len()].copy_from_slice(title_content);
                let buffer = itoa(self.locktime, &mut buffer);

                handle_ui_message(buffer, message, page)
            }

            x @ 0.. if x >= addr_item_n => {
                let idx = x - addr_item_n;
                if let Some(data) = self.addresses.get(idx as usize) {
                    let mut addr = MaybeUninit::uninit();
                    Address::from_bytes_into(data, &mut addr).map_err(|_| ViewError::Unknown)?;
                    let addr = unsafe { addr.assume_init() };
                    let label = pic_str!("Owners");
                    let ret = addr.render_item(0, title, message, page);
                    // lets change the title to Owners before leaving
                    title.iter_mut().for_each(|v| *v = 0);
                    title.copy_from_slice(label.as_bytes());
                    ret
                } else {
                    Err(ViewError::NoData)
                }
            }
            _ => Err(ViewError::NoData),
        }
    }
}
