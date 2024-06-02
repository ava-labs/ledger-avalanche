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
    bytes::complete::{tag, take},
    number::complete::{be_u32, be_u64},
    sequence::tuple,
};
use zemu_sys::ViewError;

use crate::{
    checked_add,
    handlers::handle_ui_message,
    parser::{
        u64_to_str, Address, DisplayableItem, FromBytes, ParserError, ADDRESS_LEN,
        MAX_ADDRESS_ENCODED_LEN,
    },
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct SECPOutputOwners<'b> {
    pub locktime: u64,
    pub threshold: u32,
    pub addresses: &'b [[u8; ADDRESS_LEN]],
}

impl<'b> SECPOutputOwners<'b> {
    pub const TYPE_ID: u32 = 0x0000000b;

    pub fn get_address_at(&'b self, idx: usize) -> Option<Address> {
        let data = self.addresses.get(idx)?;
        let mut addr = MaybeUninit::uninit();
        Address::from_bytes_into(data, &mut addr)
            .map_err(|_| ViewError::Unknown)
            .ok()?;
        Some(unsafe { addr.assume_init() })
    }

    pub fn num_addresses(&self) -> usize {
        self.addresses.len()
    }

    pub fn render_address_with_hrp(
        &self,
        hrp: &str,
        idx: usize,
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        if let Some(address) = self.get_address_at(idx) {
            let mut encoded = [0; MAX_ADDRESS_ENCODED_LEN];

            let len = address
                .encode_into(hrp, &mut encoded[..])
                .map_err(|_| ViewError::Unknown)?;

            handle_ui_message(&encoded[..len], message, page)
        } else {
            Err(ViewError::NoData)
        }
    }
}
impl<'b> FromBytes<'b> for SECPOutputOwners<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("SECPOutputOwners::from_bytes_into\x00");
        // get owners type and check
        let (rem, _) = tag(Self::TYPE_ID.to_be_bytes())(input)?;

        let (rem, (locktime, threshold, addr_len)) = tuple((be_u64, be_u32, be_u32))(rem)?;

        let (rem, addresses) = take(addr_len as usize * ADDRESS_LEN)(rem)?;
        // Check for invariants
        let addresses =
            bytemuck::try_cast_slice(addresses).map_err(|_| ParserError::InvalidAddressLength)?;

        if threshold as usize > addresses.len() {
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
    fn num_items(&self) -> Result<u8, ViewError> {
        // show an item for each address in the list
        let items = self.addresses.len() as u8;
        // show locktime only if it is higher than zero,
        // that is why we sum up this boolean
        checked_add!(ViewError::Unknown, items, (self.locktime > 0) as u8)
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
        use lexical_core::Number;

        let mut buffer = [0; u64::FORMATTED_SIZE_DECIMAL + 2];

        let addr_items = self.addresses.len() as u8;

        match item_n {
            0 if self.locktime > 0 => {
                let title_content = pic_str!(b"Locktime");
                title[..title_content.len()].copy_from_slice(title_content);
                let buffer =
                    u64_to_str(self.locktime, &mut buffer).map_err(|_| ViewError::Unknown)?;
                handle_ui_message(buffer, message, page)
            }
            x if (x > 0 && self.locktime > 0) || self.locktime == 0 => {
                if x < addr_items {
                    let label = pic_str!(b"Owner address");
                    title[..label.len()].copy_from_slice(label);
                    self.render_address_with_hrp("", x as usize, message, page)
                } else {
                    Err(ViewError::NoData)
                }
            }
            _ => Err(ViewError::NoData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &[u8] = &[
        0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 1, 22, 54, 119, 75, 103, 131,
        141, 236, 22, 225, 106, 182, 207, 172, 178, 27, 136, 195, 168, 97,
    ];

    #[test]
    fn parse_output_owners() {
        let (_, owner) = SECPOutputOwners::from_bytes(DATA).unwrap();
        assert_eq!(owner.locktime, 12);
        assert_eq!(owner.threshold, 1);
        assert_eq!(owner.addresses.len(), 1);
    }
}
