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
    number::complete::{be_u32, be_u64},
    sequence::tuple,
};
use zemu_sys::ViewError;

use crate::{
    checked_add,
    handlers::handle_ui_message,
    parser::{
        u32_to_str, u64_to_str, Address, DisplayableItem, FromBytes, ParserError, ADDRESS_LEN,
    },
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct NFTMintOutput<'b> {
    group_id: u32,
    pub locktime: u64,
    pub threshold: u32,
    // list of addresses allowed to use this output
    pub addresses: &'b [[u8; ADDRESS_LEN]],
}

impl<'b> NFTMintOutput<'b> {
    pub const TYPE_ID: u32 = 0x0000000a;

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
}

impl<'b> FromBytes<'b> for NFTMintOutput<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("NFTMintOutput::from_bytes_into\x00");
        // double check the type
        let (rem, _) = tag(Self::TYPE_ID.to_be_bytes())(input)?;

        let (rem, (group_id, locktime, threshold, addr_len)) =
            tuple((be_u32, be_u64, be_u32, be_u32))(rem)?;

        let (rem, addresses) = take(addr_len as usize * ADDRESS_LEN)(rem)?;

        let addresses =
            bytemuck::try_cast_slice(addresses).map_err(|_| ParserError::InvalidAddressLength)?;

        if (threshold as usize > addresses.len()) || (addresses.is_empty() && threshold != 0) {
            return Err(ParserError::InvalidThreshold.into());
        }

        //good ptr and no uninit reads
        let out = out.as_mut_ptr();

        unsafe {
            addr_of_mut!((*out).group_id).write(group_id);
            addr_of_mut!((*out).locktime).write(locktime);
            addr_of_mut!((*out).threshold).write(threshold);
            addr_of_mut!((*out).addresses).write(addresses);
        }

        Ok(rem)
    }
}

impl<'a> DisplayableItem for NFTMintOutput<'a> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // output-type, group_id, threshold and addresses
        // do not show locktime if it is 0
        checked_add!(
            ViewError::Unknown,
            3u8,
            self.addresses.len() as _,
            (self.locktime > 0) as u8
        )
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
        let addr_item_n = self.num_items()? - self.addresses.len() as u8;
        let render_locktime = self.locktime > 0;
        // Gets the page at which this field is displayed, by summing the boolean
        // directly since it offsets the pages by 1 if present
        let render_threshold_at = 2 + render_locktime as u8;

        match item_n {
            0 => {
                let title_content = pic_str!(b"Output");
                title[..title_content.len()].copy_from_slice(title_content);

                handle_ui_message(pic_str!(b"NFTTransfer"), message, page)
            }
            1 => {
                let title_content = pic_str!(b"GroupID");
                title[..title_content.len()].copy_from_slice(title_content);
                let buffer =
                    u32_to_str(self.group_id, &mut buffer).map_err(|_| ViewError::Unknown)?;

                handle_ui_message(buffer, message, page)
            }
            2 if render_locktime => {
                let title_content = pic_str!(b"Locktime");
                title[..title_content.len()].copy_from_slice(title_content);
                let buffer =
                    u64_to_str(self.locktime, &mut buffer).map_err(|_| ViewError::Unknown)?;

                handle_ui_message(buffer, message, page)
            }
            x @ 2.. if x == render_threshold_at => {
                let title_content = pic_str!(b"Threshold");
                title[..title_content.len()].copy_from_slice(title_content);

                let buffer =
                    u32_to_str(self.threshold, &mut buffer).map_err(|_| ViewError::Unknown)?;

                handle_ui_message(buffer, message, page)
            }

            x @ 3.. if x >= addr_item_n => {
                let idx = x - addr_item_n;
                if let Some(data) = self.addresses.get(idx as usize) {
                    let mut addr = MaybeUninit::uninit();
                    Address::from_bytes_into(data, &mut addr).map_err(|_| ViewError::Unknown)?;
                    let addr = unsafe { addr.assume_init() };
                    addr.render_item(0, title, message, page)
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
        0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 0, 0, 0, 0, 1, 22, 54, 119, 75,
        103, 131, 141, 236, 22, 225, 106, 182, 207, 172, 178, 27, 136, 195, 168, 97,
    ];

    #[test]
    fn parse_nft_mint_output() {
        let out = NFTMintOutput::from_bytes(DATA).unwrap().1;
        assert_eq!(out.locktime, 56);
        assert_eq!(out.group_id, 0);
        assert_eq!(out.addresses.len(), 1);
        assert_eq!(out.threshold, 0);
        assert_eq!(out.addresses[0][..], DATA[(DATA.len() - 20)..]);
    }
}
