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
    handlers::handle_ui_message,
    parser::{Address, DisplayableItem, FromBytes, ParserError, ADDRESS_LEN},
    utils::{hex_encode, is_app_mode_expert},
};

const MAX_PAYLOAD_LEN: usize = 1024;

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct NFTTransferOutput<'b> {
    group_id: u32,
    payload: &'b [u8],
    pub locktime: u64,
    pub threshold: u32,
    // list of addresses allowed to use this output
    pub addresses: &'b [[u8; ADDRESS_LEN]],
}

impl<'b> NFTTransferOutput<'b> {
    pub const TYPE_ID: u32 = 0x0000000b;
}

impl<'b> FromBytes<'b> for NFTTransferOutput<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("NFTTransfOutput::from_bytes_into\x00");
        // double check the type
        let (rem, _) = tag(Self::TYPE_ID.to_be_bytes())(input)?;

        let (rem, (group_id, payload_len)) = tuple((be_u32, be_u32))(rem)?;

        if payload_len as usize > MAX_PAYLOAD_LEN {
            return Err(ParserError::ValueOutOfRange.into());
        }

        let (rem, (payload, locktime, threshold, addr_len)) =
            tuple((take(payload_len as usize), be_u64, be_u32, be_u32))(rem)?;

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
            addr_of_mut!((*out).payload).write(payload);
            addr_of_mut!((*out).locktime).write(locktime);
            addr_of_mut!((*out).threshold).write(threshold);
            addr_of_mut!((*out).addresses).write(addresses);
        }

        Ok(rem)
    }
}

impl<'a> DisplayableItem for NFTTransferOutput<'a> {
    fn num_items(&self) -> usize {
        // output-type, group_id, threshold and addresses
        let mut items = 1 + 1 + 1 + self.addresses.len();
        // do not show locktime if it is 0
        items += (self.locktime > 0) as usize;

        if !self.payload.is_empty() && is_app_mode_expert() {
            items += 1;
        }
        items
    }

    #[inline(never)]
    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::{
            hash::{Hasher, Sha256},
            pic_str, PIC,
        };
        use lexical_core::{write as itoa, Number};

        let mut buffer = [0; u64::FORMATTED_SIZE_DECIMAL + 2];
        let addr_item_n = self.num_items() - self.addresses.len();
        let render_payload = !self.payload.is_empty() && is_app_mode_expert();
        let render_locktime = self.locktime > 0;
        // Gets the page at which this field is displayed, by summing the boolean
        // directly since it offsets the pages by 1 if present
        let render_locktime_at = 2 + render_payload as usize;
        // Gets the page at which this field is displayed, by summing the booleans
        // directly since they offset the pages by 1 or 2 if present
        let render_threshold_at = 2 + render_payload as usize + render_locktime as usize;

        match item_n as usize {
            0 => {
                let title_content = pic_str!(b"Output");
                title[..title_content.len()].copy_from_slice(title_content);

                handle_ui_message(pic_str!(b"NFTTransfer"), message, page)
            }
            1 => {
                let title_content = pic_str!(b"GroupID");
                title[..title_content.len()].copy_from_slice(title_content);
                let buffer = itoa(self.group_id, &mut buffer);

                handle_ui_message(buffer, message, page)
            }
            2 if render_payload => {
                if self.payload.is_ascii() {
                    handle_ui_message(self.payload, message, page)
                } else {
                    let sha = Sha256::digest(self.payload).map_err(|_| ViewError::Unknown)?;
                    let mut hex_buf = [0; Sha256::DIGEST_LEN * 2];
                    hex_encode(&sha[..], &mut hex_buf).map_err(|_| ViewError::Unknown)?;
                    handle_ui_message(&hex_buf, message, page)
                }
            }

            x @ 2.. if x == render_locktime_at => {
                let title_content = pic_str!(b"Locktime");
                title[..title_content.len()].copy_from_slice(title_content);
                let buffer = itoa(self.locktime, &mut buffer);

                handle_ui_message(buffer, message, page)
            }

            x @ 2.. if x == render_threshold_at => {
                let title_content = pic_str!(b"Threshold");
                title[..title_content.len()].copy_from_slice(title_content);

                let buffer = itoa(self.threshold, &mut buffer);

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
        0, 0, 0, 11, 0, 0, 0, 10, 0, 0, 0, 20, 110, 102, 116, 95, 116, 114, 97, 110, 115, 102, 101,
        114, 95, 112, 97, 121, 108, 111, 97, 100, 0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 0, 0, 0, 0, 1,
        22, 54, 119, 75, 103, 131, 141, 236, 22, 225, 106, 182, 207, 172, 178, 27, 136, 195, 168,
        97,
    ];

    #[test]
    fn parse_nft_transf_output() {
        let out = NFTTransferOutput::from_bytes(DATA).unwrap().1;
        assert_eq!(out.locktime, 56);
        assert_eq!(out.group_id, 10);
        assert_eq!(out.addresses.len(), 1);
        assert_eq!(out.threshold, 0);
        assert_eq!(out.payload, "nft_transfer_payload".as_bytes());
        assert_eq!(out.addresses[0][..], DATA[(DATA.len() - 20)..]);
    }
}
