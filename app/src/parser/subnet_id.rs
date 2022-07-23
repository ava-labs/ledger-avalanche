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
use crate::sys::ViewError;
use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::bytes::complete::take;

use crate::parser::{cb58_output_len, DisplayableItem, FromBytes, ParserError, CB58_CHECKSUM_LEN};
use crate::utils::bs58_encode;

pub const SUBNET_ID_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct SubnetId<'b>(&'b [u8; SUBNET_ID_LEN]);

impl<'b> FromBytes<'b> for SubnetId<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("SubnetId::from_bytes_into\x00");

        let (rem, subnet_id) = take(SUBNET_ID_LEN)(input)?;
        // This would not fail as previous line ensures we take
        // the right amount of bytes, also the alignemnt is correct
        let subnet_id = arrayref::array_ref!(subnet_id, 0, SUBNET_ID_LEN);

        //good ptr and no uninit reads
        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).0).write(subnet_id);
        }

        Ok(rem)
    }
}

impl<'b> DisplayableItem for SubnetId<'b> {
    fn num_items(&self) -> usize {
        1
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::hash::{Hasher, Sha256};
        use bolos::{pic_str, PIC};

        if item_n != 0 {
            return Err(ViewError::NoData);
        }

        let label = pic_str!(b"SubnetID");
        title[..label.len()].copy_from_slice(label);

        let checksum = Sha256::digest(self.0).map_err(|_| ViewError::Unknown)?;
        // prepare the data to be encoded by appending last 4-byte
        let mut data = [0; SUBNET_ID_LEN + CB58_CHECKSUM_LEN];
        data[..SUBNET_ID_LEN].copy_from_slice(&self.0[..]);
        data[SUBNET_ID_LEN..]
            .copy_from_slice(&checksum[(Sha256::DIGEST_LEN - CB58_CHECKSUM_LEN)..]);

        const MAX_SIZE: usize = cb58_output_len::<SUBNET_ID_LEN>();
        let mut encoded = [0; MAX_SIZE];

        let len = bs58_encode(data, &mut encoded[..]).map_err(|_| ViewError::Unknown)?;
        handle_ui_message(&encoded[..len], message, page)
    }
}
