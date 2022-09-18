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

use crate::{
    handlers::handle_ui_message,
    parser::{cb58_output_len, DisplayableItem, ParserError, CB58_CHECKSUM_LEN},
    utils::bs58_encode,
};

use zemu_sys::ViewError;

pub const ASSET_ID_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct AssetId<'b>(&'b [u8; ASSET_ID_LEN]);

impl<'b> AssetId<'b> {
    pub fn id(&self) -> &[u8; ASSET_ID_LEN] {
        self.0
    }
}

impl<'b> AssetId<'b> {
    #[inline(never)]
    pub fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        let (rem, addr) = take(ASSET_ID_LEN)(input)?;
        let addr = arrayref::array_ref!(addr, 0, ASSET_ID_LEN);

        //good ptr and no uninit reads
        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).0).write(addr);
        }

        Ok(rem)
    }
}

impl<'a> DisplayableItem for AssetId<'a> {
    fn num_items(&self) -> usize {
        1
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

        if item_n != 0 {
            return Err(ViewError::NoData);
        }

        let title_content = pic_str!(b"AssetId");
        title[..title_content.len()].copy_from_slice(title_content);
        let mut data = [0; ASSET_ID_LEN + CB58_CHECKSUM_LEN];

        data[..ASSET_ID_LEN].copy_from_slice(&self.0[..]);

        let checksum = Sha256::digest(&data[..ASSET_ID_LEN]).map_err(|_| ViewError::Unknown)?;

        // prepare the data to be encoded by appending last 4-byte
        data[ASSET_ID_LEN..].copy_from_slice(&checksum[(Sha256::DIGEST_LEN - CB58_CHECKSUM_LEN)..]);

        const MAX_SIZE: usize = cb58_output_len::<ASSET_ID_LEN>();
        let mut encoded = [0; MAX_SIZE];

        let len = bs58_encode(data, &mut encoded[..]).map_err(|_| ViewError::Unknown)?;

        handle_ui_message(&encoded[..len], message, page)
    }
}
