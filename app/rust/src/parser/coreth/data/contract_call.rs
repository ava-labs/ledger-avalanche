/*******************************************************************************
*   (c) 2022 Zondax AG
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

use nom::{bytes::complete::take, number::complete::be_u32};
use zemu_sys::ViewError;

use crate::{
    handlers::handle_ui_message,
    parser::{DisplayableItem, ParserError, DEPLOY_DATA_PREVIEW_LEN, ETH_ARG_LEN},
    utils::hex_encode,
};

/// General type that encompases different possibles
/// contract call. There are contract calls that we need to support
/// as ERC20, ERC721.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "derive-debug"), derive(Debug))]
pub struct ContractCall<'b>(&'b [u8]);

impl<'b> ContractCall<'b> {
    pub fn parse_into(data: &'b [u8], output: &mut MaybeUninit<Self>) -> Result<(), ParserError> {
        let out = output.as_mut_ptr();
        // a call data regarless the contract, consists of
        // - 4-bytes selector that are the first bytes
        // of the sha3("method_signature")
        // - a list or arguments, which can be empty,
        // each argument should be 32-bytes len.

        // get selector
        let (mut rem, _) = be_u32(data)?;

        // check for arguments
        // if this error means an argument
        // is malformed
        while !rem.is_empty() {
            (rem, _) = take(ETH_ARG_LEN)(rem)?;
        }
        // safe writes
        unsafe {
            addr_of_mut!((*out).0).write(data);
        }

        Ok(())
    }
}

impl DisplayableItem for ContractCall<'_> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // data
        Ok(1)
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::{pic_str, PIC};
        if item_n != 0 {
            return Err(ViewError::NoData);
        }

        let title_content = pic_str!(b"Contract Data: ");
        title[..title_content.len()].copy_from_slice(title_content);

        let prefix = pic_str!(b"0x"!);
        let suffix = pic_str!(b"...");
        let mut output = [0; DEPLOY_DATA_PREVIEW_LEN * 2 + 2 + 4];
        output[..prefix.len()].copy_from_slice(&prefix[..]);
        let mut sz = prefix.len();

        let mut len = DEPLOY_DATA_PREVIEW_LEN;
        if self.0.len() < DEPLOY_DATA_PREVIEW_LEN {
            len = self.0.len();
        }

        sz += hex_encode(&self.0[..len], &mut output[prefix.len()..])
            .map_err(|_| ViewError::Unknown)?;
        output[sz..sz + suffix.len()].copy_from_slice(&suffix[..]);
        sz += suffix.len();

        handle_ui_message(&output[..sz], message, page)
    }
}
