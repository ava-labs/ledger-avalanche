/*******************************************************************************
*   (c) 2023 Zondax AG
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
use core::ptr::addr_of_mut;

use bolos::{
    hash::{Hasher, Sha256},
    pic::PIC,
    pic_str,
};
use nom::bytes::complete::take;
use zemu_sys::ViewError;

use crate::{
    handlers::handle_ui_message,
    parser::{cb58_output_len, CB58_CHECKSUM_LEN},
    utils::bs58_encode,
};

use super::{DisplayableItem, FromBytes};

pub const NODE_ID_LEN: usize = 20;
const NODE_ID_PREFIX_LEN: usize = 7;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct NodeId<'b> {
    pub node_id: &'b [u8; NODE_ID_LEN],
}

impl<'b> FromBytes<'b> for NodeId<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<super::ParserError>> {
        crate::sys::zemu_log_stack("NodeId::from_bytes_into\x00");

        let (rem, node_id) = take(NODE_ID_LEN)(input)?;
        let node_id = arrayref::array_ref![node_id, 0, NODE_ID_LEN];

        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).node_id).write(node_id);
        }

        Ok(rem)
    }
}

impl<'b> DisplayableItem for NodeId<'b> {
    fn num_items(&self) -> usize {
        1
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        match item_n {
            0 => {
                let label = pic_str!(b"Validator");
                title[..label.len()].copy_from_slice(label);

                let mut data = [0; NODE_ID_LEN + CB58_CHECKSUM_LEN];
                data[..NODE_ID_LEN].copy_from_slice(&self.node_id[..]);

                let checksum = Sha256::digest(&self.node_id[..]).map_err(|_| ViewError::Unknown)?;
                // format the node_id
                let prefix = pic_str!(b"NodeID-"!);

                // prepare the data to be encoded by appending last 4-byte
                data[NODE_ID_LEN..]
                    .copy_from_slice(&checksum[(Sha256::DIGEST_LEN - CB58_CHECKSUM_LEN)..]);

                const MAX_SIZE: usize = cb58_output_len::<NODE_ID_LEN>() + NODE_ID_PREFIX_LEN;

                let mut node_id = [0; MAX_SIZE];

                node_id[..prefix.len()].copy_from_slice(prefix);

                let len = bs58_encode(data, &mut node_id[NODE_ID_PREFIX_LEN..])
                    .map_err(|_| ViewError::Unknown)?
                    + NODE_ID_PREFIX_LEN;

                handle_ui_message(&node_id[..len], message, page)
            }
            _ => Err(ViewError::NoData),
        }
    }
}
