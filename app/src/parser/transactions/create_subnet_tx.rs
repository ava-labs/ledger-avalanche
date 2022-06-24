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
use nom::{bytes::complete::tag, number::complete::be_u32};
use zemu_sys::ViewError;

use crate::{
    handlers::handle_ui_message,
    parser::{
        BaseTx, DisplayableItem, FromBytes, ParserError, SECPOutputOwners, PVM_CREATE_SUBNET,
    },
};

#[derive(Clone, Copy, PartialEq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct CreateSubnetTx<'b> {
    type_id: u32,
    base_tx: BaseTx<'b>,
    owners: SECPOutputOwners<'b>,
}

impl<'b> FromBytes<'b> for CreateSubnetTx<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("CreateSubnetTx::from_bytes_into\x00");

        // double check
        let (rem, raw_type_id) = tag(PVM_CREATE_SUBNET.to_be_bytes())(input)?;
        let (_, type_id) = be_u32(raw_type_id)?;

        let out = out.as_mut_ptr();
        let base_tx = unsafe { &mut *addr_of_mut!((*out).base_tx).cast() };
        let rem = BaseTx::from_bytes_into(rem, base_tx)?;

        let owners = unsafe { &mut *addr_of_mut!((*out).owners).cast() };
        let rem = SECPOutputOwners::from_bytes_into(rem, owners)?;

        //good ptr and no uninit reads
        unsafe {
            addr_of_mut!((*out).type_id).write(type_id);
        }

        Ok(rem)
    }
}

impl<'b> DisplayableItem for CreateSubnetTx<'b> {
    fn num_items(&self) -> usize {
        1 + self.owners.num_items()
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        use bolos::{pic_str, PIC};

        let owners_items = self.owners.num_items() as u8;

        match item_n {
            0 => {
                let label = pic_str!(b"CreateSubnet");
                title[..label.len()].copy_from_slice(label);
                let content = pic_str!(b"transaction");
                handle_ui_message(content, message, page)
            }

            x @ 1.. if x < owners_items + 1 => {
                let idx = x - 1;
                self.owners.render_item(idx, title, message, page)
            }
            _ => Err(ViewError::NoData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &[u8] = &[
        0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 1, 237, 95, 56, 52, 30, 67, 110, 93, 70, 226, 187, 0,
        180, 93, 98, 174, 151, 209, 176, 80, 198, 75, 198, 52, 174, 16, 98, 103, 57, 227, 92, 75,
        0, 0, 0, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 39, 16, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0,
        1, 0, 0, 0, 1, 157, 31, 52, 188, 58, 111, 35, 6, 202, 7, 144, 22, 174, 248, 92, 19, 23,
        103, 242, 56, 0, 0, 0, 1, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 0, 0, 2, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 31, 64, 0, 0,
        0, 10, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 58, 0, 0, 0, 1, 0, 0, 0, 79, 0, 0, 0, 65, 0, 0, 0,
        87, 0, 0, 0, 94, 0, 0, 0, 125, 0, 0, 1, 122, 0, 0, 0, 4, 109, 101, 109, 111, 0, 0, 0, 11,
        0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 1, 22, 54, 119, 75, 103, 131, 141, 236, 22,
        225, 106, 182, 207, 172, 178, 27, 136, 195, 168, 97,
    ];

    #[test]
    fn parse_create_subnet_tx() {
        let (_, tx) = CreateSubnetTx::from_bytes(DATA).unwrap();
        assert_eq!(tx.owners.addresses.len(), 1);
    }
}
