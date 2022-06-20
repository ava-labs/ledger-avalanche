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
use nom::number::complete::be_u32;
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

        let (rem, type_id) = be_u32(input)?;
        // double check
        if type_id != PVM_CREATE_SUBNET {
            return Err(ParserError::InvalidTransactionType.into());
        }

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
                let label = pic_str!("CreateSubnet");
                title.copy_from_slice(label.as_bytes());
                let content = pic_str!("transaction");
                handle_ui_message(content.as_bytes(), message, page)
            }

            x @ 1.. if x < owners_items + 1 => {
                let idx = x - 1;
                self.owners.render_item(idx, title, message, page)
            }
            _ => Err(ViewError::NoData),
        }
    }
}
