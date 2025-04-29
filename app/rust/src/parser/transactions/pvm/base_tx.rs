/*******************************************************************************
*   (c) 2024 Zondax AG
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

use bolos::{pic_str, PIC};
use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::bytes::complete::tag;
use zemu_sys::ViewError;

use crate::{
    checked_add,
    handlers::handle_ui_message,
    parser::{
        nano_avax_to_fp_str, BaseTxFields, DisplayableItem, FromBytes, Header, ParserError,
        PvmOutput, MAX_ADDRESS_ENCODED_LEN, PVM_BASE_TX, PVM_BASE_TX_TRANSFER, U64_FORMATTED_SIZE,
    },
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct PvmBaseTx<'b> {
    pub header: Header<'b>,
    pub base: BaseTxFields<'b, PvmOutput<'b>>,
}

impl<'b> FromBytes<'b> for PvmBaseTx<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("PvmBaseTx::from_bytes_into\x00");

        // THIS base transaction could be use as a base trransaction type
        // for other tx(PVM_BASE_TX) or as a transfer tx(PVM_BASE_TX_TRANSFER)
        // so fallback and check for the second condition.
        let (mut rem, _) = tag(PVM_BASE_TX.to_be_bytes())(input)
            .map_err(|_: nom::Err<ParserError>| ParserError::InvalidTypeId)
            .or_else(|_| tag(PVM_BASE_TX_TRANSFER.to_be_bytes())(input))?;

        let out = out.as_mut_ptr();

        // tx header
        let tx_header = unsafe { &mut *addr_of_mut!((*out).header).cast() };
        rem = Header::from_bytes_into(rem, tx_header)?;

        // base_fields
        let base_fields = unsafe { &mut *addr_of_mut!((*out).base).cast() };
        rem = BaseTxFields::<PvmOutput>::from_bytes_into(rem, base_fields)?;

        Ok(rem)
    }
}

impl DisplayableItem for PvmBaseTx<'_> {
    fn num_items(&self) -> Result<u8, ViewError> {
        let outputs = self.base.base_outputs_num_items()?;

        // Transaction description + outputs + fee
        checked_add!(ViewError::Unknown, 2u8, outputs)
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        if item_n == 0 {
            // render export title and network info
            return self.render_description(title, message, page);
        }

        let outputs_num_items = self.base.base_outputs_num_items()?;
        let new_item_n = item_n - 1;

        match new_item_n {
            x @ 0.. if x < outputs_num_items => self.render_outputs(x, title, message, page),
            x if x == outputs_num_items => {
                let title_content = pic_str!(b"Fee(AVAX)");
                title[..title_content.len()].copy_from_slice(title_content);
                let mut buffer = [0; U64_FORMATTED_SIZE + 2];
                let fee = self.fee().map_err(|_| ViewError::Unknown)?;
                let fee_str =
                    nano_avax_to_fp_str(fee, &mut buffer[..]).map_err(|_| ViewError::Unknown)?;
                handle_ui_message(fee_str, message, page)
            }
            _ => Err(ViewError::NoData),
        }
    }
}

impl<'b> PvmBaseTx<'b> {
    pub fn fee(&'b self) -> Result<u64, ParserError> {
        let inputs = self.base.sum_inputs_amount()?;
        let outputs = self.base.sum_outputs_amount()?;
        inputs
            .checked_sub(outputs)
            .ok_or(ParserError::OperationOverflows)
    }

    pub fn disable_output_if(&mut self, address: &[u8]) {
        self.base.disable_output_if(address);
    }

    fn render_description(
        &self,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        let title_content = pic_str!(b"P-Chain");
        title[..title_content.len()].copy_from_slice(title_content);

        let msg = pic_str!(b"BaseTx");

        handle_ui_message(msg, message, page)
    }

    pub fn render_outputs(
        &'b self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        let (obj, obj_item_n) = self
            .base
            .base_output_with_item(item_n)
            .map_err(|_| ViewError::NoData)?;

        // BaseTx only supports secp_transfer types similar to import/exports
        let _ = obj.output.secp_transfer().ok_or(ViewError::NoData)?;

        let num_inner_items = obj.output.num_inner_items()?;

        match obj_item_n {
            // For the first item (title), use PvmOutput's render_item
            0 => obj.render_item(obj_item_n, title, message, page),
            // For address items, handle encoding here
            x @ 1.. if x < num_inner_items => {
                // get the address index
                let address_idx = x - 1;
                let address = obj
                    .output
                    .get_address_at(address_idx as usize)
                    .ok_or(ViewError::NoData)?;
                // render encoded address with proper hrp,
                let t = pic_str!(b"Address");
                title[..t.len()].copy_from_slice(t);

                let hrp = self.header.hrp().map_err(|_| ViewError::Unknown)?;
                let mut encoded = [0; MAX_ADDRESS_ENCODED_LEN];

                let addr_len = address
                    .encode_into(hrp, &mut encoded[..])
                    .map_err(|_| ViewError::Unknown)?;

                handle_ui_message(&encoded[..addr_len], message, page)
            }
            // For locked output info, use PvmOutput's render_item
            x if x == num_inner_items => obj.render_item(obj_item_n, title, message, page),
            _ => Err(ViewError::NoData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::prelude::v1::*;

    use crate::parser::snapshots_common::ReducedPage;
    use zuit::Page;

    const DATA: &[u8] = &[
        0, 0, 0, 0, 0, 12, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 104, 112, 183, 214, 106, 195, 37, 64, 49, 19,
        121, 229, 181, 219, 173, 40, 236, 126, 184, 221, 191, 200, 244, 214, 114, 153, 235, 180,
        132, 117, 144, 122, 0, 0, 0, 7, 0, 0, 0, 0, 238, 91, 229, 192, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 1, 0, 0, 0, 1, 218, 43, 238, 1, 190, 130, 236, 192, 12, 52, 243, 97, 237, 168, 235,
        48, 251, 90, 113, 92, 0, 0, 0, 1, 223, 175, 189, 245, 200, 31, 99, 92, 146, 87, 130, 79,
        242, 28, 142, 62, 111, 123, 99, 42, 195, 6, 225, 20, 70, 238, 84, 13, 52, 113, 26, 21, 0,
        0, 0, 1, 104, 112, 183, 214, 106, 195, 37, 64, 49, 19, 121, 229, 181, 219, 173, 40, 236,
        126, 184, 221, 191, 200, 244, 214, 114, 153, 235, 180, 132, 117, 144, 122, 0, 0, 0, 5, 0,
        0, 0, 0, 238, 107, 40, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    // Transfer reference https://subnets.avax.network/p-chain/tx/2JLx1jintuSGJwEvQZZQk248S1rtzGk2V4xrPjjoKufF9oLX9Z
    const DATA_LOCKED: &[u8] = &[
        0, 0, 0, 34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 33, 230, 115, 23, 203, 196, 190, 42, 235, 0,
        103, 122, 214, 70, 39, 120, 168, 245, 34, 116, 185, 214, 5, 223, 37, 145, 178, 48, 39, 168,
        125, 255, 0, 0, 0, 7, 0, 0, 0, 0, 174, 9, 196, 118, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
        0, 0, 1, 48, 8, 21, 124, 58, 182, 56, 173, 88, 219, 90, 246, 128, 254, 197, 82, 165, 58,
        190, 174, 33, 230, 115, 23, 203, 196, 190, 42, 235, 0, 103, 122, 214, 70, 39, 120, 168,
        245, 34, 116, 185, 214, 5, 223, 37, 145, 178, 48, 39, 168, 125, 255, 0, 0, 0, 22, 0, 0, 0,
        0, 0, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0, 0, 59, 154, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 1, 73, 8, 236, 115, 188, 94, 69, 220, 141, 93, 156, 54, 132, 95, 180, 55, 56, 137,
        46, 10, 33, 230, 115, 23, 203, 196, 190, 42, 235, 0, 103, 122, 214, 70, 39, 120, 168, 245,
        34, 116, 185, 214, 5, 223, 37, 145, 178, 48, 39, 168, 125, 255, 0, 0, 0, 22, 0, 0, 0, 0, 0,
        0, 0, 1, 0, 0, 0, 7, 0, 0, 0, 0, 59, 154, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
        0, 1, 73, 8, 236, 115, 188, 94, 69, 220, 141, 93, 156, 54, 132, 95, 180, 55, 56, 137, 46,
        10, 33, 230, 115, 23, 203, 196, 190, 42, 235, 0, 103, 122, 214, 70, 39, 120, 168, 245, 34,
        116, 185, 214, 5, 223, 37, 145, 178, 48, 39, 168, 125, 255, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0,
        0, 1, 0, 0, 0, 7, 0, 0, 0, 0, 59, 154, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
        1, 73, 8, 236, 115, 188, 94, 69, 220, 141, 93, 156, 54, 132, 95, 180, 55, 56, 137, 46, 10,
        33, 230, 115, 23, 203, 196, 190, 42, 235, 0, 103, 122, 214, 70, 39, 120, 168, 245, 34, 116,
        185, 214, 5, 223, 37, 145, 178, 48, 39, 168, 125, 255, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 7, 0, 0, 0, 0, 59, 154, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1,
        73, 8, 236, 115, 188, 94, 69, 220, 141, 93, 156, 54, 132, 95, 180, 55, 56, 137, 46, 10, 33,
        230, 115, 23, 203, 196, 190, 42, 235, 0, 103, 122, 214, 70, 39, 120, 168, 245, 34, 116,
        185, 214, 5, 223, 37, 145, 178, 48, 39, 168, 125, 255, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 7, 0, 0, 0, 0, 59, 154, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1,
        73, 8, 236, 115, 188, 94, 69, 220, 141, 93, 156, 54, 132, 95, 180, 55, 56, 137, 46, 10, 33,
        230, 115, 23, 203, 196, 190, 42, 235, 0, 103, 122, 214, 70, 39, 120, 168, 245, 34, 116,
        185, 214, 5, 223, 37, 145, 178, 48, 39, 168, 125, 255, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 7, 0, 0, 0, 0, 59, 154, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1,
        73, 8, 236, 115, 188, 94, 69, 220, 141, 93, 156, 54, 132, 95, 180, 55, 56, 137, 46, 10, 33,
        230, 115, 23, 203, 196, 190, 42, 235, 0, 103, 122, 214, 70, 39, 120, 168, 245, 34, 116,
        185, 214, 5, 223, 37, 145, 178, 48, 39, 168, 125, 255, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 7, 0, 0, 0, 0, 59, 154, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1,
        73, 8, 236, 115, 188, 94, 69, 220, 141, 93, 156, 54, 132, 95, 180, 55, 56, 137, 46, 10, 33,
        230, 115, 23, 203, 196, 190, 42, 235, 0, 103, 122, 214, 70, 39, 120, 168, 245, 34, 116,
        185, 214, 5, 223, 37, 145, 178, 48, 39, 168, 125, 255, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 7, 0, 0, 0, 0, 59, 154, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1,
        73, 8, 236, 115, 188, 94, 69, 220, 141, 93, 156, 54, 132, 95, 180, 55, 56, 137, 46, 10, 33,
        230, 115, 23, 203, 196, 190, 42, 235, 0, 103, 122, 214, 70, 39, 120, 168, 245, 34, 116,
        185, 214, 5, 223, 37, 145, 178, 48, 39, 168, 125, 255, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 7, 0, 0, 0, 0, 59, 154, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1,
        73, 8, 236, 115, 188, 94, 69, 220, 141, 93, 156, 54, 132, 95, 180, 55, 56, 137, 46, 10, 33,
        230, 115, 23, 203, 196, 190, 42, 235, 0, 103, 122, 214, 70, 39, 120, 168, 245, 34, 116,
        185, 214, 5, 223, 37, 145, 178, 48, 39, 168, 125, 255, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 7, 0, 0, 0, 0, 59, 154, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1,
        73, 8, 236, 115, 188, 94, 69, 220, 141, 93, 156, 54, 132, 95, 180, 55, 56, 137, 46, 10, 33,
        230, 115, 23, 203, 196, 190, 42, 235, 0, 103, 122, 214, 70, 39, 120, 168, 245, 34, 116,
        185, 214, 5, 223, 37, 145, 178, 48, 39, 168, 125, 255, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 7, 0, 0, 0, 0, 59, 154, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1,
        73, 8, 236, 115, 188, 94, 69, 220, 141, 93, 156, 54, 132, 95, 180, 55, 56, 137, 46, 10, 33,
        230, 115, 23, 203, 196, 190, 42, 235, 0, 103, 122, 214, 70, 39, 120, 168, 245, 34, 116,
        185, 214, 5, 223, 37, 145, 178, 48, 39, 168, 125, 255, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 7, 0, 0, 0, 0, 59, 154, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1,
        73, 8, 236, 115, 188, 94, 69, 220, 141, 93, 156, 54, 132, 95, 180, 55, 56, 137, 46, 10, 33,
        230, 115, 23, 203, 196, 190, 42, 235, 0, 103, 122, 214, 70, 39, 120, 168, 245, 34, 116,
        185, 214, 5, 223, 37, 145, 178, 48, 39, 168, 125, 255, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 7, 0, 0, 0, 0, 59, 154, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1,
        73, 8, 236, 115, 188, 94, 69, 220, 141, 93, 156, 54, 132, 95, 180, 55, 56, 137, 46, 10, 33,
        230, 115, 23, 203, 196, 190, 42, 235, 0, 103, 122, 214, 70, 39, 120, 168, 245, 34, 116,
        185, 214, 5, 223, 37, 145, 178, 48, 39, 168, 125, 255, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 7, 0, 0, 0, 0, 59, 154, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1,
        73, 8, 236, 115, 188, 94, 69, 220, 141, 93, 156, 54, 132, 95, 180, 55, 56, 137, 46, 10, 33,
        230, 115, 23, 203, 196, 190, 42, 235, 0, 103, 122, 214, 70, 39, 120, 168, 245, 34, 116,
        185, 214, 5, 223, 37, 145, 178, 48, 39, 168, 125, 255, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 7, 0, 0, 0, 0, 59, 154, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1,
        73, 8, 236, 115, 188, 94, 69, 220, 141, 93, 156, 54, 132, 95, 180, 55, 56, 137, 46, 10, 33,
        230, 115, 23, 203, 196, 190, 42, 235, 0, 103, 122, 214, 70, 39, 120, 168, 245, 34, 116,
        185, 214, 5, 223, 37, 145, 178, 48, 39, 168, 125, 255, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 7, 0, 0, 0, 0, 59, 154, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1,
        73, 8, 236, 115, 188, 94, 69, 220, 141, 93, 156, 54, 132, 95, 180, 55, 56, 137, 46, 10, 33,
        230, 115, 23, 203, 196, 190, 42, 235, 0, 103, 122, 214, 70, 39, 120, 168, 245, 34, 116,
        185, 214, 5, 223, 37, 145, 178, 48, 39, 168, 125, 255, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 7, 0, 0, 0, 0, 59, 154, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1,
        73, 8, 236, 115, 188, 94, 69, 220, 141, 93, 156, 54, 132, 95, 180, 55, 56, 137, 46, 10, 33,
        230, 115, 23, 203, 196, 190, 42, 235, 0, 103, 122, 214, 70, 39, 120, 168, 245, 34, 116,
        185, 214, 5, 223, 37, 145, 178, 48, 39, 168, 125, 255, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 7, 0, 0, 0, 0, 59, 154, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1,
        73, 8, 236, 115, 188, 94, 69, 220, 141, 93, 156, 54, 132, 95, 180, 55, 56, 137, 46, 10, 33,
        230, 115, 23, 203, 196, 190, 42, 235, 0, 103, 122, 214, 70, 39, 120, 168, 245, 34, 116,
        185, 214, 5, 223, 37, 145, 178, 48, 39, 168, 125, 255, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 7, 0, 0, 0, 0, 59, 154, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1,
        73, 8, 236, 115, 188, 94, 69, 220, 141, 93, 156, 54, 132, 95, 180, 55, 56, 137, 46, 10, 33,
        230, 115, 23, 203, 196, 190, 42, 235, 0, 103, 122, 214, 70, 39, 120, 168, 245, 34, 116,
        185, 214, 5, 223, 37, 145, 178, 48, 39, 168, 125, 255, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 7, 0, 0, 0, 0, 59, 154, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1,
        73, 8, 236, 115, 188, 94, 69, 220, 141, 93, 156, 54, 132, 95, 180, 55, 56, 137, 46, 10, 33,
        230, 115, 23, 203, 196, 190, 42, 235, 0, 103, 122, 214, 70, 39, 120, 168, 245, 34, 116,
        185, 214, 5, 223, 37, 145, 178, 48, 39, 168, 125, 255, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 7, 0, 0, 0, 0, 59, 154, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1,
        73, 8, 236, 115, 188, 94, 69, 220, 141, 93, 156, 54, 132, 95, 180, 55, 56, 137, 46, 10, 33,
        230, 115, 23, 203, 196, 190, 42, 235, 0, 103, 122, 214, 70, 39, 120, 168, 245, 34, 116,
        185, 214, 5, 223, 37, 145, 178, 48, 39, 168, 125, 255, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 7, 0, 0, 0, 0, 59, 154, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1,
        73, 8, 236, 115, 188, 94, 69, 220, 141, 93, 156, 54, 132, 95, 180, 55, 56, 137, 46, 10, 33,
        230, 115, 23, 203, 196, 190, 42, 235, 0, 103, 122, 214, 70, 39, 120, 168, 245, 34, 116,
        185, 214, 5, 223, 37, 145, 178, 48, 39, 168, 125, 255, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 7, 0, 0, 0, 0, 59, 154, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1,
        73, 8, 236, 115, 188, 94, 69, 220, 141, 93, 156, 54, 132, 95, 180, 55, 56, 137, 46, 10, 0,
        0, 0, 1, 68, 228, 213, 25, 55, 221, 41, 64, 91, 122, 130, 247, 80, 248, 192, 121, 125, 238,
        59, 68, 88, 116, 235, 90, 107, 37, 252, 196, 15, 171, 33, 0, 0, 0, 0, 0, 33, 230, 115, 23,
        203, 196, 190, 42, 235, 0, 103, 122, 214, 70, 39, 120, 168, 245, 34, 116, 185, 214, 5, 223,
        37, 145, 178, 48, 39, 168, 125, 255, 0, 0, 0, 5, 0, 0, 0, 6, 8, 243, 64, 211, 0, 0, 0, 1,
        0, 0, 0, 0, 0, 0, 0, 0, //29, 148, 191, 172,
    ];

    #[test]
    fn parse_pvm_base_tx() {
        let (rem, tx) = PvmBaseTx::from_bytes(DATA).unwrap();
        assert!(rem.is_empty());

        let count = tx.base.outputs().iter().count();

        // we know there are 1 outputs
        assert_eq!(count, 1);

        let count = tx.base.inputs().iter().count();
        // we know there are 1 inputs
        assert_eq!(count, 1);

        let fee = tx.fee().unwrap();
        assert_eq!(fee, 1000000);
    }

    #[test]
    fn parse_pvm_base_tx_locked() {
        println!("-------------------- Base TX Locked ------------------------");

        let (_, tx) = PvmBaseTx::from_bytes(DATA_LOCKED).unwrap();

        let items = tx.num_items().expect("Overflow?");

        let mut pages = Vec::<Page<18, 1024>>::with_capacity(items as usize);
        for i in 0..items {
            let mut page = Page::default();

            tx.render_item(i as _, &mut page.title, &mut page.message, 0)
                .unwrap();

            pages.push(page);
        }

        let reduced = pages.iter().map(ReducedPage::from).collect::<Vec<_>>();
        insta::assert_debug_snapshot!(reduced);
    }
}
