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
        PvmOutput, MAX_ADDRESS_ENCODED_LEN, PVM_BASE_TX, PVM_BASE_TX_TRANSFER, U64_FORMATTED_SIZE
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

        // BaseTx only supports secp_transfer types similar to import/exports?
        let obj = (*obj).secp_transfer().ok_or(ViewError::NoData)?;

        // get the number of items for the obj wrapped up by PvmOutput
        let num_inner_items = obj.num_items()?;

        // do a custom rendering of the first base_output_items
        match obj_item_n {
            0 => {
                // render amount
                obj.render_item(0, title, message, page)
            }
            // address rendering, according to avax team 99.99% of transactions only comes with one
            // address, but we support rendering any
            x @ 1.. if x < num_inner_items => {
                // get the address index
                let address_idx = x - 1;
                let address = obj
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
            _ => Err(ViewError::NoData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
