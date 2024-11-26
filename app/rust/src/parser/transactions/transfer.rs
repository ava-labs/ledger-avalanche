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
use nom::bytes::complete::tag;
use zemu_sys::ViewError;

use crate::checked_add;
use crate::handlers::handle_ui_message;
use crate::parser::{
    nano_avax_to_fp_str, AvmOutput, BaseTxFields, DisplayableItem, FromBytes, Header, ParserError,
    MAX_ADDRESS_ENCODED_LEN, TRANSFER_TX,
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct Transfer<'b> {
    header: Header<'b>,
    base: BaseTxFields<'b, AvmOutput<'b>>,
}

impl<'b> Transfer<'b> {
    pub fn disable_output_if(&mut self, address: &[u8]) {
        self.base.disable_output_if(address);
    }

    fn render_outputs(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        use bolos::{pic_str, PIC};

        let (obj, idx) = self
            .base
            .base_output_with_item(item_n)
            .map_err(|_| ViewError::NoData)?;

        // this is a secp_transfer so it contain
        // 1 item amount
        // x items which is one item for each address
        let num_inner_items = obj.num_items()?;

        match idx {
            0 => {
                // render using default obj impl
                let res = obj.render_item(0, title, message, page);

                title.iter_mut().for_each(|v| *v = 0);

                // customize the label
                let label = pic_str!(b"Transfer");
                title[..label.len()].copy_from_slice(label);

                res
            }

            x @ 1.. if x < num_inner_items => {
                let addr_idx = x - 1;
                // Transfer only supports secp_transfer outputs
                // Unwrap is safe as we check outputs while parsing
                let obj = obj.secp_transfer().unwrap();

                let address = obj
                    .get_address_at(addr_idx as usize)
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

    fn fee(&self) -> Result<u64, ParserError> {
        let outputs = self.base.sum_outputs_amount()?;
        let inputs = self.base.sum_inputs_amount()?;
        inputs
            .checked_sub(outputs)
            .ok_or(ParserError::OperationOverflows)
    }
}

impl<'b> FromBytes<'b> for Transfer<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("Transfer::from_bytes_into\x00");

        let (rem, _) = tag(TRANSFER_TX.to_be_bytes())(input)?;

        let out = out.as_mut_ptr();
        // tx header
        let tx_header = unsafe { &mut *addr_of_mut!((*out).header).cast() };
        let rem = Header::from_bytes_into(rem, tx_header)?;

        // base_tx
        let base_tx = unsafe { &mut *addr_of_mut!((*out).base).cast() };
        let rem = BaseTxFields::<AvmOutput>::from_bytes_into(rem, base_tx)?;
        let base = unsafe { base_tx.assume_init_ref() };
        // filter outputs, the only one allow is secp_transfers
        if base
            .outputs()
            .iter()
            .map(|to| *to)
            .any(|o| o.secp_transfer().is_none())
        {
            return Err(ParserError::UnexpectedType.into());
        }

        Ok(rem)
    }
}

impl<'b> DisplayableItem for Transfer<'b> {
    fn num_items(&self) -> Result<u8, ViewError> {
        checked_add!(ViewError::Unknown, 2u8, self.base.base_outputs_num_items()?)
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        use bolos::{pic_str, PIC};
        use lexical_core::Number;

        if item_n == 0 {
            let label = pic_str!(b"Transfer");
            title[..label.len()].copy_from_slice(label);
            let content = pic_str!(b"Transaction");
            return handle_ui_message(content, message, page);
        }

        let item_n = item_n - 1;

        let outputs_items = self.base.base_outputs_num_items()?;

        match item_n {
            // render outputs
            x @ 0.. if x < outputs_items => self.render_outputs(x, title, message, page),

            x if x == outputs_items => {
                let t = pic_str!(b"Fee(AVAX)");
                title[..t.len()].copy_from_slice(t);

                let fee = self.fee().map_err(|_| ViewError::Unknown)?;
                let mut content = [0; u64::FORMATTED_SIZE_DECIMAL + 2];
                let fee =
                    nano_avax_to_fp_str(fee, &mut content[..]).map_err(|_| ViewError::Unknown)?;

                // write avax
                handle_ui_message(fee, message, page)
            }

            _ => Err(ViewError::NoData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &[u8] = &[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0xab, 0x68, 0xeb, 0x1e, 0xe1, 0x42, 0xa0,
        0x5c, 0xfe, 0x76, 0x8c, 0x36, 0xe1, 0x1f, 0x0b, 0x59, 0x6d, 0xb5, 0xa3, 0xc6, 0xc7, 0x7a,
        0xab, 0xe6, 0x65, 0xda, 0xd9, 0xe6, 0x38, 0xca, 0x94, 0xf7, 0x00, 0x00, 0x00, 0x02, 0x3d,
        0x9b, 0xda, 0xc0, 0xed, 0x1d, 0x76, 0x13, 0x30, 0xcf, 0x68, 0x0e, 0xfd, 0xeb, 0x1a, 0x42,
        0x15, 0x9e, 0xb3, 0x87, 0xd6, 0xd2, 0x95, 0x0c, 0x96, 0xf7, 0xd2, 0x8f, 0x61, 0xbb, 0xe2,
        0xaa, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE8, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x7F,
        0x67, 0x1C, 0x73, 0x0D, 0x48, 0x07, 0xC2, 0x9E, 0xA1, 0x9B, 0x19, 0xA2, 0x3C, 0x70, 0x0B,
        0x19, 0x8F, 0x8B, 0x51, 0x3d, 0x9b, 0xda, 0xc0, 0xed, 0x1d, 0x76, 0x13, 0x30, 0xcf, 0x68,
        0x0e, 0xfd, 0xeb, 0x1a, 0x42, 0x15, 0x9e, 0xb3, 0x87, 0xd6, 0xd2, 0x95, 0x0c, 0x96, 0xf7,
        0xd2, 0x8f, 0x61, 0xbb, 0xe2, 0xaa, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x6A, 0xCB, 0xD8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01, 0xA4, 0xAF, 0xAB, 0xFF, 0x30, 0x81, 0x95, 0x25, 0x99, 0x90, 0xA9,
        0xE5, 0x31, 0xBD, 0x82, 0x30, 0xD1, 0x1A, 0x9A, 0x2A, 0x00, 0x00, 0x00, 0x02, 0x1C, 0x03,
        0x06, 0xE5, 0x8B, 0x75, 0x4E, 0xEB, 0x92, 0xE7, 0xA5, 0x79, 0xC5, 0x9A, 0x69, 0x33, 0x23,
        0xCD, 0x99, 0x94, 0xA5, 0x94, 0x61, 0x62, 0x72, 0x6F, 0x3B, 0x68, 0x0E, 0x9E, 0x48, 0x34,
        0x00, 0x00, 0x00, 0x00, 0x3d, 0x9b, 0xda, 0xc0, 0xed, 0x1d, 0x76, 0x13, 0x30, 0xcf, 0x68,
        0x0e, 0xfd, 0xeb, 0x1a, 0x42, 0x15, 0x9e, 0xb3, 0x87, 0xd6, 0xd2, 0x95, 0x0c, 0x96, 0xf7,
        0xd2, 0x8f, 0x61, 0xbb, 0xe2, 0xaa, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x29, 0x71, 0x0D, 0xE0,
        0x93, 0xE2, 0xF4, 0x10, 0xB5, 0xA3, 0x5E, 0x2C, 0x60, 0x59, 0x38, 0x39, 0x2D, 0xA0, 0xDE,
        0x80, 0x2C, 0x74, 0xE2, 0x5D, 0x78, 0xD2, 0xBF, 0x11, 0x87, 0xDC, 0x9A, 0xD6, 0x00, 0x00,
        0x00, 0x00, 0x3d, 0x9b, 0xda, 0xc0, 0xed, 0x1d, 0x76, 0x13, 0x30, 0xcf, 0x68, 0x0e, 0xfd,
        0xeb, 0x1a, 0x42, 0x15, 0x9e, 0xb3, 0x87, 0xd6, 0xd2, 0x95, 0x0c, 0x96, 0xf7, 0xd2, 0x8f,
        0x61, 0xbb, 0xe2, 0xaa, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7A, 0x11,
        0x9C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x00,
    ];

    #[test]
    fn parse_normal_transfer() {
        let (_, tx) = Transfer::from_bytes(DATA).unwrap();

        assert_eq!(tx.fee().unwrap(), 1000000);
    }
}
