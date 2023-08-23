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
use crate::{checked_add, sys::ViewError};
use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::bytes::complete::tag;

use crate::{
    handlers::handle_ui_message,
    parser::{
        nano_avax_to_fp_str, BaseTxFields, DisplayableItem, FromBytes, Header, ParserError,
        PvmOutput, SubnetAuth, SubnetId, Validator, PVM_ADD_SUBNET_VALIDATOR,
    },
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct AddSubnetValidatorTx<'b> {
    pub tx_header: Header<'b>,
    pub base_tx: BaseTxFields<'b, PvmOutput<'b>>,
    pub validator: Validator<'b>,
    pub subnet_id: SubnetId<'b>,
    pub subnet_auth: SubnetAuth<'b>,
}

impl<'b> FromBytes<'b> for AddSubnetValidatorTx<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("AddSubnetValidatorTx::from_bytes_into\x00");

        let (rem, _) = tag(PVM_ADD_SUBNET_VALIDATOR.to_be_bytes())(input)?;

        let out = out.as_mut_ptr();

        // tx header
        let tx_header = unsafe { &mut *addr_of_mut!((*out).tx_header).cast() };
        let rem = Header::from_bytes_into(rem, tx_header)?;

        // base_tx
        let base_tx = unsafe { &mut *addr_of_mut!((*out).base_tx).cast() };
        let rem = BaseTxFields::<PvmOutput>::from_bytes_into(rem, base_tx)?;

        // validator
        let validator = unsafe { &mut *addr_of_mut!((*out).validator).cast() };
        let rem = Validator::from_bytes_into(rem, validator)?;

        // SubnetId
        let subnet_id = unsafe { &mut *addr_of_mut!((*out).subnet_id).cast() };
        let rem = SubnetId::from_bytes_into(rem, subnet_id)?;

        // subnetAuth
        let subnet_auth = unsafe { &mut *addr_of_mut!((*out).subnet_auth).cast() };
        let rem = SubnetAuth::from_bytes_into(rem, subnet_auth)?;

        Ok(rem)
    }
}

impl<'b> DisplayableItem for AddSubnetValidatorTx<'b> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // tx_info, validator_items(4),
        // subnet_id and fee
        checked_add!(ViewError::Unknown, 3u8, self.validator.num_items()?)
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
            let label = pic_str!(b"SubnetValidator");
            title[..label.len()].copy_from_slice(label);
            let content = pic_str!(b"Transaction");
            return handle_ui_message(content, message, page);
        }

        let item_n = item_n - 1;

        let validator_items = self.validator.num_items()?;

        match item_n {
            // render validator info
            x @ 0.. if x < validator_items => self.validator.render_item(x, title, message, page),

            // render subnet_id
            x if x == validator_items => self.subnet_id.render_item(0, title, message, page),

            // render fee
            x if x == validator_items + 1 => {
                let label = pic_str!(b"Fee(AVAX)");
                title[..label.len()].copy_from_slice(label);

                let fee = self.fee().map_err(|_| ViewError::Unknown)?;

                let mut buffer = [0; u64::FORMATTED_SIZE_DECIMAL + 2];
                let fee_buff =
                    nano_avax_to_fp_str(fee, &mut buffer[..]).map_err(|_| ViewError::Unknown)?;
                handle_ui_message(fee_buff, message, page)
            }
            _ => Err(ViewError::NoData),
        }
    }
}

impl<'b> AddSubnetValidatorTx<'b> {
    fn fee(&'b self) -> Result<u64, ParserError> {
        let sum_inputs = self.base_tx.sum_inputs_amount()?;

        let total_outputs = self.base_tx.sum_outputs_amount()?;

        let fee = sum_inputs
            .checked_sub(total_outputs)
            .ok_or(ParserError::OperationOverflows)?;
        Ok(fee)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &[u8] = &[
        0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x30, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xdb,
        0xcf, 0x89, 0x0f, 0x77, 0xf4, 0x9b, 0x96, 0x85, 0x76, 0x48, 0xb7, 0x2b, 0x77, 0xf9, 0xf8,
        0x29, 0x37, 0xf2, 0x8a, 0x68, 0x70, 0x4a, 0xf0, 0x5d, 0xa0, 0xdc, 0x12, 0xba, 0x53, 0xf2,
        0xdb, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0xee, 0x5b, 0xe5, 0xc0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0xda,
        0x2b, 0xee, 0x01, 0xbe, 0x82, 0xec, 0xc0, 0x0c, 0x34, 0xf3, 0x61, 0xed, 0xa8, 0xeb, 0x30,
        0xfb, 0x5a, 0x71, 0x5c, 0x00, 0x00, 0x00, 0x01, 0xdf, 0xaf, 0xbd, 0xf5, 0xc8, 0x1f, 0x63,
        0x5c, 0x92, 0x57, 0x82, 0x4f, 0xf2, 0x1c, 0x8e, 0x3e, 0x6f, 0x7b, 0x63, 0x2a, 0xc3, 0x06,
        0xe1, 0x14, 0x46, 0xee, 0x54, 0x0d, 0x34, 0x71, 0x1a, 0x15, 0x00, 0x00, 0x00, 0x01, 0xdb,
        0xcf, 0x89, 0x0f, 0x77, 0xf4, 0x9b, 0x96, 0x85, 0x76, 0x48, 0xb7, 0x2b, 0x77, 0xf9, 0xf8,
        0x29, 0x37, 0xf2, 0x8a, 0x68, 0x70, 0x4a, 0xf0, 0x5d, 0xa0, 0xdc, 0x12, 0xba, 0x53, 0xf2,
        0xdb, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x01, 0xd2, 0x97, 0xb5, 0x48, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe9, 0x09, 0x4f, 0x73, 0x69,
        0x80, 0x02, 0xfd, 0x52, 0xc9, 0x08, 0x19, 0xb4, 0x57, 0xb9, 0xfb, 0xc8, 0x66, 0xab, 0x80,
        0x00, 0x00, 0x00, 0x00, 0x5f, 0x21, 0xf3, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x5f, 0x49, 0x7d,
        0xc6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd4, 0x31, 0x58, 0xb1, 0x09, 0x28, 0x71, 0xdb,
        0x85, 0xbc, 0x75, 0x27, 0x42, 0x05, 0x4e, 0x2e, 0x8b, 0xe0, 0xad, 0xf8, 0x16, 0x6e, 0xc1,
        0xf0, 0xf0, 0x76, 0x9f, 0x47, 0x79, 0xf1, 0x4c, 0x71, 0xd7, 0xeb, 0x00, 0x00, 0x00, 0x0a,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn parse_add_subnet_validator() {
        let (_, tx) = AddSubnetValidatorTx::from_bytes(DATA).unwrap();
        assert_eq!(tx.subnet_auth.sig_indices.len(), 1);
    }
}
