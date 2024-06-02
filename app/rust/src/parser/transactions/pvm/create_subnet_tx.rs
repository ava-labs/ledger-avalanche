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
use avalanche_app_derive::match_ranges;
use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::bytes::complete::tag;
use zemu_sys::ViewError;

use crate::{
    checked_add,
    handlers::handle_ui_message,
    parser::{
        nano_avax_to_fp_str, BaseTxFields, DisplayableItem, FromBytes, Header, ParserError,
        PvmOutput, SECPOutputOwners, PVM_CREATE_SUBNET,
    },
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct CreateSubnetTx<'b> {
    pub tx_header: Header<'b>,
    pub base_tx: BaseTxFields<'b, PvmOutput<'b>>,
    owners: SECPOutputOwners<'b>,
}

impl<'b> CreateSubnetTx<'b> {
    fn fee(&'b self) -> Result<u64, ParserError> {
        let sum_inputs = self.base_tx.sum_inputs_amount()?;

        let base_outputs = self.base_tx.sum_outputs_amount()?;

        let fee = sum_inputs
            .checked_sub(base_outputs)
            .ok_or(ParserError::OperationOverflows)?;
        Ok(fee)
    }

    fn render_owners(
        &self,
        addr_idx: usize,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        use bolos::{pic_str, PIC};

        let label = pic_str!(b"Owner address");
        title[..label.len()].copy_from_slice(label);

        let hrp = self.tx_header.hrp().map_err(|_| ViewError::Unknown)?;
        self.owners
            .render_address_with_hrp(hrp, addr_idx, message, page)
    }
}

impl<'b> FromBytes<'b> for CreateSubnetTx<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("CreateSubnetTx::from_bytes_into\x00");

        // double check
        let (rem, _) = tag(PVM_CREATE_SUBNET.to_be_bytes())(input)?;

        let out = out.as_mut_ptr();
        // tx header
        let tx_header = unsafe { &mut *addr_of_mut!((*out).tx_header).cast() };
        let rem = Header::from_bytes_into(rem, tx_header)?;

        // base_tx
        let base_tx = unsafe { &mut *addr_of_mut!((*out).base_tx).cast() };
        let rem = BaseTxFields::<PvmOutput>::from_bytes_into(rem, base_tx)?;

        let owners = unsafe { &mut *addr_of_mut!((*out).owners).cast() };
        let rem = SECPOutputOwners::from_bytes_into(rem, owners)?;

        Ok(rem)
    }
}

impl<'b> DisplayableItem for CreateSubnetTx<'b> {
    fn num_items(&self) -> Result<u8, ViewError> {
        checked_add!(ViewError::Unknown, 2u8, self.owners.num_items()?)
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

        let owner_items = self.owners.num_items()?;

        match_ranges! {
            match item_n alias x {
                0 => {
                    let label = pic_str!(b"CreateSubnet");
                    title[..label.len()].copy_from_slice(label);

                    let content = pic_str!(b"transaction");
                    handle_ui_message(content, message, page)
                },
                until owner_items => self.render_owners(x as usize, title, message, page),
                until 1 => {
                    let label = pic_str!(b"Fee(AVAX)");
                    title[..label.len()].copy_from_slice(label);

                    let mut buffer = [0; u64::FORMATTED_SIZE_DECIMAL + 2];
                    let fee = self.fee().map_err(|_| ViewError::Unknown)?;
                    let fee_buff =
                        nano_avax_to_fp_str(fee, &mut buffer[..]).map_err(|_| ViewError::Unknown)?;

                    handle_ui_message(fee_buff, message, page)
                }
                _ => Err(ViewError::NoData),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &[u8] = &[
        0, 0, 0, 16, 0, 0, 0, 1, 237, 95, 56, 52, 30, 67, 110, 93, 70, 226, 187, 0, 180, 93, 98,
        174, 151, 209, 176, 80, 198, 75, 198, 52, 174, 16, 98, 103, 57, 227, 92, 75, 0, 0, 0, 1, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 39, 16, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 1,
        157, 31, 52, 188, 58, 111, 35, 6, 202, 7, 144, 22, 174, 248, 92, 19, 23, 103, 242, 56, 0,
        0, 0, 1, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 0, 0, 0, 2, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 31, 64, 0, 0, 0, 10, 0, 0,
        0, 4, 0, 0, 0, 5, 0, 0, 0, 58, 0, 0, 0, 1, 0, 0, 0, 79, 0, 0, 0, 65, 0, 0, 0, 87, 0, 0, 0,
        94, 0, 0, 0, 125, 0, 0, 1, 122, 0, 0, 0, 4, 109, 101, 109, 111, 0, 0, 0, 11, 0, 0, 0, 0, 0,
        0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 1, 22, 54, 119, 75, 103, 131, 141, 236, 22, 225, 106, 182,
        207, 172, 178, 27, 136, 195, 168, 97,
    ];

    #[test]
    fn parse_create_subnet_tx() {
        let (_, tx) = CreateSubnetTx::from_bytes(DATA).unwrap();
        assert_eq!(tx.owners.addresses.len(), 1);
    }
}
