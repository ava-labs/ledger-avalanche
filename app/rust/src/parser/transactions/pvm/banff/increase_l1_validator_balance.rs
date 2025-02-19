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
use crate::utils::hex_encode;
use crate::{
    handlers::handle_ui_message,
    parser::{
        nano_avax_to_fp_str, BaseTxFields, DisplayableItem, FromBytes, Header, ParserError,
        PvmOutput, PVM_INCREASE_L1_VALIDATOR_BALANCE, U64_FORMATTED_SIZE
    },
};
use bolos::PIC;
use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::bytes::complete::{tag, take};
use nom::number::complete::be_u64;
use zemu_sys::ViewError;

pub const VALIDATION_ID_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct IncreaseL1ValidatorBalanceTx<'b> {
    pub tx_header: Header<'b>,
    pub base_tx: BaseTxFields<'b, PvmOutput<'b>>,
    pub validation_id: &'b [u8; VALIDATION_ID_LEN],
    pub balance: u64,
}

// Info at https://github.com/ava-labs/avalanchejs/blob/master/src/utils/getBurnedAmountByTx.ts
impl<'b> IncreaseL1ValidatorBalanceTx<'b> {
    fn fee(&'b self) -> Result<u64, ParserError> {
        let sum_inputs = self.base_tx.sum_inputs_amount()?;

        let base_outputs = self.base_tx.sum_outputs_amount()?;

        let mut fee = sum_inputs
            .checked_sub(base_outputs)
            .ok_or(ParserError::OperationOverflows)?;

        fee = fee
            .checked_sub(self.balance)
            .ok_or(ParserError::OperationOverflows)?;
        Ok(fee)
    }
}

impl<'b> FromBytes<'b> for IncreaseL1ValidatorBalanceTx<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("IncreaseL1ValidatorBalanceTx::from_bytes_into\x00");

        let (rem, _) = tag(PVM_INCREASE_L1_VALIDATOR_BALANCE.to_be_bytes())(input)?;

        let out = out.as_mut_ptr();

        // tx header
        let tx_header = unsafe { &mut *addr_of_mut!((*out).tx_header).cast() };
        let rem = Header::from_bytes_into(rem, tx_header)?;

        // base_tx
        let base_tx = unsafe { &mut *addr_of_mut!((*out).base_tx).cast() };
        let rem = BaseTxFields::<PvmOutput>::from_bytes_into(rem, base_tx)?;

        // validation_id
        let (rem, validation_id) = take(32usize)(rem)?; // Read 32 bytes
        let validation_id = arrayref::array_ref!(validation_id, 0, 32);

        // balance
        let (rem, balance) = be_u64(rem)?;

        unsafe {
            addr_of_mut!((*out).validation_id).write(validation_id);
            addr_of_mut!((*out).balance).write(balance);
        }

        Ok(rem)
    }
}

impl<'b> DisplayableItem for IncreaseL1ValidatorBalanceTx<'b> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // tx_info, validation_id, amount, fee
        Ok(4u8)
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        use bolos::pic_str;

        let mut buffer = [0; U64_FORMATTED_SIZE + 2];

        match item_n {
            0 => {
                let label = pic_str!(b"IncreaseL1ValBal");
                title[..label.len()].copy_from_slice(label);
                let content = pic_str!(b"Transaction");
                handle_ui_message(content, message, page)
            }
            1 => {
                let prefix = pic_str!(b"0x"!);
                let label = pic_str!(b"Validator");
                title[..label.len()].copy_from_slice(label);

                // prefix
                let mut out = [0; VALIDATION_ID_LEN * 2 + 2];
                let mut sz = prefix.len();
                out[..prefix.len()].copy_from_slice(&prefix[..]);

                sz += hex_encode(self.validation_id, &mut out[prefix.len()..])
                    .map_err(|_| ViewError::Unknown)?;

                handle_ui_message(&out[..sz], message, page)
            }
            2 => {
                let label = pic_str!(b"Amount(AVAX)");
                title[..label.len()].copy_from_slice(label);

                let balance_buff = nano_avax_to_fp_str(self.balance, &mut buffer[..])
                    .map_err(|_| ViewError::Unknown)?;

                handle_ui_message(balance_buff, message, page)
            }
            3 => {
                let label = pic_str!(b"Fee(AVAX)");
                title[..label.len()].copy_from_slice(label);

                let fee = self.fee().map_err(|_| ViewError::Unknown)?;
                let fee_buff =
                    nano_avax_to_fp_str(fee, &mut buffer[..]).map_err(|_| ViewError::Unknown)?;

                handle_ui_message(fee_buff, message, page)
            }
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

    const DATA: &[u8] = &[];

    include!("testvectors/increase_l1_validator_balance.rs");
    #[test]
    fn parse_increase_l1_validator_balance() {
        let validation_id = &[
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];

        let (_, tx) =
            IncreaseL1ValidatorBalanceTx::from_bytes(INCREASE_L1_VALIDATOR_BALANCE_DATA).unwrap();
        assert_eq!(tx.validation_id, validation_id);
        assert_eq!(tx.balance, 1000000000);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn ui_increase_l1_validator_balance() {
        println!("-------------------- Increase L1 Validator Balance TX ------------------------");
        let (_, tx) =
            IncreaseL1ValidatorBalanceTx::from_bytes(INCREASE_L1_VALIDATOR_BALANCE_DATA).unwrap();

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
