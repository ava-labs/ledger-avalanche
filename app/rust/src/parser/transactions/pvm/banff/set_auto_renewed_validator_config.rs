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
use crate::utils::hex_encode;
use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::{
    bytes::complete::{tag, take},
    number::complete::{be_u32, be_u64},
};
use zemu_sys::ViewError;

use crate::{
    handlers::handle_ui_message,
    parser::{
        intstr_to_fpstr_inplace, nano_avax_to_fp_str, u64_to_str, BaseTxFields, DisplayableItem,
        FromBytes, Header, ParserError, PvmOutput, SubnetAuth, DELEGATION_FEE_DIGITS,
        PVM_SET_AUTO_RENEWED_VALIDATOR_CONFIG, U64_FORMATTED_SIZE,
    },
};

pub const TX_ID_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct SetAutoRenewedValidatorConfigTx<'b> {
    pub tx_header: Header<'b>,
    pub base_tx: BaseTxFields<'b, PvmOutput<'b>>,
    pub tx_id: &'b [u8; TX_ID_LEN],
    pub auth: SubnetAuth<'b>,
    pub auto_compound_reward_shares: u32,
    pub period: u64,
}

impl<'b> SetAutoRenewedValidatorConfigTx<'b> {
    fn fee(&'b self) -> Result<u64, ParserError> {
        let sum_inputs = self.base_tx.sum_inputs_amount()?;
        let base_outputs = self.base_tx.sum_outputs_amount()?;

        let fee = sum_inputs
            .checked_sub(base_outputs)
            .ok_or(ParserError::OperationOverflows)?;
        Ok(fee)
    }
}

impl<'b> FromBytes<'b> for SetAutoRenewedValidatorConfigTx<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("SetAutoRenewedValidatorConfigTx::from_bytes_into\x00");

        let (rem, _) = tag(PVM_SET_AUTO_RENEWED_VALIDATOR_CONFIG.to_be_bytes())(input)?;

        let out = out.as_mut_ptr();

        // tx header
        let tx_header = unsafe { &mut *addr_of_mut!((*out).tx_header).cast() };
        let rem = Header::from_bytes_into(rem, tx_header)?;

        // base_tx
        let base_tx = unsafe { &mut *addr_of_mut!((*out).base_tx).cast() };
        let rem = BaseTxFields::<PvmOutput>::from_bytes_into(rem, base_tx)?;

        // tx_id (32 bytes — references the creation transaction)
        let (rem, tx_id) = take(TX_ID_LEN)(rem)?;
        let tx_id = arrayref::array_ref!(tx_id, 0, TX_ID_LEN);

        // auth (SubnetAuth, type_id 0x0a)
        let auth = unsafe { &mut *addr_of_mut!((*out).auth).cast() };
        let rem = SubnetAuth::from_bytes_into(rem, auth)?;

        // auto_compound_reward_shares
        let (rem, auto_compound_reward_shares) = be_u32(rem)?;

        // period
        let (rem, period) = be_u64(rem)?;

        unsafe {
            (*out).tx_id = tx_id;
            addr_of_mut!((*out).auto_compound_reward_shares).write(auto_compound_reward_shares);
            addr_of_mut!((*out).period).write(period);
        }

        Ok(rem)
    }
}

impl DisplayableItem for SetAutoRenewedValidatorConfigTx<'_> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // tx description, tx_id, auto_compound, period, fee
        Ok(5)
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        use bolos::{pic_str, PIC};
        let mut buffer = [0; U64_FORMATTED_SIZE + 2];

        match item_n {
            0 => {
                let label = pic_str!(b"SetAutoRenewConf");
                title[..label.len()].copy_from_slice(label);
                let content = pic_str!(b"Transaction");
                handle_ui_message(content, message, page)
            }
            1 => {
                let label = pic_str!(b"TxID");
                title[..label.len()].copy_from_slice(label);

                let prefix = pic_str!(b"0x"!);
                let mut out = [0; TX_ID_LEN * 2 + 2];
                let mut sz = prefix.len();
                out[..prefix.len()].copy_from_slice(&prefix[..]);

                sz += hex_encode(self.tx_id, &mut out[prefix.len()..])
                    .map_err(|_| ViewError::Unknown)?;

                handle_ui_message(&out[..sz], message, page)
            }
            2 => {
                let label = pic_str!(b"AutoCompound(%)");
                title[..label.len()].copy_from_slice(label);
                u64_to_str(self.auto_compound_reward_shares as _, &mut buffer[..])
                    .map_err(|_| ViewError::Unknown)?;
                let buffer = intstr_to_fpstr_inplace(&mut buffer[..], DELEGATION_FEE_DIGITS)
                    .map_err(|_| ViewError::Unknown)?;
                handle_ui_message(buffer, message, page)
            }
            3 => {
                let label = pic_str!(b"Period(seconds)");
                title[..label.len()].copy_from_slice(label);
                let period_buff = u64_to_str(self.period, &mut buffer[..])
                    .map_err(|_| ViewError::Unknown)?;
                handle_ui_message(period_buff, message, page)
            }
            4 => {
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

    include!("testvectors/set_auto_renewed_validator_config.rs");

    #[test]
    fn parse_set_auto_renewed_validator_config() {
        let (_, tx) = SetAutoRenewedValidatorConfigTx::from_bytes(
            SET_AUTO_RENEWED_VALIDATOR_CONFIG_DATA,
        )
        .unwrap();
        assert_eq!(tx.auto_compound_reward_shares, 750_000);
        assert_eq!(tx.period, 1_209_600);
        assert_eq!(tx.auth.sig_indices.len(), 1);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn ui_set_auto_renewed_validator_config() {
        println!("---------- SetAutoRenewedValidatorConfig TX ----------");
        let (_, tx) = SetAutoRenewedValidatorConfigTx::from_bytes(
            SET_AUTO_RENEWED_VALIDATOR_CONFIG_DATA,
        )
        .unwrap();

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
