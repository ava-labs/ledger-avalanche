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

use core::{mem::MaybeUninit, ptr::addr_of_mut};

use bolos::{pic::PIC, pic_str};
use nom::{
    bytes::complete::tag,
    number::complete::{be_u32, be_u64, be_u8},
};
use zemu_sys::ViewError;

use crate::{
    handlers::handle_ui_message,
    parser::{
        nano_avax_to_fp_str, AssetId, BaseTxFields, DisplayableItem, FromBytes, Header,
        ParserError, PvmOutput, SubnetAuth, SubnetId, PVM_TRANSFORM_SUBNET,
    },
    utils::is_app_mode_expert,
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct TransformSubnetTx<'b> {
    tx_header: Header<'b>,
    base_tx: BaseTxFields<'b, PvmOutput<'b>>,

    subnet_id: SubnetId<'b>,
    asset_id: AssetId<'b>,

    initial_supply: u64,
    maximum_supply: u64,

    min_consumption_rate: u64,
    max_consumption_rate: u64,

    min_validator_stake: u64,
    max_validator_stake: u64,

    min_stake_duration: u32,
    max_stake_duration: u32,

    min_delegation_fee: u32,
    min_delegator_stake: u64,

    max_validator_weight_factor: u8,

    uptime_requirement: u32,

    auth: SubnetAuth<'b>,
}

impl<'b> FromBytes<'b> for TransformSubnetTx<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("TransformSubnetTx::from_bytes_into\x00");

        let (rem, _) = tag(PVM_TRANSFORM_SUBNET.to_be_bytes())(input)?;

        let out = out.as_mut_ptr();

        let tx_header = unsafe { &mut *addr_of_mut!((*out).tx_header).cast() };
        let rem = Header::from_bytes_into(rem, tx_header)?;

        let base_tx = unsafe { &mut *addr_of_mut!((*out).base_tx).cast() };
        let rem = BaseTxFields::<PvmOutput>::from_bytes_into(rem, base_tx)?;

        let subnet_id = unsafe { &mut *addr_of_mut!((*out).subnet_id).cast() };
        let rem = SubnetId::from_bytes_into(rem, subnet_id)?;

        let asset_id = unsafe { &mut *addr_of_mut!((*out).asset_id).cast() };
        let rem = AssetId::from_bytes_into(rem, asset_id)?;

        let (rem, initial_supply) = be_u64(rem)?;
        let (rem, maximum_supply) = be_u64(rem)?;

        let (rem, min_consumption_rate) = be_u64(rem)?;
        let (rem, max_consumption_rate) = be_u64(rem)?;

        let (rem, min_validator_stake) = be_u64(rem)?;
        let (rem, max_validator_stake) = be_u64(rem)?;

        let (rem, min_stake_duration) = be_u32(rem)?;
        let (rem, max_stake_duration) = be_u32(rem)?;

        let (rem, min_delegation_fee) = be_u32(rem)?;
        let (rem, min_delegator_stake) = be_u64(rem)?;

        let (rem, max_validator_weight_factor) = be_u8(rem)?;

        let (rem, uptime_requirement) = be_u32(rem)?;

        let auth = unsafe { &mut *addr_of_mut!((*out).auth).cast() };
        let rem = SubnetAuth::from_bytes_into(rem, auth)?;

        unsafe {
            addr_of_mut!((*out).initial_supply).write(initial_supply);
            addr_of_mut!((*out).maximum_supply).write(maximum_supply);

            addr_of_mut!((*out).min_consumption_rate).write(min_consumption_rate);
            addr_of_mut!((*out).max_consumption_rate).write(max_consumption_rate);

            addr_of_mut!((*out).min_validator_stake).write(min_validator_stake);
            addr_of_mut!((*out).max_validator_stake).write(max_validator_stake);

            addr_of_mut!((*out).min_stake_duration).write(min_stake_duration);
            addr_of_mut!((*out).max_stake_duration).write(max_stake_duration);

            addr_of_mut!((*out).min_delegation_fee).write(min_delegation_fee);
            addr_of_mut!((*out).min_delegator_stake).write(min_delegator_stake);

            addr_of_mut!((*out).max_validator_weight_factor).write(max_validator_weight_factor);

            addr_of_mut!((*out).uptime_requirement).write(uptime_requirement);
        }

        Ok(rem)
    }
}

impl<'b> TransformSubnetTx<'b> {
    fn fee(&self) -> Result<u64, ParserError> {
        let sum_inputs = self.base_tx.sum_inputs_amount()?;

        let total_outputs = self.base_tx.sum_outputs_amount()?;

        let fee = sum_inputs
            .checked_sub(total_outputs)
            .ok_or(ParserError::OperationOverflows)?;
        Ok(fee)
    }

    fn render_expert(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use lexical_core::{write as itoa, Number};

        let mut buffer = [0; u64::FORMATTED_SIZE_DECIMAL + 2];

        match item_n {
            0 => {
                let label = pic_str!(b"Initial supply");
                title[..label.len()].copy_from_slice(label);

                let buffer = itoa(self.initial_supply, &mut buffer);
                handle_ui_message(buffer, message, page)
            }
            1 => {
                let label = pic_str!(b"Maximum supply");
                title[..label.len()].copy_from_slice(label);

                let buffer = itoa(self.maximum_supply, &mut buffer);
                handle_ui_message(buffer, message, page)
            }
            2 => {
                let label = pic_str!(b"Min consumption");
                title[..label.len()].copy_from_slice(label);

                let buffer = itoa(self.min_consumption_rate, &mut buffer);
                handle_ui_message(buffer, message, page)
            }
            3 => {
                let label = pic_str!(b"Max consumption");
                title[..label.len()].copy_from_slice(label);

                let buffer = itoa(self.max_consumption_rate, &mut buffer);
                handle_ui_message(buffer, message, page)
            }
            4 => {
                let label = pic_str!(b"Min valid. stake");
                title[..label.len()].copy_from_slice(label);

                let buffer = itoa(self.min_validator_stake, &mut buffer);
                handle_ui_message(buffer, message, page)
            }
            5 => {
                let label = pic_str!(b"Max valid. stake");
                title[..label.len()].copy_from_slice(label);

                let buffer = itoa(self.max_validator_stake, &mut buffer);
                handle_ui_message(buffer, message, page)
            }
            6 => {
                let label = pic_str!(b"Min stake time");
                title[..label.len()].copy_from_slice(label);

                let buffer = itoa(self.min_stake_duration, &mut buffer);
                handle_ui_message(buffer, message, page)
            }
            7 => {
                let label = pic_str!(b"Max stake time");
                title[..label.len()].copy_from_slice(label);

                let buffer = itoa(self.max_stake_duration, &mut buffer);
                handle_ui_message(buffer, message, page)
            }
            8 => {
                let label = pic_str!(b"Min delegate fee");
                title[..label.len()].copy_from_slice(label);

                let buffer = itoa(self.min_delegation_fee, &mut buffer);
                handle_ui_message(buffer, message, page)
            }
            9 => {
                let label = pic_str!(b"Min delega. stake");
                title[..label.len()].copy_from_slice(label);

                let buffer = itoa(self.min_delegator_stake, &mut buffer);
                handle_ui_message(buffer, message, page)
            }
            10 => {
                let label = pic_str!(b"Max weight fact.");
                title[..label.len()].copy_from_slice(label);

                // TODO: determine how to display properly
                let buffer = itoa(self.max_validator_weight_factor, &mut buffer);
                handle_ui_message(buffer, message, page)
            }
            11 => {
                let label = pic_str!(b"Uptime req.");
                title[..label.len()].copy_from_slice(label);

                // TODO: determine how to display properly
                let buffer = itoa(self.uptime_requirement, &mut buffer);
                handle_ui_message(buffer, message, page)
            }
            _ => Err(ViewError::NoData),
        }
    }
}

impl<'b> DisplayableItem for TransformSubnetTx<'b> {
    fn num_items(&self) -> usize {
        let num_expert_items = if is_app_mode_expert() {
            // init/max supply + min/max consumption rate
            // + min/max stake duration
            // + min delegation fee + min delegator stake
            // + max validator weight factor
            // + uptime requirement
            12
        } else {
            0
        };

        //tx info, subnet id, asset id, fee
        // + expert items
        1 + self.subnet_id.num_items() + self.asset_id.num_items() + 1 + num_expert_items
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use lexical_core::Number;

        let expert = is_app_mode_expert();

        match item_n {
            0 => {
                let label = pic_str!(b"TransformSubnet");
                title[..label.len()].copy_from_slice(label);

                let content = pic_str!(b"Transaction");
                return handle_ui_message(content, message, page);
            }
            1 => self.subnet_id.render_item(0, title, message, page),
            2 => self.asset_id.render_item(0, title, message, page),
            3 => {
                let label = pic_str!(b"Fee(AVAX)");
                title[..label.len()].copy_from_slice(label);

                let fee = self.fee().map_err(|_| ViewError::Unknown)?;

                let mut buffer = [0; u64::FORMATTED_SIZE_DECIMAL + 2];
                let fee_buff =
                    nano_avax_to_fp_str(fee, &mut buffer[..]).map_err(|_| ViewError::Unknown)?;
                handle_ui_message(fee_buff, message, page)
            }
            4..=15 if expert => self.render_expert(item_n - 4, title, message, page),
            _ => Err(ViewError::NoData),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::prelude::v1::*;

    use crate::parser::snapshots_common::ReducedPage;
    use zuit::Page;

    use super::*;

    include!("testvectors/transform_subnet.rs");

    #[test]
    fn parse_transform_subnet_tx() {
        let (_, tx) = TransformSubnetTx::from_bytes(SAMPLE).unwrap();
        assert_eq!(tx.max_validator_weight_factor, 5);

        let subnet_id = SubnetId::new(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38,
        ]);

        let asset_id = &[
            0x99, 0x77, 0x55, 0x77, 0x11, 0x33, 0x55, 0x31, 0x99, 0x77, 0x55, 0x77, 0x11, 0x33,
            0x55, 0x31, 0x99, 0x77, 0x55, 0x77, 0x11, 0x33, 0x55, 0x31, 0x99, 0x77, 0x55, 0x77,
            0x11, 0x33, 0x55, 0x31,
        ];

        let (_, tx) = TransformSubnetTx::from_bytes(SIMPLE_TRANSFORM_SUBNET).unwrap();
        assert_eq!(tx.asset_id.id(), asset_id);
        assert_eq!(tx.subnet_id, subnet_id);
        assert_eq!(tx.min_consumption_rate, 1_000);
        assert_eq!(tx.uptime_requirement, 950_000);
        assert_eq!(tx.max_validator_weight_factor, 1);

        let (_, tx) = TransformSubnetTx::from_bytes(COMPLEX_TRANSFORM_SUBNET).unwrap();
        assert_eq!(
            tx.base_tx
                .outputs()
                .iter()
                .nth(1)
                .expect("2 outputs")
                .output
                .locktime
                .expect("locktime present"),
            876543210
        );
        assert_eq!(tx.asset_id.id(), asset_id);
        assert_eq!(tx.subnet_id, subnet_id);
        assert_eq!(tx.min_consumption_rate, 0);
        assert_eq!(tx.uptime_requirement, 0);
        assert_eq!(tx.max_validator_weight_factor, 255);
    }

    #[test]
    fn ui_transform_subnet() {
        for (i, data) in [
            SAMPLE,
            SIMPLE_TRANSFORM_SUBNET,
            // COMPLEX_TRANSFORM_SUBNET, //sum of inputs overflows u64
        ]
        .iter()
        .enumerate()
        {
            println!("-------------------- Transform Subnet TX #{i} ------------------------");
            let (_, tx) = TransformSubnetTx::from_bytes(data).unwrap();

            let items = tx.num_items();

            let mut pages = Vec::<Page<18, 1024>>::with_capacity(items);
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
}
