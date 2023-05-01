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
    use super::*;

    const DATA: &[u8] = &[
        0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x30, 0x39, 0xe9, 0x02, 0xa9, 0xa8, 0x66, 0x40, 0xbf,
        0xdb, 0x1c, 0xd0, 0xe3, 0x6c, 0x0c, 0xc9, 0x82, 0xb8, 0x3e, 0x57, 0x65, 0xfa, 0xd5, 0xf6,
        0xbb, 0xe6, 0xab, 0xdc, 0xce, 0x7b, 0x5a, 0xe7, 0xd7, 0xc7, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x4a, 0x17, 0x72, 0x05, 0xdf, 0x5c, 0x29, 0x92, 0x9d, 0x06, 0xdb, 0x9d,
        0x94, 0x1f, 0x83, 0xd5, 0xea, 0x98, 0x5d, 0xe3, 0x02, 0x01, 0x5e, 0x99, 0x25, 0x2d, 0x16,
        0x46, 0x9a, 0x66, 0x10, 0xdb, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x0a, 0xd1, 0x2b, 0x8e, 0xe8,
        0x92, 0x8e, 0xdf, 0x24, 0x8c, 0xa9, 0x1c, 0xa5, 0x56, 0x00, 0xfb, 0x38, 0x3f, 0x07, 0xc3,
        0x2b, 0xff, 0x1d, 0x6d, 0xec, 0x47, 0x2b, 0x25, 0xcf, 0x59, 0xa7, 0x00, 0x00, 0x00, 0x05,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x5f, 0xa2, 0x9e, 0xd4, 0x35, 0x69, 0x03, 0xda, 0xc2, 0x36,
        0x47, 0x13, 0xc6, 0x0f, 0x57, 0xd8, 0x47, 0x2c, 0x7d, 0xda, 0x4a, 0x5e, 0x08, 0xd8, 0x8a,
        0x88, 0xad, 0x8e, 0xa7, 0x1a, 0xed, 0x60, 0xf3, 0x08, 0x6d, 0x7b, 0xfc, 0x35, 0xbe, 0x1c,
        0x68, 0xdb, 0x66, 0x4b, 0xa9, 0xce, 0x61, 0xa2, 0x06, 0x01, 0x26, 0xb0, 0xd6, 0xb4, 0xbf,
        0xb0, 0x9f, 0xd7, 0xa5, 0xfb, 0x76, 0x78, 0xca, 0xda, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5,
        0x10, 0x00, 0x00, 0x00, 0x09, 0x18, 0x4e, 0x72, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x17,
        0x48, 0x76, 0xe8, 0x00, 0x00, 0x00, 0x01, 0xd1, 0xa9, 0x4a, 0x20, 0x00, 0x00, 0x01, 0x51,
        0x80, 0x01, 0xe1, 0x33, 0x80, 0x00, 0x00, 0x27, 0x10, 0x00, 0x00, 0x00, 0x17, 0x48, 0x76,
        0xe8, 0x00, 0x05, 0x00, 0x0c, 0x35, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x5f, 0xa2, 0x9e, 0xd4, 0x35, 0x69, 0x03, 0xda, 0xc2, 0x36, 0x47,
        0x13, 0xc6, 0x0f, 0x57, 0xd8, 0x47, 0x2c, 0x7d, 0xda, 0x4a, 0x5e, 0x08, 0xd8, 0x8a, 0x88,
        0xad, 0x8e, 0xa7, 0x1a, 0xed, 0x60, 0xf3, 0x08, 0x6d, 0x7b, 0xfc, 0x35, 0xbe, 0x1c, 0x68,
        0xdb, 0x66, 0x4b, 0xa9, 0xce, 0x61, 0xa2, 0x06, 0x01, 0x26, 0xb0, 0xd6, 0xb4, 0xbf, 0xb0,
        0x9f, 0xd7, 0xa5, 0xfb, 0x76, 0x78, 0xca, 0xda, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10,
        0x00, 0x00, 0x00, 0x09, 0x18, 0x4e, 0x72, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x17, 0x48,
        0x76, 0xe8, 0x00, 0x00, 0x00, 0x01, 0xd1, 0xa9, 0x4a, 0x20, 0x00, 0x00, 0x01, 0x51, 0x80,
        0x01, 0xe1, 0x33, 0x80, 0x00, 0x00, 0x27, 0x10, 0x00, 0x00, 0x00, 0x17, 0x48, 0x76, 0xe8,
        0x00, 0x05, 0x00, 0x0c, 0x35, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00,
    ];

    #[test]
    fn parse_transform_subnet_tx() {
        let (_, tx) = TransformSubnetTx::from_bytes(DATA).unwrap();
        assert_eq!(tx.max_validator_weight_factor, 5);
    }

    #[test]
    fn ui_transform_subnet() {
        let (_, tx) = TransformSubnetTx::from_bytes(DATA).unwrap();
        let mut title = [0; 100];
        let mut value = [0; 100];

        for i in 0..tx.num_items() {
            tx.render_item(i as _, title.as_mut(), value.as_mut(), 0)
                .unwrap();
            let t = std::string::String::from_utf8_lossy(&title);
            let v = std::string::String::from_utf8_lossy(&value);
            std::println!("{}:", t);
            std::println!("     {}", v);
            title.iter_mut().for_each(|b| *b = 0);
            value.iter_mut().for_each(|b| *b = 0);
        }
    }
}
