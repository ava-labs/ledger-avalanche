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
use nom::{
    bytes::complete::tag,
    number::complete::{be_u32, be_u64},
};
use zemu_sys::ViewError;

use crate::{
    checked_add,
    handlers::handle_ui_message,
    parser::{
        intstr_to_fpstr_inplace, nano_avax_to_fp_str, proof_of_possession::BLSSigner, u64_to_str,
        BaseTxFields, DisplayableItem, FromBytes, Header, NodeId, ObjectList, OutputIdx,
        ParserError, PvmOutput, SECPOutputOwners, TransferableOutput, DELEGATION_FEE_DIGITS,
        MAX_ADDRESS_ENCODED_LEN, NODE_ID_LEN, PVM_ADD_AUTO_RENEWED_VALIDATOR, U64_FORMATTED_SIZE,
    },
};

use avalanche_app_derive::match_ranges;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct AddAutoRenewedValidatorTx<'b> {
    pub tx_header: Header<'b>,
    pub base_tx: BaseTxFields<'b, PvmOutput<'b>>,
    pub node_id: NodeId<'b>,
    pub signer: BLSSigner<'b>,
    // a bit-wise idx that tells what stake outputs could be displayed
    // in the ui stage.
    // this is set during the parsing stage
    renderable_out: OutputIdx,
    pub stake: ObjectList<'b, TransferableOutput<'b, PvmOutput<'b>>>,
    pub validator_rewards_owner: SECPOutputOwners<'b>,
    pub delegator_rewards_owner: SECPOutputOwners<'b>,
    pub owner: SECPOutputOwners<'b>,
    pub delegation_shares: u32,
    pub auto_compound_reward_shares: u32,
    pub period: u64,
}

impl<'b> FromBytes<'b> for AddAutoRenewedValidatorTx<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("AutoRenewed::from_bytes\x00");

        let (rem, _) = tag(PVM_ADD_AUTO_RENEWED_VALIDATOR.to_be_bytes())(input)?;

        let out = out.as_mut_ptr();

        // tx header
        let tx_header = unsafe { &mut *addr_of_mut!((*out).tx_header).cast() };
        let rem = Header::from_bytes_into(rem, tx_header)?;
        crate::sys::zemu_log_stack("AutoRenewed::header ok\x00");

        // base_tx
        let base_tx = unsafe { &mut *addr_of_mut!((*out).base_tx).cast() };
        let rem = BaseTxFields::<PvmOutput>::from_bytes_into(rem, base_tx)?;
        crate::sys::zemu_log_stack("AutoRenewed::base_tx ok\x00");

        // node_id: avalanchego types it as a JSONByteSlice ([]byte), so the codec
        // emits a 4-byte big-endian length prefix before the 20-byte id. Validate the
        // prefix equals NODE_ID_LEN; a mismatched length would otherwise misalign the
        // rest of the parse and let us display a node_id that differs from what is signed.
        let (rem, node_id_len) = be_u32(rem)?;
        if node_id_len as usize != NODE_ID_LEN {
            return Err(ParserError::InvalidLength.into());
        }
        let node_id = unsafe { &mut *addr_of_mut!((*out).node_id).cast() };
        let rem = NodeId::from_bytes_into(rem, node_id)?;
        crate::sys::zemu_log_stack("AutoRenewed::node_id ok\x00");

        // BLS signer
        let signer = unsafe { &mut *addr_of_mut!((*out).signer).cast() };
        let rem = BLSSigner::from_bytes_into(rem, signer)?;
        crate::sys::zemu_log_stack("AutoRenewed::signer ok\x00");

        // stake outputs
        let (_, num_outputs) = be_u32(rem)?;
        if num_outputs > OutputIdx::BITS {
            return Err(ParserError::TooManyOutputs.into());
        }

        let stake = unsafe { &mut *addr_of_mut!((*out).stake).cast() };
        let rem = ObjectList::<TransferableOutput<PvmOutput>>::new_into(rem, stake)?;
        crate::sys::zemu_log_stack("AutoRenewed::stake ok\x00");

        // validator rewards_owner
        let validator_rewards_owner =
            unsafe { &mut *addr_of_mut!((*out).validator_rewards_owner).cast() };
        let rem = SECPOutputOwners::from_bytes_into(rem, validator_rewards_owner)?;
        crate::sys::zemu_log_stack("AutoRenewed::val_rwd ok\x00");

        // delegator rewards_owner
        let delegator_rewards_owner =
            unsafe { &mut *addr_of_mut!((*out).delegator_rewards_owner).cast() };
        let rem = SECPOutputOwners::from_bytes_into(rem, delegator_rewards_owner)?;
        crate::sys::zemu_log_stack("AutoRenewed::del_rwd ok\x00");

        // owner (config authorization)
        let owner = unsafe { &mut *addr_of_mut!((*out).owner).cast() };
        let rem = SECPOutputOwners::from_bytes_into(rem, owner)?;
        crate::sys::zemu_log_stack("AutoRenewed::owner ok\x00");

        // delegation_shares
        let (rem, delegation_shares) = be_u32(rem)?;

        // auto_compound_reward_shares
        let (rem, auto_compound_reward_shares) = be_u32(rem)?;

        // period
        let (rem, period) = be_u64(rem)?;
        crate::sys::zemu_log_stack("AutoRenewed::parse done\x00");

        unsafe {
            addr_of_mut!((*out).delegation_shares).write(delegation_shares);
            addr_of_mut!((*out).auto_compound_reward_shares).write(auto_compound_reward_shares);
            addr_of_mut!((*out).period).write(period);
            // by default all outputs are renderable
            addr_of_mut!((*out).renderable_out).write(OutputIdx::MAX);
        }

        Ok(rem)
    }
}

impl DisplayableItem for AddAutoRenewedValidatorTx<'_> {
    fn num_items(&self) -> Result<u8, ViewError> {
        let base = self.base_tx.base_outputs_num_items()?;
        let signer = self.signer.num_items()?;
        let validator_rewards = self.validator_rewards_owner.num_addresses() as u8;
        let delegator_rewards = self.delegator_rewards_owner.num_addresses() as u8;
        let owner_addresses = self.owner.num_addresses() as u8;
        let stake = self.num_stake_items()?;

        // 1(header) + base + 1(node_id) + signer + stake
        // + validator_rewards + delegator_rewards + owner_addresses
        // + 1(delegation_fee) + 1(auto_compound) + 1(period) + 1(fee)
        checked_add!(
            ViewError::Unknown,
            6u8,
            base,
            signer,
            stake,
            validator_rewards,
            delegator_rewards,
            owner_addresses
        )
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        let signer_items = self.signer.num_items()?;
        let base_outputs_items = self.base_tx.base_outputs_num_items()?;
        let stake_outputs_items = self.num_stake_items()?;

        let total_items = self.num_items()?;

        match_ranges! {
            match item_n alias x {
                0x00 => {
                    let label = pic_str!(b"AutoRenewedValid");
                    title[..label.len()].copy_from_slice(label);
                    let content = pic_str!(b"Transaction");
                    handle_ui_message(content, message, page)
                },
                until base_outputs_items => self.render_base_outputs(x, title, message, page),
                until 1 => self.node_id.render_item(0, title, message, page),
                until signer_items => self.signer.render_item(x, title, message, page),
                until stake_outputs_items => self.render_stake_outputs(x, title, message, page),
                until total_items => self.render_last_items(x, title, message, page),
                _ => Err(ViewError::NoData),
            }
        }
    }
}

impl<'b> AddAutoRenewedValidatorTx<'b> {
    pub fn disable_output_if(&mut self, address: &[u8]) {
        // for this stake transaction, transfer information
        // is not important so even if there is only one
        // output, just hide it from the UI as long as
        // the change address match
        self.base_tx.force_disable_output(address);

        let mut idx = 0;
        let mut render = self.renderable_out;

        self.stake.iterate_with(|o| {
            if o.num_addresses() == 1 && o.contain_address(address) {
                render ^= 1 << idx;
            }
            idx += 1;
        });
        self.renderable_out = render;
    }

    fn fee(&'b self) -> Result<u64, ParserError> {
        let sum_inputs = self.base_tx.sum_inputs_amount()?;

        let base_outputs = self.base_tx.sum_outputs_amount()?;
        let stake_outputs = Self::sum_stake_outputs_amount(&self.stake)?;

        let total_outputs = base_outputs
            .checked_add(stake_outputs)
            .ok_or(ParserError::OperationOverflows)?;

        let fee = sum_inputs
            .checked_sub(total_outputs)
            .ok_or(ParserError::OperationOverflows)?;
        Ok(fee)
    }

    fn num_stake_items(&self) -> Result<u8, ViewError> {
        let mut items = 0;
        let mut idx = 0;
        let mut err: Option<ViewError> = None;

        self.stake.iterate_with(|o| {
            let render = self.renderable_out & (1 << idx);
            if render > 0 {
                match o
                    .num_items()
                    .and_then(|a| a.checked_add(items).ok_or(ViewError::Unknown))
                {
                    Ok(i) => items = i,
                    Err(_) => err = Some(ViewError::Unknown),
                }
            }
            idx += 1;
        });

        if err.is_some() {
            return Err(ViewError::Unknown);
        }
        Ok(items)
    }

    fn render_base_outputs(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        let (obj, item_idx) = self
            .base_tx
            .base_output_with_item(item_n)
            .map_err(|_| ViewError::NoData)?;

        let header = pic_str!(b"Transfer");
        self.render_output_with_header(&obj, item_idx, title, message, page, header)
    }

    fn render_stake_outputs(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        let (obj, item_idx) = self
            .stake_output_with_item(item_n)
            .map_err(|_| ViewError::NoData)?;

        let header = pic_str!(b"Stake");
        self.render_output_with_header(&obj, item_idx, title, message, page, header)
    }

    fn render_output_with_header(
        &'b self,
        &obj: &TransferableOutput<'b, PvmOutput<'b>>,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
        header: &[u8],
    ) -> Result<u8, ViewError> {
        let num_inner_items = obj.output.num_inner_items()?;

        match item_n {
            0 => {
                title[..header.len()].copy_from_slice(header);
                let res = obj.render_item(0, title, message, page);
                title.iter_mut().for_each(|v| *v = 0);
                title[..header.len()].copy_from_slice(header);
                res
            }
            x @ 1.. if x < num_inner_items => {
                let address_idx = x - 1;
                let address = obj
                    .output
                    .get_address_at(address_idx as usize)
                    .ok_or(ViewError::NoData)?;
                let t = pic_str!(b"Address");
                title[..t.len()].copy_from_slice(t);

                let hrp = self.tx_header.hrp().map_err(|_| ViewError::Unknown)?;
                let mut encoded = [0; MAX_ADDRESS_ENCODED_LEN];

                let addr_len = address
                    .encode_into(hrp, &mut encoded[..])
                    .map_err(|_| ViewError::Unknown)?;

                handle_ui_message(&encoded[..addr_len], message, page)
            }
            _ => obj.render_item(item_n, title, message, page),
        }
    }

    fn sum_stake_outputs_amount(
        stake: &'b ObjectList<'b, TransferableOutput<PvmOutput<'b>>>,
    ) -> Result<u64, ParserError> {
        stake
            .iter()
            .filter_map(|output| output.amount())
            .try_fold(0u64, |acc, x| acc.checked_add(x))
            .ok_or(ParserError::OperationOverflows)
    }

    fn render_rewards_to(
        &self,
        addr_idx: usize,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        let hrp = self.tx_header.hrp().map_err(|_| ViewError::Unknown)?;
        let validators = self.validator_rewards_owner.num_addresses();
        let delegators = self.delegator_rewards_owner.num_addresses();
        let owners = self.owner.num_addresses();

        match_ranges! {
            match addr_idx alias x {
                until validators => {
                    let label = pic_str!(b"Valida rewards to");
                    title[..label.len()].copy_from_slice(label);
                    self.validator_rewards_owner.render_address_with_hrp(hrp, x, message, page)
                }
                until delegators => {
                    let label = pic_str!(b"Delega rewards to");
                    title[..label.len()].copy_from_slice(label);
                    self.delegator_rewards_owner.render_address_with_hrp(hrp, x, message, page)
                }
                until owners => {
                    let label = pic_str!(b"Owner address");
                    title[..label.len()].copy_from_slice(label);
                    self.owner.render_address_with_hrp(hrp, x, message, page)
                }
                _ => Err(ViewError::NoData)
            }
        }
    }

    fn render_last_items(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        let mut buffer = [0; U64_FORMATTED_SIZE + 2];
        let num_addresses = (self.validator_rewards_owner.num_addresses()
            + self.delegator_rewards_owner.num_addresses()
            + self.owner.num_addresses()) as u8;

        match_ranges! {
            match item_n alias x {
                until num_addresses => {
                    self.render_rewards_to(x as usize, title, message, page)
                }
                until 1 => {
                    let label = pic_str!(b"Delegate fee(%)");
                    title[..label.len()].copy_from_slice(label);
                    u64_to_str(self.delegation_shares as _, &mut buffer[..])
                        .map_err(|_| ViewError::Unknown)?;
                    let buffer = intstr_to_fpstr_inplace(&mut buffer[..], DELEGATION_FEE_DIGITS)
                        .map_err(|_| ViewError::Unknown)?;
                    handle_ui_message(buffer, message, page)
                }
                until 1 => {
                    let label = pic_str!(b"AutoCompound(%)");
                    title[..label.len()].copy_from_slice(label);
                    u64_to_str(self.auto_compound_reward_shares as _, &mut buffer[..])
                        .map_err(|_| ViewError::Unknown)?;
                    let buffer = intstr_to_fpstr_inplace(&mut buffer[..], DELEGATION_FEE_DIGITS)
                        .map_err(|_| ViewError::Unknown)?;
                    handle_ui_message(buffer, message, page)
                }
                until 1 => {
                    let label = pic_str!(b"Period(seconds)");
                    title[..label.len()].copy_from_slice(label);
                    let period_buff = u64_to_str(self.period, &mut buffer[..])
                        .map_err(|_| ViewError::Unknown)?;
                    handle_ui_message(period_buff, message, page)
                }
                until 1 => {
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

    pub fn stake_output_with_item(
        &'b self,
        item_n: u8,
    ) -> Result<(TransferableOutput<'b, PvmOutput<'b>>, u8), ParserError> {
        let mut count = 0usize;
        let mut obj_item_n = 0;
        let mut idx = 0;

        let filter = |o: &TransferableOutput<'b, PvmOutput<'b>>| -> bool {
            let render = self.renderable_out & (1 << idx) > 0;
            idx += 1;
            if !render {
                return false;
            }

            let Ok(n) = o.num_items() else {
                return false;
            };

            for index in 0..n {
                count += 1;
                obj_item_n = index;
                if count == item_n as usize + 1 {
                    return true;
                }
            }
            false
        };

        let obj = self
            .stake
            .get_obj_if(filter)
            .ok_or(ParserError::DisplayIdxOutOfRange)?;
        Ok((obj, obj_item_n))
    }
}

#[cfg(test)]
mod tests {
    use std::prelude::v1::*;

    use crate::parser::snapshots_common::ReducedPage;
    use zuit::Page;

    use super::*;

    include!("testvectors/add_auto_renewed_validator.rs");

    #[test]
    fn parse_add_auto_renewed_validator_tx() {
        let (_, tx) =
            AddAutoRenewedValidatorTx::from_bytes(SIMPLE_ADD_AUTO_RENEWED_VALIDATOR).unwrap();
        assert_eq!(tx.delegation_shares, 20_000);
        assert_eq!(tx.auto_compound_reward_shares, 500_000);
        assert_eq!(tx.period, 604800);
        assert!(matches!(tx.signer, BLSSigner::Proof(_)));
        assert_eq!(tx.owner.num_addresses(), 1);
        assert_eq!(tx.validator_rewards_owner.num_addresses(), 1);
        assert_eq!(tx.delegator_rewards_owner.num_addresses(), 1);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn ui_auto_renewed_validator() {
        for (i, data) in [SIMPLE_ADD_AUTO_RENEWED_VALIDATOR].iter().enumerate() {
            println!(
                "-------------------- AddAutoRenewedValidator TX #{i} ------------------------"
            );
            let (_, tx) = AddAutoRenewedValidatorTx::from_bytes(data).unwrap();

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
}
