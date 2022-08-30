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
use bolos::{pic_str, PIC};
use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::{bytes::complete::tag, number::complete::be_u32};
use zemu_sys::ViewError;

use crate::{
    handlers::handle_ui_message,
    parser::{
        intstr_to_fpstr_inplace, nano_avax_to_fp_str, u64_to_str, Address, BaseTxFields,
        DisplayableItem, FromBytes, Header, ObjectList, OutputIdx, ParserError, PvmOutput,
        SECPOutputOwners, TransferableOutput, Validator, DELEGATION_FEE_DIGITS,
        MAX_ADDRESS_ENCODED_LEN, PVM_ADD_VALIDATOR,
    },
};

#[derive(Clone, Copy, PartialEq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct AddValidatorTx<'b> {
    pub tx_header: Header<'b>,
    pub base_tx: BaseTxFields<'b, PvmOutput<'b>>,
    pub validator: Validator<'b>,
    // a bit-wise idx that tells what stake outputs could be displayed
    // in the ui stage.
    // this is set during the parsing stage
    renderable_out: OutputIdx,
    pub stake: ObjectList<'b, TransferableOutput<'b, PvmOutput<'b>>>,
    pub rewards_owner: SECPOutputOwners<'b>,
    pub shares: u32,
}

impl<'b> FromBytes<'b> for AddValidatorTx<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("AddValidatorTx::from_bytes_into\x00");

        let (rem, _) = tag(PVM_ADD_VALIDATOR.to_be_bytes())(input)?;

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

        // stake
        // check for the number of stake-outputs before parsing then as now
        // it has to be checked for the outputIdx capacity which is used
        // to tell if an output should be rendered or not.
        let (_, num_outputs) = be_u32(rem)?;
        if num_outputs > OutputIdx::BITS {
            return Err(ParserError::TooManyOutputs.into());
        }
        let stake = unsafe { &mut *addr_of_mut!((*out).stake).cast() };
        let rem = ObjectList::<TransferableOutput<PvmOutput>>::new_into(rem, stake)?;

        // valid pointers read as memory was initialized
        let staked_list = unsafe { &*stake.as_ptr() };

        let validator_stake = unsafe { (*validator.as_ptr()).weight };

        // get locked outputs amount to check for invariant
        let stake = Self::sum_stake_outputs_amount(staked_list)?;

        // Check for invariant, the locked utxos must be equals to validators' stake
        if validator_stake != stake {
            return Err(ParserError::InvalidStakingAmount.into());
        }

        // rewards_owner
        let rewards_owner = unsafe { &mut *addr_of_mut!((*out).rewards_owner).cast() };
        let rem = SECPOutputOwners::from_bytes_into(rem, rewards_owner)?;

        // shares
        let (rem, shares) = be_u32(rem)?;

        //good ptr and no uninit reads
        unsafe {
            addr_of_mut!((*out).shares).write(shares);
            // by default all outputs are renderable
            addr_of_mut!((*out).renderable_out).write(OutputIdx::MAX);
        }

        Ok(rem)
    }
}

impl<'b> DisplayableItem for AddValidatorTx<'b> {
    fn num_items(&self) -> usize {
        // tx_info, base_tx items, validator_items(4),
        // fee, fee_delegation, rewards_to and stake items
        1 + self.base_tx.base_outputs_num_items()
            + self.validator.num_items()
            + self.rewards_owner.addresses.len()
            + self.num_stake_items()
            + 1
            + 1
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        let validator_items = self.validator.num_items() as u8;
        let base_outputs_items = self.base_tx.base_outputs_num_items() as u8;
        let stake_outputs_items = self.num_stake_items() as u8;

        if item_n == 0 {
            let label = pic_str!(b"AddValidator");
            title[..label.len()].copy_from_slice(label);
            let content = pic_str!(b"Transaction");
            return handle_ui_message(content, message, page);
        }

        let item_n = item_n - 1;

        // when to start rendering staked outputs
        let render_stake_outputs_at = validator_items + base_outputs_items;
        let render_last_items_at = base_outputs_items + validator_items + stake_outputs_items;
        let total_items = self.num_items() as u8;

        match item_n {
            // render base_outputs
            x @ 0.. if x < base_outputs_items => self.render_base_outputs(x, title, message, page),

            // render validator items
            x if x >= base_outputs_items && x < render_stake_outputs_at => {
                let new_idx = x - base_outputs_items;
                self.validator.render_item(new_idx, title, message, page)
            }

            // render stake items
            x if x >= render_stake_outputs_at
                && x < (render_stake_outputs_at + stake_outputs_items) =>
            {
                let new_idx = x - render_stake_outputs_at;
                self.render_stake_outputs(new_idx, title, message, page)
            }

            // render rewards to, delegate fee and fee
            x if x >= render_last_items_at && x < total_items - 1 => {
                // normalize index to zero
                let new_idx = x - (base_outputs_items + stake_outputs_items + validator_items);
                self.render_last_items(new_idx, title, message, page)
            }
            _ => Err(ViewError::NoData),
        }
    }
}

impl<'b> AddValidatorTx<'b> {
    pub fn disable_output_if(&mut self, address: &[u8]) {
        self.base_tx.disable_output_if(address);

        // omit if there is only one stake output
        let num_outs = self.stake.iter().count();
        if num_outs <= 1 {
            return;
        }

        // The 99.99% of the outputs contain only one address(best case),
        // In the worse case we just show every output.
        self.stake.iter().enumerate().for_each(|(idx, o)| {
            if o.num_addresses() == 1 && o.contain_address(address) {
                self.renderable_out ^= 1 << idx;
            }
        });
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

    fn num_stake_items(&self) -> usize {
        let mut items = 0;
        let mut idx = 0;
        self.stake.iterate_with(|o| {
            let render = self.renderable_out & (1 << idx);
            if render > 0 {
                items += o.num_items();
            }
            idx += 1;
        });
        items
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

        // for base_outputs the header is Transfer
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

        // for base_outputs the header is Transfer
        let header = pic_str!(b"Stake");

        self.render_output_with_header(&obj, item_idx, title, message, page, header)
    }

    // helper function to render any TransferableOutput<PvmOutput>,
    // either locked or normal(comming as part of base_tx_fields)
    // the rendering is the same, the only difference is that
    // locked outputs uses a Stake label as the first item
    fn render_output_with_header(
        &'b self,
        &obj: &TransferableOutput<'b, PvmOutput<'b>>,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
        header: &[u8],
    ) -> Result<u8, ViewError> {
        //  'Transfer' or 'Stake':
        //      '0.5 AVAX to
        //  Address:
        //      hrp + 1asxdpfsmah8wqr6m8ymfwse5e4pa9fwnvudmpn
        //  Funds locked:
        //      0.5 AVAX until 2021-05-31 21:28:00 UTC

        // get the number of items for the obj wrapped up by PvmOutput
        let num_inner_items = obj.output.num_inner_items() as _;

        // do a custom rendering of the first base_output_items
        match item_n {
            0 => {
                title[..header.len()].copy_from_slice(header);

                // render using default obj impl
                let res = obj.render_item(0, title, message, page);

                // customize the label
                title.iter_mut().for_each(|v| *v = 0);
                title[..header.len()].copy_from_slice(header);

                res
            }
            // address rendering, according to avax team 99.99% of transactions only comes with one
            // address, but we support rendering any
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

                let hrp = self.tx_header.hrp().map_err(|_| ViewError::Unknown)?;
                let mut encoded = [0; MAX_ADDRESS_ENCODED_LEN];

                let addr_len = address
                    .encode_into(hrp, &mut encoded[..])
                    .map_err(|_| ViewError::Unknown)?;

                handle_ui_message(&encoded[..addr_len], message, page)
            }
            // by default we call the objects impl here,
            // if it is a locked output, that info will be shown otherwise,
            // this returns an error
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
        let label = pic_str!(b"Rewards to");
        title[..label.len()].copy_from_slice(label);

        // render owner addresses
        if let Some(addr) = self.rewards_owner.addresses.get(addr_idx) {
            let hrp = self.tx_header.hrp().map_err(|_| ViewError::Unknown)?;

            let mut address = MaybeUninit::uninit();
            Address::from_bytes_into(addr, &mut address).map_err(|_| ViewError::Unknown)?;

            let mut encoded = [0; MAX_ADDRESS_ENCODED_LEN];
            // valid read as memory was initialized
            let address = unsafe { address.assume_init() };

            let len = address
                .encode_into(hrp, &mut encoded[..])
                .map_err(|_| ViewError::Unknown)?;

            return handle_ui_message(&encoded[..len], message, page);
        }

        Err(ViewError::NoData)
    }

    fn render_last_items(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        use lexical_core::Number;

        let mut buffer = [0; u64::FORMATTED_SIZE_DECIMAL + 2];
        let num_addresses = self.rewards_owner.addresses.len() as u8;

        match item_n {
            // render rewards
            x @ 0.. if x < num_addresses => {
                self.render_rewards_to(x as usize, title, message, page)
            }
            x if x >= num_addresses && x < (num_addresses + 1) => {
                let label = pic_str!(b"Delegate fee(%)");
                title[..label.len()].copy_from_slice(label);
                u64_to_str(self.shares as _, &mut buffer[..]).map_err(|_| ViewError::Unknown)?;

                let buffer = intstr_to_fpstr_inplace(&mut buffer[..], DELEGATION_FEE_DIGITS)
                    .map_err(|_| ViewError::Unknown)?;

                handle_ui_message(buffer, message, page)
            }
            x if x == (num_addresses + 1) => {
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

    // Gets the obj that contain the item_n, along with the index
    // of the item. Returns an error otherwise
    pub fn stake_output_with_item(
        &'b self,
        item_n: u8,
    ) -> Result<(TransferableOutput<PvmOutput>, u8), ParserError> {
        let mut count = 0usize;
        let mut obj_item_n = 0;
        let mut idx = 0;
        // gets the output that contains item_n
        // and its corresponding index
        let filter = |o: &TransferableOutput<'b, PvmOutput>| -> bool {
            let render = self.renderable_out & (1 << idx) > 0;
            idx += 1;
            if !render {
                return false;
            }

            let n = o.num_items();
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
        Ok((obj, obj_item_n as u8))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &[u8] = &[
        0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x3D,
        0x9B, 0xDA, 0xC0, 0xED, 0x1D, 0x76, 0x13, 0x30, 0xCF, 0x68, 0x0E, 0xFD, 0xEB, 0x1A, 0x42,
        0x15, 0x9E, 0xB3, 0x87, 0xD6, 0xD2, 0x95, 0x0C, 0x96, 0xF7, 0xD2, 0x8F, 0x61, 0xBB, 0xE2,
        0xAA, // StakeableLockOut
        0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x60, 0xB5, 0x54, 0xE0,
        // Nested Output
        0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x1D, 0xCD, 0x65, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0xEC, 0x0C,
        0xD0, 0xA6, 0x1B, 0xED, 0xCE, 0xE0, 0x0F, 0x5B, 0x39, 0x36, 0x97, 0x43, 0x34, 0xCD, 0x43,
        0xD2, 0xA5, 0xD3, // Inputs
        0x00, 0x00, 0x00, 0x01, 0x3D, 0x43, 0x9C, 0xCE, 0x13, 0x78, 0xC6, 0x7A, 0x3E, 0x7A, 0x81,
        0x20, 0x82, 0x45, 0x06, 0xC5, 0x39, 0x41, 0x2B, 0x24, 0x29, 0x02, 0xED, 0xE4, 0x5E, 0x7D,
        0x4E, 0xCF, 0x6E, 0x10, 0xA6, 0xB6, 0x00, 0x00, 0x00, 0x00, 0x3D, 0x9B, 0xDA, 0xC0, 0xED,
        0x1D, 0x76, 0x13, 0x30, 0xCF, 0x68, 0x0E, 0xFD, 0xEB, 0x1A, 0x42, 0x15, 0x9E, 0xB3, 0x87,
        0xD6, 0xD2, 0x95, 0x0C, 0x96, 0xF7, 0xD2, 0x8F, 0x61, 0xBB, 0xE2, 0xAA,
        // StakeableLockIn
        0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x00, 0x60, 0xB5, 0x54, 0xE0,
        // Nested input
        0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x59, 0x68, 0x2F, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        // Node ID
        0xDE, 0x31, 0xB4, 0xD8, 0xB2, 0x29, 0x91, 0xD5, 0x1A, 0xA6, 0xAA, 0x1F, 0xC7, 0x33, 0xF2,
        0x3A, 0x85, 0x1A, 0x8C, 0x94, // Start time
        0x00, 0x00, 0x00, 0x00, 0x60, 0x4F, 0xBE, 0x07, // End time
        0x00, 0x00, 0x00, 0x00, 0x62, 0x30, 0xEF, 0x2F, // Weight
        0x00, 0x00, 0x00, 0x00, 0x3B, 0x9A, 0xCA, 0x00, // Stake:
        0x00, 0x00, 0x00, 0x01, 0x3D, 0x9B, 0xDA, 0xC0, 0xED, 0x1D, 0x76, 0x13, 0x30, 0xCF, 0x68,
        0x0E, 0xFD, 0xEB, 0x1A, 0x42, 0x15, 0x9E, 0xB3, 0x87, 0xD6, 0xD2, 0x95, 0x0C, 0x96, 0xF7,
        0xD2, 0x8F, 0x61, 0xBB, 0xE2, 0xAA, // StakeableLockOut
        0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x60, 0xB5, 0x54, 0xE0,
        // Nested output
        0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x3B, 0x9A, 0xCA, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0xEC, 0x0C,
        0xD0, 0xA6, 0x1B, 0xED, 0xCE, 0xE0, 0x0F, 0x5B, 0x39, 0x36, 0x97, 0x43, 0x34, 0xCD, 0x43,
        0xD2, 0xA5, 0xD3, // Rewards owner
        0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0xB6, 0x6C, 0x0D, 0x31, 0x28, 0xA6, 0x81, 0x2A, 0x30, 0xC9,
        0xBF, 0xDC, 0x2D, 0xA0, 0x99, 0x92, 0x4D, 0x0C, 0x08, 0x1F, // Shares
        0x00, 0x00, 0x4E, 0x20,
    ];

    #[test]
    fn parse_add_validator_tx() {
        let (_, tx) = AddValidatorTx::from_bytes(DATA).unwrap();
        assert_eq!(tx.shares, 20_000);
        assert_eq!(tx.validator.weight, 1000000000);
    }

    #[test]
    fn ui_validator() {
        let (_, tx) = AddValidatorTx::from_bytes(DATA).unwrap();
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
