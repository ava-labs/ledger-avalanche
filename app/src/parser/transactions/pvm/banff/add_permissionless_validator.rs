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
use bolos::{pic_str, PIC};
use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::{bytes::complete::tag, number::complete::be_u32};
use zemu_sys::ViewError;

use crate::{
    handlers::handle_ui_message,
    parser::{
        intstr_to_fpstr_inplace, nano_avax_to_fp_str, proof_of_possession::BLSSigner, u64_to_str,
        Address, BaseTxFields, DisplayableItem, FromBytes, Header, ObjectList, OutputIdx,
        ParserError, PvmOutput, SECPOutputOwners, SubnetId, TransferableOutput, Validator,
        DELEGATION_FEE_DIGITS, MAX_ADDRESS_ENCODED_LEN, PVM_ADD_PERMISSIONLESS_VALIDATOR,
    },
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct AddPermissionlessValidatorTx<'b> {
    pub tx_header: Header<'b>,
    pub base_tx: BaseTxFields<'b, PvmOutput<'b>>,
    pub validator: Validator<'b>,
    pub subnet_id: SubnetId<'b>,
    pub signer: BLSSigner<'b>,
    // a bit-wise idx that tells what stake outputs could be displayed
    // in the ui stage.
    // this is set during the parsing stage
    renderable_out: OutputIdx,
    pub stake: ObjectList<'b, TransferableOutput<'b, PvmOutput<'b>>>,
    pub validator_rewards_owner: SECPOutputOwners<'b>,
    pub delegator_rewards_owner: SECPOutputOwners<'b>,
    pub shares: u32,
}

impl<'b> FromBytes<'b> for AddPermissionlessValidatorTx<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("AddPermissionlessValidatorTx::from_bytes_into\x00");

        let (rem, _) = tag(PVM_ADD_PERMISSIONLESS_VALIDATOR.to_be_bytes())(input)?;

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

        // BLS signer
        let signer = unsafe { &mut *addr_of_mut!((*out).signer).cast() };
        let rem = BLSSigner::from_bytes_into(rem, signer);

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

        // validator rewards_owner
        let validator_rewards_owner =
            unsafe { &mut *addr_of_mut!((*out).validator_rewards_owner).cast() };
        let rem = SECPOutputOwners::from_bytes_into(rem, validator_rewards_owner)?;

        // delegator rewards_owner
        let delegator_rewards_owner =
            unsafe { &mut *addr_of_mut!((*out).delegator_rewards_owner).cast() };
        let rem = SECPOutputOwners::from_bytes_into(rem, delegator_rewards_owner)?;

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

impl<'b> DisplayableItem for AddPermissionlessValidatorTx<'b> {
    fn num_items(&self) -> usize {
        // tx_info, base_tx items, validator_items(4),
        // fee, fee_delegation, validator_rewards_to, delegator_rewards_to,
        // and stake items
        1 + self.base_tx.base_outputs_num_items()
            + self.validator.num_items()
            + self.signer.num_items()
            + self.validator_rewards_owner.addresses.len()
            + self.delegator_rewards_owner.addresses.len()
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
        let signer_items = self.signer.num_items() as u8;
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
        let render_stake_outputs_at = validator_items + base_outputs_items + signer_items;
        let render_last_items_at = base_outputs_items + validator_items + stake_outputs_items;
        let total_items = self.num_items() as u8;

        match item_n {
            // render base_outputs
            x @ 0.. if x < base_outputs_items => self.render_base_outputs(x, title, message, page),

            // render validator items
            x if x >= base_outputs_items && x < render_stake_outputs_at - signer_items => {
                let new_idx = x - base_outputs_items;
                self.validator.render_item(new_idx, title, message, page)
            }

            //if signer_items is 0 this will be skipped already but let's make the check
            // explicit
            x if x >= base_outputs_items && x < render_stake_outputs_at && signer_items != 0 => {
                self.signer.render_item(0, title, message, page)
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

impl<'b> AddPermissionlessValidatorTx<'b> {
    pub fn disable_output_if(&mut self, address: &[u8]) {
        // for this stake transaction, transfer information
        // is not important so even if there is only one
        // output, just hide it from the UI as long as
        // the change address match
        self.base_tx.force_disable_output(address);

        let mut idx = 0;
        let mut render = self.renderable_out;

        self.stake.iterate_with(|o| {
            // The 99.99% of the outputs contain only one address(best case),
            // In the worse case we just show every output.
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
        let render_addr = |addr: Address| {
            let hrp = self.tx_header.hrp().map_err(|_| ViewError::Unknown)?;

            let mut encoded = [0; MAX_ADDRESS_ENCODED_LEN];

            let len = addr
                .encode_into(hrp, &mut encoded[..])
                .map_err(|_| ViewError::Unknown)?;

            return handle_ui_message(&encoded[..len], message, page);
        };

        //look for validator address first
        if let Some(addr) = self.validator_rewards_owner.get_address_at(addr_idx) {
            // FIXME: title truncated
            let label = pic_str!(b"Valida rewards to");
            title[..label.len()].copy_from_slice(label);
            render_addr(addr)
        }
        //if no address found then look into the delegeators
        else if let Some(addr) = self
            .delegator_rewards_owner
            // with an offset
            .get_address_at(addr_idx - self.validator_rewards_owner.num_addresses())
        {
            // FIXME: title truncated
            let label = pic_str!(b"Delega rewards to");
            title[..label.len()].copy_from_slice(label);
            render_addr(addr)
        } else {
            Err(ViewError::NoData)
        }
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
        let num_addresses = (self.validator_rewards_owner.num_addresses()
            + self.delegator_rewards_owner.num_addresses()) as u8;

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
        0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x30, 0x39, 0xe9, 0x02, 0xa9, 0xa8, 0x66, 0x40, 0xbf,
        0xdb, 0x1c, 0xd0, 0xe3, 0x6c, 0x0c, 0xc9, 0x82, 0xb8, 0x3e, 0x57, 0x65, 0xfa, 0xd5, 0xf6,
        0xbb, 0xe6, 0xab, 0xdc, 0xce, 0x7b, 0x5a, 0xe7, 0xd7, 0xc7, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x4a, 0x17, 0x72, 0x05, 0xdf, 0x5c, 0x29, 0x92, 0x9d, 0x06, 0xdb, 0x9d,
        0x94, 0x1f, 0x83, 0xd5, 0xea, 0x98, 0x5d, 0xe3, 0x02, 0x01, 0x5e, 0x99, 0x25, 0x2d, 0x16,
        0x46, 0x9a, 0x66, 0x10, 0xdb, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x0a, 0xd1, 0x2b, 0x8e, 0xe8,
        0x92, 0x8e, 0xdf, 0x24, 0x8c, 0xa9, 0x1c, 0xa5, 0x56, 0x00, 0xfb, 0x38, 0x3f, 0x07, 0xc3,
        0x2b, 0xff, 0x1d, 0x6d, 0xec, 0x47, 0x2b, 0x25, 0xcf, 0x59, 0xa7, 0x00, 0x00, 0x00, 0x05,
        0x00, 0x00, 0x01, 0xd1, 0xa9, 0x4a, 0x20, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x5f, 0xa2, 0x9e, 0xd4, 0x35, 0x69, 0x03, 0xda, 0xc2, 0x36,
        0x47, 0x13, 0xc6, 0x0f, 0x57, 0xd8, 0x47, 0x2c, 0x7d, 0xda, 0x00, 0x00, 0x00, 0x00, 0x63,
        0x97, 0x61, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x63, 0xbe, 0xee, 0x6e, 0x00, 0x00, 0x01, 0xd1,
        0xa9, 0x4a, 0x20, 0x00, 0xf3, 0x08, 0x6d, 0x7b, 0xfc, 0x35, 0xbe, 0x1c, 0x68, 0xdb, 0x66,
        0x4b, 0xa9, 0xce, 0x61, 0xa2, 0x06, 0x01, 0x26, 0xb0, 0xd6, 0xb4, 0xbf, 0xb0, 0x9f, 0xd7,
        0xa5, 0xfb, 0x76, 0x78, 0xca, 0xda, 0x00, 0x00, 0x00, 0x1c, 0xa5, 0xaf, 0x17, 0x9e, 0x41,
        0x88, 0x58, 0x38, 0x93, 0xc2, 0xb9, 0x9e, 0x1a, 0x8b, 0xe2, 0x7d, 0x90, 0xa9, 0x21, 0x3c,
        0xfb, 0xff, 0x1d, 0x75, 0xb7, 0x4f, 0xe2, 0xbc, 0x9f, 0x3b, 0x07, 0x2c, 0x2d, 0xed, 0x08,
        0x63, 0xa9, 0xd9, 0xac, 0xd9, 0x03, 0x3f, 0x22, 0x32, 0x95, 0x81, 0x0e, 0x42, 0x92, 0x38,
        0xe2, 0x8d, 0x3c, 0x9b, 0x7f, 0x72, 0x12, 0xb6, 0x3d, 0x74, 0x6b, 0x2a, 0xe7, 0x3a, 0x54,
        0xfe, 0x08, 0xa3, 0xde, 0x61, 0xb1, 0x32, 0xf2, 0xf8, 0x9e, 0x9e, 0xef, 0xf9, 0x7d, 0x4d,
        0x7c, 0xa3, 0xa3, 0xc8, 0x89, 0x86, 0xaa, 0x85, 0x5c, 0xd3, 0x62, 0x96, 0xfc, 0xfe, 0x8f,
        0x02, 0x16, 0x2d, 0x02, 0x58, 0xbe, 0x49, 0x4d, 0x26, 0x7d, 0x4c, 0x57, 0x98, 0xbc, 0x08,
        0x1a, 0xb6, 0x02, 0xde, 0xd9, 0x0b, 0x0f, 0xc1, 0x6d, 0x8a, 0x03, 0x5e, 0x68, 0xff, 0x52,
        0x94, 0x79, 0x4c, 0xb6, 0x3f, 0xf1, 0xee, 0x06, 0x8f, 0xbf, 0xc2, 0xb4, 0xc8, 0xcd, 0x2d,
        0x08, 0xeb, 0xf2, 0x97, 0x00, 0x00, 0x00, 0x01, 0x3d, 0x0a, 0xd1, 0x2b, 0x8e, 0xe8, 0x92,
        0x8e, 0xdf, 0x24, 0x8c, 0xa9, 0x1c, 0xa5, 0x56, 0x00, 0xfb, 0x38, 0x3f, 0x07, 0xc3, 0x2b,
        0xff, 0x1d, 0x6d, 0xec, 0x47, 0x2b, 0x25, 0xcf, 0x59, 0xa7, 0x00, 0x00, 0x00, 0x07, 0x00,
        0x00, 0x01, 0xd1, 0xa9, 0x4a, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x33, 0xee, 0xff, 0xc6, 0x47, 0x85, 0xcf,
        0x9d, 0x80, 0xe7, 0x73, 0x1d, 0x9f, 0x31, 0xf6, 0x7b, 0xd0, 0x3c, 0x5c, 0xf0, 0x00, 0x00,
        0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x01, 0x72, 0xf3, 0xeb, 0x9a, 0xea, 0xf8, 0x28, 0x30, 0x11, 0xce, 0x6e, 0x43,
        0x7f, 0xde, 0xcd, 0x65, 0xea, 0xce, 0x8f, 0x52, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0xb2, 0xb9,
        0x13, 0x13, 0xac, 0x48, 0x7c, 0x22, 0x24, 0x45, 0x25, 0x4e, 0x26, 0xcd, 0x02, 0x6d, 0x21,
        0xf6, 0xf4, 0x40, 0x00, 0x00, 0x4e, 0x20,
    ];

    #[test]
    fn parse_add_permissionless_validator_tx() {
        let (_, tx) = AddPermissionlessValidatorTx::from_bytes(DATA).unwrap();
        assert_eq!(tx.shares, 20_000);
        assert_eq!(tx.validator.weight, 1000000000);
        assert!(matches!(tx.signer, BLSSigner::Proof(_)))
    }

    #[test]
    fn ui_permissionless_validator() {
        let (_, tx) = AddPermissionlessValidatorTx::from_bytes(DATA).unwrap();
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
