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
use bolos::{hex_encode, PIC};
use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::bytes::complete::{tag, take};
use nom::number::complete::be_u32;
use zemu_sys::ViewError;

use crate::parser::chain_id::ChainId;
use crate::{
    constants::CHAIN_ID_LEN,
    handlers::handle_ui_message,
    parser::{
        l1_validator::L1Validator, nano_avax_to_fp_str, BaseTxFields, DisplayableItem, FromBytes,
        Header, ObjectList, ParserError, PvmOutput, SubnetAuth, SubnetId, PVM_CONVERT_SUBNET_L1, U64_FORMATTED_SIZE
    },
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct ConvertSubnetToL1Tx<'b> {
    pub tx_header: Header<'b>,
    pub base_tx: BaseTxFields<'b, PvmOutput<'b>>,
    pub subnet_id: SubnetId<'b>,
    pub chain_id: ChainId<'b>,
    pub address: &'b [u8],
    pub address_len: u32,
    pub validators: ObjectList<'b, L1Validator<'b>>,
    pub subnet_auth: SubnetAuth<'b>,
}

pub const BASE_FIELDS_LEN: u8 = 4;

impl<'b> ConvertSubnetToL1Tx<'b> {
    /// Sums the balances of all L1 validators in the list.
    fn sum_validators_balances(&self) -> Result<u64, ParserError> {
        let mut total_balance = 0u64;

        for validator in self.validators.iter() {
            total_balance = total_balance
                .checked_add(validator.balance)
                .ok_or(ParserError::OperationOverflows)?;
        }

        Ok(total_balance)
    }

    // Info at https://github.com/ava-labs/avalanchejs/blob/master/src/utils/getBurnedAmountByTx.ts
    fn fee(&'b self) -> Result<u64, ParserError> {
        let sum_inputs = self.base_tx.sum_inputs_amount()?;

        let base_outputs = self.base_tx.sum_outputs_amount()?;

        let mut fee = sum_inputs
            .checked_sub(base_outputs)
            .ok_or(ParserError::OperationOverflows)?;

        fee = fee
            .checked_sub(self.sum_validators_balances()?)
            .ok_or(ParserError::OperationOverflows)?;

        Ok(fee)
    }

    /// Returns the number of validators in the list.
    fn num_validators(&self) -> usize {
        self.validators.iter().count()
    }
}

impl<'b> FromBytes<'b> for ConvertSubnetToL1Tx<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("ConvertSubnetToL1Tx::from_bytes_into\x00");

        let (rem, _) = tag(PVM_CONVERT_SUBNET_L1.to_be_bytes())(input)?;

        let out = out.as_mut_ptr();

        // tx header
        let tx_header = unsafe { &mut *addr_of_mut!((*out).tx_header).cast() };
        let rem = Header::from_bytes_into(rem, tx_header)?;

        // base_tx
        let base_tx = unsafe { &mut *addr_of_mut!((*out).base_tx).cast() };
        let rem = BaseTxFields::<PvmOutput>::from_bytes_into(rem, base_tx)?;

        // subnet_id
        let subnet_id = unsafe { &mut *addr_of_mut!((*out).subnet_id).cast() };
        let rem = SubnetId::from_bytes_into(rem, subnet_id)?;
        let subnet_id_ref = unsafe { subnet_id.assume_init_ref() }; // Get a reference to the initialized value

        if subnet_id_ref.is_primary_network() {
            return Err(ParserError::UnexpectedField.into());
        }

        // chain_id
        let chain_id = unsafe { &mut *addr_of_mut!((*out).chain_id).cast() };
        let rem = ChainId::from_bytes_into(rem, chain_id)?;

        // address
        let (rem, address_len) = be_u32(rem)?;
        let (rem, address) = take(address_len as usize)(rem)?;

        // validators
        let validators = unsafe { &mut *addr_of_mut!((*out).validators).cast() };
        let rem = ObjectList::<L1Validator>::new_into(rem, validators)?;

        // subnetAuth
        let subnet_auth = unsafe { &mut *addr_of_mut!((*out).subnet_auth).cast() };
        let rem = SubnetAuth::from_bytes_into(rem, subnet_auth)?;

        unsafe {
            addr_of_mut!((*out).address).write(address);
        }

        Ok(rem)
    }
}

impl DisplayableItem for ConvertSubnetToL1Tx<'_> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // tx description, chain_id, address, fee, validators
        let num_validators = BASE_FIELDS_LEN + self.num_validators() as u8;
        Ok(num_validators)
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
        let prefix = pic_str!(b"0x"!);
        match item_n {
            0 => {
                let label = pic_str!(b"ConvertSubnetToL1");
                title[..label.len()].copy_from_slice(label);
                let content = pic_str!(b"Transaction");
                handle_ui_message(content, message, page)
            }
            1 => self.chain_id.render_item(0, title, message, page),
            2 => {
                let label = pic_str!(b"Validator");
                title[..label.len()].copy_from_slice(label);

                // prefix
                let mut out = [0; CHAIN_ID_LEN * 2 + 2];
                let mut sz = prefix.len();
                out[..prefix.len()].copy_from_slice(&prefix[..]);

                sz += hex_encode(self.address, &mut out[prefix.len()..])
                    .map_err(|_| ViewError::Unknown)?;

                handle_ui_message(&out[..sz], message, page)
            }
            3 => {
                let label = pic_str!(b"Fee(AVAX)");
                title[..label.len()].copy_from_slice(label);

                let fee = self.fee().map_err(|_| ViewError::Unknown)?;
                let fee_buff =
                    nano_avax_to_fp_str(fee, &mut buffer[..]).map_err(|_| ViewError::Unknown)?;

                handle_ui_message(fee_buff, message, page)
            }
            x @ 4.. => {
                let validator_n = x - 4;
                let validator = self.validators.get((validator_n + 1).into()).unwrap();
                // Print the chain ID for the validator
                validator.node_id.render_item(0, title, message, page)
            }
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

    include!("testvectors/convert_subnet_to_l1.rs");
    #[test]
    fn parse_convert_subnet() {
        let subnet_id = SubnetId::new(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38,
        ]);
        let manager_chain_id = ChainId::new(&[
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
            0x27, 0x28, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
        ]);

        let manager_address = &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xde, 0xad,
        ];

        let (_, tx) = ConvertSubnetToL1Tx::from_bytes(SIMPLE_CONVERT_SUBNET).unwrap();
        assert_eq!(tx.subnet_id, subnet_id);
        assert_eq!(tx.chain_id, manager_chain_id);
        assert_eq!(tx.address, manager_address);

        let (_, tx) = ConvertSubnetToL1Tx::from_bytes(COMPLEX_CONVERT_SUBNET).unwrap();
        assert_eq!(tx.subnet_id, subnet_id);
        assert_eq!(tx.chain_id, manager_chain_id);
        assert_eq!(tx.address, manager_address);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn ui_convert_subnet_to_l1() {
        for (i, data) in [SIMPLE_CONVERT_SUBNET, COMPLEX_CONVERT_SUBNET]
            .iter()
            .enumerate()
        {
            println!("-------------------- Convert Subnet to L1 TX #{i} ------------------------");
            let (_, tx) = ConvertSubnetToL1Tx::from_bytes(data).unwrap();

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
