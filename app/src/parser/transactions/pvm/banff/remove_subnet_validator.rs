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
use crate::{parser::NodeId, sys::ViewError};
use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::bytes::complete::tag;

use crate::{
    handlers::handle_ui_message,
    parser::{
        nano_avax_to_fp_str, BaseTxFields, DisplayableItem, FromBytes, Header, ParserError,
        PvmOutput, SubnetAuth, SubnetId, PVM_REMOVE_SUBNET_VALIDATOR,
    },
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct RemoveSubnetValidatorTx<'b> {
    pub tx_header: Header<'b>,
    pub base_tx: BaseTxFields<'b, PvmOutput<'b>>,
    pub node_id: NodeId<'b>,
    pub subnet_id: SubnetId<'b>,
    pub subnet_auth: SubnetAuth<'b>,
}

impl<'b> FromBytes<'b> for RemoveSubnetValidatorTx<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("RemoveSubnetValidatorTx::from_bytes_into\x00");

        let (rem, _) = tag(PVM_REMOVE_SUBNET_VALIDATOR.to_be_bytes())(input)?;

        let out = out.as_mut_ptr();

        // tx header
        let tx_header = unsafe { &mut *addr_of_mut!((*out).tx_header).cast() };
        let rem = Header::from_bytes_into(rem, tx_header)?;

        // base_tx
        let base_tx = unsafe { &mut *addr_of_mut!((*out).base_tx).cast() };
        let rem = BaseTxFields::<PvmOutput>::from_bytes_into(rem, base_tx)?;

        // node id
        let node_id = unsafe { &mut *addr_of_mut!((*out).node_id).cast() };
        let rem = NodeId::from_bytes_into(rem, node_id)?;

        // SubnetId
        let subnet_id = unsafe { &mut *addr_of_mut!((*out).subnet_id).cast() };
        let rem = SubnetId::from_bytes_into(rem, subnet_id)?;

        // subnetAuth
        let subnet_auth = unsafe { &mut *addr_of_mut!((*out).subnet_auth).cast() };
        let rem = SubnetAuth::from_bytes_into(rem, subnet_auth)?;

        Ok(rem)
    }
}

impl<'b> DisplayableItem for RemoveSubnetValidatorTx<'b> {
    fn num_items(&self) -> usize {
        // tx_info, node_id_items(1),
        // subnet_id and fee
        1 + self.node_id.num_items() + 1 + 1
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
            // FIXME: truncated because otherwise it doesn't fit in the
            // 17 character limit for Nano S
            let label = pic_str!(b"RemoveSubnetValid");
            title[..label.len()].copy_from_slice(label);
            let content = pic_str!(b"Transaction");
            return handle_ui_message(content, message, page);
        }

        let item_n = item_n - 1;

        match item_n {
            // render validator info
            0 => self.node_id.render_item(0, title, message, page),

            // render subnet_id
            1 => self.subnet_id.render_item(0, title, message, page),

            // render fee
            2 => {
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

impl<'b> RemoveSubnetValidatorTx<'b> {
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
    use std::prelude::v1::*;

    use crate::parser::snapshots_common::ReducedPage;
    use zuit::Page;

    use super::*;

    include!("testvectors/remove_subnet_validator.rs");

    #[test]
    fn parse_remove_subnet_validator() {
        let (_, tx) = RemoveSubnetValidatorTx::from_bytes(SAMPLE).unwrap();
        assert_eq!(tx.subnet_auth.sig_indices.len(), 1);

        let subnet_id = SubnetId::new(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38,
        ]);

        let (_, tx) = RemoveSubnetValidatorTx::from_bytes(SIMPLE_REMOVE_SUBNET_VALIDATOR).unwrap();
        assert_eq!(tx.subnet_id, subnet_id);
        assert_eq!(tx.subnet_auth.sig_indices.len(), 1);

        let (_, tx) = RemoveSubnetValidatorTx::from_bytes(COMPLEX_REMOVE_SUBNET_VALIDATOR).unwrap();
        assert_eq!(
            tx.base_tx
                .outputs()
                .iter()
                .nth(1)
                .expect("2 outputs")
                .secp_transfer()
                .expect("secp transfer")
                .threshold,
            1
        );
        assert_eq!(tx.subnet_id, subnet_id);
        assert_eq!(tx.subnet_auth.sig_indices.len(), 0);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn ui_remove_subnet_validator() {
        for (i, data) in [
            SAMPLE,
            SIMPLE_REMOVE_SUBNET_VALIDATOR,
            // COMPLEX_REMOVE_SUBNET_VALIDATOR, //sum of inputs overflows u64
        ]
        .iter()
        .enumerate()
        {
            println!(
                "-------------------- Remove Subnet Validator TX #{i} ------------------------"
            );
            let (_, tx) = RemoveSubnetValidatorTx::from_bytes(data).unwrap();

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
