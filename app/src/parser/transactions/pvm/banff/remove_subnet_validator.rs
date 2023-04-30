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
    use super::*;

    const DATA: &[u8] = &[
        0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x30, 0x39, 0x3d, 0x0a, 0xd1, 0x2b, 0x8e, 0xe8, 0x92,
        0x8e, 0xdf, 0x24, 0x8c, 0xa9, 0x1c, 0xa5, 0x56, 0x00, 0xfb, 0x38, 0x3f, 0x07, 0xc3, 0x2b,
        0xff, 0x1d, 0x6d, 0xec, 0x47, 0x2b, 0x25, 0xcf, 0x59, 0xa7, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe9, 0x02, 0xa9, 0xa8, 0x66, 0x40, 0xbf, 0xdb,
        0x1c, 0xd0, 0xe3, 0x6c, 0x0c, 0xc9, 0x82, 0xb8, 0x3e, 0x57, 0x65, 0xfa, 0x4a, 0x17, 0x72,
        0x05, 0xdf, 0x5c, 0x29, 0x92, 0x9d, 0x06, 0xdb, 0x9d, 0x94, 0x1f, 0x83, 0xd5, 0xea, 0x98,
        0x5d, 0xe3, 0x02, 0x01, 0x5e, 0x99, 0x25, 0x2d, 0x16, 0x46, 0x9a, 0x66, 0x10, 0xdb, 0x00,
        0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn parse_remove_subnet_validator() {
        let (_, tx) = RemoveSubnetValidatorTx::from_bytes(DATA).unwrap();
        assert_eq!(tx.subnet_auth.sig_indices.len(), 1);
    }
}
