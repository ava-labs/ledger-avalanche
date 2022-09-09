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
use crate::handlers::handle_ui_message;
use crate::parser::{
    nano_avax_to_fp_str, AvmOutput, BaseTxFields, ChainId, DisplayableItem, FromBytes, Header,
    ObjectList, ParserError, TransferableOp, AVM_OPERATION_TX, MAX_ADDRESS_ENCODED_LEN,
};
use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::bytes::complete::tag;
use zemu_sys::ViewError;

#[derive(Clone, Copy, PartialEq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct OperationTx<'b> {
    pub tx_header: Header<'b>,
    pub base_tx: BaseTxFields<'b, AvmOutput<'b>>,
    pub operations: ObjectList<'b, TransferableOp<'b>>,
}

impl<'b> OperationTx<'b> {
    pub fn disable_output_if(&mut self, address: &[u8]) {
        self.base_tx.disable_output_if(address);
    }

    fn fee(&'b self) -> Result<u64, ParserError> {
        let sum_inputs = self.base_tx.sum_inputs_amount()?;

        let base_outputs = self.base_tx.sum_outputs_amount()?;

        let fee = sum_inputs
            .checked_sub(base_outputs)
            .ok_or(ParserError::OperationOverflows)?;
        Ok(fee)
    }

    fn operation_items(&self) -> usize {
        let mut num_items = 0;
        self.operations.iterate_with(|op| {
            num_items += op.num_items();
        });
        num_items
    }

    fn render_description(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        use bolos::{pic_str, PIC};

        if item_n != 0 {
            return Err(zemu_sys::ViewError::NoData);
        }

        let label = pic_str!(b"Operation");
        title[..label.len()].copy_from_slice(label);
        let content = pic_str!(b"Transaction");
        handle_ui_message(content, message, page)
    }

    pub fn op_with_item(&'b self, item_n: u8) -> Result<(TransferableOp, u8), ParserError> {
        let mut count = 0usize;
        let mut obj_item_n = 0;
        let mut idx = 0;
        // gets the operation that contains item_n
        // and its corresponding index
        let filter = |o: &TransferableOp<'b>| -> bool {
            let n = o.num_items();
            for index in 0..n {
                obj_item_n = index;
                if count == item_n as usize {
                    return true;
                }
                count += 1;
            }
            false
        };

        let obj = self
            .operations
            .get_obj_if(filter)
            .ok_or(ParserError::DisplayIdxOutOfRange)?;

        Ok((obj, obj_item_n as u8))
    }

    fn render_outputs(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        use bolos::{pic_str, PIC};

        let (obj, idx) = self
            .base_tx
            .base_output_with_item(item_n)
            .map_err(|_| ViewError::NoData)?;

        // this is a secp_transfer so it contain
        // 1 item amount
        // x items which is one item for each address
        let num_inner_items = obj.num_items() as _;

        match idx {
            0 => {
                // render using default obj impl
                let res = obj.render_item(0, title, message, page);

                title.iter_mut().for_each(|v| *v = 0);

                // customize the label
                let label = pic_str!(b"Transfer");
                title[..label.len()].copy_from_slice(label);

                res
            }

            x @ 1.. if x < num_inner_items => {
                let addr_idx = x - 1;
                // Operations only supports secp_transfer outputs
                let obj = obj.secp_transfer().ok_or(ViewError::NoData)?;

                let address = obj
                    .get_address_at(addr_idx as usize)
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

            _ => Err(ViewError::NoData),
        }
    }
}

impl<'b> FromBytes<'b> for OperationTx<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("OperationTx::from_bytes_into\x00");

        let (rem, _) = tag(AVM_OPERATION_TX.to_be_bytes())(input)?;

        let out = out.as_mut_ptr();

        // tx header
        let tx_header = unsafe { &mut *addr_of_mut!((*out).tx_header).cast() };
        let rem = Header::from_bytes_into(rem, tx_header)?;

        // This transaction is only valid if comes from XChain
        let chain_id = unsafe { (&*tx_header.as_ptr()).chain_id()? };
        if !matches!(chain_id, ChainId::XChain) {
            return Err(ParserError::InvalidChainId.into());
        }

        // base_tx
        let base_tx = unsafe { &mut *addr_of_mut!((*out).base_tx).cast() };
        let rem = BaseTxFields::<AvmOutput>::from_bytes_into(rem, base_tx)?;

        // operations
        let states = unsafe { &mut *addr_of_mut!((*out).operations).cast() };
        let rem = ObjectList::<TransferableOp>::new_into(rem, states)?;

        Ok(rem)
    }
}

impl<'b> DisplayableItem for OperationTx<'b> {
    fn num_items(&self) -> usize {
        // description +
        1 + self.base_tx.base_outputs_num_items() + self.operation_items() + 1 // fee
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::{pic_str, PIC};
        use lexical_core::Number;

        if item_n == 0 {
            let title_content = pic_str!(b"Operation");
            title[..title_content.len()].copy_from_slice(title_content);

            return handle_ui_message(pic_str!(b"Transaction"), message, page);
        }

        let item_n = item_n - 1;

        let base_items = self.base_tx.base_outputs_num_items() as u8;

        match item_n {
            x @ 0.. if x < base_items => self.render_outputs(item_n, title, message, page),
            x if x >= base_items && x < self.num_items() as u8 - 2 => {
                let x = item_n - base_items;
                let (op, idx) = self.op_with_item(x).map_err(|_| ViewError::NoData)?;
                op.render_item(idx, title, message, page)
            }
            x if x == self.num_items() as u8 - 2 => {
                let title_content = pic_str!(b"Fee(AVAX)");
                title[..title_content.len()].copy_from_slice(title_content);

                let mut buffer = [0; u64::FORMATTED_SIZE_DECIMAL + 2];
                let fee = self.fee().map_err(|_| ViewError::Unknown)?;

                let fee_str =
                    nano_avax_to_fp_str(fee, &mut buffer[..]).map_err(|_| ViewError::Unknown)?;
                handle_ui_message(fee_str, message, page)
            }

            _ => Err(ViewError::NoData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &[u8] = &[
        // base tx:
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0xab, 0x68, 0xeb, 0x1e, 0xe1, 0x42, 0xa0,
        0x5c, 0xfe, 0x76, 0x8c, 0x36, 0xe1, 0x1f, 0x0b, 0x59, 0x6d, 0xb5, 0xa3, 0xc6, 0xc7, 0x7a,
        0xab, 0xe6, 0x65, 0xda, 0xd9, 0xe6, 0x38, 0xca, 0x94, 0xf7, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xd4, 0x31, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x51,
        0x02, 0x5c, 0x61, 0xfb, 0xcf, 0xc0, 0x78, 0xf6, 0x93, 0x34, 0xf8, 0x34, 0xbe, 0x6d, 0xd2,
        0x6d, 0x55, 0xa9, 0x55, 0xc3, 0x34, 0x41, 0x28, 0xe0, 0x60, 0x12, 0x8e, 0xde, 0x35, 0x23,
        0xa2, 0x4a, 0x46, 0x1c, 0x89, 0x43, 0xab, 0x08, 0x59, 0x00, 0x00, 0x00, 0x01, 0xf1, 0xe1,
        0xd1, 0xc1, 0xb1, 0xa1, 0x91, 0x81, 0x71, 0x61, 0x51, 0x41, 0x31, 0x21, 0x11, 0x01, 0xf0,
        0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x07,
        0x5b, 0xcd, 0x15, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x02, 0x03, // number of operations:
        0x00, 0x00, 0x00, 0x01, // transfer operation:
        // assetID:
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, // number of utxoIDs:
        0x00, 0x00, 0x00, 0x01, // txID:
        0xf1, 0xe1, 0xd1, 0xc1, 0xb1, 0xa1, 0x91, 0x81, 0x71, 0x61, 0x51, 0x41, 0x31, 0x21, 0x11,
        0x01, 0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20,
        0x10, 0x00, // utxoIndex:
        0x00, 0x00, 0x00, 0x05, // op:
        0x00, 0x00, 0x00, 0x0d, // number of address indices:
        0x00, 0x00, 0x00, 0x02, // address index 0:
        0x00, 0x00, 0x00, 0x07, // address index 1:
        0x00, 0x00, 0x00, 0x03, // groupID:
        0x00, 0x00, 0x30, 0x39, // length of payload:
        0x00, 0x00, 0x00, 48, // payload:
        0xe8, 0xbf, 0x99, 0xe6, 0x98, 0xaf, 0xe4, 0xbb, 0x80, 0xe4, 0xb9, 0x88, 0xe4, 0xb8, 0x8d,
        0xef, 0xbc, 0x8c, 0xe9, 0x82, 0xa3, 0xe4, 0xb8, 0x8d, 0xe6, 0x98, 0xaf, 0xe6, 0x9d, 0x82,
        0xe5, 0xbf, 0x97, 0xe3, 0x80, 0x82, 0xe9, 0x82, 0xa3, 0xe6, 0x98, 0xaf, 0xe5, 0xad, 0x97,
        0xe5, 0x85, 0xb8, // l,ocktime:
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd4, 0x31, // threshold:
        0x00, 0x00, 0x00, 0x01, // number of addresses:
        0x00, 0x00, 0x00, 0x02, // addrs[0]:
        0x51, 0x02, 0x5c, 0x61, 0xfb, 0xcf, 0xc0, 0x78, 0xf6, 0x93, 0x34, 0xf8, 0x34, 0xbe, 0x6d,
        0xd2, 0x6d, 0x55, 0xa9, 0x55, // addrs[1]:
        0xc3, 0x34, 0x41, 0x28, 0xe0, 0x60, 0x12, 0x8e, 0xde, 0x35, 0x23, 0xa2, 0x4a, 0x46, 0x1c,
        0x89, 0x43, 0xab, 0x08, 0x59,
    ];

    #[test]
    fn parse_operation_tx() {
        let (_, tx) = OperationTx::from_bytes(DATA).unwrap();
    }
}
