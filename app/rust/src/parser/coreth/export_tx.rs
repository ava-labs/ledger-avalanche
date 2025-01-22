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
use core::{convert::TryFrom, mem::MaybeUninit, ptr::addr_of_mut};
use nom::{
    bytes::complete::{tag, take},
    number::complete::be_u32,
};
use zemu_sys::ViewError;

use crate::{
    checked_add,
    constants::chain_alias_lookup,
    handlers::handle_ui_message,
    parser::{
        nano_avax_to_fp_str, ChainId, DisplayableItem, FromBytes, Header, ObjectList, OutputIdx,
        ParserError, TransferableOutput, BLOCKCHAIN_ID_LEN, EVM_EXPORT_TX, MAX_ADDRESS_ENCODED_LEN,
        U64_FORMATTED_SIZE,
    },
};

use super::{inputs::EVMInput, outputs::EOutput};

const DESTINATION_CHAIN_LEN: usize = BLOCKCHAIN_ID_LEN;
const EXPORT_TX_DESCRIPTION_LEN: usize = 13; //X to C Chain

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct ExportTx<'b> {
    pub tx_header: Header<'b>,
    /// Identified which blockchain the funds go to
    pub destination_chain: &'b [u8; DESTINATION_CHAIN_LEN],
    pub inputs: ObjectList<'b, EVMInput<'b>>,
    pub outputs: ObjectList<'b, TransferableOutput<'b, EOutput<'b>>>,
    // a bit-wise idx that tells what outputs could be displayed
    // in the ui stage.
    // this is set during the parsing stage.
    renderable_out: OutputIdx,
}

impl<'b> FromBytes<'b> for ExportTx<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("EVMExportTx::from_bytes_into\x00");
        let this = out.as_mut_ptr();

        let (rem, _) = tag(Self::TYPE_ID.to_be_bytes())(input)?;

        // tx header
        let tx_header = unsafe { &mut *addr_of_mut!((*this).tx_header).cast() };
        let rem = Header::from_bytes_into(rem, tx_header)?;

        let (rem, destination_chain_id) = take(DESTINATION_CHAIN_LEN)(rem)?;
        let destination_chain =
            arrayref::array_ref!(destination_chain_id, 0, DESTINATION_CHAIN_LEN);

        // get chains info
        let header = tx_header.as_ptr();
        let blockchain_id = unsafe { (*header).chain_id()? };
        let dest_id = ChainId::try_from(destination_chain)?;

        // Exporting to the same chain is an error
        if blockchain_id == dest_id {
            return Err(ParserError::InvalidTransactionType.into());
        }

        let inputs = unsafe { &mut *addr_of_mut!((*this).inputs).cast() };
        let rem = ObjectList::<EVMInput>::new_into(rem, inputs)?;

        // check for the number of outputs before parsing them as now
        // it has to be checked for the outputIdx capacity which is used
        // to tell is an output should be rendered or not.
        let (_, num_outputs) = be_u32(rem)?;

        if num_outputs > OutputIdx::BITS {
            return Err(ParserError::TooManyOutputs.into());
        }

        let outputs = unsafe { &mut *addr_of_mut!((*this).outputs).cast() };
        let rem = ObjectList::<TransferableOutput<EOutput>>::new_into(rem, outputs)?;

        //good ptr and no uninit reads
        unsafe {
            addr_of_mut!((*this).destination_chain).write(destination_chain);
            // by default all outputs are renderable
            addr_of_mut!((*this).renderable_out).write(OutputIdx::MAX);
        }

        Ok(rem)
    }
}

impl<'b> ExportTx<'b> {
    pub const TYPE_ID: u32 = EVM_EXPORT_TX;

    pub fn disable_output_if(&mut self, address: &[u8]) {
        let num_outs = self.outputs.iter().count();
        // skip filtering out outputs if there is only one
        if num_outs <= 1 {
            return;
        }

        let mut idx = 0;
        let mut render = self.renderable_out;

        // outputs is define as an Object List of TransferableOutputs,
        // when parsing transactions we ensure that it is not longer than
        // 64, as we use that value as a limit for the bitwise operation,
        // this ensures that render ^= 1 << idx never overflows.
        self.outputs.iterate_with(|o| {
            // The 99.99% of the outputs contain only one address(best case),
            // In the worse case we just show every output.
            if o.num_addresses() == 1 && o.contain_address(address) {
                render ^= 1 << idx;
            }
            idx += 1;
        });
        self.renderable_out = render;
    }

    fn fee(&self) -> Result<u64, ParserError> {
        let inputs = self.sum_inputs_amount()?;
        let export_outputs = self.sum_outputs_amount()?;

        let fee = inputs
            .checked_sub(export_outputs)
            .ok_or(ParserError::OperationOverflows)?;
        Ok(fee)
    }

    fn fee_to_fp_str(&self, out_str: &'b mut [u8]) -> Result<&mut [u8], ParserError> {

        let fee = self.fee()?;

        // the number plus '0.'
        if out_str.len() < U64_FORMATTED_SIZE + 2 {
            return Err(ParserError::UnexpectedBufferEnd);
        }
        nano_avax_to_fp_str(fee, out_str)
    }

    fn sum_inputs_amount(&self) -> Result<u64, ParserError> {
        self.inputs
            .iter()
            .map(|input| input.amount().ok_or(ParserError::UnexpectedError))
            .try_fold(0u64, |acc, x| {
                acc.checked_add(x?).ok_or(ParserError::OperationOverflows)
            })
    }

    fn sum_outputs_amount(&self) -> Result<u64, ParserError> {
        self.outputs
            .iter()
            .map(|output| output.amount().ok_or(ParserError::UnexpectedError))
            .try_fold(0u64, |acc, x| {
                acc.checked_add(x?).ok_or(ParserError::OperationOverflows)
            })
    }

    fn num_outputs_items(&self) -> Result<u8, ViewError> {
        let mut items = 0;
        let mut idx = 0;

        // store an error during execution, specifically
        // if an overflows happens
        let mut err: Option<ViewError> = None;

        // outputs is defined as an Object List of TransferableOutputs,
        // when parsing transactions we ensure that it is not longer than
        // 64, as we use that value as a limit for the bitwise operation,
        // this ensures that render ^= 1 << idx never overflows.
        self.outputs.iterate_with(|o| {
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

    fn render_outputs(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        let mut count = 0usize;
        let mut obj_item_n = 0;
        // gets the SECPTranfer output that contains item_n
        // and its corresponding index
        let mut idx = 0;

        // gets the output that contains item_n
        // and its corresponding index
        let filter = |o: &TransferableOutput<EOutput>| -> bool {
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

        let obj = self.outputs.get_obj_if(filter).ok_or(ViewError::NoData)?;

        // ETH Import/Export only supports secp_transfer types
        let obj = (*obj).secp_transfer().ok_or(ViewError::NoData)?;

        // get the number of items for Output
        let num_inner_items = obj.num_items()?;

        // do a custom rendering of the first base_output_items
        match obj_item_n {
            0 => {
                // render amount
                obj.render_item(0, title, message, page)
            }
            // address rendering, according to avax team 99.99% of transactions only comes with one
            // address, but we support rendering any
            x @ 1.. if x < num_inner_items => {
                // get the address index
                let address_idx = x - 1;
                let address = obj
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
            _ => Err(ViewError::NoData),
        }
    }

    fn render_export_description(
        &self,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        use arrayvec::ArrayVec;

        let title_content = pic_str!(b"Export Tx");
        title[..title_content.len()].copy_from_slice(title_content);
        let to = pic_str!(b"C to "!);
        let chain = pic_str!(b" Chain");

        // render from where this transaction is moving founds to
        let mut export_str: ArrayVec<u8, EXPORT_TX_DESCRIPTION_LEN> = ArrayVec::new();

        // render from where this transaction is moving founds to
        let to_alias = chain_alias_lookup(self.destination_chain)
            .map(|a| a.as_bytes())
            .map_err(|_| ViewError::Unknown)?;

        export_str
            .try_extend_from_slice(to)
            .map_err(|_| ViewError::Unknown)?;
        export_str
            .try_extend_from_slice(to_alias)
            .map_err(|_| ViewError::Unknown)?;
        export_str
            .try_extend_from_slice(chain)
            .map_err(|_| ViewError::Unknown)?;

        handle_ui_message(&export_str, message, page)
    }
}

impl<'b> DisplayableItem for ExportTx<'b> {
    fn num_items(&self) -> Result<u8, ViewError> {
        //description + number outputs + fee
        checked_add!(ViewError::Unknown, 2u8, self.num_outputs_items()?)
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {

        if item_n == 0 {
            // render export title and network info
            return self.render_export_description(title, message, page);
        }

        let outputs_num_items = self.num_outputs_items()?;
        let new_item_n = item_n - 1;

        match new_item_n {
            x @ 0.. if x < outputs_num_items => self.render_outputs(x, title, message, page),
            x if x == outputs_num_items => {
                let title_content = pic_str!(b"Fee(AVAX)");
                title[..title_content.len()].copy_from_slice(title_content);

                let mut buffer = [0; U64_FORMATTED_SIZE + 2];
                let fee_str = self
                    .fee_to_fp_str(&mut buffer[..])
                    .map_err(|_| ViewError::Unknown)?;
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
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x9d, 0x07, 0x75, 0xf4, 0x50, 0x60, 0x4b,
        0xd2, 0xfb, 0xc4, 0x9c, 0xe0, 0xc5, 0xc1, 0xc6, 0xdf, 0xeb, 0x2d, 0xc2, 0xac, 0xb8, 0xc9,
        0x2c, 0x26, 0xee, 0xae, 0x6e, 0x6d, 0xf4, 0x50, 0x2b, 0x19, 0xd8, 0x91, 0xad, 0x56, 0x05,
        0x6d, 0x9c, 0x01, 0xf1, 0x8f, 0x43, 0xf5, 0x8b, 0x5c, 0x78, 0x4a, 0xd0, 0x7a, 0x4a, 0x49,
        0xcf, 0x3d, 0x1f, 0x11, 0x62, 0x38, 0x04, 0xb5, 0xcb, 0xa2, 0xc6, 0xbf, 0x00, 0x00, 0x00,
        0x01, 0x8d, 0xb9, 0x7c, 0x7c, 0xec, 0xe2, 0x49, 0xc2, 0xb9, 0x8b, 0xdc, 0x02, 0x26, 0xcc,
        0x4c, 0x2a, 0x57, 0xbf, 0x52, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x84, 0x80, 0xdb,
        0xcf, 0x89, 0x0f, 0x77, 0xf4, 0x9b, 0x96, 0x85, 0x76, 0x48, 0xb7, 0x2b, 0x77, 0xf9, 0xf8,
        0x29, 0x37, 0xf2, 0x8a, 0x68, 0x70, 0x4a, 0xf0, 0x5d, 0xa0, 0xdc, 0x12, 0xba, 0x53, 0xf2,
        0xdb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xdb, 0xcf,
        0x89, 0x0f, 0x77, 0xf4, 0x9b, 0x96, 0x85, 0x76, 0x48, 0xb7, 0x2b, 0x77, 0xf9, 0xf8, 0x29,
        0x37, 0xf2, 0x8a, 0x68, 0x70, 0x4a, 0xf0, 0x5d, 0xa0, 0xdc, 0x12, 0xba, 0x53, 0xf2, 0xdb,
        0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x66, 0xf9,
        0x0d, 0xb6, 0x13, 0x7a, 0x78, 0xf7, 0x6b, 0x36, 0x93, 0xf7, 0xf2, 0xbc, 0x50, 0x79, 0x56,
        0xda, 0xe5, 0x63,
    ];

    #[test]
    fn parse_coreth_export_tx() {
        let (rem, tx) = ExportTx::from_bytes(DATA).unwrap();
        assert!(rem.is_empty());

        let count = tx.inputs.iter().count();
        // we know there are 1 inouts
        assert_eq!(count, 1);

        let count = tx.outputs.iter().count();
        // we know there are 1 outputs
        assert_eq!(count, 1);

        let fee = tx.fee().unwrap();
        // 2_000_000 - 1_000_000
        assert_eq!(fee, 1_000_000);
    }

    const DATA2: &[u8] = &[
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x30, 0x39, 0x9d, 0x07, 0x75, 0xf4, 0x50, 0x60, 0x4b,
        0xd2, 0xfb, 0xc4, 0x9c, 0xe0, 0xc5, 0xc1, 0xc6, 0xdf, 0xeb, 0x2d, 0xc2, 0xac, 0xb8, 0xc9,
        0x2c, 0x26, 0xee, 0xae, 0x6e, 0x6d, 0xf4, 0x50, 0x2b, 0x19, 0xd8, 0x91, 0xad, 0x56, 0x05,
        0x6d, 0x9c, 0x01, 0xf1, 0x8f, 0x43, 0xf5, 0x8b, 0x5c, 0x78, 0x4a, 0xd0, 0x7a, 0x4a, 0x49,
        0xcf, 0x3d, 0x1f, 0x11, 0x62, 0x38, 0x04, 0xb5, 0xcb, 0xa2, 0xc6, 0xbf, 0x00, 0x00, 0x00,
        0x01, 0x8d, 0xb9, 0x7c, 0x7c, 0xec, 0xe2, 0x49, 0xc2, 0xb9, 0x8b, 0xdc, 0x02, 0x26, 0xcc,
        0x4c, 0x2a, 0x57, 0xbf, 0x52, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x84, 0x80, 0xdb,
        0xcf, 0x89, 0x0f, 0x77, 0xf4, 0x9b, 0x96, 0x85, 0x76, 0x48, 0xb7, 0x2b, 0x77, 0xf9, 0xf8,
        0x29, 0x37, 0xf2, 0x8a, 0x68, 0x70, 0x4a, 0xf0, 0x5d, 0xa0, 0xdc, 0x12, 0xba, 0x53, 0xf2,
        0xdb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xdb, 0xcf,
        0x89, 0x0f, 0x77, 0xf4, 0x9b, 0x96, 0x85, 0x76, 0x48, 0xb7, 0x2b, 0x77, 0xf9, 0xf8, 0x29,
        0x37, 0xf2, 0x8a, 0x68, 0x70, 0x4a, 0xf0, 0x5d, 0xa0, 0xdc, 0x12, 0xba, 0x53, 0xf2, 0xdb,
        0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x66, 0xf9,
        0x0d, 0xb6, 0x13, 0x7a, 0x78, 0xf7, 0x6b, 0x36, 0x93, 0xf7, 0xf2, 0xbc, 0x50, 0x79, 0x56,
        0xda, 0xe5, 0x63,
    ];

    #[test]
    fn parse_coreth_export_tx2() {
        let (rem, tx) = ExportTx::from_bytes(DATA2).unwrap();
        assert!(rem.is_empty());
        let count = tx.inputs.iter().count();

        // we know there are 1 inputs
        assert_eq!(count, 1);

        let count = tx.outputs.iter().count();
        // we know there are 1 outputs
        assert_eq!(count, 1);

        let amount = tx.sum_outputs_amount().unwrap();
        assert_eq!(amount, 1_000_000);

        let input = tx.inputs.iter().next().unwrap();
        assert_eq!(
            input.asset_id().id(),
            &[
                0xdb, 0xcf, 0x89, 0x0f, 0x77, 0xf4, 0x9b, 0x96, 0x85, 0x76, 0x48, 0xb7, 0x2b, 0x77,
                0xf9, 0xf8, 0x29, 0x37, 0xf2, 0x8a, 0x68, 0x70, 0x4a, 0xf0, 0x5d, 0xa0, 0xdc, 0x12,
                0xba, 0x53, 0xf2, 0xdb,
            ]
        );

        let fee = tx.fee().unwrap();
        // 2_000_000 - 1_000_000
        assert_eq!(fee, 1_000_000);
    }
}
