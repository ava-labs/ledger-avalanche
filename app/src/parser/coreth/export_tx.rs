/*******************************************************************************
*   (c) 2022 Zondax AG
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

use core::{
    convert::TryFrom,
    mem::MaybeUninit,
    ptr::{addr_of, addr_of_mut},
};
use nom::{
    bytes::complete::{tag, take},
    number::complete::be_u32,
};
use zemu_sys::ViewError;

use crate::{
    constants::chain_alias_lookup,
    handlers::handle_ui_message,
    parser::{
        intstr_to_fpstr_inplace, ChainId, DisplayableItem, FromBytes, ObjectList, Output,
        ParserError, TransferableOutput, BLOCKCHAIN_ID_LEN, EVM_EXPORT_TX,
        NANO_AVAX_DECIMAL_DIGITS,
    },
    utils::ApduPanic,
};

use super::inputs::EVMInput;

const DESTINATION_CHAIN_LEN: usize = BLOCKCHAIN_ID_LEN;
const EXPORT_TX_DESCRIPTION_LEN: usize = 12; //X to C Chain

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct ExportTx<'b> {
    pub network_id: u32,
    /// Identifies which blockchain this transaction was issued to
    pub blockchain_id: &'b [u8; BLOCKCHAIN_ID_LEN],
    /// Identified which blockchain the funds go to
    pub destination_chain: &'b [u8; DESTINATION_CHAIN_LEN],
    pub inputs: ObjectList<'b, EVMInput<'b>>,
    pub outputs: ObjectList<'b, TransferableOutput<'b>>,
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

        let (rem, network_id) = be_u32(rem)?;

        let (rem, blockchain_id) = take(BLOCKCHAIN_ID_LEN)(rem)?;
        let blockchain = arrayref::array_ref!(blockchain_id, 0, BLOCKCHAIN_ID_LEN);

        let (rem, destination_chain_id) = take(DESTINATION_CHAIN_LEN)(rem)?;
        let destination_chain =
            arrayref::array_ref!(destination_chain_id, 0, DESTINATION_CHAIN_LEN);

        // Exporting to the same chain is an error
        if blockchain_id == destination_chain_id {
            return Err(ParserError::InvalidTransactionType.into());
        }

        let inputs = unsafe { &mut *addr_of_mut!((*this).inputs).cast() };
        let rem = ObjectList::<EVMInput>::new_into(rem, inputs)?;

        let outputs = unsafe { &mut *addr_of_mut!((*this).outputs).cast() };
        let rem = ObjectList::<TransferableOutput>::new_into(rem, outputs)?;

        //verify that all outputs are Secp256K1TransferOutput
        {
            let outputs: &ObjectList<TransferableOutput> = unsafe {
                addr_of!((*this).outputs)
                    .cast::<MaybeUninit<_>>()
                    .as_ref()
                    //we know the pointer is good
                    .apdu_unwrap()
                    .assume_init_ref()
            };

            if outputs
                .iter()
                .any(|output| !matches!(output.output(), Output::SECPTransfer(_)))
            {
                return Err(ParserError::InvalidTransactionType.into());
            }
        }

        //good ptr and no uninit reads
        unsafe {
            addr_of_mut!((*this).network_id).write(network_id);
            addr_of_mut!((*this).blockchain_id).write(blockchain);
            addr_of_mut!((*this).destination_chain).write(destination_chain);
        }

        Ok(rem)
    }
}

impl<'b> ExportTx<'b> {
    pub const TYPE_ID: u32 = EVM_EXPORT_TX;

    fn fee(&self) -> Result<u64, ParserError> {
        let inputs = self.sum_inputs_amount()?;
        let export_outputs = self.sum_outputs_amount()?;

        let fee = inputs
            .checked_sub(export_outputs)
            .ok_or(ParserError::OperationOverflows)?;
        Ok(fee)
    }

    fn fee_to_fp_str(&self, out_str: &'b mut [u8]) -> Result<&mut [u8], ParserError> {
        use lexical_core::{write as itoa, Number};

        let fee = self.fee()?;

        // the number plus '0.'
        if out_str.len() < u64::FORMATTED_SIZE_DECIMAL + 2 {
            return Err(ParserError::UnexpectedBufferEnd);
        }

        itoa(fee, out_str);
        intstr_to_fpstr_inplace(out_str, NANO_AVAX_DECIMAL_DIGITS)
            .map_err(|_| ParserError::UnexpectedError)
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

    fn num_outputs_items(&self) -> usize {
        self.outputs.iter().map(|output| output.num_items()).sum()
    }

    fn render_outputs(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        let mut count = 0usize;
        let mut obj_item_n = 0;
        // gets the SECPTranfer output that contains item_n
        // and its corresponding index
        let filter = |o: &TransferableOutput| -> bool {
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

        let obj = self.outputs.iter().find(filter).ok_or(ViewError::NoData)?;

        obj.render_item(obj_item_n as u8, title, message, page)
    }

    fn render_export_description(
        &self,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        use arrayvec::ArrayString;
        use bolos::{pic_str, PIC};

        let title_content = pic_str!(b"Export Tx");
        title[..title_content.len()].copy_from_slice(title_content);

        // render from where this transaction is moving founds to
        let mut export_str: ArrayString<EXPORT_TX_DESCRIPTION_LEN> = ArrayString::new();
        let to_alias =
            chain_alias_lookup(self.destination_chain).map_err(|_| ViewError::Unknown)?;

        export_str.push_str(pic_str!("C to "!));
        export_str.push_str(to_alias);
        export_str.push_str(pic_str!(" Chain"!));

        handle_ui_message(export_str.as_bytes(), message, page)
    }
}

impl<'b> DisplayableItem for ExportTx<'b> {
    fn num_items(&self) -> usize {
        //description + number outputs + fee
        1 + self.num_outputs_items() + 1
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
            // render export title and network info
            return self.render_export_description(title, message, page);
        }

        let outputs_num_items = self.num_outputs_items();
        let new_item_n = item_n - 1;

        match new_item_n {
            x @ 0.. if x < outputs_num_items as u8 => self.render_outputs(x, title, message, page),
            x if x == outputs_num_items as u8 => {
                let title_content = pic_str!(b"Fee");
                title[..title_content.len()].copy_from_slice(title_content);

                let mut buffer = [0; u64::FORMATTED_SIZE_DECIMAL + 2];
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
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x91, 0x06, 0x0e, 0xab, 0xfb, 0x5a, 0x57,
        0x17, 0x20, 0x10, 0x9b, 0x58, 0x96, 0xe5, 0xff, 0x00, 0x01, 0x0a, 0x1c, 0xfe, 0x6b, 0x10,
        0x3d, 0x58, 0x5e, 0x6e, 0xbf, 0x27, 0xb9, 0x7a, 0x17, 0x35, 0xd8, 0x91, 0xad, 0x56, 0x05,
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
        assert_eq!(fee, 0);
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
        assert_eq!(amount, 10_000);

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
        assert_eq!(fee, 1_000);
    }
}
