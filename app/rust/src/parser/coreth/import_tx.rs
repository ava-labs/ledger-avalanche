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
        coreth::outputs::EVMOutput, nano_avax_to_fp_str, ChainId, DisplayableItem, FromBytes,
        Header, ObjectList, OutputIdx, ParserError, TransferableInput, BLOCKCHAIN_ID_LEN,
        EVM_IMPORT_TX, U64_FORMATTED_SIZE,
    },
};

const SOURCE_CHAIN_LEN: usize = BLOCKCHAIN_ID_LEN;
const IMPORT_DESCRIPTION_LEN: usize = 8;

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct ImportTx<'b> {
    pub tx_header: Header<'b>,
    /// Identified which blockchain the funds come from
    pub source_chain: &'b [u8; SOURCE_CHAIN_LEN],
    pub inputs: ObjectList<'b, TransferableInput<'b>>,
    pub outputs: ObjectList<'b, EVMOutput<'b>>,
    // a bit-wise idx that tells what outputs could be displayed
    // in the ui stage.
    // this is set during the parsing stage.
    renderable_out: OutputIdx,
}

impl<'b> FromBytes<'b> for ImportTx<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("EVMImportTx::from_bytes_into\x00");
        let this = out.as_mut_ptr();

        let (rem, _) = tag(Self::TYPE_ID.to_be_bytes())(input)?;

        // tx header
        let tx_header = unsafe { &mut *addr_of_mut!((*this).tx_header).cast() };
        let rem = Header::from_bytes_into(rem, tx_header)?;
        let (rem, source_chain_id) = take(SOURCE_CHAIN_LEN)(rem)?;
        let source_chain = arrayref::array_ref!(source_chain_id, 0, SOURCE_CHAIN_LEN);
        // get chains info
        let header = tx_header.as_ptr();
        let blockchain_id = unsafe { (*header).chain_id()? };
        let src_id = ChainId::try_from(source_chain)?;

        // Importing from the same chain is an error
        if blockchain_id == src_id {
            return Err(ParserError::InvalidTransactionType.into());
        }

        let inputs = unsafe { &mut *addr_of_mut!((*this).inputs).cast() };
        let rem = ObjectList::<TransferableInput>::new_into(rem, inputs)?;

        // check for the number of outputs before parsing then as now
        // it has to be checked for the outputIdx capacity which is used
        // to tell is an output should be rendered or not.
        let (_, num_outputs) = be_u32(rem)?;

        if num_outputs > OutputIdx::BITS {
            return Err(ParserError::TooManyOutputs.into());
        }
        let outs = unsafe { &mut *addr_of_mut!((*this).outputs).cast() };
        let rem = ObjectList::<EVMOutput>::new_into(rem, outs)?;

        //good ptr and no uninit reads
        unsafe {
            addr_of_mut!((*this).source_chain).write(source_chain);
            // by default all outputs are renderable
            addr_of_mut!((*this).renderable_out).write(OutputIdx::MAX);
        }

        Ok(rem)
    }
}

impl<'b> ImportTx<'b> {
    pub const TYPE_ID: u32 = EVM_IMPORT_TX;

    pub fn disable_output_if(&mut self, address: &[u8]) {
        let num_outs = self.outputs.iter().count();
        // skip filtering out outputs if there is only one
        if num_outs <= 1 {
            return;
        }

        let mut idx = 0;
        let mut render = self.renderable_out;
        self.outputs.iterate_with(|o| {
            // The 99.99% of the outputs contain only one address(best case),
            // In the worse case we just show every output.
            if o.address().raw_address().as_slice() == address {
                render ^= 1 << idx;
            }
            idx += 1;
        });
        self.renderable_out = render;
    }

    fn fee(&self) -> Result<u64, ParserError> {
        let inputs = self.sum_inputs_amount()?;
        let outputs = self.sum_outputs_amount()?;

        let fee = inputs
            .checked_sub(outputs)
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

    pub fn sum_outputs_amount(&self) -> Result<u64, ParserError> {
        self.outputs
            .iter()
            .map(|output| output.amount().ok_or(ParserError::UnexpectedError))
            .try_fold(0u64, |acc, x| {
                acc.checked_add(x?).ok_or(ParserError::OperationOverflows)
            })
    }

    fn num_output_items(&self) -> Result<u8, ViewError> {
        let mut items = 0;
        let mut idx = 0;

        // store an error during execution, specifically
        // if an overflows happens
        let mut err: Option<ViewError> = None;

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

    // use outputs, which contains the amount
    // and the address(es) that will receive the funds
    fn render_imports(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        let mut count = 0usize;
        let mut obj_item_n = 0;
        let mut idx = 0;
        // gets the outputs that contains item_n
        // and its corresponding index
        let filter = |o: &EVMOutput| -> bool {
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
        obj.render_item(obj_item_n, title, message, page)
    }

    fn render_import_description(
        &self,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        use arrayvec::ArrayString;

        let title_content = pic_str!(b"From ");
        title[..title_content.len()].copy_from_slice(title_content);

        // render from where this transaction is receiving funds from
        let mut export_str: ArrayString<IMPORT_DESCRIPTION_LEN> = ArrayString::new();
        let from_alias = chain_alias_lookup(self.source_chain).map_err(|_| ViewError::Unknown)?;

        export_str
            .try_push_str(from_alias)
            .map_err(|_| ViewError::Unknown)?;
        export_str
            .try_push_str(pic_str!(" Chain"))
            .map_err(|_| ViewError::Unknown)?;

        handle_ui_message(export_str.as_bytes(), message, page)
    }
}

impl<'b> DisplayableItem for ImportTx<'b> {
    fn num_items(&self) -> Result<u8, ViewError> {
        //type + number outputs + fee + description
        checked_add!(ViewError::Unknown, 3u8, self.num_output_items()?)
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {

        if item_n == 0 {
            let title_content = pic_str!(b"ImportTx");
            title[..title_content.len()].copy_from_slice(title_content);
            return handle_ui_message(pic_str!(b"Importing in C-Chain"), message, page);
        }

        let outputs_num_items = self.num_output_items()?;
        let new_item_n = item_n - 1;

        match new_item_n {
            x @ 0.. if x < outputs_num_items => self.render_imports(x, title, message, page),
            x if x == outputs_num_items => self.render_import_description(title, message, page),
            x if x == (outputs_num_items + 1) => {
                let title_content = pic_str!(b"Fee");
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
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x9d, 0x07, 0x75, 0xf4, 0x50, 0x60, 0x4b,
        0xd2, 0xfb, 0xc4, 0x9c, 0xe0, 0xc5, 0xc1, 0xc6, 0xdf, 0xeb, 0x2d, 0xc2, 0xac, 0xb8, 0xc9,
        0x2c, 0x26, 0xee, 0xae, 0x6e, 0x6d, 0xf4, 0x50, 0x2b, 0x19, 0xd8, 0x91, 0xad, 0x56, 0x05,
        0x6d, 0x9c, 0x01, 0xf1, 0x8f, 0x43, 0xf5, 0x8b, 0x5c, 0x78, 0x4a, 0xd0, 0x7a, 0x4a, 0x49,
        0xcf, 0x3d, 0x1f, 0x11, 0x62, 0x38, 0x04, 0xb5, 0xcb, 0xa2, 0xc6, 0xbf, 0x00, 0x00, 0x00,
        0x01, 0x66, 0x13, 0xa4, 0x0d, 0xcd, 0xd8, 0xd2, 0x2e, 0xa4, 0xaa, 0x99, 0xa4, 0xc8, 0x43,
        0x49, 0x05, 0x63, 0x17, 0xcf, 0x55, 0x0b, 0x66, 0x85, 0xe0, 0x45, 0xe4, 0x59, 0x95, 0x4f,
        0x25, 0x8e, 0x59, 0x00, 0x00, 0x00, 0x01, 0xdb, 0xcf, 0x89, 0x0f, 0x77, 0xf4, 0x9b, 0x96,
        0x85, 0x76, 0x48, 0xb7, 0x2b, 0x77, 0xf9, 0xf8, 0x29, 0x37, 0xf2, 0x8a, 0x68, 0x70, 0x4a,
        0xf0, 0x5d, 0xa0, 0xdc, 0x12, 0xba, 0x53, 0xf2, 0xdb, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00,
        0x00, 0x74, 0x6a, 0x52, 0x88, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x0e, 0xb5, 0xcc, 0xb8, 0x5c, 0x29, 0x00, 0x9b, 0x60, 0x60, 0xde, 0xcb,
        0x35, 0x3a, 0x38, 0xea, 0x3b, 0x52, 0xcd, 0x20, 0x00, 0x00, 0x00, 0x74, 0x6a, 0x52, 0x88,
        0x00, 0xdb, 0xcf, 0x89, 0x0f, 0x77, 0xf4, 0x9b, 0x96, 0x85, 0x76, 0x48, 0xb7, 0x2b, 0x77,
        0xf9, 0xf8, 0x29, 0x37, 0xf2, 0x8a, 0x68, 0x70, 0x4a, 0xf0, 0x5d, 0xa0, 0xdc, 0x12, 0xba,
        0x53, 0xf2, 0xdb,
    ];

    #[test]
    fn parse_coreth_import_tx() {
        let (rem, tx) = ImportTx::from_bytes(DATA).unwrap();
        assert!(rem.is_empty());
        let count = tx.inputs.iter().count();

        // we know there are 1 inputs
        assert_eq!(count, 1);

        let count = tx.outputs.iter().count();
        // we know there are 1 outputs
        assert_eq!(count, 1);

        let fee = tx.fee().unwrap();
        assert_eq!(fee, 0);
    }

    const DATA2: &[u8] = &[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39, 0x9d, 0x07, 0x75, 0xf4, 0x50, 0x60, 0x4b,
        0xd2, 0xfb, 0xc4, 0x9c, 0xe0, 0xc5, 0xc1, 0xc6, 0xdf, 0xeb, 0x2d, 0xc2, 0xac, 0xb8, 0xc9,
        0x2c, 0x26, 0xee, 0xae, 0x6e, 0x6d, 0xf4, 0x50, 0x2b, 0x19, 0xd8, 0x91, 0xad, 0x56, 0x05,
        0x6d, 0x9c, 0x01, 0xf1, 0x8f, 0x43, 0xf5, 0x8b, 0x5c, 0x78, 0x4a, 0xd0, 0x7a, 0x4a, 0x49,
        0xcf, 0x3d, 0x1f, 0x11, 0x62, 0x38, 0x04, 0xb5, 0xcb, 0xa2, 0xc6, 0xbf, 0x00, 0x00, 0x00,
        0x01, 0xf1, 0xe1, 0xd1, 0xc1, 0xb1, 0xa1, 0x91, 0x81, 0x71, 0x61, 0x51, 0x41, 0x31, 0x21,
        0x11, 0x01, 0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30,
        0x20, 0x10, 0x00, 0x00, 0x00, 0x00, 0x05, 0xdb, 0xcf, 0x89, 0x0f, 0x77, 0xf4, 0x9b, 0x96,
        0x85, 0x76, 0x48, 0xb7, 0x2b, 0x77, 0xf9, 0xf8, 0x29, 0x37, 0xf2, 0x8a, 0x68, 0x70, 0x4a,
        0xf0, 0x5d, 0xa0, 0xdc, 0x12, 0xba, 0x53, 0xf2, 0xdb, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00,
        0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
        0x00, 0xdb, 0xcf, 0x89, 0x0f, 0x77, 0xf4, 0x9b, 0x96, 0x85, 0x76, 0x48, 0xb7, 0x2b, 0x77,
        0xf9, 0xf8, 0x29, 0x37, 0xf2, 0x8a, 0x68, 0x70, 0x4a, 0xf0, 0x5d, 0xa0, 0xdc, 0x12, 0xba,
        0x53, 0xf2, 0xdb,
    ];

    #[test]
    fn parse_coreth_import_tx2() {
        let (rem, tx) = ImportTx::from_bytes(DATA2).unwrap();
        assert!(rem.is_empty());
        let count = tx.inputs.iter().count();

        // we know there are 1 inputs
        assert_eq!(count, 1);

        let count = tx.outputs.iter().count();
        // we know there are 1 outputs
        assert_eq!(count, 1);

        let amount = tx.sum_outputs_amount().unwrap();
        assert_eq!(amount, 268435456);

        let output = tx.outputs.iter().next().unwrap();
        assert_eq!(
            output.asset_id().id(),
            &[
                0xdb, 0xcf, 0x89, 0x0f, 0x77, 0xf4, 0x9b, 0x96, 0x85, 0x76, 0x48, 0xb7, 0x2b, 0x77,
                0xf9, 0xf8, 0x29, 0x37, 0xf2, 0x8a, 0x68, 0x70, 0x4a, 0xf0, 0x5d, 0xa0, 0xdc, 0x12,
                0xba, 0x53, 0xf2, 0xdb,
            ]
        );

        let fee = tx.fee().unwrap();
        assert_eq!(fee, 0);
    }
}
