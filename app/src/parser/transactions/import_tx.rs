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

use core::{convert::TryFrom, mem::MaybeUninit, ptr::addr_of_mut};
use nom::{bytes::complete::take, number::complete::be_u32};
use zemu_sys::ViewError;

use crate::{
    constants::chain_alias_lookup,
    handlers::handle_ui_message,
    parser::{
        intstr_to_fpstr_inplace, BaseTx, ChainId, DisplayableItem, FromBytes, ObjectList,
        ParserError, TransferableInput, TransferableOutput, AVM_IMPORT_TX, BLOCKCHAIN_ID_LEN,
        NANO_AVAX_DECIMAL_DIGITS, PVM_IMPORT_TX,
    },
};

const SOURCE_CHAIN_LEN: usize = BLOCKCHAIN_ID_LEN;
const IMPORT_DESCRIPTION_LEN: usize = 7;

// ImportTx represents a transaction that move
// founds to the chain indicated by the BaseTx
// The chainId for which this representation is valid
// are the P and X chain. C-Chain defines
// a custom ImportTx type.
#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct ImportTx<'b> {
    pub type_id: u32,
    pub base_tx: BaseTx<'b>,
    pub source_chain: &'b [u8; 32],
    pub inputs: ObjectList<'b>,
}

impl<'b> FromBytes<'b> for ImportTx<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("ImportTx::from_bytes_into\x00");

        let (rem, type_id) = be_u32(input)?;

        // The ImportTx type is the same for avm and pvm
        // virtual machines. so we need to check if
        // the passed in id corresponds to one of them
        if !(type_id == PVM_IMPORT_TX || type_id == AVM_IMPORT_TX) {
            return Err(ParserError::InvalidTransactionType.into());
        }

        let out = out.as_mut_ptr();
        let base_tx = unsafe { &mut *addr_of_mut!((*out).base_tx).cast() };
        let rem = BaseTx::from_bytes_into(rem, base_tx)?;

        let (rem, source_chain) = take(SOURCE_CHAIN_LEN)(rem)?;
        let source_chain = arrayref::array_ref!(source_chain, 0, SOURCE_CHAIN_LEN);

        // get chains info
        let base_ptr = base_tx.as_ptr();
        let base_chain_id = unsafe { (&*base_ptr).network_info()?.chain_id };
        let dest_chain_id = ChainId::try_from(source_chain)?;

        // check that the transaction type corresponds to the chain it was created from
        match (type_id, base_chain_id) {
            (PVM_IMPORT_TX, ChainId::PChain) | (AVM_IMPORT_TX, ChainId::XChain) => {}
            _ => return Err(ParserError::InvalidTransactionType.into()),
        }

        // Importing from the same chain is an error
        if dest_chain_id == base_chain_id {
            return Err(ParserError::InvalidTransactionType.into());
        }

        let inputs = unsafe { &mut *addr_of_mut!((*out).inputs).cast() };

        let rem = ObjectList::new_into::<TransferableInput>(rem, inputs)?;

        //good ptr and no uninit reads
        unsafe {
            addr_of_mut!((*out).type_id).write(type_id);
            addr_of_mut!((*out).source_chain).write(source_chain);
        }

        Ok(rem)
    }
}

impl<'b> ImportTx<'b> {
    fn fee(&self) -> Result<u64, ParserError> {
        let inputs = self.sum_inputs_amount()?;
        let outputs = self.base_tx.sum_outputs_amount()?;

        let fee = inputs
            .checked_sub(outputs)
            .ok_or(ParserError::OperationOverflows)?;
        Ok(fee)
    }

    fn fee_to_fp_str(&self, out_str: &'b mut [u8]) -> Result<&mut [u8], ParserError> {
        use lexical_core::{write as itoa, Number};

        let fee = self.fee()?;

        // the number plus '0.'
        if out_str.len() < usize::FORMATTED_SIZE_DECIMAL + 2 {
            return Err(ParserError::UnexpectedBufferEnd);
        }

        itoa(fee, out_str);
        intstr_to_fpstr_inplace(out_str, NANO_AVAX_DECIMAL_DIGITS)
            .map_err(|_| ParserError::UnexpectedError)
    }

    fn sum_inputs_amount(&self) -> Result<u64, ParserError> {
        let base_inputs = self.base_tx.sum_inputs_amount()?;

        let import_inputs = self
            .inputs
            .iter::<TransferableInput>()
            .map(|input| {
                if let Ok(input) = input {
                    return input.amount().ok_or(ParserError::UnexpectedError);
                }
                Err(ParserError::UnexpectedError)
            })
            .try_fold(0u64, |acc, x| {
                let x = x?;
                acc.checked_add(x).ok_or(ParserError::OperationOverflows)
            })?;

        import_inputs
            .checked_add(base_inputs)
            .ok_or(ParserError::OperationOverflows)
    }

    fn num_input_items(&self) -> usize {
        self.base_tx
            .outputs
            .iter::<TransferableOutput>()
            .flatten()
            .map(|output| output.num_items())
            .sum()
    }

    // use base.outputs, which contains the amount and address(es)
    // the founds is being received from
    fn render_imports(
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

        let obj = self
            .base_tx
            .outputs
            .iter::<TransferableOutput>()
            .flatten()
            .find(filter)
            .ok_or(ViewError::NoData)?;

        obj.render_item(obj_item_n as u8, title, message, page)
    }

    fn render_import_description(
        &self,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        use arrayvec::ArrayString;
        use bolos::{pic_str, PIC};

        let title_content = pic_str!(b"From ");
        title[..title_content.len()].copy_from_slice(title_content);

        // render from where this transaction is receiving founds to
        let mut export_str: ArrayString<IMPORT_DESCRIPTION_LEN> = ArrayString::new();
        let from_alias = chain_alias_lookup(self.source_chain).map_err(|_| ViewError::Unknown)?;

        export_str.push_str(from_alias);
        export_str.push_str(pic_str!(" Chain"));

        handle_ui_message(export_str.as_bytes(), message, page)
    }
}

impl<'b> DisplayableItem for ImportTx<'b> {
    fn num_items(&self) -> usize {
        // only support SECP256k1 outputs
        // and to keep compatibility with the legacy app,
        // we show only 4 items for each output
        // tx info, amount, address and fee which is the sum of all inputs minus all outputs
        // and the chain description
        1 + self.num_input_items() + 1 + 1
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
            let title_content = pic_str!(b"ImportTx");
            title[..title_content.len()].copy_from_slice(title_content);
            let value_content = pic_str!(b"Sending");
            return handle_ui_message(&value_content[..], message, page);
        }

        let inputs_num_items = self.num_input_items() as u8;
        let new_item_n = item_n - 1;

        match new_item_n {
            x @ 0.. if x < inputs_num_items as u8 => self.render_imports(x, title, message, page),
            x if x == inputs_num_items => self.render_import_description(title, message, page),
            x if x == (inputs_num_items + 1) => {
                let title_content = pic_str!(b"Fee");
                title[..title_content.len()].copy_from_slice(title_content);
                let mut buffer = [0; usize::FORMATTED_SIZE + 2];
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
        0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 237, 95, 56, 52, 30, 67, 110, 93, 70, 226, 187, 0, 180,
        93, 98, 174, 151, 209, 176, 80, 198, 75, 198, 52, 174, 16, 98, 103, 57, 227, 92, 75, 0, 0,
        0, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 39, 16, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 1, 0,
        0, 0, 1, 157, 31, 52, 188, 58, 111, 35, 6, 202, 7, 144, 22, 174, 248, 92, 19, 23, 103, 242,
        56, 0, 0, 0, 1, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 0, 0, 0, 2, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 31, 64, 0, 0, 0, 10,
        0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 58, 0, 0, 0, 1, 0, 0, 0, 79, 0, 0, 0, 65, 0, 0, 0, 87, 0,
        0, 0, 94, 0, 0, 0, 125, 0, 0, 1, 122, 0, 0, 0, 4, 109, 101, 109, 111, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 0, 0, 0, 2, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 31, 64, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0,
        0, 5, 0, 0, 0, 58, 0, 0, 0, 1, 0, 0, 0, 79, 0, 0, 0, 65, 0, 0, 0, 87, 0, 0, 0, 94, 0, 0, 0,
        125, 0, 0, 1, 122,
    ];

    #[test]
    fn parse_import_tx() {
        let (rem, tx) = ImportTx::from_bytes(DATA).unwrap();
        assert!(rem.is_empty());
        let count = tx.inputs.iter::<TransferableInput>().count();

        // we know there are 1 inputs
        assert_eq!(count, 1);

        let count = tx.base_tx.outputs.iter::<TransferableOutput>().count();
        // we know there are 1 outputs
        assert_eq!(count, 1);

        let source_chain = ChainId::try_from(tx.source_chain).unwrap();
        assert_eq!(source_chain, ChainId::PChain);

        let fee = tx.fee().unwrap();
        assert_eq!(fee, 6000);
    }
}
