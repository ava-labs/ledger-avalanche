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

use core::{convert::TryFrom, hint::unreachable_unchecked, mem::MaybeUninit, ptr::addr_of_mut};
use nom::{bytes::complete::take, number::complete::be_u32};
use zemu_sys::ViewError;

use crate::{
    constants::chain_alias_lookup,
    handlers::handle_ui_message,
    parser::{
        intstr_to_fpstr_inplace, BaseTx, ChainId, DisplayableItem, FromBytes, ObjectList,
        ParserError, TransferableInput, TransferableOutput, AVM_EXPORT_TX,
        NANO_AVAX_DECIMAL_DIGITS, PVM_EXPORT_TX,
    },
};

const DESTINATION_CHAIN_LEN: usize = 32;
const EXPORT_TX_DESCRIPTION_LEN: usize = 12; //X to C Chain

pub fn check_export_tx_types(tx_type: u32) -> bool {
    // The ExportTx type is the same for avm and pvm
    // virtual machines. so we need to check if
    // the passed in id corresponds to one of these 2 possible
    // transactions.
    tx_type == PVM_EXPORT_TX || tx_type == AVM_EXPORT_TX
}

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct ExportTx<'b> {
    pub type_id: u32,
    pub base_tx: BaseTx<'b>,
    pub destination_chain: &'b [u8; 32],
    pub outputs: ObjectList<'b>,
}

impl<'b> FromBytes<'b> for ExportTx<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("BaseTx::from_bytes_into\x00");

        let (rem, type_id) = be_u32(input)?;
        // double check
        if !check_export_tx_types(type_id) {
            return Err(ParserError::InvalidTransactionType.into());
        }

        let out = out.as_mut_ptr();
        let base_tx = unsafe { &mut *addr_of_mut!((*out).base_tx).cast() };
        let rem = BaseTx::from_bytes_into(rem, base_tx)?;

        let (rem, destination_chain) = take(DESTINATION_CHAIN_LEN)(rem)?;
        let destination_chain = arrayref::array_ref!(destination_chain, 0, DESTINATION_CHAIN_LEN);

        // get chains info
        let base_ptr = base_tx.as_ptr();
        let base_chain_id = unsafe { (&*base_ptr).network_info()?.chain_id };
        let dest_chain_id = ChainId::try_from(destination_chain)?;

        // check that the transaction type corresponds to the chain is was created from
        match (type_id, base_chain_id) {
            (PVM_EXPORT_TX, ChainId::PChain) | (AVM_EXPORT_TX, ChainId::XChain) => {}
            _ => return Err(ParserError::InvalidTransactionType.into()),
        }

        // Exporting to the same chain is an error
        if dest_chain_id == base_chain_id {
            return Err(ParserError::InvalidTransactionType.into());
        }

        let outputs = unsafe { &mut *addr_of_mut!((*out).outputs).cast() };

        let rem = ObjectList::new_into::<TransferableOutput>(rem, outputs)?;

        //good ptr and no uninit reads
        unsafe {
            addr_of_mut!((*out).type_id).write(type_id);
            addr_of_mut!((*out).destination_chain).write(destination_chain);
        }

        Ok(rem)
    }
}

impl<'b> DisplayableItem for ExportTx<'b> {
    fn num_items(&self) -> usize {
        // only support SECP256k1 outputs
        // and to keep compatibility with the legacy app,
        // we show only 4 items for each output
        // chains info, amount, address and fee which is the sum of all inputs minus all outputs
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

impl<'b> ExportTx<'b> {
    fn fee(&self) -> Result<u64, ParserError> {
        let inputs = self.sum_inputs_amount()?;
        let base_outputs = self.sum_base_outputs_amount()?;
        let export_outputs = self.sum_export_outputs_amount()?;
        let total_outputs = base_outputs
            .checked_add(export_outputs)
            .ok_or(ParserError::OperationOverflows)?;

        let fee = inputs
            .checked_sub(total_outputs)
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
        self.base_tx
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
            })
    }

    fn sum_base_outputs_amount(&self) -> Result<u64, ParserError> {
        self.base_tx
            .outputs
            .iter::<TransferableOutput>()
            .map(|output| {
                if let Ok(output) = output {
                    return output.amount().ok_or(ParserError::UnexpectedError);
                }
                Err(ParserError::UnexpectedError)
            })
            .try_fold(0u64, |acc, x| {
                let x = x?;
                acc.checked_add(x).ok_or(ParserError::OperationOverflows)
            })
    }

    fn sum_export_outputs_amount(&self) -> Result<u64, ParserError> {
        self.outputs
            .iter::<TransferableOutput>()
            .map(|output| {
                if let Ok(output) = output {
                    return output.amount().ok_or(ParserError::UnexpectedError);
                }
                Err(ParserError::UnexpectedError)
            })
            .try_fold(0u64, |acc, x| {
                let x = x?;
                acc.checked_add(x).ok_or(ParserError::OperationOverflows)
            })
    }

    fn num_outputs_items(&self) -> usize {
        self.outputs
            .iter::<TransferableOutput>()
            .flatten()
            .map(|output| output.num_items())
            .sum()
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

        let obj = self
            .outputs
            .iter::<TransferableOutput>()
            .flatten()
            .find(filter)
            .ok_or(ViewError::NoData)?;

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
        let from_alias =
            chain_alias_lookup(self.base_tx.blockchain_id).map_err(|_| ViewError::Unknown)?;
        let to_alias =
            chain_alias_lookup(self.destination_chain).map_err(|_| ViewError::Unknown)?;

        // can we use format! or a better alternative
        // would we have problems with PIC because of
        // the literal strings bellow, the assumpion is that
        // it is copied into.
        export_str.push_str(from_alias);
        export_str.push_str(" to ");
        export_str.push_str(to_alias);
        export_str.push_str(" Chain");

        handle_ui_message(export_str.as_bytes(), message, page)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &[u8] = &[
        0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 1, 237, 95, 56, 52, 30, 67, 110, 93, 70, 226, 187, 0, 180,
        93, 98, 174, 151, 209, 176, 80, 198, 75, 198, 52, 174, 16, 98, 103, 57, 227, 92, 75, 0, 0,
        0, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 25, 100, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 1, 0,
        0, 0, 1, 157, 31, 52, 188, 58, 111, 35, 6, 202, 7, 144, 22, 174, 248, 92, 19, 23, 103, 242,
        56, 0, 0, 0, 1, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 0, 0, 0, 2, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 31, 64, 0, 0, 0, 10,
        0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 58, 0, 0, 0, 1, 0, 0, 0, 79, 0, 0, 0, 65, 0, 0, 0, 87, 0,
        0, 0, 94, 0, 0, 0, 125, 0, 0, 1, 122, 0, 0, 0, 4, 109, 101, 109, 111, 4, 39, 212, 178, 42,
        42, 120, 188, 221, 212, 86, 116, 44, 175, 145, 181, 107, 173, 191, 249, 133, 238, 25, 174,
        241, 69, 115, 231, 52, 63, 214, 82, 0, 0, 0, 1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 1, 244,
        0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 1, 157, 31, 52, 188, 58, 111, 35, 6, 202, 7,
        144, 22, 174, 248, 92, 19, 23, 103, 242, 56,
    ];

    #[test]
    fn parse_export_tx() {
        let (rem, tx) = ExportTx::from_bytes(DATA).unwrap();
        assert!(rem.is_empty());
        let count = tx.outputs.iter::<TransferableOutput>().count();

        // we know there are 1 outputs
        assert_eq!(count, 1);

        let count = tx.base_tx.outputs.iter::<TransferableOutput>().count();
        // we know there are 1 outputs
        assert_eq!(count, 1);

        let base_chain = tx.base_tx.network_info().unwrap();
        assert_eq!(base_chain.chain_id, ChainId::XChain);

        let fee = tx.fee().unwrap();
        assert_eq!(fee, 1000);
    }
}
