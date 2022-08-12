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
use core::ops::Deref;

use core::{convert::TryFrom, mem::MaybeUninit, ptr::addr_of_mut};
use nom::bytes::complete::take;
use zemu_sys::ViewError;

use crate::{
    constants::chain_alias_lookup,
    handlers::handle_ui_message,
    parser::{
        BaseTxFields, ChainId, DisplayableItem, FromBytes, Header, ObjectList, Output, ParserError,
        TransferableInput, TransferableOutput, BLOCKCHAIN_ID_LEN,
    },
};

pub const DESTINATION_CHAIN_LEN: usize = BLOCKCHAIN_ID_LEN;
const EXPORT_TX_DESCRIPTION_LEN: usize = 13; //X to C Chain

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct BaseExport<'b, O>
where
    O: FromBytes<'b> + DisplayableItem + Deref<Target = Output<'b>> + 'b,
{
    pub tx_header: Header<'b>,
    pub base_tx: BaseTxFields<'b, O>,
    pub destination_chain: &'b [u8; 32],
    pub outputs: ObjectList<'b, TransferableOutput<'b, O>>,
}

impl<'b, O> FromBytes<'b> for BaseExport<'b, O>
where
    O: FromBytes<'b> + DisplayableItem + Deref<Target = Output<'b>> + 'b,
{
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        let out = out.as_mut_ptr();
        // tx header
        let tx_header = unsafe { &mut *addr_of_mut!((*out).tx_header).cast() };
        let rem = Header::from_bytes_into(input, tx_header)?;

        // base_tx
        let base_tx = unsafe { &mut *addr_of_mut!((*out).base_tx).cast() };
        let rem = BaseTxFields::<O>::from_bytes_into(rem, base_tx)?;

        let (rem, destination_chain) = take(DESTINATION_CHAIN_LEN)(rem)?;
        let destination_chain = arrayref::array_ref!(destination_chain, 0, DESTINATION_CHAIN_LEN);

        // get chains info
        let header = tx_header.as_ptr();
        let base_chain_id = unsafe { (&*header).chain_id()? };
        let dest_chain_id = ChainId::try_from(destination_chain)?;

        // Exporting to the same chain is an error
        if dest_chain_id == base_chain_id {
            return Err(ParserError::InvalidTransactionType.into());
        }

        let outputs = unsafe { &mut *addr_of_mut!((*out).outputs).cast() };
        let rem = ObjectList::<TransferableOutput<O>>::new_into(rem, outputs)?;

        //good ptr and no uninit reads
        unsafe {
            addr_of_mut!((*out).destination_chain).write(destination_chain);
        }

        Ok(rem)
    }
}

impl<'b, O> BaseExport<'b, O>
where
    O: FromBytes<'b> + DisplayableItem + Deref<Target = Output<'b>> + 'b,
{
    // Use the info contained in the transaction header
    // to get the corresponding hrp, useful to encode addresses
    pub fn chain_hrp(&self) -> Result<&'static str, ParserError> {
        self.tx_header.hrp()
    }

    pub fn base_inputs(&self) -> &ObjectList<TransferableInput> {
        &self.base_tx.inputs
    }

    pub fn base_outputs(&'b self) -> &ObjectList<TransferableOutput<O>> {
        &self.base_tx.outputs
    }

    pub fn export_outputs(&'b self) -> &ObjectList<TransferableOutput<O>> {
        &self.base_tx.outputs
    }

    pub fn fee(&'b self) -> Result<u64, ParserError> {
        let inputs = self.base_tx.sum_inputs_amount()?;
        let base_outputs = self.base_tx.sum_outputs_amount()?;
        let export_outputs = self.sum_export_outputs_amount()?;
        let total_outputs = base_outputs
            .checked_add(export_outputs)
            .ok_or(ParserError::OperationOverflows)?;

        let fee = inputs
            .checked_sub(total_outputs)
            .ok_or(ParserError::OperationOverflows)?;
        Ok(fee)
    }

    pub fn sum_export_outputs_amount(&'b self) -> Result<u64, ParserError> {
        self.outputs
            .iter()
            .map(|output| output.amount().ok_or(ParserError::UnexpectedError))
            .try_fold(0u64, |acc, x| {
                acc.checked_add(x?).ok_or(ParserError::OperationOverflows)
            })
    }

    // Default implementation similar to "num_items", this relies on the
    // inner objects, but callers might want to filter it
    // out.
    pub fn num_outputs_items(&'b self) -> usize {
        let mut items = 0;
        self.outputs.iterate_with(|o| {
            items += o.num_items();
        });
        items
    }

    // Gets the obj that contain the item_n, along with the index
    // of the item. Returns an error otherwise
    pub fn get_output_with_item(
        &'b self,
        item_n: u8,
    ) -> Result<(TransferableOutput<O>, u8), ViewError> {
        let mut count = 0usize;
        let mut obj_item_n = 0;
        // gets the output that contains item_n
        // and its corresponding index
        let filter = |o: &TransferableOutput<'b, O>| -> bool {
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

        let obj = self.outputs.get_obj_if(filter).ok_or(ViewError::NoData)?;
        Ok((obj, obj_item_n as u8))
    }

    // default render_item implementation that
    // relies on the DisplayableItem trait implementation
    // of the objects in the list.
    pub fn render_outputs(
        &'b self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        let (obj, obj_item_n) = self.get_output_with_item(item_n)?;
        obj.render_item(obj_item_n as u8, title, message, page)
    }

    pub fn render_export_description(
        &self,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        use arrayvec::{ArrayString, ArrayVec};
        use bolos::{pic_str, PIC};

        let title_content = pic_str!(b"Export Tx");
        title[..title_content.len()].copy_from_slice(title_content);

        let to = pic_str!(b" to "!);
        let chain = pic_str!(b" Chain");

        // render from where this transaction is moving founds to
        let mut export_str: ArrayVec<u8, EXPORT_TX_DESCRIPTION_LEN> = ArrayVec::new();

        match self.tx_header.chain_id().map_err(|_| ViewError::Unknown)? {
            ChainId::PChain => export_str.push(b'P'),
            ChainId::XChain => export_str.push(b'X'),
            ChainId::CChain => export_str.push(b'C'),
            _ => return Err(ViewError::Unknown),
        }
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
