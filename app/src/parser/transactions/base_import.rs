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

use bolos::{pic_str, PIC};
use core::{convert::TryFrom, mem::MaybeUninit, ptr::addr_of_mut};
use nom::bytes::complete::take;
use zemu_sys::ViewError;

use crate::{
    constants::chain_alias_lookup,
    handlers::handle_ui_message,
    parser::{
        BaseTxFields, ChainId, DisplayableItem, FromBytes, Header, ObjectList, Output, ParserError,
        TransferableInput, TransferableOutput, BLOCKCHAIN_ID_LEN, MAX_ADDRESS_ENCODED_LEN,
    },
};

const SOURCE_CHAIN_LEN: usize = BLOCKCHAIN_ID_LEN;
const IMPORT_DESCRIPTION_LEN: usize = 8;

// BaseImport<'b, O> represents a transaction that move
// founds to the chain indicated by the BaseTx
// The chainId for which this representation is valid
// are the P and X chain and local. C-Chain defines
// a custom BaseImport<'b, O> type.
#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct BaseImport<'b, O>
where
    O: FromBytes<'b> + DisplayableItem + Deref<Target = Output<'b>> + 'b,
{
    pub tx_header: Header<'b>,
    pub base_tx: BaseTxFields<'b, O>,
    pub source_chain: &'b [u8; 32],
    pub inputs: ObjectList<'b, TransferableInput<'b>>,
}

impl<'b, O> FromBytes<'b> for BaseImport<'b, O>
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

        let (rem, source_chain) = take(SOURCE_CHAIN_LEN)(rem)?;
        let source_chain = arrayref::array_ref!(source_chain, 0, SOURCE_CHAIN_LEN);

        // get chains info
        let header = tx_header.as_ptr();
        let base_chain_id = unsafe { (&*header).chain_id()? };
        let dest_chain_id = ChainId::try_from(source_chain)?;

        // Importing from the same chain is an error
        if dest_chain_id == base_chain_id {
            return Err(ParserError::InvalidTransactionType.into());
        }

        let inputs = unsafe { &mut *addr_of_mut!((*out).inputs).cast() };

        let rem = ObjectList::<TransferableInput>::new_into(rem, inputs)?;

        //good ptr and no uninit reads
        unsafe {
            addr_of_mut!((*out).source_chain).write(source_chain);
        }

        Ok(rem)
    }
}

impl<'b, O> BaseImport<'b, O>
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

    // The objec that holds this base_exports
    // knows the concrete outputs this type contains, that is why
    // we take in a closure to allow the caller to deal with the output it expects.
    // Outputs can be of type Avm, Pvm, and also locked.
    pub fn fee(&'b self) -> Result<u64, ParserError> {
        let inputs = self.sum_inputs_amount()?;
        let outputs = self.base_tx.sum_outputs_amount()?;

        let fee = inputs
            .checked_sub(outputs)
            .ok_or(ParserError::OperationOverflows)?;
        Ok(fee)
    }

    fn sum_inputs_amount(&self) -> Result<u64, ParserError> {
        let base_inputs = self.base_tx.sum_inputs_amount()?;

        let import_inputs = self
            .inputs
            .iter()
            .map(|input| input.amount().ok_or(ParserError::UnexpectedError))
            .try_fold(0u64, |acc, x| {
                acc.checked_add(x?).ok_or(ParserError::OperationOverflows)
            })?;

        import_inputs
            .checked_add(base_inputs)
            .ok_or(ParserError::OperationOverflows)
    }

    // Gets the obj that contain the item_n, along with the index
    // of the item. Returns an error otherwise
    pub fn get_output_with_item(
        &'b self,
        item_n: u8,
    ) -> Result<(TransferableOutput<O>, u8), ViewError> {
        self.base_tx
            .base_output_with_item(item_n)
            .map_err(|_| ViewError::Unknown)
    }

    pub fn num_input_items(&'b self) -> usize {
        self.base_tx.base_outputs_num_items()
    }

    // default render_item implementation that
    // relies on the DisplayableItem trait implementation
    // of the outputs in the base_fields.
    pub fn render_imports(
        &'b self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        let (obj, obj_item_n) = self.get_output_with_item(item_n)?;
        // Base Import/Export only supports secp_transfer types
        let obj = (*obj).secp_transfer().ok_or(ViewError::NoData)?;

        // get the number of items for the obj wrapped up by PvmOutput
        let num_inner_items = obj.num_items() as _;

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

    pub fn render_import_description(
        &self,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        use arrayvec::ArrayString;

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
