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
        ParserError, TransferableInput, TransferableOutput, AVM_IMPORT_TX, BLOCKCHAIN_ID_LEN,
        NANO_AVAX_DECIMAL_DIGITS, PVM_IMPORT_TX,
    },
};

const SOURCE_CHAIN_LEN: usize = BLOCKCHAIN_ID_LEN;

pub fn check_import_tx_types(tx_type: u32) -> bool {
    // The ExportTx type is the same for avm and pvm
    // virtual machines. so we need to check if
    // the passed in id corresponds to one of these 2 possible
    // transactions.
    tx_type == PVM_IMPORT_TX || tx_type == AVM_IMPORT_TX
}

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
        crate::sys::zemu_log_stack("BaseTx::from_bytes_into\x00");

        let (rem, type_id) = be_u32(input)?;
        // double check
        if !check_import_tx_types(type_id) {
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

        // check that the transaction type corresponds to the chain is was created from
        match (type_id, base_chain_id) {
            (PVM_IMPORT_TX, ChainId::PChain) | (AVM_IMPORT_TX, ChainId::XChain) => {}
            _ => return Err(ParserError::InvalidTransactionType.into()),
        }

        // Exporting to the same chain is an error
        if dest_chain_id == base_chain_id {
            return Err(ParserError::InvalidTransactionType.into());
        }

        let inputs = unsafe { &mut *addr_of_mut!((*out).inputs).cast() };

        let rem = ObjectList::new_into::<TransferableOutput>(rem, inputs)?;

        //good ptr and no uninit reads
        unsafe {
            addr_of_mut!((*out).type_id).write(type_id);
            addr_of_mut!((*out).source_chain).write(source_chain);
        }

        Ok(rem)
    }
}
