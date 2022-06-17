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
        PVM_EXPORT_TX,
    },
};

const DESTINATION_CHAIN_LEN: usize = 32;

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

        // need to check that base chain and destination chain are
        // not the same, otherwise, an error should be returned
        let base_ptr = base_tx.as_ptr();
        let base_chain_id = unsafe { (&*base_ptr).network_info()?.chain_id };
        let dest_chain_id = ChainId::try_from(destination_chain)?;
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


#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &[u8] = &[
        0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0,
        1, 244, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 2, 0, 0, 0, 2, 22, 54, 119, 75, 103, 131, 141,
        236, 22, 225, 106, 182, 207, 172, 178, 27, 136, 195, 168, 97, 157, 31, 52, 188, 58, 111,
        35, 6, 202, 7, 144, 22, 174, 248, 92, 19, 23, 103, 242, 56, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 7, 0, 0, 0, 0,
        0, 0, 1, 244, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 2, 0, 0, 0, 2, 22, 54, 119, 75, 103, 131,
        141, 236, 22, 225, 106, 182, 207, 172, 178, 27, 136, 195, 168, 97, 157, 31, 52, 188, 58,
        111, 35, 6, 202, 7, 144, 22, 174, 248, 92, 19, 23, 103, 242, 56, 0, 0, 0, 0, 0, 0, 0, 4,
        109, 101, 109, 111, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
        6, 6, 6, 6, 6, 6, 6, 6, 0, 0, 0, 5, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 1, 244, 0, 0, 0, 0,
        0, 0, 0, 12, 0, 0, 0, 2, 0, 0, 0, 2, 22, 54, 119, 75, 103, 131, 141, 236, 22, 225, 106,
        182, 207, 172, 178, 27, 136, 195, 168, 97, 157, 31, 52, 188, 58, 111, 35, 6, 202, 7, 144,
        22, 174, 248, 92, 19, 23, 103, 242, 56, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 1, 244, 0, 0, 0,
        0, 0, 0, 0, 12, 0, 0, 0, 2, 0, 0, 0, 2, 22, 54, 119, 75, 103, 131, 141, 236, 22, 225, 106,
        182, 207, 172, 178, 27, 136, 195, 168, 97, 157, 31, 52, 188, 58, 111, 35, 6, 202, 7, 144,
        22, 174, 248, 92, 19, 23, 103, 242, 56, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 1, 244, 0, 0, 0,
        0, 0, 0, 0, 12, 0, 0, 0, 2, 0, 0, 0, 2, 22, 54, 119, 75, 103, 131, 141, 236, 22, 225, 106,
        182, 207, 172, 178, 27, 136, 195, 168, 97, 157, 31, 52, 188, 58, 111, 35, 6, 202, 7, 144,
        22, 174, 248, 92, 19, 23, 103, 242, 56, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 1, 244, 0, 0, 0,
        0, 0, 0, 0, 12, 0, 0, 0, 2, 0, 0, 0, 2, 22, 54, 119, 75, 103, 131, 141, 236, 22, 225, 106,
        182, 207, 172, 178, 27, 136, 195, 168, 97, 157, 31, 52, 188, 58, 111, 35, 6, 202, 7, 144,
        22, 174, 248, 92, 19, 23, 103, 242, 56, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 1, 244, 0, 0, 0,
        0, 0, 0, 0, 12, 0, 0, 0, 2, 0, 0, 0, 2, 22, 54, 119, 75, 103, 131, 141, 236, 22, 225, 106,
        182, 207, 172, 178, 27, 136, 195, 168, 97, 157, 31, 52, 188, 58, 111, 35, 6, 202, 7, 144,
        22, 174, 248, 92, 19, 23, 103, 242, 56,
    ];

    #[test]
    fn parse_export_tx() {
        let (rem, tx) = ExportTx::from_bytes(DATA).unwrap();
        assert!(rem.is_empty());
        let count = tx.outputs.iter::<TransferableOutput>().count();

        // we know there are 5 outputs
        assert_eq!(count, 5);

        let count = tx.base_tx.outputs.iter::<TransferableOutput>().count();
        // we know there are 2 outputs
        assert_eq!(count, 2);

        // destination_chain
        assert_eq!(tx.destination_chain, &[6; 32]);
    }
}
