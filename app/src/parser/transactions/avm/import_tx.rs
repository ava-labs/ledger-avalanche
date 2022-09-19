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

use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::bytes::complete::tag;
use zemu_sys::ViewError;

use crate::{
    handlers::handle_ui_message,
    parser::{
        nano_avax_to_fp_str, AvmOutput, BaseImport, DisplayableItem, FromBytes, ParserError,
        AVM_IMPORT_TX,
    },
};

// AvmImportTx represents a transaction that move
// founds to the chain indicated by the header
// The chainId for which this representation is valid
// are the P and X chain, locals?. C-Chain defines
// a custom AvmImportTx type.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct AvmImportTx<'b>(BaseImport<'b, AvmOutput<'b>>);

impl<'b> FromBytes<'b> for AvmImportTx<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("AvmImportTx::from_bytes_into\x00");

        let (rem, _) = tag(AVM_IMPORT_TX.to_be_bytes())(input)?;

        let out = out.as_mut_ptr();
        let base_import = unsafe { &mut *addr_of_mut!((*out).0).cast() };
        let rem = BaseImport::<AvmOutput>::from_bytes_into(rem, base_import)?;

        Ok(rem)
    }
}

impl<'b> AvmImportTx<'b> {
    pub fn fee(&'b self) -> Result<u64, ParserError> {
        self.0.fee()
    }

    pub fn disable_output_if(&mut self, address: &[u8]) {
        self.0.disable_output_if(address);
    }
}

impl<'b> DisplayableItem for AvmImportTx<'b> {
    fn num_items(&self) -> usize {
        // only support SECP256k1 outputs
        // and to keep compatibility with the legacy app,
        // we show only 4 items for each output
        // tx info, amount, address and fee which is the sum of all inputs minus all outputs
        // and the chain description
        1 + self.0.num_input_items() + 1 + 1
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

        let inputs_num_items = self.0.num_input_items() as u8;
        let new_item_n = item_n - 1;

        match new_item_n {
            x @ 0.. if x < inputs_num_items as u8 => self.0.render_imports(x, title, message, page),
            x if x == inputs_num_items => self.0.render_import_description(title, message, page),
            x if x == (inputs_num_items + 1) => {
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
    use crate::parser::ChainId;
    use core::convert::TryFrom;

    const DATA: &[u8] = &[
        0, 0, 0, 3, 0, 0, 0, 1, 237, 95, 56, 52, 30, 67, 110, 93, 70, 226, 187, 0, 180, 93, 98,
        174, 151, 209, 176, 80, 198, 75, 198, 52, 174, 16, 98, 103, 57, 227, 92, 75, 0, 0, 0, 1, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 39, 16, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 1,
        157, 31, 52, 188, 58, 111, 35, 6, 202, 7, 144, 22, 174, 248, 92, 19, 23, 103, 242, 56, 0,
        0, 0, 1, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 0, 0, 0, 2, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 31, 64, 0, 0, 0, 10, 0, 0,
        0, 4, 0, 0, 0, 5, 0, 0, 0, 58, 0, 0, 0, 1, 0, 0, 0, 79, 0, 0, 0, 65, 0, 0, 0, 87, 0, 0, 0,
        94, 0, 0, 0, 125, 0, 0, 1, 122, 0, 0, 0, 4, 109, 101, 109, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0,
        0, 0, 2, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 31, 64, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 5,
        0, 0, 0, 58, 0, 0, 0, 1, 0, 0, 0, 79, 0, 0, 0, 65, 0, 0, 0, 87, 0, 0, 0, 94, 0, 0, 0, 125,
        0, 0, 1, 122,
    ];

    #[test]
    fn parse_import_tx() {
        let (rem, tx) = AvmImportTx::from_bytes(DATA).unwrap();
        assert!(rem.is_empty());
        let count = tx.0.base_inputs().iter().count();

        // we know there are 1 inputs
        assert_eq!(count, 1);

        let count = tx.0.base_outputs().iter().count();
        // we know there are 1 outputs
        assert_eq!(count, 1);

        let source_chain = ChainId::try_from(tx.0.source_chain).unwrap();
        assert_eq!(source_chain, ChainId::PChain);

        let fee = tx.fee().unwrap();
        assert_eq!(fee, 6000);
    }
}
