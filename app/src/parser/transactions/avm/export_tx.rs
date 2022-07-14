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
        nano_avax_to_fp_str, AvmOutput, BaseExport, DisplayableItem, FromBytes, ParserError,
        AVM_EXPORT_TX,
    },
};

#[derive(Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct AvmExportTx<'b> {
    pub base_export: BaseExport<'b, AvmOutput<'b>>,
}

impl<'b> FromBytes<'b> for AvmExportTx<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("AvmExportTx::from_bytes_into\x00");

        let (rem, _) = tag(AVM_EXPORT_TX.to_be_bytes())(input)?;

        let out = out.as_mut_ptr();

        // base_export
        let base_export = unsafe { &mut *addr_of_mut!((*out).base_export).cast() };
        let rem = BaseExport::<AvmOutput>::from_bytes_into(rem, base_export)?;

        Ok(rem)
    }
}

impl<'b> DisplayableItem for AvmExportTx<'b> {
    fn num_items(&self) -> usize {
        // only support SECP256k1 outputs
        // and to keep compatibility with the legacy app,
        // we show only 4 items for each output
        // chains info, amount, address and fee which is the sum of all inputs minus all outputs
        1 + self.base_export.num_outputs_items() + 1
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
            return self
                .base_export
                .render_export_description(title, message, page);
        }

        let outputs_num_items = self.base_export.num_outputs_items();
        let new_item_n = item_n - 1;

        match new_item_n {
            x @ 0.. if x < outputs_num_items as u8 => {
                self.base_export.render_outputs(x, title, message, page)
            }
            x if x == outputs_num_items as u8 => {
                let title_content = pic_str!(b"Fee");
                title[..title_content.len()].copy_from_slice(title_content);
                let mut buffer = [0; usize::FORMATTED_SIZE + 2];
                let fee = self.fee().map_err(|_| ViewError::Unknown)?;
                let fee_str =
                    nano_avax_to_fp_str(fee, &mut buffer[..]).map_err(|_| ViewError::Unknown)?;
                handle_ui_message(fee_str, message, page)
            }
            _ => Err(ViewError::NoData),
        }
    }
}

impl<'b> AvmExportTx<'b> {
    pub fn fee(&'b self) -> Result<u64, ParserError> {
        self.base_export.fee()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ChainId;

    const DATA: &[u8] = &[
        0, 0, 0, 4, 0, 0, 0, 1, 237, 95, 56, 52, 30, 67, 110, 93, 70, 226, 187, 0, 180, 93, 98,
        174, 151, 209, 176, 80, 198, 75, 198, 52, 174, 16, 98, 103, 57, 227, 92, 75, 0, 0, 0, 1, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 25, 100, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 1,
        157, 31, 52, 188, 58, 111, 35, 6, 202, 7, 144, 22, 174, 248, 92, 19, 23, 103, 242, 56, 0,
        0, 0, 1, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 0, 0, 0, 2, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 31, 64, 0, 0, 0, 10, 0, 0,
        0, 4, 0, 0, 0, 5, 0, 0, 0, 58, 0, 0, 0, 1, 0, 0, 0, 79, 0, 0, 0, 65, 0, 0, 0, 87, 0, 0, 0,
        94, 0, 0, 0, 125, 0, 0, 1, 122, 0, 0, 0, 4, 109, 101, 109, 111, 4, 39, 212, 178, 42, 42,
        120, 188, 221, 212, 86, 116, 44, 175, 145, 181, 107, 173, 191, 249, 133, 238, 25, 174, 241,
        69, 115, 231, 52, 63, 214, 82, 0, 0, 0, 1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 1, 244, 0, 0,
        0, 0, 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 1, 157, 31, 52, 188, 58, 111, 35, 6, 202, 7, 144,
        22, 174, 248, 92, 19, 23, 103, 242, 56,
    ];

    #[test]
    fn parse_export_tx() {
        let (rem, tx) = AvmExportTx::from_bytes(DATA).unwrap();
        assert!(rem.is_empty());
        let count = tx.base_export.outputs.iter().count();

        // we know there are 1 outputs
        assert_eq!(count, 1);

        let count = tx.base_export.base_tx.outputs.iter().count();
        // we know there are 1 outputs
        assert_eq!(count, 1);

        let base_chain_id = tx.base_export.tx_header.chain_id().unwrap();
        assert_eq!(base_chain_id, ChainId::XChain);

        let fee = tx.fee().unwrap();
        assert_eq!(fee, 1000);
    }
}
