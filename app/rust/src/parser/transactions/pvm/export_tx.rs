/*******************************************************************************
*   (c) 2018-2024 Zondax AG
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
    checked_add,
    handlers::handle_ui_message,
    parser::{
        nano_avax_to_fp_str, BaseExport, DisplayableItem, FromBytes, ParserError, PvmOutput,
        PVM_EXPORT_TX,
    },
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct PvmExportTx<'b>(BaseExport<'b, PvmOutput<'b>>);

impl<'b> FromBytes<'b> for PvmExportTx<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("PvmExportTx::from_bytes_into\x00");

        let (rem, _) = tag(PVM_EXPORT_TX.to_be_bytes())(input)?;

        let out = out.as_mut_ptr();

        // base_export
        let base_export = unsafe { &mut *addr_of_mut!((*out).0).cast() };
        let rem = BaseExport::<PvmOutput>::from_bytes_into(rem, base_export)?;
        let base_export = unsafe { &*base_export.as_ptr() };

        // check invariant as for this transaction type
        // outputs can not be locked.
        if base_export
            .base_outputs()
            .iter()
            .any(|transfer| transfer.output.is_locked())
        {
            return Err(ParserError::UnexpectedType.into());
        }
        if base_export
            .export_outputs()
            .iter()
            .any(|transfer| transfer.output.is_locked())
        {
            return Err(ParserError::UnexpectedType.into());
        }

        Ok(rem)
    }
}

impl<'b> DisplayableItem for PvmExportTx<'b> {
    fn num_items(&self) -> Result<u8, ViewError> {
        let outputs = self.0.num_outputs_items()?;

        checked_add!(ViewError::Unknown, 2u8, outputs)
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
            return self.0.render_export_description(title, message, page);
        }

        let outputs_num_items = self.0.num_outputs_items()?;
        let new_item_n = item_n - 1;

        match new_item_n {
            x @ 0.. if x < outputs_num_items => self.0.render_outputs(x, title, message, page),
            x if x == outputs_num_items => {
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

impl<'b> PvmExportTx<'b> {
    pub fn fee(&'b self) -> Result<u64, ParserError> {
        self.0.fee()
    }

    pub fn disable_output_if(&mut self, address: &[u8]) {
        self.0.disable_output_if(address);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ChainId;

    const DATA: &[u8] = &[
        0, 0, 0, 18, 0, 0, 0, 1, 237, 95, 56, 52, 30, 67, 110, 93, 70, 226, 187, 0, 180, 93, 98,
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
        let (rem, tx) = PvmExportTx::from_bytes(DATA).unwrap();
        assert!(rem.is_empty());
        let count = tx.0.export_outputs().iter().count();

        // we know there are 1 outputs
        assert_eq!(count, 1);

        let count = tx.0.base_outputs().iter().count();
        // we know there are 1 outputs
        assert_eq!(count, 1);

        let base_chain = tx.0.tx_header.network_info().unwrap();
        assert_eq!(base_chain.chain_id, ChainId::XChain);

        let fee = tx.fee().unwrap();
        assert_eq!(fee, 1000);
    }
}
