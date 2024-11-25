use crate::utils::hex_encode;
use crate::{
    handlers::handle_ui_message,
    parser::{
        nano_avax_to_fp_str, BaseTxFields, DisplayableItem, FromBytes, Header, ParserError,
        PvmOutput, PVM_SET_L1_VALIDATOR_WEIGHT,
    },
};
use bolos::PIC;
use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::{
    bytes::complete::{tag, take},
    number::complete::{be_u16, be_u32, be_u64},
};
use zemu_sys::ViewError;
pub const VALIDATION_ID_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct SetL1ValidatorWeightTx<'b> {
    pub tx_header: Header<'b>,
    pub base_tx: BaseTxFields<'b, PvmOutput<'b>>,
    // Addressed Call
    pub codec_id: u16,
    pub type_id: u32,
    pub validation_id: &'b [u8; 32],
    pub nonce: u64,
    pub weight: u64,
}

impl<'b> FromBytes<'b> for SetL1ValidatorWeightTx<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("SetL1ValidatorWeightTx::from_bytes_into\x00");

        let (rem, _) = tag(PVM_SET_L1_VALIDATOR_WEIGHT.to_be_bytes())(input)?;

        let out = out.as_mut_ptr();

        // tx header
        let tx_header = unsafe { &mut *addr_of_mut!((*out).tx_header).cast() };
        let rem = Header::from_bytes_into(rem, tx_header)?;

        // base_tx
        let base_tx = unsafe { &mut *addr_of_mut!((*out).base_tx).cast() };
        let rem = BaseTxFields::<PvmOutput>::from_bytes_into(rem, base_tx)?;

        // codec_id
        let (rem, codec_id) = be_u16(rem)?;

        // type_id
        let (rem, type_id) = be_u32(rem)?;
        if type_id != 3 {
            return Err(nom::Err::Error(ParserError::InvalidTypeId));
        }

        // validation_id
        let (rem, validation_id) = take(32usize)(rem)?;
        let validation_id = arrayref::array_ref!(validation_id, 0, 32);

        // nonce
        let (rem, nonce) = be_u64(rem)?;

        // weight
        let (rem, weight) = be_u64(rem)?;

        unsafe {
            addr_of_mut!((*out).codec_id).write(codec_id);
            addr_of_mut!((*out).validation_id).write(validation_id);
            addr_of_mut!((*out).nonce).write(nonce);
            addr_of_mut!((*out).weight).write(weight);
        }

        Ok(rem)
    }
}

impl<'b> SetL1ValidatorWeightTx<'b> {
    fn fee(&'b self) -> Result<u64, ParserError> {
        let sum_inputs = self.base_tx.sum_inputs_amount()?;

        let base_outputs = self.base_tx.sum_outputs_amount()?;

        let fee = sum_inputs
            .checked_sub(base_outputs)
            .ok_or(ParserError::OperationOverflows)?;
        Ok(fee)
    }
}

impl<'b> DisplayableItem for SetL1ValidatorWeightTx<'b> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // tx_info, validation_id, nonce, weight
        Ok(4u8)
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::pic_str;
        use lexical_core::{write as itoa, Number};
        let mut buffer = [0; u64::FORMATTED_SIZE + 2];

        match item_n {
            0 => {
                let label = pic_str!(b"SetL1ValWeight");
                title[..label.len()].copy_from_slice(label);
                let content = pic_str!(b"Transaction");
                handle_ui_message(content, message, page)
            }
            1 => {
                let prefix = pic_str!(b"0x"!);
                let label = pic_str!(b"Validation ID");
                title[..label.len()].copy_from_slice(label);

                // prefix
                let mut out = [0; VALIDATION_ID_LEN * 2 + 2];
                let mut sz = prefix.len();
                out[..prefix.len()].copy_from_slice(&prefix[..]);

                sz += hex_encode(self.validation_id, &mut out[prefix.len()..])
                    .map_err(|_| ViewError::Unknown)?;

                handle_ui_message(&out[..sz], message, page)
            }
            2 => {
                let label = pic_str!(b"Nonce");
                title[..label.len()].copy_from_slice(label);
                let buffer = itoa(self.nonce, &mut buffer);
                handle_ui_message(buffer, message, page)
            }
            3 => {
                let label = pic_str!(b"Weight");
                title[..label.len()].copy_from_slice(label);
                let buffer = itoa(self.weight, &mut buffer);
                handle_ui_message(buffer, message, page)
            }
            4 => {
                let label = pic_str!(b"Fee(AVAX)");
                title[..label.len()].copy_from_slice(label);

                let fee = self.fee().map_err(|_| ViewError::Unknown)?;
                let fee_buff =
                    nano_avax_to_fp_str(fee, &mut buffer[..]).map_err(|_| ViewError::Unknown)?;

                handle_ui_message(fee_buff, message, page)
            }
            _ => Err(ViewError::NoData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::prelude::v1::*;

    use crate::parser::snapshots_common::ReducedPage;
    use zuit::Page;

    const DATA: &[u8] = &[];

    include!("testvectors/set_l1_validator_weight.rs");
    #[test]
    fn parse_set_l1_validator_weight() {
        let validation_id = &[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let (_, tx) = SetL1ValidatorWeightTx::from_bytes(SET_L1_VALIDATOR_WEIGHT_DATA).unwrap();
        assert_eq!(tx.validation_id, validation_id);
        assert_eq!(tx.nonce, 0x2122232425262728);
        assert_eq!(tx.weight, 0x292a2b2c2d2e2f30);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn ui_set_l1_validator_weight() {
        println!("-------------------- Set L1 Validator Weight TX ------------------------");
        let (_, tx) = SetL1ValidatorWeightTx::from_bytes(SET_L1_VALIDATOR_WEIGHT_DATA).unwrap();

        let items = tx.num_items().expect("Overflow?");

        let mut pages = Vec::<Page<18, 1024>>::with_capacity(items as usize);
        for i in 0..items {
            let mut page = Page::default();

            tx.render_item(i as _, &mut page.title, &mut page.message, 0)
                .unwrap();

            pages.push(page);
        }

        let reduced = pages.iter().map(ReducedPage::from).collect::<Vec<_>>();
        insta::assert_debug_snapshot!(reduced);
    }
}
