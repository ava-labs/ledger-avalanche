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

mod secp_transfer_input;
pub use secp_transfer_input::SECPTransferInput;

use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::{
    bytes::complete::{tag, take},
    number::complete::{be_u32, be_u64},
    sequence::tuple,
};
use zemu_sys::ViewError;

use crate::{
    checked_add,
    handlers::handle_ui_message,
    parser::{error::ParserError, AssetId, DisplayableItem, FromBytes},
    utils::hex_encode,
};

const TX_ID_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct TransferableInput<'b> {
    tx_id: &'b [u8; TX_ID_LEN],
    utxo_index: u32,
    asset_id: AssetId<'b>,
    // it is set if this TransferableInput
    // contains a stakeable_locked input.
    // althought this apply only to p-chain transactions,
    // in order to reduce code, and because it is the only defined input,
    // we put this here. later can use the output approach of making wrappers,
    // and this type generic over the wrapper in used
    locktime: Option<u64>,
    input: Input<'b>,
}

impl<'b> TransferableInput<'b> {
    pub const LOCKED_INPUT_TAG: u32 = 0x00000015;

    pub fn amount(&self) -> Option<u64> {
        self.input.amount()
    }

    pub fn is_locked(&self) -> bool {
        self.locktime.is_some()
    }

    pub fn locktime(&self) -> Option<u64> {
        self.locktime
    }

    pub fn asset_id(&self) -> &AssetId<'b> {
        &self.asset_id
    }
}

impl<'b> FromBytes<'b> for TransferableInput<'b> {
    #[inline(never)]
    fn from_bytes_into(
        bytes: &'b [u8],
        input: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("TransferableInput::from_bytes_into\x00");

        let (rem, (tx_id, utxo_id)) = tuple((take(TX_ID_LEN), be_u32))(bytes)?;
        let tx_id = arrayref::array_ref!(tx_id, 0, TX_ID_LEN);

        // asset_id
        let input = input.as_mut_ptr();
        let asset = unsafe { &mut *addr_of_mut!((*input).asset_id).cast() };
        let mut rem = AssetId::from_bytes_into(rem, asset)?;

        let mut locktime = None;

        // Check if this is a locked input
        if let Ok((r, _)) = tag::<_, _, ParserError>(Self::LOCKED_INPUT_TAG.to_be_bytes())(rem) {
            let (r, raw_locktime) = be_u64(r)?;
            locktime = Some(raw_locktime);
            rem = r;
        }
        // input
        let data = unsafe { &mut *addr_of_mut!((*input).input).cast() };
        let rem = Input::from_bytes_into(rem, data)?;

        //good ptr and no uninit reads
        unsafe {
            addr_of_mut!((*input).tx_id).write(tx_id);
            addr_of_mut!((*input).utxo_index).write(utxo_id);
            addr_of_mut!((*input).locktime).write(locktime);
        }
        Ok(rem)
    }
}

impl<'b> DisplayableItem for TransferableInput<'b> {
    fn num_items(&self) -> Result<u8, ViewError> {
        checked_add!(
            ViewError::Unknown,
            2u8,
            self.asset_id.num_items()?,
            self.input.num_items()?
        )
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::{
            hash::{Hasher, Sha256},
            pic_str, PIC,
        };
        use lexical_core::{write as itoa, Number};

        let mut buffer = [0; u64::FORMATTED_SIZE_DECIMAL + 2];

        match item_n {
            0 => {
                let title_content = pic_str!(b"TransactionID");
                title[..title_content.len()].copy_from_slice(title_content);
                let sha = Sha256::digest(self.tx_id).map_err(|_| ViewError::Unknown)?;
                let mut hex_buf = [0; Sha256::DIGEST_LEN * 2];
                hex_encode(&sha[..], &mut hex_buf).map_err(|_| ViewError::Unknown)?;

                handle_ui_message(&hex_buf, message, page)
            }
            1 => {
                let title_content = pic_str!(b"Utxo index");
                title[..title_content.len()].copy_from_slice(title_content);
                let buffer = itoa(self.utxo_index, &mut buffer);

                handle_ui_message(buffer, message, page)
            }

            2 => self.asset_id.render_item(0, title, message, page),

            x @ 3.. if x < 3 + self.input.num_items()? => {
                let index = x - 3;
                self.input.render_item(index, title, message, page)
            }
            _ => Err(ViewError::NoData),
        }
    }
}

// Important: do not change the repr attribute,
// as this type is use as the tag field
// for the Input enum which has the same representation
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum InputType {
    SECPTransfer,
}

impl InputType {
    fn from_bytes(input: &[u8]) -> Result<(&[u8], Self), nom::Err<ParserError>> {
        let (rem, variant_type) = be_u32(input)?;

        let v = match variant_type {
            SECPTransferInput::TYPE_ID => Self::SECPTransfer,
            _ => return Err(ParserError::InvalidTypeId.into()),
        };

        Ok((rem, v))
    }
}

#[repr(C)]
struct SECPTransferVariant<'b>(InputType, SECPTransferInput<'b>);

// The documentation states that
// later new input types could be defined
// that is why this type is defined as an enum(holding one variant for now)
// because new variants can be easily added
#[derive(Clone, Copy, PartialEq, Eq)]
// DO not change the representation
// as it would cause unalignment issues
// with the InputType tag
#[repr(u8)]
#[cfg_attr(test, derive(Debug))]
pub enum Input<'b> {
    SECPTransfer(SECPTransferInput<'b>),
}
impl<'b> Input<'b> {
    pub fn amount(&self) -> Option<u64> {
        // follow clippy suggestion,because this enum
        // holds only one variant, if time comes with
        // a new requirement of adding a new variant,
        // we should use a match catchall instead.
        let Self::SECPTransfer(input) = self;
        Some(input.amount)
    }
}

impl<'b> FromBytes<'b> for Input<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("Input::from_bytes_into\x00");

        let (_, variant_type) = InputType::from_bytes(input)?;

        let rem = match variant_type {
            InputType::SECPTransfer => {
                let out = out.as_mut_ptr() as *mut SECPTransferVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = SECPTransferInput::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(InputType::SECPTransfer);
                }
                rem
            }
        };
        Ok(rem)
    }
}

impl<'a> DisplayableItem for Input<'a> {
    fn num_items(&self) -> Result<u8, ViewError> {
        match self {
            Self::SECPTransfer(t) => t.num_items(),
        }
    }

    #[inline(never)]
    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        match self {
            Self::SECPTransfer(t) => t.render_item(item_n, title, message, page),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TransferableInput { tx_id: [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7],
    // utxo_index: 2,
    // asset_id: [8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8],
    // input: SECP256K1TransferInput { type_id: 5, amount: 186, address_indices: [4, 5, 58, 1, 79, 65, 87, 94, 125, 378] } }

    const DATA: &[u8] = &[
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 0, 0, 0, 2, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 186, 0, 0, 0, 10, 0, 0, 0, 4, 0,
        0, 0, 5, 0, 0, 0, 58, 0, 0, 0, 1, 0, 0, 0, 79, 0, 0, 0, 65, 0, 0, 0, 87, 0, 0, 0, 94, 0, 0,
        0, 125, 0, 0, 1, 122,
    ];

    const LOCKED_DATA: &[u8] = &[
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 0, 0, 0, 2, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 0, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0,
        0, 186, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 58, 0, 0, 0, 1, 0, 0, 0, 79, 0, 0, 0,
        65, 0, 0, 0, 87, 0, 0, 0, 94, 0, 0, 0, 125, 0, 0, 1, 122,
    ];

    #[test]
    fn parse_transferable_input() {
        let t = TransferableInput::from_bytes(DATA).unwrap().1;
        assert_eq!(t.tx_id, &[7; TX_ID_LEN]);
        assert_eq!(t.utxo_index, 2);
        assert!(matches!(t.input, Input::SECPTransfer(..)));
    }

    #[test]
    fn parse_transferable_locked_input() {
        let t = TransferableInput::from_bytes(LOCKED_DATA).unwrap().1;
        assert_eq!(t.tx_id, &[7; TX_ID_LEN]);
        assert_eq!(t.utxo_index, 2);
        assert!(matches!(t.input, Input::SECPTransfer(..)));
        assert_eq!(t.locktime.unwrap(), 8);
    }
}
