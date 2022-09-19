/*******************************************************************************
*   (c) 2018 - 2022 Zondax AG
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

mod nft_mint_operation;
mod nft_transfer_operation;
mod secp_mint_operation;

pub use nft_mint_operation::NFTMintOperation;
pub use nft_transfer_operation::NFTTransferOperation;
use nom::number::complete::be_u32;
pub use secp_mint_operation::SECPMintOperation;

use core::convert::TryFrom;
use core::{mem::MaybeUninit, ptr::addr_of_mut};

use crate::handlers::handle_ui_message;
use crate::parser::{AssetId, DisplayableItem, FromBytes, ObjectList, UtxoId};

use super::ParserError;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct TransferableOp<'b> {
    asset_id: AssetId<'b>,
    utx_id: ObjectList<'b, UtxoId<'b>>,
    operation: Operation<'b>,
}

impl<'b> FromBytes<'b> for TransferableOp<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("TransferableOp::from_bytes\x00");
        let output = out.as_mut_ptr();

        let asset = unsafe { &mut *addr_of_mut!((*output).asset_id).cast() };
        let rem = AssetId::from_bytes_into(input, asset)?;

        let utx_id = unsafe { &mut *addr_of_mut!((*output).utx_id).cast() };
        let rem = ObjectList::<UtxoId>::new_into(rem, utx_id)?;

        let op = unsafe { &mut *addr_of_mut!((*output).operation).cast() };
        let rem = Operation::from_bytes_into(rem, op)?;

        Ok(rem)
    }
}

impl<'b> DisplayableItem for TransferableOp<'b> {
    fn num_items(&self) -> usize {
        self.operation.num_items()
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        self.operation.render_item(item_n, title, message, page)
    }
}

// Important: do not change the repr attribute,
// as this type is use as the tag field
// for the Operation enum which has the same representation
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
#[repr(u8)]
pub enum OpType {
    SECPMintOp,
    NFTTransferOp,
    NFTMintOp,
}

impl TryFrom<u32> for OpType {
    type Error = ParserError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        let t = match value {
            SECPMintOperation::TYPE_ID => Self::SECPMintOp,
            NFTMintOperation::TYPE_ID => Self::NFTMintOp,
            NFTTransferOperation::TYPE_ID => Self::NFTTransferOp,
            _ => return Err(ParserError::InvalidTypeId),
        };
        Ok(t)
    }
}

#[repr(C)]
struct SECPOpVariant<'b>(OpType, SECPMintOperation<'b>);

#[repr(C)]
struct NFTMintOpVariant<'b>(OpType, NFTMintOperation<'b>);

#[repr(C)]
struct NFTTransferOpVariant<'b>(OpType, NFTTransferOperation<'b>);

#[derive(Clone, Copy, PartialEq, Eq)]
// DO not change the representation
// as it would cause unalignment issues
// with the OutputType tag
#[repr(u8)]
#[cfg_attr(test, derive(Debug))]
pub enum Operation<'b> {
    SECPMint(SECPMintOperation<'b>),
    NFTTransfer(NFTTransferOperation<'b>),
    NFTMint(NFTMintOperation<'b>),
}

impl<'b> Operation<'b> {
    pub fn operation_name(&self) -> &'static str {
        use bolos::{pic_str, PIC};

        match self {
            Operation::SECPMint(_) => pic_str!("SECPMintOperation"),
            Operation::NFTTransfer(_) => pic_str!("NFTTransferOperation"),
            Operation::NFTMint(_) => pic_str!("NFTMintOperation"),
        }
    }
}

impl<'b> FromBytes<'b> for Operation<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("Operation::from_bytes\x00");

        let (_, id) = be_u32(input)?;
        let op_type = OpType::try_from(id)?;

        let rem = match op_type {
            OpType::SECPMintOp => {
                let out = out.as_mut_ptr() as *mut SECPOpVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = SECPMintOperation::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(op_type);
                }

                rem
            }
            OpType::NFTMintOp => {
                let out = out.as_mut_ptr() as *mut NFTMintOpVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = NFTMintOperation::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(op_type);
                }

                rem
            }
            OpType::NFTTransferOp => {
                let out = out.as_mut_ptr() as *mut NFTTransferOpVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = NFTTransferOperation::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(op_type);
                }

                rem
            }
        };
        Ok(rem)
    }
}

impl<'b> DisplayableItem for Operation<'b> {
    fn num_items(&self) -> usize {
        // operation description
        // + operation items
        1 + match self {
            Operation::NFTMint(op) => op.num_items(),
            Operation::NFTTransfer(op) => op.num_items(),
            Operation::SECPMint(op) => op.num_items(),
        }
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        use bolos::{pic_str, PIC};

        if item_n == 0 {
            let title_content = pic_str!(b"Op. Type:");
            title[..title_content.len()].copy_from_slice(title_content);

            let op_type = self.operation_name();

            return handle_ui_message(op_type.as_bytes(), message, page);
        }

        let item_n = item_n - 1;

        match self {
            Operation::NFTMint(op) => op.render_item(item_n, title, message, page),
            Operation::NFTTransfer(op) => op.render_item(item_n, title, message, page),
            Operation::SECPMint(op) => op.render_item(item_n, title, message, page),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &[u8] = &[
        // assetID:
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, // number of utxoIDs:
        0x00, 0x00, 0x00, 0x01, // txID:
        0xf1, 0xe1, 0xd1, 0xc1, 0xb1, 0xa1, 0x91, 0x81, 0x71, 0x61, 0x51, 0x41, 0x31, 0x21, 0x11,
        0x01, 0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20,
        0x10, 0x00, // utxoIndex:
        0x00, 0x00, 0x00, 0x05, // op:
        0x00, 0x00, 0x00, 0x0d, // number of address indices:
        0x00, 0x00, 0x00, 0x02, // address index 0:
        0x00, 0x00, 0x00, 0x07, // address index 1:
        0x00, 0x00, 0x00, 0x03, // groupID:
        0x00, 0x00, 0x30, 0x39, // length of payload:
        0x00, 0x00, 0x00, 0x03, // payload:
        0x43, 0x11, 0x00, // locktime:
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd4, 0x31, // threshold:
        0x00, 0x00, 0x00, 0x01, // number of addresses:
        0x00, 0x00, 0x00, 0x02, // addrs[0]:
        0x51, 0x02, 0x5c, 0x61, 0xfb, 0xcf, 0xc0, 0x78, 0xf6, 0x93, 0x34, 0xf8, 0x34, 0xbe, 0x6d,
        0xd2, 0x6d, 0x55, 0xa9, 0x55, // addrs[1]:
        0xc3, 0x34, 0x41, 0x28, 0xe0, 0x60, 0x12, 0x8e, 0xde, 0x35, 0x23, 0xa2, 0x4a, 0x46, 0x1c,
        0x89, 0x43, 0xab, 0x08, 0x59,
    ];

    #[test]
    fn parse_transferable_operation() {
        let op = TransferableOp::from_bytes(DATA).unwrap().1;
        assert!(matches!(op.operation, Operation::NFTTransfer(..)));
    }
}
