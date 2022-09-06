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

use crate::parser::{AssetId, DisplayableItem, FromBytes, UtxoId};

use super::ParserError;

#[derive(Clone, Copy, PartialEq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct TransferableOp<'b> {
    asset_id: AssetId<'b>,
    utx_id: UtxoId<'b>,
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
        let rem = UtxoId::from_bytes_into(rem, utx_id)?;

        let op = unsafe { &mut *addr_of_mut!((*output).operation).cast() };
        let rem = Operation::from_bytes_into(rem, op)?;

        Ok(rem)
    }
}

// Important: do not change the repr attribute,
// as this type is use as the tag field
// for the Operation enum which has the same representation
#[derive(Clone, Copy, PartialEq)]
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

#[derive(Clone, Copy, PartialEq)]
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

impl<'b> FromBytes<'b> for Operation<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("Operation::from_bytes\x00");

        let (rem, id) = be_u32(input)?;
        let op_type = OpType::try_from(id)?;

        let rem = match op_type {
            OpType::SECPMintOp => {
                let out = out.as_mut_ptr() as *mut SECPOpVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = SECPMintOperation::from_bytes_into(rem, data)?;

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

                let rem = NFTMintOperation::from_bytes_into(rem, data)?;

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

                let rem = NFTTransferOperation::from_bytes_into(rem, data)?;

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
