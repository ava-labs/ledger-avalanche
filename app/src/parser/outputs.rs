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

mod nft_mint_output;
mod nft_transfer_output;
mod secp_mint_output;
mod secp_output_owners;
mod secp_transfer_output;
pub use nft_mint_output::NFTMintOutput;
pub use nft_transfer_output::NFTTransferOutput;
pub use secp_mint_output::SECPMintOutput;
pub use secp_output_owners::SECPOutputOwners;
pub use secp_transfer_output::SECPTransferOutput;

use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::number::complete::be_u32;
use zemu_sys::ViewError;

use crate::parser::{error::ParserError, AssetId, DisplayableItem, FromBytes};

#[derive(Clone, Copy, PartialEq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct TransferableOutput<'b> {
    asset_id: AssetId<'b>,
    output: Output<'b>,
}

impl<'b> TransferableOutput<'b> {
    pub fn amount(&self) -> Option<u64> {
        self.output.amount()
    }
}

impl<'b> FromBytes<'b> for TransferableOutput<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("TransferableOutput::from_bytes_into\x00");

        let output = out.as_mut_ptr() as *mut TransferableOutput;
        let asset = unsafe { &mut *addr_of_mut!((*output).asset_id).cast() };
        let rem = AssetId::from_bytes_into(input, asset)?;

        //valid pointer
        let data = unsafe { &mut *addr_of_mut!((*output).output).cast() };
        Output::from_bytes_into(rem, data)
    }
}

impl<'b> DisplayableItem for TransferableOutput<'b> {
    fn num_items(&self) -> usize {
        // the asset_id is not part of the summary we need from objects of this type,
        // but could give to higher level objects information to display such information.
        self.output.num_items()
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        self.output.render_item(item_n as _, title, message, page)
    }
}

// Important: do not change the repr attribute,
// as this type is use as the tag field
// for the Output enum which has the same representation
#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
enum OutputType {
    SECPTransfer,
    SECPMint,
    NFTTransfer,
    NFTMint,
}

impl OutputType {
    fn from_bytes(input: &[u8]) -> Result<(&[u8], Self), nom::Err<ParserError>> {
        let (rem, variant_type) = be_u32(input)?;

        let v = match variant_type {
            SECPTransferOutput::TYPE_ID => Self::SECPTransfer,
            SECPMintOutput::TYPE_ID => Self::SECPMint,

            NFTTransferOutput::TYPE_ID => Self::NFTTransfer,
            NFTMintOutput::TYPE_ID => Self::NFTMint,
            _ => return Err(ParserError::InvalidTypeId.into()),
        };

        Ok((rem, v))
    }
}

#[repr(C)]
struct SECPTransferVariant<'b>(OutputType, SECPTransferOutput<'b>);

#[repr(C)]
struct SECPMintVariant<'b>(OutputType, SECPMintOutput<'b>);

#[repr(C)]
struct NFTTransferVariant<'b>(OutputType, NFTTransferOutput<'b>);

#[repr(C)]
struct NFTMintVariant<'b>(OutputType, NFTMintOutput<'b>);

#[derive(Clone, Copy, PartialEq)]
// DO not change the representation
// as it would cause unalignment issues
// with the OutputType tag
#[repr(u8)]
#[cfg_attr(test, derive(Debug))]
pub enum Output<'b> {
    SECPTransfer(SECPTransferOutput<'b>),
    SECPMint(SECPMintOutput<'b>),
    NFTTransfer(NFTTransferOutput<'b>),
    NFTMint(NFTMintOutput<'b>),
}

impl<'b> Output<'b> {
    pub fn amount(&self) -> Option<u64> {
        match self {
            Self::SECPTransfer(secp) => Some(secp.amount),
            _ => None,
        }
    }
}

impl<'b> FromBytes<'b> for Output<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("Output::from_bytes_into\x00");

        let (rem, variant_type) = OutputType::from_bytes(input)?;
        let rem = match variant_type {
            OutputType::SECPTransfer => {
                let out = out.as_mut_ptr() as *mut SECPTransferVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = SECPTransferOutput::from_bytes_into(rem, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(OutputType::SECPTransfer);
                }

                rem
            }
            OutputType::SECPMint => {
                let out = out.as_mut_ptr() as *mut SECPMintVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = SECPMintOutput::from_bytes_into(rem, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(OutputType::SECPMint);
                }

                rem
            }
            OutputType::NFTTransfer => {
                let out = out.as_mut_ptr() as *mut NFTTransferVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = NFTTransferOutput::from_bytes_into(rem, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(OutputType::NFTTransfer);
                }
                rem
            }
            OutputType::NFTMint => {
                let out = out.as_mut_ptr() as *mut NFTMintVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = NFTMintOutput::from_bytes_into(rem, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(OutputType::NFTMint);
                }
                rem
            }
        };
        Ok(rem)
    }
}

impl<'a> DisplayableItem for Output<'a> {
    fn num_items(&self) -> usize {
        match self {
            Self::SECPTransfer(t) => t.num_items(),
            Self::SECPMint(m) => m.num_items(),
            Self::NFTTransfer(t) => t.num_items(),
            Self::NFTMint(m) => m.num_items(),
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
            Self::SECPMint(m) => m.render_item(item_n, title, message, page),
            Self::NFTTransfer(t) => t.render_item(item_n, title, message, page),
            Self::NFTMint(m) => m.render_item(item_n, title, message, page),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &[u8] = &[
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 0, 0, 0, 0, 1, 22, 54,
        119, 75, 103, 131, 141, 236, 22, 225, 106, 182, 207, 172, 178, 27, 136, 195, 168, 97,
    ];

    #[test]
    fn parse_transferable_output() {
        let t = TransferableOutput::from_bytes(DATA).unwrap().1;
        assert!(matches!(t.output, Output::NFTMint(..)));
    }
}
