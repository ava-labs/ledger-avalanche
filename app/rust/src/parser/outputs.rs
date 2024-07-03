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
use core::ops::Deref;

use crate::parser::{Address, AssetId, DisplayableItem, FromBytes, ParserError};
use crate::sys::ViewError;
use crate::utils::ApduPanic;
use core::{mem::MaybeUninit, ptr::addr_of_mut};

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

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct TransferableOutput<'b, O>
where
    O: FromBytes<'b> + DisplayableItem + Deref<Target = Output<'b>> + 'b,
{
    asset_id: AssetId<'b>,
    pub output: O,
}

impl<'b, O> Deref for TransferableOutput<'b, O>
where
    O: FromBytes<'b> + DisplayableItem + Deref<Target = Output<'b>> + 'b,
{
    type Target = O::Target;

    fn deref(&self) -> &Self::Target {
        &self.output
    }
}

impl<'b, O> TransferableOutput<'b, O>
where
    O: FromBytes<'b> + DisplayableItem + Deref<Target = Output<'b>> + 'b,
{
    pub fn amount(&self) -> Option<u64> {
        (*self.output).amount()
    }

    pub fn asset_id(&self) -> &AssetId<'b> {
        &self.asset_id
    }

    pub fn output(&self) -> &Output<'b> {
        &self.output
    }

    pub fn num_addresses(&self) -> usize {
        self.output().num_addresses()
    }

    // Any output whose address match any of the
    // paths in the change_path list should not be
    // rendered, unless the output contains more
    // than one address, in that case the output
    // would be rendered along with each of its addresses.
    pub fn contain_address(&self, change_address: &[u8]) -> bool {
        let num_address = self.output().num_addresses();
        for idx in 0..num_address {
            let address = self.output().get_address(idx).apdu_unwrap();
            if address.raw_address() == change_address {
                return true;
            }
        }
        false
    }
}

impl<'b, O> FromBytes<'b> for TransferableOutput<'b, O>
where
    O: FromBytes<'b> + DisplayableItem + Deref<Target = Output<'b>> + 'b,
{
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("TransferableOutput::from_bytes_into\x00");

        let output = out.as_mut_ptr();
        //valid pointer
        let asset = unsafe { &mut *addr_of_mut!((*output).asset_id).cast() };
        let rem = AssetId::from_bytes_into(input, asset)?;

        //valid pointer
        let data = unsafe { &mut *addr_of_mut!((*output).output).cast() };
        let rem = O::from_bytes_into(rem, data)?;

        Ok(rem)
    }
}

impl<'b, O> DisplayableItem for TransferableOutput<'b, O>
where
    O: FromBytes<'b> + DisplayableItem + Deref<Target = Output<'b>> + 'b,
{
    fn num_items(&self) -> Result<u8, ViewError> {
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
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
#[repr(u8)]
pub enum OutputType {
    SECPTransfer,
    SECPMint,
    NFTTransfer,
    NFTMint,
    SECPOwners,
}

#[repr(C)]
struct SECPTransferVariant<'b>(OutputType, SECPTransferOutput<'b>);

#[repr(C)]
struct SECPMintVariant<'b>(OutputType, SECPMintOutput<'b>);

#[repr(C)]
struct NFTTransferVariant<'b>(OutputType, NFTTransferOutput<'b>);

#[repr(C)]
struct NFTMintVariant<'b>(OutputType, NFTMintOutput<'b>);

#[repr(C)]
struct SECPOwnersVariant<'b>(OutputType, SECPOutputOwners<'b>);

#[derive(Clone, Copy, PartialEq, Eq)]
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
    SECPOwners(SECPOutputOwners<'b>),
}

impl<'b> Output<'b> {
    pub fn num_addresses(&self) -> usize {
        match self {
            Self::SECPTransfer(t) => t.num_addresses(),
            Self::SECPMint(m) => m.num_addresses(),
            Self::NFTTransfer(t) => t.num_addresses(),
            Self::NFTMint(m) => m.num_addresses(),
            Self::SECPOwners(o) => o.num_addresses(),
        }
    }

    pub fn get_address(&'b self, idx: usize) -> Option<Address<'b>> {
        match self {
            Self::SECPTransfer(t) => t.get_address_at(idx),
            Self::SECPMint(m) => m.get_address_at(idx),
            Self::NFTTransfer(t) => t.get_address_at(idx),
            Self::NFTMint(m) => m.get_address_at(idx),
            Self::SECPOwners(o) => o.get_address_at(idx),
        }
    }

    pub fn secp_transfer(&self) -> Option<&SECPTransferOutput> {
        if let Self::SECPTransfer(ref secp) = self {
            Some(secp)
        } else {
            None
        }
    }
    pub fn amount(&self) -> Option<u64> {
        match self {
            Self::SECPTransfer(secp) => Some(secp.amount),
            _ => None,
        }
    }

    #[inline(never)]
    pub fn from_bytes(
        input: &'b [u8],
        variant: OutputType,
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("Output::from_bytes\x00");

        let rem = match variant {
            OutputType::SECPTransfer => {
                let out = out.as_mut_ptr() as *mut SECPTransferVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = SECPTransferOutput::from_bytes_into(input, data)?;

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

                let rem = SECPMintOutput::from_bytes_into(input, data)?;

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

                let rem = NFTTransferOutput::from_bytes_into(input, data)?;

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

                let rem = NFTMintOutput::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(OutputType::NFTMint);
                }
                rem
            }
            OutputType::SECPOwners => {
                let out = out.as_mut_ptr() as *mut SECPOwnersVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = SECPOutputOwners::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(OutputType::SECPOwners);
                }

                rem
            }
        };
        Ok(rem)
    }
}

impl<'a> DisplayableItem for Output<'a> {
    fn num_items(&self) -> Result<u8, ViewError> {
        match self {
            Self::SECPTransfer(t) => t.num_items(),
            Self::SECPMint(m) => m.num_items(),
            Self::NFTTransfer(t) => t.num_items(),
            Self::NFTMint(m) => m.num_items(),
            Self::SECPOwners(o) => o.num_items(),
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
            Self::SECPOwners(o) => o.render_item(item_n, title, message, page),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{AvmOutput, PvmOutput};

    const DATA: &[u8] = &[
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 0, 0, 0, 0, 1, 22, 54,
        119, 75, 103, 131, 141, 236, 22, 225, 106, 182, 207, 172, 178, 27, 136, 195, 168, 97,
    ];

    const LOCKED_OUTPUT: &[u8] = &[
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x0, 0x0, 0x0, 0x8, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x01, 0xd1, 0xa9, 0x4a, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x3c, 0xb7, 0xd3, 0x84, 0x2e,
        0x8c, 0xee, 0x6a, 0x0e, 0xbd, 0x09, 0xf1, 0xfe, 0x88, 0x4f, 0x68, 0x61, 0xe1, 0xb2, 0x9c,
    ];

    #[test]
    fn parse_transferable_output_pvm_output() {
        let res = TransferableOutput::<PvmOutput>::from_bytes(DATA);
        // should faild as output for pvm only support secp_transfer and owners
        assert!(res.is_err());
    }

    #[test]
    fn parse_locked_output() {
        let output = TransferableOutput::<PvmOutput>::from_bytes(LOCKED_OUTPUT)
            .unwrap()
            .1;
        assert_eq!(output.output.locktime.unwrap(), 8);
    }

    #[test]
    fn parse_transferable_output_avm_output() {
        let t = TransferableOutput::<AvmOutput>::from_bytes(DATA).unwrap().1;
        assert!(matches!(t.output.0, Output::NFTMint(..)));
    }
}
