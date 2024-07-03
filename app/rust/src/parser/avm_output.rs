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

use crate::parser::{
    error::ParserError, DisplayableItem, FromBytes, NFTMintOutput, NFTTransferOutput, Output,
    OutputType, SECPMintOutput, SECPTransferOutput,
};

use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::number::complete::be_u32;
use zemu_sys::ViewError;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct AvmOutput<'b>(pub Output<'b>);

impl<'b> AvmOutput<'b> {
    pub fn amount(&self) -> Option<u64> {
        self.0.amount()
    }
}
impl<'b> Deref for AvmOutput<'b> {
    type Target = Output<'b>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'b> FromBytes<'b> for AvmOutput<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("AvmOutput::from_bytes_into\x00");

        let output = out.as_mut_ptr();
        let data = unsafe { &mut *addr_of_mut!((*output).0).cast() };

        let rem = Self::parse_output_type(input, data)?;
        Ok(rem)
    }
}

impl<'b> AvmOutput<'b> {
    fn parse_output_type(
        input: &'b [u8],
        output: &mut MaybeUninit<Output<'b>>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        let (_, variant_type) = be_u32(input)?;

        let rem = match variant_type {
            SECPTransferOutput::TYPE_ID => {
                Output::from_bytes(input, OutputType::SECPTransfer, output)?
            }

            SECPMintOutput::TYPE_ID => Output::from_bytes(input, OutputType::SECPMint, output)?,
            NFTTransferOutput::TYPE_ID => {
                Output::from_bytes(input, OutputType::NFTTransfer, output)?
            }
            NFTMintOutput::TYPE_ID => Output::from_bytes(input, OutputType::NFTMint, output)?,
            _ => {
                crate::sys::zemu_log_stack("invalid_output_type\x00");
                return Err(ParserError::InvalidTypeId.into());
            }
        };

        Ok(rem)
    }
}

impl<'b> DisplayableItem for AvmOutput<'b> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // the asset_id is not part of the summary we need from objects of this type,
        // but could give to higher level objects information to display such information.
        self.0.num_items()
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        self.0.render_item(item_n as _, title, message, page)
    }
}
