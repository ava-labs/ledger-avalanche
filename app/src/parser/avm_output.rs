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

#[derive(Clone, Copy, PartialEq)]
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
        let variant_type = Self::parse_output_type(input)?;
        let out = out.as_mut_ptr();
        //valid pointer
        let data = unsafe { &mut *addr_of_mut!((*out).0).cast() };
        let rem = Output::from_bytes(input, variant_type, data)?;
        Ok(rem)
    }
}

impl<'b> AvmOutput<'b> {
    fn parse_output_type(input: &[u8]) -> Result<OutputType, nom::Err<ParserError>> {
        let (_, variant_type) = be_u32(input)?;

        let v = match variant_type {
            SECPTransferOutput::TYPE_ID => OutputType::SECPTransfer,
            SECPMintOutput::TYPE_ID => OutputType::SECPMint,

            NFTTransferOutput::TYPE_ID => OutputType::NFTTransfer,
            NFTMintOutput::TYPE_ID => OutputType::NFTMint,
            _ => return Err(ParserError::InvalidTypeId.into()),
        };

        Ok(v)
    }
}

impl<'b> DisplayableItem for AvmOutput<'b> {
    fn num_items(&self) -> usize {
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
