/*******************************************************************************
*   (c) 2022 Zondax AG
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

use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::number::complete::{be_u32, be_u64};
use zemu_sys::ViewError;

use crate::{
    handlers::handle_ui_message,
    parser::{
        error::ParserError, Address, AssetId, DisplayableItem, FromBytes, Output, OutputType,
        SECPTransferOutput,
    },
};

// Wrapper for the Output type
#[derive(Clone, Copy, PartialEq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct EOutput<'b>(pub Output<'b>);

impl<'b> EOutput<'b> {
    pub fn amount(&self) -> Option<u64> {
        self.0.amount()
    }
}

impl<'b> Deref for EOutput<'b> {
    type Target = Output<'b>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'b> FromBytes<'b> for EOutput<'b> {
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

impl<'b> EOutput<'b> {
    fn parse_output_type(input: &[u8]) -> Result<OutputType, nom::Err<ParserError>> {
        let (_, variant_type) = be_u32(input)?;

        // Coreth only supports the SECPTransferOutput variant
        let v = match variant_type {
            SECPTransferOutput::TYPE_ID => OutputType::SECPTransfer,
            _ => return Err(ParserError::InvalidTypeId.into()),
        };

        Ok(v)
    }
}

impl<'b> DisplayableItem for EOutput<'b> {
    fn num_items(&self) -> usize {
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

#[derive(Clone, Copy, PartialEq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct EVMOutput<'b> {
    /// EVM address from which to transfer funds
    address: Address<'b>,
    /// Amount of the asset to be transferred,
    /// in the smallest denomination possible
    amount: u64,
    asset_id: AssetId<'b>,
}

impl<'b> EVMOutput<'b> {
    pub fn amount(&self) -> Option<u64> {
        Some(self.amount)
    }

    pub fn asset_id(&self) -> &AssetId<'_> {
        &self.asset_id
    }
}

impl<'b> FromBytes<'b> for EVMOutput<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<crate::parser::ParserError>> {
        crate::sys::zemu_log_stack("EVMOutput::from_bytes_into\x00");

        let this = out.as_mut_ptr();

        // address
        let address = unsafe { &mut *addr_of_mut!((*this).address).cast() };
        let rem = Address::from_bytes_into(input, address)?;

        // amount
        let (rem, amount) = be_u64(rem)?;

        // asset_id
        let asset_id = unsafe { &mut *addr_of_mut!((*this).asset_id).cast() };
        let rem = AssetId::from_bytes_into(rem, asset_id)?;

        unsafe {
            addr_of_mut!((*this).amount).write(amount);
        }

        Ok(rem)
    }
}

impl<'b> DisplayableItem for EVMOutput<'b> {
    fn num_items(&self) -> usize {
        //type, asset id, amount, address
        1 + self.asset_id.num_items() + 1 + self.address.num_items()
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::{pic_str, PIC};
        use lexical_core::{write as itoa, Number};

        let mut buffer = [0; u64::FORMATTED_SIZE_DECIMAL + 2];

        match item_n as usize {
            0 => {
                let title_content = pic_str!(b"Output");
                title[..title_content.len()].copy_from_slice(title_content);

                handle_ui_message(pic_str!(b"EVM Output"), message, page)
            }
            1 => self.asset_id.render_item(0, title, message, page),
            2 => {
                let title_content = pic_str!(b"Amount");
                title[..title_content.len()].copy_from_slice(title_content);
                let buffer = itoa(self.amount, &mut buffer);

                handle_ui_message(buffer, message, page)
            }
            3 => self.address.render_item(0, title, message, page),
            _ => Err(ViewError::NoData),
        }
    }
}
