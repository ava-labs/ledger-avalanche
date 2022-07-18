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
    error::ParserError, DisplayableItem, FromBytes, Output, OutputType, SECPOutputOwners,
    SECPTransferOutput,
};

use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::{
    bytes::complete::tag,
    number::complete::{be_i64, be_u32},
};
use zemu_sys::ViewError;

#[derive(Clone, Copy, PartialEq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct PvmOutput<'b> {
    pub locktime: Option<i64>,
    pub output: Output<'b>,
}

impl<'b> Deref for PvmOutput<'b> {
    type Target = Output<'b>;

    fn deref(&self) -> &Self::Target {
        &self.output
    }
}

impl<'b> PvmOutput<'b> {
    const LOCKED_OUTPUT_TAG: u32 = 0x00000016;

    pub fn amount(&self) -> Option<u64> {
        self.output.amount()
    }

    pub fn is_locked(&self) -> bool {
        self.locktime.is_some()
    }
}

impl<'b> FromBytes<'b> for PvmOutput<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        // initialize locktime
        let mut locktime = None;
        let output = out.as_mut_ptr() as *mut PvmOutput;

        // check first if this output is locked
        let rem = if let Ok((r, _)) =
            tag::<_, _, ParserError>(Self::LOCKED_OUTPUT_TAG.to_be_bytes())(input)
        {
            // locked outputs should come with a locktime
            let (rem, raw_locktime) = be_i64(r)?;
            locktime = Some(raw_locktime);
            rem
        } else {
            input
        };

        // now parse the input
        let variant_type = Self::parse_output_type(rem)?;

        let data = unsafe { &mut *addr_of_mut!((*output).output).cast() };
        let rem = Output::from_bytes(rem, variant_type, data)?;

        // Safe write, pointer is valid
        unsafe {
            addr_of_mut!((*output).locktime).write(locktime);
        }

        Ok(rem)
    }
}

impl<'b> PvmOutput<'b> {
    fn parse_output_type(input: &[u8]) -> Result<OutputType, nom::Err<ParserError>> {
        let (_, variant_type) = be_u32(input)?;

        let v = match variant_type {
            SECPTransferOutput::TYPE_ID => OutputType::SECPTransfer,
            SECPOutputOwners::TYPE_ID => OutputType::SECPOwners,

            _ => return Err(ParserError::InvalidTypeId.into()),
        };

        Ok(v)
    }
}

impl<'b> DisplayableItem for PvmOutput<'b> {
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
