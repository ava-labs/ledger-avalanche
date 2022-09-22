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
use crate::{
    handlers::handle_ui_message,
    parser::{
        error::ParserError, nano_avax_to_fp_str, timestamp_to_str_date, Address, DisplayableItem,
        FromBytes, Output, OutputType, SECPOutputOwners, SECPTransferOutput,
        FORMATTED_STR_DATE_LEN,
    },
};
use core::ops::Deref;

use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::{
    bytes::complete::tag,
    number::complete::{be_i64, be_u32},
};
use zemu_sys::ViewError;

// This literal can be defined inline but, it is part of a big
// buffer on which we write other information so that we need
// its length to initialize such buffer and having the length defined as a constant and the
// literal inlined can lead to len mismatch which can cause overlapping.
const AVAX_UNTIL: &[u8; 12] = b" AVAX until ";

#[derive(Clone, Copy, PartialEq, Eq)]
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

    pub fn num_inner_items(&self) -> usize {
        self.output.num_items()
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
            // by definition p-chain also uses this type, but the
            // ecosystem do not support this yet.
            SECPOutputOwners::TYPE_ID => OutputType::SECPOwners,

            _ => return Err(ParserError::InvalidTypeId.into()),
        };

        Ok(v)
    }

    pub fn get_address_at(&'b self, idx: usize) -> Option<Address> {
        match self.output {
            Output::SECPTransfer(ref o) => o.get_address_at(idx),
            Output::SECPOwners(ref o) => o.get_address_at(idx),
            _ => None,
        }
    }
}

impl<'b> DisplayableItem for PvmOutput<'b> {
    fn num_items(&self) -> usize {
        // check if output is locked, if so the number of items
        // includes the locked information
        if self.is_locked() {
            // amount, address and locked info
            self.num_inner_items() + 1
        } else {
            self.num_inner_items()
        }
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::{pic_str, PIC};
        use lexical_core::Number;

        let num_inner_items = self.output.num_items() as _;
        match item_n {
            // Use the default implementation, if transactions require to improve this they can do
            // separately in their ui implementation
            // title
            0 => self.output.render_item(item_n as _, title, message, page),
            // render inner output addresses or other info
            x @ 1.. if x < num_inner_items => {
                self.output.render_item(item_n as _, title, message, page)
            }
            // render "locked" informations which inner output DO not know nothing about
            // only after rendering all inner_output items
            x if x == num_inner_items && self.is_locked() => {
                // legacy app displays:
                // 'Funds locked', body: '0.5 AVAX until 2021-05-31 21:28:00 UTC'},
                // so lets do the same thing
                let t = pic_str!(b"Funds locked");
                title[..t.len()].copy_from_slice(t);

                let avax_until = PIC::new(AVAX_UNTIL).into_inner();
                let mut content = [0; AVAX_UNTIL.len()
                    + FORMATTED_STR_DATE_LEN
                    + u64::FORMATTED_SIZE_DECIMAL
                    + 2];
                // write the amount
                let amount = self.amount().ok_or(ViewError::Unknown)?;
                let num_len = nano_avax_to_fp_str(amount, &mut content[..])
                    .map_err(|_| ViewError::Unknown)?
                    .len();
                // write avax until
                let mut total_len = num_len + avax_until.len();
                content[num_len..total_len].copy_from_slice(avax_until);
                // finally, write the date
                let locktime = self.locktime.ok_or(ViewError::NoData)?;
                let date_str = timestamp_to_str_date(locktime).map_err(|_| ViewError::Unknown)?;
                content[total_len..]
                    .iter_mut()
                    .zip(date_str.as_slice())
                    .take(date_str.len())
                    .for_each(|(d, s)| *d = *s);
                total_len += date_str.len();

                handle_ui_message(&content[..total_len], message, page)
            }
            _ => Err(ViewError::NoData),
        }
    }
}
