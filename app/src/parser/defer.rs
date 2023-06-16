/*******************************************************************************
*   (c) 2023 Zondax AG
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
use core::{marker::PhantomData, mem::MaybeUninit, ptr::addr_of_mut};
use educe::Educe;
use nom::bytes::complete::take;
use zemu_sys::ViewError;

use crate::parser::{FromBytes, ParserError};

use super::DisplayableItem;

#[derive(Educe)]
#[cfg_attr(test, educe(Debug))]
#[educe(Clone, Copy, PartialEq, Eq)]
/// Represents an object that will be lazily parsed from memory
///
/// During initialization, the object is verified to be able to be parsed
pub struct Defer<'b, Obj> {
    data: &'b [u8],
    // type of object that this should parse
    #[cfg_attr(test, educe(Debug(ignore)))]
    #[educe(PartialEq(ignore))]
    _phantom: PhantomData<Obj>,
}

impl<'b, Obj> Defer<'b, Obj>
where
    Obj: FromBytes<'b>,
{
    #[inline(always)]
    pub fn read_into(&self, out: &mut MaybeUninit<Obj>) {
        //safety: &self.data is checked during the constructor
        Obj::from_bytes_into(&self.data, out)
            .unwrap_or_else(|_| unsafe { core::hint::unreachable_unchecked() });
    }

    #[inline(always)]
    pub fn read(&self) -> Obj {
        let mut obj = MaybeUninit::uninit();

        self.read_into(&mut obj);

        unsafe { obj.assume_init() }
    }
}

impl<'b, Obj> FromBytes<'b> for Defer<'b, Obj>
where
    Obj: FromBytes<'b>,
{
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        let len = input.len();

        let mut object = MaybeUninit::uninit();
        let left = Obj::from_bytes_into(input, &mut object)?;

        let (_, data) = take(len - left.len())(input)?;

        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).data).write(data);
        }

        Ok(left)
    }
}

impl<'b, Obj> DisplayableItem for Defer<'b, Obj>
where
    Obj: DisplayableItem + FromBytes<'b>,
{
    #[inline(always)]
    fn num_items(&self) -> usize {
        self.read().num_items()
    }

    #[inline(always)]
    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        self.read().render_item(item_n, title, message, page)
    }
}
