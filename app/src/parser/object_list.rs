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
use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::{bytes::complete::take, number::complete::be_u32};

use crate::parser::{FromBytes, ParserError};

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct ObjectList<'b> {
    data: &'b [u8],
    // counter used to track the amount of bytes
    // that were read when parsing a inner element in the list
    read: usize,
}

impl<'b> ObjectList<'b> {
    #[inline(never)]
    pub fn new_into<Obj: FromBytes<'b>>(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        if input.is_empty() {
            return Err(ParserError::UnexpectedBufferEnd.into());
        }

        let (rem, num_objects) = be_u32(input)?;
        let mut len = rem.len();
        let mut bytes_left = rem;
        let mut object = MaybeUninit::uninit();

        for _ in 0..num_objects {
            bytes_left = Obj::from_bytes_into(bytes_left, &mut object)?;
        }

        // this calculates the length in bytes of the list of objects
        // using the amount of bytes left after iterating over each parsed element.
        // This does not include the bytes
        // used to read the number of such objects as we already skip them
        len -= bytes_left.len();

        let (rem, data) = take(len)(rem)?;

        //good ptr and no uninit reads
        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).read).write(0);
            addr_of_mut!((*out).data).write(data);
        }

        Ok(rem)
    }

    #[inline(never)]
    fn parse_into<Obj: FromBytes<'b>>(
        &self,
        out: &mut MaybeUninit<Obj>,
    ) -> Result<Option<usize>, nom::Err<ParserError>> {
        let data = match self.data.get(self.read..) {
            Some(data) => data,
            _ => return Ok(None),
        };

        let rem = Obj::from_bytes_into(data, out)?;

        Ok(Some(self.data.len() - rem.len()))
    }

    pub fn parse_next<Obj: FromBytes<'b>>(
        &mut self,
        out: &mut MaybeUninit<Obj>,
    ) -> Result<Option<()>, nom::Err<ParserError>> {
        match self.parse_into(out) {
            Ok(Some(read)) => {
                self.read = read;
                Ok(Some(()))
            }
            Ok(None) => Ok(None),
            Err(err) => Err(err),
        }
    }

    pub fn peek_next<Obj: FromBytes<'b>>(
        &mut self,
        out: &mut MaybeUninit<Obj>,
    ) -> Result<Option<()>, nom::Err<ParserError>> {
        match self.parse_into(out) {
            Ok(Some(_)) => Ok(Some(())),
            Ok(None) => Ok(None),
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::TransferableOutput;
    use core::mem::MaybeUninit;
    const DATA: &[u8] = &[
        0, 0, 0, 10, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 1, 244, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0,
        2, 0, 0, 0, 2, 22, 54, 119, 75, 103, 131, 141, 236, 22, 225, 106, 182, 207, 172, 178, 27,
        136, 195, 168, 97, 157, 31, 52, 188, 58, 111, 35, 6, 202, 7, 144, 22, 174, 248, 92, 19, 23,
        103, 242, 56, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 1, 244, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0,
        2, 0, 0, 0, 2, 22, 54, 119, 75, 103, 131, 141, 236, 22, 225, 106, 182, 207, 172, 178, 27,
        136, 195, 168, 97, 157, 31, 52, 188, 58, 111, 35, 6, 202, 7, 144, 22, 174, 248, 92, 19, 23,
        103, 242, 56, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 1, 244, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0,
        2, 0, 0, 0, 2, 22, 54, 119, 75, 103, 131, 141, 236, 22, 225, 106, 182, 207, 172, 178, 27,
        136, 195, 168, 97, 157, 31, 52, 188, 58, 111, 35, 6, 202, 7, 144, 22, 174, 248, 92, 19, 23,
        103, 242, 56, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 1, 244, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0,
        2, 0, 0, 0, 2, 22, 54, 119, 75, 103, 131, 141, 236, 22, 225, 106, 182, 207, 172, 178, 27,
        136, 195, 168, 97, 157, 31, 52, 188, 58, 111, 35, 6, 202, 7, 144, 22, 174, 248, 92, 19, 23,
        103, 242, 56, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 1, 244, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0,
        2, 0, 0, 0, 2, 22, 54, 119, 75, 103, 131, 141, 236, 22, 225, 106, 182, 207, 172, 178, 27,
        136, 195, 168, 97, 157, 31, 52, 188, 58, 111, 35, 6, 202, 7, 144, 22, 174, 248, 92, 19, 23,
        103, 242, 56, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 1, 244, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0,
        2, 0, 0, 0, 2, 22, 54, 119, 75, 103, 131, 141, 236, 22, 225, 106, 182, 207, 172, 178, 27,
        136, 195, 168, 97, 157, 31, 52, 188, 58, 111, 35, 6, 202, 7, 144, 22, 174, 248, 92, 19, 23,
        103, 242, 56, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 1, 244, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0,
        2, 0, 0, 0, 2, 22, 54, 119, 75, 103, 131, 141, 236, 22, 225, 106, 182, 207, 172, 178, 27,
        136, 195, 168, 97, 157, 31, 52, 188, 58, 111, 35, 6, 202, 7, 144, 22, 174, 248, 92, 19, 23,
        103, 242, 56, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 1, 244, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0,
        2, 0, 0, 0, 2, 22, 54, 119, 75, 103, 131, 141, 236, 22, 225, 106, 182, 207, 172, 178, 27,
        136, 195, 168, 97, 157, 31, 52, 188, 58, 111, 35, 6, 202, 7, 144, 22, 174, 248, 92, 19, 23,
        103, 242, 56, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 1, 244, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0,
        2, 0, 0, 0, 2, 22, 54, 119, 75, 103, 131, 141, 236, 22, 225, 106, 182, 207, 172, 178, 27,
        136, 195, 168, 97, 157, 31, 52, 188, 58, 111, 35, 6, 202, 7, 144, 22, 174, 248, 92, 19, 23,
        103, 242, 56, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 1, 244, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0,
        2, 0, 0, 0, 2, 22, 54, 119, 75, 103, 131, 141, 236, 22, 225, 106, 182, 207, 172, 178, 27,
        136, 195, 168, 97, 157, 31, 52, 188, 58, 111, 35, 6, 202, 7, 144, 22, 174, 248, 92, 19, 23,
        103, 242, 56,
    ];

    #[test]
    fn parse_object_list() {
        let mut list = MaybeUninit::uninit();
        let list = ObjectList::new_into::<TransferableOutput>(DATA, &mut list).unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn object_list_parse_next() {
        let mut list = MaybeUninit::uninit();
        let _ = ObjectList::new_into::<TransferableOutput>(DATA, &mut list).unwrap();
        let mut list = unsafe { list.assume_init() };
        let mut output: MaybeUninit<TransferableOutput> = MaybeUninit::uninit();
        let mut count = 0;
        while let Ok(Some(_)) = list.parse_next(&mut output) {
            count += 1;
        }

        // we know there are 10 outputs
        assert_eq!(count, 10);
    }
}
