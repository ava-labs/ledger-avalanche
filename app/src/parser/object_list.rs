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
use core::{marker::PhantomData, mem::MaybeUninit, ptr::addr_of_mut};
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
    #[cfg(test)]
    pub fn new<Obj: FromBytes<'b>>(
        input: &'b [u8],
    ) -> Result<(&'b [u8], Self), nom::Err<ParserError>> {
        let mut list = MaybeUninit::uninit();
        let rem = ObjectList::new_into::<Obj>(input, &mut list)?;
        let list = unsafe { list.assume_init() };
        Ok((rem, list))
    }
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

        // we are not saving parsed data but ensuring everything
        // parsed correctly.
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
        let data = &self.data[self.read..];
        if data.is_empty() {
            return Ok(None);
        }

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

    pub fn data_index(&self) -> usize {
        self.read
    }

    // this is unsafe as setting a wrong value can make
    // further reading impossible. this is intended as a way to
    // reset the index.
    pub unsafe fn set_data_index(&mut self, read: usize) {
        self.read = read;
    }

    pub fn iter<Obj: FromBytes<'b> + 'b>(
        &'b self,
    ) -> impl Iterator<Item = Result<Obj, nom::Err<ParserError>>> + 'b {
        // we do not want to change the state
        // of the current list, as a result, we just
        // make a copy, in order to reset its read index
        // so that iteration always starts from the begining
        let mut list = *self;
        unsafe {
            // this is safe as we do not used the current index
            // setting it at the start of the list,
            list.set_data_index(0);
        }
        ObjectListIterator::new(list)
    }
}

struct ObjectListIterator<'b, Obj: FromBytes<'b>> {
    list: ObjectList<'b>,
    // a simple marker, to ensure this iterator is bound to the expected object
    marker: PhantomData<Obj>,
}

impl<'b, Obj> ObjectListIterator<'b, Obj>
where
    Obj: FromBytes<'b>,
{
    fn new(list: ObjectList<'b>) -> Self {
        Self {
            list,
            marker: PhantomData,
        }
    }
}

impl<'b, Obj> Iterator for ObjectListIterator<'b, Obj>
where
    Obj: FromBytes<'b>,
{
    type Item = Result<Obj, nom::Err<ParserError>>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut output = MaybeUninit::uninit();
        let res = self.list.parse_next::<Obj>(&mut output);
        match res {
            Ok(Some(())) => Some(Ok(unsafe { output.assume_init() })),
            Ok(None) => None,
            Err(err) => Some(Err(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{DisplayableItem, TransferableOutput};
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
        let (list, _) = ObjectList::new::<TransferableOutput>(DATA).unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn object_list_parse_next() {
        let (rem, mut list) = ObjectList::new::<TransferableOutput>(DATA).unwrap();
        assert!(rem.is_empty());
        let mut output: MaybeUninit<TransferableOutput> = MaybeUninit::uninit();
        let mut count = 0;
        while let Ok(Some(_)) = list.parse_next(&mut output) {
            count += 1;
        }

        // we know there are 10 outputs
        assert_eq!(count, 10);
    }

    #[test]
    fn object_list_iterator() {
        let (_, list) = ObjectList::new::<TransferableOutput>(DATA).unwrap();
        let num_items: usize = list
            .iter::<TransferableOutput>()
            .map(|output| output.map(|o| o.num_items()).unwrap())
            .sum();
        // the iterator does not change the state of the
        // main list object, as we return just a copy
        assert_eq!(list.read, 0);
        assert!(num_items > 0);
    }
}
