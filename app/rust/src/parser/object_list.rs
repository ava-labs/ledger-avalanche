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
use educe::Educe;
use nom::{bytes::complete::take, number::complete::be_u32};

use crate::{
    parser::{FromBytes, ParserError},
    utils::ApduPanic,
};

#[derive(Educe)]
#[cfg_attr(test, educe(Debug))]
#[educe(Clone, Copy, PartialEq, Eq)]
/// Represents an object list
///
/// The number of objects is prepended as a BE u32 to the objects bytes
pub struct ObjectList<'b, Obj> {
    data: &'b [u8],
    // counter used to track the amount of bytes
    // that were read when parsing a inner element in the list
    #[educe(PartialEq(ignore))]
    read: usize,
    // type of object that the ObjectList contains
    #[cfg_attr(test, educe(Debug(ignore)))]
    #[educe(PartialEq(ignore))]
    _phantom: PhantomData<Obj>,
}

impl<'b, Obj> ObjectList<'b, Obj>
where
    Obj: FromBytes<'b>,
{
    #[cfg(test)]
    pub fn new(input: &'b [u8]) -> Result<(&'b [u8], Self), nom::Err<ParserError>> {
        let mut list = MaybeUninit::uninit();
        let rem = ObjectList::new_into(input, &mut list)?;
        let list = unsafe { list.assume_init() };
        Ok((rem, list))
    }

    /// Attempt to parse the provided input as an [`ObjectList`] of the given `Obj` type.
    /// The number of elements in the list should be provided. This is useful in cases
    /// where the number of elements has an arbitrary type or is not part of the input
    /// buffer.
    ///
    /// Will fail if the input bytes are not properly encoded for the list or if any of the objects inside fail to parse.
    /// This also means accessing any inner objects shouldn't fail to parse
    #[inline(never)]
    pub fn new_into_with_len(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
        num_objs: usize,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        let mut len = input.len();
        let mut bytes_left = input;
        let mut object = MaybeUninit::uninit();

        // we are not saving parsed data but ensuring everything
        // parsed correctly.
        for _ in 0..num_objs {
            bytes_left = Obj::from_bytes_into(bytes_left, &mut object)?;
        }

        // this calculates the length in bytes of the list of objects
        // using the amount of bytes left after iterating over each parsed element.
        // This does not include the bytes
        // used to read the number of such objects as we already skip them
        len -= bytes_left.len();

        let (rem, data) = take(len)(input)?;

        //good ptr and no uninit reads
        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).read).write(0);
            addr_of_mut!((*out).data).write(data);
        }

        Ok(rem)
    }

    #[inline(never)]
    /// Attempt to parse the provided input as an [`ObjectList`] of the given `Obj` type.
    /// This method would read the number of objects as a u32 from the input buffer.
    ///
    /// Will fail if the input bytes are not properly encoded for the list or if any of the objects inside fail to parse.
    /// This also means accessing any inner objects shouldn't fail to parse
    pub fn new_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        if input.is_empty() {
            return Err(ParserError::UnexpectedBufferEnd.into());
        }

        let (rem, num_objects) = be_u32(input)?;

        Self::new_into_with_len(rem, out, num_objects as _)
    }

    #[inline(never)]
    /// Parses an object into the given location, returning the amount of bytes read.
    ///
    /// If no bytes could be read (for example, end of list), then None is returned.
    ///
    /// # Note
    /// Does not move the internal cursor forward, useful for peeking
    fn parse_into(&self, out: &mut MaybeUninit<Obj>) -> Option<usize> {
        let data = &self.data[self.read..];
        if data.is_empty() {
            return None;
        }

        //ok to panic as we parsed beforehand
        let rem = Obj::from_bytes_into(data, out).apdu_unwrap();

        Some(self.data.len() - rem.len())
    }

    /// Parses an object into the given location.
    ///
    /// If no bytes could be read, then None is returned.
    pub fn parse_next(&mut self, out: &mut MaybeUninit<Obj>) -> Option<()> {
        match self.parse_into(out) {
            Some(read) => {
                self.read = read;
                Some(())
            }
            None => None,
        }
    }

    /// Looks for the first object in the list that meets
    /// the condition defined by the closure `f`.
    ///
    /// it is like iter().filter(), but memory efficient.
    /// `None` is returned if no object meets that condition
    ///
    /// This function does not change the internal state.
    pub fn get_obj_if<F>(&self, mut f: F) -> Option<Obj>
    where
        F: FnMut(&Obj) -> bool,
    {
        let mut out = MaybeUninit::uninit();
        // lets clone and start from the begining
        let mut this = *self;
        unsafe {
            this.set_data_index(0);
        }
        while let Some(()) = this.parse_next(&mut out) {
            let obj_ptr = out.as_mut_ptr();
            // valid read as memory was initialized
            if f(unsafe { &*obj_ptr }) {
                return Some(unsafe { out.assume_init() });
            }
            // drop the object, this is safe
            // as user does not longer hold a reference
            // to this object.
            unsafe {
                obj_ptr.drop_in_place();
            }
        }
        None
    }

    /// Iterates and calls `f` passing each object
    /// in the list. This is intended to reduce stack by reusing the same
    /// memory. The closure F gives the user the option to compute
    /// any require data from each item.
    ///
    /// This function does not change the internal state.
    pub fn iterate_with<F>(&self, mut f: F)
    where
        F: FnMut(&Obj),
    {
        let mut out = MaybeUninit::uninit();
        // lets clone and start from the begining
        let mut this = *self;
        unsafe {
            this.set_data_index(0);
        }
        while let Some(()) = this.parse_next(&mut out) {
            let obj_ptr = out.as_mut_ptr();
            unsafe {
                // valid read as memory was initialized
                f(&*obj_ptr);
                // drop the object, this is safe
                // as user does not longer hold a reference
                // to obj.
                obj_ptr.drop_in_place();
            }
        }
    }

    /// Parses an object into the given location, without moving forward the internal cursor.
    ///
    /// See also [`ObjList::parse_next`].
    pub fn peek_next(&mut self, out: &mut MaybeUninit<Obj>) -> Option<()> {
        self.parse_into(out).map(|_| ())
    }

    /// Returns the internal cursor position
    pub fn data_index(&self) -> usize {
        self.read
    }

    /// Overwrite the internal cursor position
    ///
    /// Intended to be used as a way to reset the cursor, see below.
    ///
    /// # Safety
    /// Setting `read` to a position that is inside an object will render
    /// further reading impossible.
    ///
    /// If you start to panic when parsing object incorrect usage
    /// of this method is most likely the cause
    pub unsafe fn set_data_index(&mut self, read: usize) {
        self.read = read;
    }

    pub fn get(&self, index: usize) -> Option<Obj> {
        let mut out = MaybeUninit::uninit();
        let mut this = *self;

        // Reset the internal cursor to the beginning
        unsafe {
            this.set_data_index(0);
        }

        for _ in 0..index {
            // Attempt to parse the next object
            if this.parse_next(&mut out).is_none() {
                return None; // Return None if the index is out of bounds
            }
        }

        // Return the object at the specified index
        Some(unsafe { out.assume_init() })
    }
}

impl<'b, Obj> ObjectList<'b, Obj>
where
    Obj: FromBytes<'b> + 'b,
{
    /// Creates an [`ObjectListIterator`] for object out of the given object list
    pub fn iter(&self) -> impl Iterator<Item = Obj> + 'b {
        ObjectListIterator::new(self)
    }
}

struct ObjectListIterator<'b, Obj: FromBytes<'b>> {
    list: ObjectList<'b, Obj>,
}

impl<'b, Obj> ObjectListIterator<'b, Obj>
where
    Obj: FromBytes<'b>,
{
    /// Creates a new [`ObjectListIterator`] by copying the given list
    ///
    /// Iteration will always start from the beginning as the internal cursor
    /// of the copied list is reset
    fn new(list: &ObjectList<'b, Obj>) -> Self {
        // we do not want to change the state
        // of the passed in list, as a result, we just
        // make a copy, so we can reset the read index,
        // so iteration always starts from the beginning
        let mut list = *list;
        unsafe {
            // this is safe as we do have not used the current index
            // and setting it at the start of the list is always safe
            list.set_data_index(0);
        }
        Self { list }
    }
}

impl<'b, Obj> Iterator for ObjectListIterator<'b, Obj>
where
    Obj: FromBytes<'b>,
{
    type Item = Obj;

    fn next(&mut self) -> Option<Self::Item> {
        let mut output = MaybeUninit::uninit();
        self.list
            .parse_next(&mut output)
            .map(|_| unsafe { output.assume_init() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{AvmOutput, DisplayableItem, TransferableOutput};
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
        let (list, _) = ObjectList::<TransferableOutput<AvmOutput>>::new(DATA).unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn object_list_parse_next() {
        let (rem, mut list) = ObjectList::<TransferableOutput<AvmOutput>>::new(DATA).unwrap();
        assert!(rem.is_empty());
        let mut output: MaybeUninit<_> = MaybeUninit::uninit();
        let mut count = 0;
        while list.parse_next(&mut output).is_some() {
            count += 1;
        }

        // we know there are 10 outputs
        assert_eq!(count, 10);
    }

    #[test]
    fn object_list_iterator() {
        let (_, list) = ObjectList::<TransferableOutput<AvmOutput>>::new(DATA).unwrap();
        let num_items: usize = list
            .iter()
            .map(|output| output.num_items().expect("Overflow!") as usize)
            .sum();
        // the iterator does not change the state of the
        // main list object, as we return just a copy
        assert_eq!(list.read, 0);
        assert!(num_items > 0);
    }
}
