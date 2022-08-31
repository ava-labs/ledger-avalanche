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
use bolos::crypto::bip32::BIP32Path;
use core::{mem::MaybeUninit, ptr::addr_of_mut};

use crate::parser::{FromBytes, ParserError, U32_SIZE};
use nom::{bytes::complete::take, number::complete::be_u8};

/// A simple wrapper around BIP32Path objects, in order to use it along
/// with ObjectList.
pub struct PathWrapper<const PATH_DEPTH: usize>(BIP32Path<PATH_DEPTH>);

impl<'b, const PATH_DEPTH: usize> FromBytes<'b> for PathWrapper<PATH_DEPTH> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("PathWrapper::from_bytes_into\x00");

        let (_, num_components) = be_u8(input)?;
        // compute the amount of bytes for this path
        let bytes = (num_components as usize * U32_SIZE) + 1;

        let (rem, raw_path) = take(bytes)(input)?;

        // get the path and also validates
        let path = BIP32Path::read(raw_path).map_err(|_| ParserError::InvalidPath)?;

        //good ptr and no uninit reads
        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).0).write(path);
        }

        Ok(rem)
    }
}

impl<const PATH_DEPTH: usize> PathWrapper<PATH_DEPTH> {
    pub fn path(&self) -> BIP32Path<PATH_DEPTH> {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MAX_BIP32_PATH_DEPTH;
    use crate::parser::ObjectList;

    const NUM_PATHS: usize = 3;
    const LIST: &[u8] = &[
        // "0/0", "0/1", "1/100"
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64,
    ];

    #[test]
    fn test_path_list() {
        let mut list: MaybeUninit<ObjectList<PathWrapper<MAX_BIP32_PATH_DEPTH>>> =
            MaybeUninit::uninit();
        let _ = ObjectList::new_into_with_len(LIST, &mut list, NUM_PATHS).unwrap();
        let list = unsafe { list.assume_init() };
        list.iter()
            .for_each(|path| assert_eq!(path.path().components().len(), 2));
        assert_eq!(list.iter().count(), NUM_PATHS);
    }
}
