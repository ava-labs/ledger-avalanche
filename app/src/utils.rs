/*******************************************************************************
*   (c) 2022 Zondax GmbH
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
#![allow(dead_code, unused_macros)]

use bolos::PIC;

git_testament::git_testament_macros!(git);

pub const GIT_COMMIT_HASH: &str = git_commit_hash!();

mod apdu_unwrap;
pub use apdu_unwrap::*;

mod apdu_wrapper;
pub use apdu_wrapper::*;

mod keccak;
pub(crate) use keccak::{Hasher as KHasher, Keccak};
pub mod convert_to_rs;
pub use convert_to_rs::{convert_der_to_rs, ConvertError};

mod buffer_upload;
pub use buffer_upload::*;

mod app_mode;
pub use app_mode::*;

pub mod blind_sign_toggle;

#[cfg(test)]
#[macro_export]
macro_rules! assert_error_code {
    ($tx:expr, $buffer:ident, $expected:expr) => {
        let pos: usize = $tx as _;
        let actual: ApduError = (&$buffer[pos - 2..pos]).try_into().unwrap();
        assert_eq!(actual, $expected);
    };
}

/// This function returns the index of the first null byte in the slice
#[cfg(test)]
pub fn strlen(s: &[u8]) -> usize {
    let mut count = 0;
    while let Some(&c) = s.get(count) {
        if c == 0 {
            return count;
        }
        count += 1;
    }

    panic!("byte slice did not terminate with null byte, s: {:x?}", s)
}

/// This function returns the index of the
/// first null byte in the slice or the total len of the slice,
/// whichever comes first
pub fn rs_strlen(s: &[u8]) -> usize {
    let mut count = 0;
    while let Some(&c) = s.get(count) {
        if c == 0 {
            return count;
        }
        count += 1;
    }

    s.len()
}

pub struct OutputBufferTooSmall;
pub fn hex_encode(
    input: impl AsRef<[u8]>,
    output: &mut [u8],
) -> Result<usize, OutputBufferTooSmall> {
    let input = input.as_ref();

    if input.len() * 2 > output.len() {
        return Err(OutputBufferTooSmall);
    }

    const HEX_CHARS_LOWER: &[u8; 16] = b"0123456789abcdef";

    let table = PIC::new(HEX_CHARS_LOWER).into_inner();
    for (byte, out) in input.iter().zip(output.chunks_mut(2)) {
        let high = table[((byte & 0xf0) >> 4) as usize];
        let low = table[(byte & 0xf) as usize];

        //number of items guaranteed
        // as we checked the size beforehand so
        // output will always be at least the right length
        // to encode input
        out[0] = high;
        out[1] = low;
    }

    Ok(input.len() * 2)
}

pub fn bs58_encode(
    input: impl AsRef<[u8]>,
    output: &mut [u8],
) -> Result<usize, OutputBufferTooSmall> {
    const ALPHABET_ENCODE: &[u8; 58] =
        b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let table = PIC::new(ALPHABET_ENCODE).into_inner();

    let input = input.as_ref();
    let mut index = 0;

    for &val in input.iter() {
        let mut carry = val as usize;
        for byte in &mut output[..index] {
            carry += (*byte as usize) << 8;
            *byte = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            if index == output.len() {
                return Err(OutputBufferTooSmall);
            }
            output[index] = (carry % 58) as u8;
            index += 1;
            carry /= 58;
        }
    }

    for _ in input.iter().take_while(|v| **v == 0) {
        if index == output.len() {
            return Err(OutputBufferTooSmall);
        }
        output[index] = 0;
        index += 1;
    }

    for val in &mut output[..index] {
        *val = table[*val as usize];
    }

    output.get_mut(..index).apdu_unwrap().reverse();
    Ok(index)
}

/// Reads a byte slice preprended with the slice len
pub fn read_slice(input: &[u8]) -> Option<(usize, &[u8])> {
    let len = input.get(0)?;
    let len = *len as usize;

    input.get(1..1 + len).map(|bytes| (1 + len, bytes))
}

#[cfg(test)]
mod maybe_null_terminated_to_string {
    use core::str::Utf8Error;
    use std::borrow::ToOwned;
    use std::ffi::{CStr, CString};
    use std::string::String;

    ///This trait is a utility trait to convert a slice of bytes into a CString
    ///
    /// If the string is nul terminated already then no null termination is added
    pub trait MaybeNullTerminatedToString {
        fn to_string_with_check_null(&self) -> Result<String, Utf8Error>;
    }

    impl MaybeNullTerminatedToString for &[u8] {
        fn to_string_with_check_null(&self) -> Result<String, Utf8Error> {
            //attempt to make a cstr first
            if let Ok(cstr) = CStr::from_bytes_with_nul(self) {
                return cstr.to_owned().into_string().map_err(|e| e.utf8_error());
            }

            //in the case above,
            // we could be erroring due to a null byte in the middle
            // or a null byte _missing_ at the end
            //
            //but here we'll error for a null byte at the end or a null byte in the middle
            match CString::new(self.to_vec()) {
                Ok(cstring) => cstring.into_string().map_err(|e| e.utf8_error()),
                Err(err) => {
                    // so with the above error, we can only be erroring here only with a null byte in the middle
                    let nul_pos = err.nul_position();
                    //truncate the string
                    CStr::from_bytes_with_nul(&self[..=nul_pos])
                        //we can't be erroring for a missing null byte at the end,
                        // and also can't error due to a null byte in the middle,
                        // because this is literally the smaller substring to be terminated
                        .unwrap()
                        .to_owned()
                        .into_string()
                        .map_err(|e| e.utf8_error())
                }
            }
        }
    }

    impl<const S: usize> MaybeNullTerminatedToString for [u8; S] {
        fn to_string_with_check_null(&self) -> Result<String, Utf8Error> {
            (&self[..]).to_string_with_check_null()
        }
    }
}

#[cfg(test)]
pub use maybe_null_terminated_to_string::MaybeNullTerminatedToString;

#[macro_export]
/// Convert the return of Show::show into something more usable for apdu handlers
///
/// sets `tx` to the amount returned if given,
/// otherwise tx is returned only on success and discarded on failure
macro_rules! show_ui {
    ($show:expr, $tx:ident) => {
        match unsafe { $show } {
            Ok((size, err)) if err == crate::constants::ApduError::Success as u16 => {
                *$tx = size as _;
                Ok(())
            }
            Ok((size, err)) => {
                use ::core::convert::TryInto;
                *$tx = size as _;

                match err.try_into() {
                    Ok(err) => Err(err),
                    Err(_) => Err(crate::constants::ApduError::ExecutionError),
                }
            }
            Err(_) => Err(crate::constants::ApduError::ExecutionError),
        }
    };
    ($show:expr) => {
        match unsafe { $show } {
            Ok((size, err)) if err == crate::constants::ApduError::Success as u16 => Ok(size as _),
            Ok((_, err)) => {
                use ::core::convert::TryInto;

                match err.try_into() {
                    Ok(err) => Err(err),
                    Err(_) => Err(crate::constants::ApduError::ExecutionError),
                }
            }
            Err(_) => Err(crate::constants::ApduError::ExecutionError),
        }
    };
}
