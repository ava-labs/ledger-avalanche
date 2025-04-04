/*******************************************************************************
*   (c) 2018-2024 Zondax AG
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

// taken from: https://github.com/Zondax/ledger-tezos/blob/main/rust/app/src/handlers/utils.rs
//
mod path_wrapper;
mod time;
pub use self::time::timestamp_to_str_date;
pub use path_wrapper::{parse_path_list, PathWrapper};

use crate::parser::{ParserError, CB58_CHECKSUM_LEN, NANO_AVAX_DECIMAL_DIGITS, U64_FORMATTED_SIZE, U32_FORMATTED_SIZE, U8_FORMATTED_SIZE};
use crate::sys::PIC;

#[cfg_attr(any(test, feature = "derive-debug"), derive(Debug))]
pub enum IntStrToFpStrError {
    BufferFull,
    BufferTooShort,
    /// Digit at .0 is not an ascii number
    NotAllDigitsAreNumbers(usize),
}

/// Return the len of the string until null termination
fn strlen(bytes: &[u8]) -> usize {
    bytes.split(|&n| n == 0).next().unwrap_or(bytes).len()
}

/// Returns the length of a slice
/// to be use to write the encoding
/// for an input with length I
pub const fn cb58_output_len<const I: usize>() -> usize {
    // I * log(2, 256) / log(2, 58) =  1.36 ~= 1.4 ~= 14/10 = factor + 2(just to round-up approximation)
    (I * 14) / 10 + CB58_CHECKSUM_LEN + 2
}

pub fn nano_avax_to_fp_str(value: u64, out_str: &mut [u8]) -> Result<&mut [u8], ParserError> {
    // the number plus '0.'
    if out_str.len() < U64_FORMATTED_SIZE + 2 {
        return Err(ParserError::UnexpectedBufferEnd);
    }

    u64_to_str(value, &mut out_str[..])?;

    intstr_to_fpstr_inplace(out_str, NANO_AVAX_DECIMAL_DIGITS)
        .map_err(|_| ParserError::UnexpectedError)
}

macro_rules! num_to_str {
    // we can use a procedural macro to "attach " the type name to the function name
    // but lets do it later.
    ($int_type:ty, $_name: ident) => {
        pub fn $_name(number: $int_type, output: &mut [u8]) -> Result<&mut [u8], ParserError> {
            let required_size = match std::any::TypeId::of::<$int_type>() {
                // Match the type to the corresponding constant
                id if id == std::any::TypeId::of::<u64>() => U64_FORMATTED_SIZE,
                id if id == std::any::TypeId::of::<u32>() => U32_FORMATTED_SIZE,
                id if id == std::any::TypeId::of::<u8>() => U8_FORMATTED_SIZE,
                _ => return Err(ParserError::UnexpectedBufferEnd), // Handle unexpected types
            };

            if output.len() < required_size {
                return Err(ParserError::UnexpectedBufferEnd);
            }
            if number == 0 {
                output[0] = b'0';
                return Ok(&mut output[..1]);
            }

            let mut offset = 0;
            let mut number = number;
            while number != 0 {
                let rem = number % 10;
                output[offset] = b'0' + rem as u8;
                offset += 1;
                number /= 10;
            }

            // swap values
            let len = offset;
            let mut idx = 0;
            while idx < offset {
                offset -= 1;
                output.swap(idx, offset);
                idx += 1;
            }

            Ok(&mut output[..len])
        }
    };
}

num_to_str!(u64, u64_to_str);
num_to_str!(u32, u32_to_str);
num_to_str!(u8, u8_to_str);

#[inline(never)]
/// Converts an integer number string
/// to a fixed point number string, in place
///
/// Returns Ok(subslice) which is the subslice with actual content,
/// trimming excess bytes
pub fn intstr_to_fpstr_inplace(
    s: &mut [u8],
    decimals: usize,
) -> Result<&mut [u8], IntStrToFpStrError> {
    //find the length of the string
    // if no 0s are found then the entire string is full with digits
    // so we return error
    let mut num_chars = strlen(s);

    if num_chars == s.len() {
        return Err(IntStrToFpStrError::BufferFull);
    }

    if s.is_empty() {
        return Err(IntStrToFpStrError::BufferTooShort);
    }

    //empty input string
    // let's just write a 0
    if num_chars == 0 {
        s[0] = b'0';
        num_chars = 1;
    }

    let mut first_digit_idx = None;
    //check that all are ascii numbers
    // and first the first digit
    let number_ascii_range = PIC::new(&(b'0'..=b'9')).into_inner();
    for (i, c) in s[..num_chars].iter_mut().enumerate() {
        if !number_ascii_range.contains(c) {
            return Err(IntStrToFpStrError::NotAllDigitsAreNumbers(i));
        }

        //just find the first digit
        if *c != b'0' {
            first_digit_idx = Some(i);
            break;
        }
    }

    //if we have a first digit
    if let Some(idx) = first_digit_idx {
        //move first_digit.. to the front
        s.copy_within(idx.., 0);

        //zero out the remaining
        s[num_chars - idx..].fill(0);

        //same as strlen(s)
        //we know where the string ends
        num_chars -= idx;
    } else {
        //if the first digit wasn't found
        // then it's just all 0s
        //we trim all the 0s after the first one
        s[1..].fill(0);
    }

    //we can return early if we have no decimals
    if decimals == 0 {
        num_chars = strlen(s);
        return Ok(&mut s[..num_chars]);
    }

    // Now insert decimal point

    //        0123456789012     <-decimal places
    //        abcd              < numChars = 4
    //                 abcd     < shift
    //        000000000abcd     < fill
    //        0.00000000abcd    < add decimal point

    if num_chars < decimals + 1 {
        // Move to end
        let padding = decimals - num_chars + 1;
        s.copy_within(..num_chars, padding);

        //fill the front with zeros
        s[..padding].fill(b'0');
        num_chars = strlen(s);
    }

    // add decimal point
    let point_position = num_chars - decimals;
    //shift content
    // by 1 space after point
    s.copy_within(
        point_position..point_position + decimals, //from: point to all the decimals
        point_position + 1,                        //to: just after point
    );
    s[point_position] = b'.';

    num_chars = strlen(s);

    // skip the trailing zeroes
    // for example 0.00500, so the last two
    // zeroes are completely irrelevant,
    // the same for 2000.00, the fixed point and the zero
    // are not important
    let mut len = num_chars;
    // skip characters before the decimal point
    for x in s[point_position..num_chars].iter().rev() {
        if *x == b'0' {
            len -= 1;
        } else if *x == b'.' {
            // this means everything after
            // the decimal point is zero
            // so remove the decimal point as well
            len -= 1;
            break;
        } else {
            break;
        }
    }

    // recalculate the new len after the filtering above
    let len = num_chars - (num_chars - len);

    Ok(&mut s[..len])
}

#[macro_export]
macro_rules! checked_add {
    ($err_type:path, $first:expr $(, $rest:expr)*) => {{
        // Start with the first value
        let mut sum = $first;

        // Try to add each of the rest, checking for overflow
        $(
            sum = sum.checked_add($rest).ok_or($err_type)?;
        )*

        // If we reach here, the sum is valid
        Ok(sum)
    }};
}

#[cfg(test)]
mod tests {
    use super::{intstr_to_fpstr_inplace, u64_to_str, U64_FORMATTED_SIZE};
    use rand::Rng;
    use std::{format, string::String, vec::Vec};

    const SUITE: &[(&[u8], usize, &str)] = &[
        //NORMAL
        (b"1", 0, "1"),
        (b"123", 0, "123"),
        (b"123", 5, "0.00123"),
        (b"100000", 9, "0.0001"),
        (b"1234", 5, "0.01234"),
        (b"12345", 5, "0.12345"),
        (b"123456", 5, "1.23456"),
        (b"1234567", 5, "12.34567"),
        //EXTRA
        (b"12345", 2, "123.45"),
        (b"12", 0, "12"),
        (b"12", 1, "1.2"),
        (b"012", 1, "1.2"),
        (b"0012345", 3, "12.345"),
        (b"9", 6, "0.000009"),
        // TRIM LEADING
        (b"0", 0, "0"),
        (b"00", 0, "0"),
        (b"0000", 0, "0"),
        (b"00001", 0, "1"),
        (b"000011", 0, "11"),
        (b"10000", 0, "10000"),
        (b"2000000000000", 9, "2000"),
        //EMPTY
        (b"", 0, "0"),
        (b"", 1, "0"),
        (b"", 2, "0"),
        (b"", 5, "0"),
        (b"", 10, "0"),
    ];

    fn create_number_table() -> std::vec::Vec<(u64, String)> {
        let mut rng = rand::rng();
        (0..200)
            .map(|_| {
                let num = rng.random_range(0..u64::MAX);
                let string = format!("{}", num);
                (num, string)
            })
            .collect::<Vec<(u64, String)>>()
    }

    #[test]
    fn int_to_str() {
        let mut output = [0; U64_FORMATTED_SIZE];
        let test = create_number_table();
        for (number, dat) in test {
            let res = {
                let res = u64_to_str(number as _, &mut output[..]).unwrap();
                core::str::from_utf8(res).unwrap()
            };
            assert_eq!(dat, res);
            output.iter_mut().for_each(|v| *v = 0);
        }
    }

    #[test]
    fn intstr_to_fpstr_inplace_test() {
        for &(input, decimals, expected_output) in SUITE.iter() {
            std::dbg!(
                "SUITE:",
                (
                    core::str::from_utf8(input).unwrap(),
                    decimals,
                    expected_output
                )
            );

            let mut input = std::vec::Vec::from(input);
            input.resize(input.len() + decimals + 2, 0);

            let out = intstr_to_fpstr_inplace(&mut input, decimals).unwrap();
            let out = core::str::from_utf8(out).unwrap();

            assert_eq!(out, expected_output)
        }
    }
}
