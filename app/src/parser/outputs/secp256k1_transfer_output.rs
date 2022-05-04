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
use nom::{
    bytes::complete::take,
    number::complete::{be_u32, be_u64},
    sequence::tuple,
};
use zemu_sys::ViewError;

use crate::handlers::parser_common::ParserError;

use crate::parser::DisplayableItem;
use crate::parser::ADDRESS_LEN;

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct SECP256K1TransfOutput<'b> {
    // groups amount(u64), locktime(u64), threshold(u32)
    ints: &'b [u8; 20],
    // list of addresses allowed to use this output
    pub addresses: &'b [[u8; ADDRESS_LEN]],
}

impl<'b> SECP256K1TransfOutput<'b> {
    pub const TYPE_ID: u32 = 0x00000007;

    pub fn fields_from_bytes(
        input: &'b [u8],
    ) -> Result<(&'b [u8], (&'b [u8; 20], &'b [[u8; ADDRESS_LEN]])), nom::Err<ParserError>> {
        let (rem, (ints, addr_len)) = tuple((take(20usize), be_u32))(input)?;

        let (rem, addresses) = take(addr_len as usize * ADDRESS_LEN)(rem)?;
        let ints = arrayref::array_ref!(ints, 0, 20);

        let addresses =
            bytemuck::try_cast_slice(addresses).map_err(|_| ParserError::InvalidAddressLength)?;

        let threshold = be_u32(&ints[(ints.len() - 4)..])?.1 as usize;

        if (threshold > addresses.len()) || (addresses.is_empty() && threshold != 0) {
            return Err(ParserError::InvalidThreshold.into());
        }

        Ok((rem, (ints, addresses)))
    }

    #[inline(never)]
    pub fn from_bytes(input: &'b [u8]) -> Result<(&'b [u8], Self), nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("SECP256K1TransfOutput::from_bytes\x00");

        let (rem, (ints, addresses)) = Self::fields_from_bytes(input)?;
        Ok((rem, Self { ints, addresses }))
    }

    #[inline(never)]
    pub fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("SECP256K1TransfOutput::from_bytes_into\x00");

        let (rem, (ints, addresses)) = Self::fields_from_bytes(input)?;

        let out = out.as_mut_ptr();

        //good ptr and no uninit reads
        unsafe {
            addr_of_mut!((*out).ints).write(ints);
            addr_of_mut!((*out).addresses).write(addresses);
        }

        Ok(rem)
    }
    pub fn amount(&'b self) -> Result<u64, nom::Err<ParserError>> {
        //amount(u64), locktime(u64), threshold(u32)
        be_u64(self.ints.as_ref()).map(|(_, v)| v)
    }

    pub fn locktime(&self) -> Result<u64, nom::Err<ParserError>> {
        //amount(u64), locktime(u64), threshold(u32)
        // skip amount
        let offset = 8;
        be_u64(&self.ints[offset..]).map(|(_, v)| v)
    }

    pub fn threshold(&self) -> Result<u32, nom::Err<ParserError>> {
        //amount(u64), locktime(u64), threshold(u32)
        let offset = self.ints.len() - 4;
        be_u32(&self.ints[offset..]).map(|(_, v)| v)
    }
}

impl<'a> DisplayableItem for SECP256K1TransfOutput<'a> {
    fn num_items(&self) -> usize {
        todo!()
    }

    #[inline(never)]
    fn render_item(
        &self,
        _item_n: u8,
        _title: &mut [u8],
        _message: &mut [u8],
        _page: u8,
    ) -> Result<u8, ViewError> {
        //use bolos::{pic_str, PIC};

        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_secp256k1_output() {
        let raw_output = [
            0, 0, 0, 7, 0, 0, 0, 0, 5, 215, 92, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
            1, 107, 106, 1, 167, 20, 122, 95, 155, 189, 52, 132, 21, 94, 230, 26, 133, 92, 231, 53,
            186, 0, 0, 0, 0, 0, 0, 0, 0, 127, 201, 61, 133, 198, 214, 44, 91, 42, 192, 181, 25,
            200, 112, 16, 234, 82, 148, 1, 45, 30, 64, 112, 48, 214, 172, 208, 2, 28, 172, 16, 213,
            0, 0, 0, 1, 71, 17, 128, 245, 190, 100, 113, 53, 172, 8, 240, 180, 27, 164, 33, 138,
            21, 117, 13, 78, 36, 121, 31, 186, 118, 70, 237, 151, 61, 204, 110, 123, 0, 0, 0, 0,
            61, 155, 218, 192, 237, 29, 118, 19, 48, 207, 104, 14, 253, 235, 26, 66, 21, 158, 179,
            135, 214, 210, 149, 12, 150, 247, 210, 143, 97, 187, 226, 170, 0, 0, 0, 5, 0, 0, 0, 0,
            5, 230, 158, 192, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 9, 0, 0, 0, 1, 69, 136,
            235, 111, 206, 248, 241, 99, 249, 22, 126, 93, 117, 195, 56, 35, 129, 23, 81, 11, 56,
            150, 186, 96, 172, 81, 75, 154, 159, 54, 203, 31, 16, 82, 38, 127, 166, 131, 153, 81,
            171, 12, 160, 85, 169, 248, 58, 101, 211, 76, 120, 5, 137, 18, 213, 222, 36, 191, 169,
            28, 203, 145, 255, 8, 0,
        ];

        // output SECP256K1TransferOutput { type_id: 7, amount: 98000000, locktime: 0, threshhold: 1, addresses: [Address { address_bytes: [107, 106, 1, 167, 20, 122, 95, 155, 189, 52, 132, 21, 94, 230, 26, 133, 92, 231, 53, 186], serialized_address: None }] }
        let output = SECP256K1TransfOutput::from_bytes(&raw_output[4..])
            .unwrap()
            .1;
        let amount = output.amount().unwrap();
        let locktime = output.locktime().unwrap();
        let threshold = output.threshold().unwrap();
        assert_eq!(amount, 98000000);
        assert_eq!(locktime, 0);
        assert_eq!(threshold, 1);
        assert_eq!(output.addresses.len(), 1);
    }

    #[test]
    fn parse_secp256k1_output_invalid_threshold() {
        let raw_output = [
            0, 0, 0, 7, 0, 0, 0, 0, 5, 215, 92, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0,
            1, 107, 106, 1, 167, 20, 122, 95, 155, 189, 52, 132, 21, 94, 230, 26, 133, 92, 231, 53,
            186, 0, 0, 0, 0, 0, 0, 0, 0, 127, 201, 61, 133, 198, 214, 44, 91, 42, 192, 181, 25,
            200, 112, 16, 234, 82, 148, 1, 45, 30, 64, 112, 48, 214, 172, 208, 2, 28, 172, 16, 213,
            0, 0, 0, 1, 71, 17, 128, 245, 190, 100, 113, 53, 172, 8, 240, 180, 27, 164, 33, 138,
            21, 117, 13, 78, 36, 121, 31, 186, 118, 70, 237, 151, 61, 204, 110, 123, 0, 0, 0, 0,
            61, 155, 218, 192, 237, 29, 118, 19, 48, 207, 104, 14, 253, 235, 26, 66, 21, 158, 179,
            135, 214, 210, 149, 12, 150, 247, 210, 143, 97, 187, 226, 170, 0, 0, 0, 5, 0, 0, 0, 0,
            5, 230, 158, 192, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 9, 0, 0, 0, 1, 69, 136,
            235, 111, 206, 248, 241, 99, 249, 22, 126, 93, 117, 195, 56, 35, 129, 23, 81, 11, 56,
            150, 186, 96, 172, 81, 75, 154, 159, 54, 203, 31, 16, 82, 38, 127, 166, 131, 153, 81,
            171, 12, 160, 85, 169, 248, 58, 101, 211, 76, 120, 5, 137, 18, 213, 222, 36, 191, 169,
            28, 203, 145, 255, 8, 0,
        ];

        // output SECP256K1TransferOutput { type_id: 7, amount: 98000000, locktime: 0, threshhold: 1, addresses: [Address { address_bytes: [107, 106, 1, 167, 20, 122, 95, 155, 189, 52, 132, 21, 94, 230, 26, 133, 92, 231, 53, 186], serialized_address: None }] }
        let output = SECP256K1TransfOutput::from_bytes(&raw_output[4..]).unwrap_err();
        assert_eq!(output, ParserError::InvalidThreshold.into());
    }
}
