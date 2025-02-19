/*******************************************************************************
*   (c) 2018-2024 Zondax AG AG
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
    bytes::complete::{tag, take},
    number::complete::{be_u32, be_u64},
    sequence::tuple,
};
use zemu_sys::ViewError;

use crate::{
    checked_add,
    handlers::handle_ui_message,
    parser::{nano_avax_to_fp_str, Address, DisplayableItem, FromBytes, ParserError, ADDRESS_LEN, U64_FORMATTED_SIZE},
};

const AVAX_TO_LEN: usize = 9; //b" AVAX to "

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct SECPTransferOutput<'b> {
    pub amount: u64,
    pub locktime: u64,
    pub threshold: u32,
    // list of addresses allowed to use this output
    pub addresses: &'b [[u8; ADDRESS_LEN]],
}

impl<'b> SECPTransferOutput<'b> {
    pub const TYPE_ID: u32 = 0x00000007;

    pub fn get_address_at(&'b self, idx: usize) -> Option<Address> {
        let data = self.addresses.get(idx)?;
        let mut addr = MaybeUninit::uninit();
        Address::from_bytes_into(data, &mut addr).ok()?;
        Some(unsafe { addr.assume_init() })
    }

    pub fn num_addresses(&self) -> usize {
        self.addresses.len()
    }
}

impl<'b> FromBytes<'b> for SECPTransferOutput<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("SECPTransferOutput::from_bytes_into\x00");
        // get owners type and check
        let (rem, _) = tag(Self::TYPE_ID.to_be_bytes())(input)?;

        let (rem, (amount, locktime, threshold, addr_len)) =
            tuple((be_u64, be_u64, be_u32, be_u32))(rem)?;

        let (rem, addresses) = take(addr_len as usize * ADDRESS_LEN)(rem)?;

        let addresses =
            bytemuck::try_cast_slice(addresses).map_err(|_| ParserError::InvalidAddressLength)?;

        if (threshold as usize > addresses.len()) || (addresses.is_empty() && threshold != 0) {
            return Err(ParserError::InvalidThreshold.into());
        }

        //good ptr and no uninit reads
        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).amount).write(amount);
            addr_of_mut!((*out).locktime).write(locktime);
            addr_of_mut!((*out).threshold).write(threshold);
            addr_of_mut!((*out).addresses).write(addresses);
        }

        Ok(rem)
    }
}

impl<'a> DisplayableItem for SECPTransferOutput<'a> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // According to avalanche team, and to be "compatible" at presentation layer
        // we should summarize the items to show. As they suggested we only show the amount
        // and address. Legacy app errors if there is more than 1 address, in our case we dont yet.
        //
        // amount and addresses
        checked_add!(ViewError::Unknown, 1u8, self.addresses.len() as u8)
    }

    #[inline(never)]
    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::{pic_str, PIC};

        let mut buffer = [0; U64_FORMATTED_SIZE + 2 + AVAX_TO_LEN];
        let addr_item_n = self.num_items()? - self.addresses.len() as u8;

        match item_n {
            0 => {
                let title_content = pic_str!(b"Amount");
                title[..title_content.len()].copy_from_slice(title_content);

                let avax_to = pic_str!(b" AVAX to ");

                // write the amount
                let len = nano_avax_to_fp_str(self.amount, &mut buffer[..])
                    .map_err(|_| ViewError::Unknown)?
                    .len();

                // write avax
                buffer[len..(len + avax_to.len())].copy_from_slice(avax_to);
                handle_ui_message(&buffer[..(len + avax_to.len())], message, page)
            }

            x @ 1.. if x >= addr_item_n => {
                let idx = x - addr_item_n;
                let addr = self.get_address_at(idx as usize).ok_or(ViewError::NoData)?;
                addr.render_item(0, title, message, page)
            }
            _ => Err(ViewError::NoData),
        }
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
        let output = SECPTransferOutput::from_bytes(&raw_output[..]).unwrap().1;

        assert_eq!(output.amount, 98000000);
        assert_eq!(output.locktime, 0);
        assert_eq!(output.threshold, 1);
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

        let output = SECPTransferOutput::from_bytes(&raw_output).unwrap_err();
        assert_eq!(output, ParserError::InvalidThreshold.into());
    }
}
