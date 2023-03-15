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
use nom::bytes::complete::take;

use crate::{
    constants::ASCII_HRP_MAX_SIZE,
    handlers::handle_ui_message,
    parser::{DisplayableItem, FromBytes, ParserError},
    utils::{hex_encode, ApduPanic},
};
use bolos::{pic_str, PIC};

use bech32::Variant;

use crate::sys::{bech32, hash::Ripemd160};
use zemu_sys::ViewError;

pub const ADDRESS_LEN: usize = Ripemd160::DIGEST_LEN;
pub const MAX_ADDRESS_ENCODED_LEN: usize = bech32::estimate_size(ASCII_HRP_MAX_SIZE, ADDRESS_LEN);

// ripemd160(sha256(compress(secp256k1.publicKey()))
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "derive-debug"), derive(Debug))]
pub struct Address<'b>(&'b [u8; ADDRESS_LEN]);

impl<'a> Address<'a> {
    // Get the address encoding
    pub fn encode_into(&self, hrp: &str, encoded: &mut [u8]) -> Result<usize, ParserError> {
        if hrp.len() > ASCII_HRP_MAX_SIZE {
            return Err(ParserError::InvalidAsciiValue);
        }

        let len = bech32::encode(hrp, self.0, encoded, Variant::Bech32)
            .map_err(|_| ParserError::UnexpectedBufferEnd)?;

        Ok(len)
    }

    pub fn raw_address(&self) -> &[u8; ADDRESS_LEN] {
        self.0
    }

    pub fn render_eth_address(&self, message: &mut [u8], page: u8) -> Result<u8, ViewError> {
        let prefix = pic_str!(b"0x"!);
        // prefix
        let mut out = [0; ADDRESS_LEN * 2 + 2];
        let mut sz = prefix.len();
        out[..prefix.len()].copy_from_slice(&prefix[..]);

        // address was previously check
        let address = self.raw_address();

        sz += hex_encode(address, &mut out[prefix.len()..]).map_err(|_| ViewError::Unknown)?;

        handle_ui_message(&out[..sz], message, page)
    }
}

impl<'b> FromBytes<'b> for Address<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        let (rem, addr) = take(ADDRESS_LEN)(input)?;
        let addr = arrayref::array_ref!(addr, 0, ADDRESS_LEN);

        //good ptr and no uninit reads
        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).0).write(addr);
        }

        Ok(rem)
    }
}

impl<'a> DisplayableItem for Address<'a> {
    fn num_items(&self) -> usize {
        1
    }

    #[inline(never)]
    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        if item_n != 0 {
            return Err(ViewError::NoData);
        }

        let mut addr = [0; MAX_ADDRESS_ENCODED_LEN];

        let len = self
            .encode_into("", &mut addr[..])
            .map_err(|_| ViewError::Unknown)?;

        let title_content = pic_str!(b"Address");
        title[..title_content.len()].copy_from_slice(title_content);

        handle_ui_message(&addr[..len], message, page)
    }
}

// ripemd160(sha256(compress(secp256k1.publicKey()))
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct OwnedAddress([u8; ADDRESS_LEN]);

impl OwnedAddress {
    pub fn raw_address(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn address(&self) -> Address<'_> {
        let mut address = MaybeUninit::uninit();
        _ = Address::from_bytes_into(&self.0[..], &mut address).apdu_unwrap();
        unsafe { address.assume_init() }
    }

    pub fn render_eth_address(&self, message: &mut [u8], page: u8) -> Result<u8, ViewError> {
        let address = self.address();
        address.render_eth_address(message, page)
    }
}

impl<'b> FromBytes<'b> for OwnedAddress {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        let (rem, addr) = take(ADDRESS_LEN)(input)?;
        let addr = arrayref::array_ref!(addr, 0, ADDRESS_LEN);

        //good ptr and no uninit reads
        let out = out.as_mut_ptr();
        unsafe {
            (*out).0.copy_from_slice(addr);
        }

        Ok(rem)
    }
}
