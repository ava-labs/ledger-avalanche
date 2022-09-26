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
use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::{bytes::complete::take, number::complete::be_u8};

use crate::parser::{Address, FromBytes, ParserError, ADDRESS_LEN, COLLECTION_NAME_MAX_LEN};
use crate::utils::ApduPanic;

const NAME_LENGTH_SIZE: usize = 1;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct NftInfo {
    contract_address: [u8; ADDRESS_LEN],
    collection_name: [u8; COLLECTION_NAME_MAX_LEN + 1],
}

impl NftInfo {
    pub fn address(&self) -> Address<'_> {
        let mut address = MaybeUninit::uninit();
        // this wont fail as address was already parsed
        _ = Address::from_bytes_into(&self.contract_address[..], &mut address).apdu_unwrap();
        unsafe { address.assume_init() }
    }
}

impl<'b> FromBytes<'b> for NftInfo {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        if input.is_empty() {
            return Err(ParserError::UnexpectedBufferEnd.into());
        }
        // get nft collection name
        let name_len = input[0] as usize;
        if name_len > COLLECTION_NAME_MAX_LEN {
            return Err(ParserError::ValueOutOfRange.into());
        }

        let (rem, name) = take(name_len as usize)(&input[1..])?;
        let (rem, address) = take(ADDRESS_LEN)(rem)?;

        let out = out.as_mut_ptr();

        unsafe {
            let collection_name = &mut *addr_of_mut!((*out).collection_name);
            collection_name[..name.len()].copy_from_slice(name);
            let contract_address = &mut *addr_of_mut!((*out).contract_address);
            contract_address.copy_from_slice(address);
        }

        Ok(rem)
    }
}
