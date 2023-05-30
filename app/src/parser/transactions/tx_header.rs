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
use core::{convert::TryFrom, mem::MaybeUninit, ptr::addr_of_mut};
use nom::{bytes::complete::take, number::complete::be_u32, sequence::tuple};

use crate::parser::{ChainId, FromBytes, NetworkId, NetworkInfo, ParserError};

pub const BLOCKCHAIN_ID_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct Header<'b> {
    pub network_id: u32,
    pub blockchain_id: &'b [u8; BLOCKCHAIN_ID_LEN],
}

impl<'b> Header<'b> {
    pub fn network_info(&self) -> Result<NetworkInfo, ParserError> {
        NetworkInfo::try_from((self.network_id, self.blockchain_id))
    }

    pub fn chain_id(&self) -> Result<ChainId, ParserError> {
        ChainId::try_from(self.blockchain_id)
    }

    pub fn network_id(&self) -> Result<NetworkId, ParserError> {
        NetworkId::try_from(self.network_id)
    }

    pub fn hrp(&self) -> Result<&'static str, ParserError> {
        let info = self.network_id()?;
        Ok(info.hrp())
    }
}

impl<'b> FromBytes<'b> for Header<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("Header::from_bytes_into\x00");

        let (rem, (network_id, blockchain_id)) = tuple((be_u32, take(BLOCKCHAIN_ID_LEN)))(input)?;
        let blockchain_id = arrayref::array_ref!(blockchain_id, 0, BLOCKCHAIN_ID_LEN);

        //good ptr and no uninit reads
        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).network_id).write(network_id);
            addr_of_mut!((*out).blockchain_id).write(blockchain_id);
        }

        Ok(rem)
    }
}
