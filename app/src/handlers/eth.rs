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

pub mod provide_erc20;
pub mod public_key;
pub mod signing;

mod utils {
    use crate::{constants::MAX_BIP32_PATH_DEPTH, parser::ParserError, utils::ApduPanic};
    use bolos::crypto::bip32::BIP32Path;
    use nom::{bytes::complete::take, number::complete::le_u8};

    /// Parse a BIP32 path
    ///
    /// This function is here to guarantee the parsing
    /// is fixed and the same as what the eth app does
    pub fn parse_bip32_eth(
        data: &[u8],
    ) -> Result<(&[u8], BIP32Path<MAX_BIP32_PATH_DEPTH>), nom::Err<ParserError>> {
        let (rem, len) = le_u8(data)?;

        let (rem, components) = take(len as usize * 4)(rem)?;
        let components: &[[u8; 4]] = bytemuck::try_cast_slice(components).apdu_unwrap();

        let path = BIP32Path::new(components.iter().map(|n| u32::from_be_bytes(*n)))
            .map_err(|_| ParserError::ValueOutOfRange)?;

        Ok((rem, path))
    }

    pub mod u256;
}
