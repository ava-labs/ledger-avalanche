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

pub mod get_app_configuration;
pub mod personal_msg;
pub mod provide_erc20;
pub mod provide_nft_info;
pub mod public_key;
pub mod set_plugin;
pub mod signing;

use zemu_sys::{ViewError, Viewable};

pub enum EthUi {
    Tx(crate::handlers::eth::signing::SignUI),
    Msg(crate::handlers::eth::personal_msg::SignUI),
    Addr(crate::handlers::eth::public_key::AddrUI),
}

impl Viewable for EthUi {
    fn num_items(&mut self) -> Result<u8, ViewError> {
        match self {
            Self::Tx(obj) => obj.num_items(),
            Self::Msg(obj) => obj.num_items(),
            Self::Addr(obj) => obj.num_items(),
        }
    }

    #[inline(never)]
    fn render_item(
        &mut self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        match self {
            Self::Tx(obj) => obj.render_item(item_n, title, message, page),
            Self::Msg(obj) => obj.render_item(item_n, title, message, page),
            Self::Addr(obj) => obj.render_item(item_n, title, message, page),
        }
    }

    fn accept(&mut self, out: &mut [u8]) -> (usize, u16) {
        match self {
            Self::Tx(obj) => obj.accept(out),
            Self::Msg(obj) => obj.accept(out),
            Self::Addr(obj) => obj.accept(out),
        }
    }

    fn reject(&mut self, out: &mut [u8]) -> (usize, u16) {
        match self {
            Self::Tx(obj) => obj.reject(out),
            Self::Msg(obj) => obj.reject(out),
            Self::Addr(obj) => obj.reject(out),
        }
    }
}

mod utils {
    pub mod u256;

    use crate::constants::ApduError as Error;
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

    /// Return the number of bytes of the ethereum tx
    ///
    /// Note: This function expects a transaction version plus
    /// a rlp-encoded list. other types are not supported
    /// as it means that the received data is not a conformant
    /// Ethereum transaction type
    ///
    /// Returns the number of bytes read and the number of bytes to read
    pub fn get_tx_rlp_len(mut data: &[u8]) -> Result<(usize, u64), Error> {
        const U64_SIZE: usize = core::mem::size_of::<u64>();

        let mut read = 0;

        //skip version if present/recognized
        // otherwise tx is probably legacy so no version, just rlp data
        let version = *data.first().ok_or(Error::DataInvalid)?;
        match version {
            0x01 | 0x02 => {
                data = data.get(1..).ok_or(Error::DataInvalid)?;
                read += 1;
            }
            _ => {}
        }

        let marker = *data.first().ok_or(Error::DataInvalid)?;

        match marker {
            slist @ 0xC0..=0xF7 => Ok((read + 1, slist as u64 - 0xC0)),
            list @ 0xF8.. => {
                // For lists longer than 55 bytes the length is encoded
                // differently.
                // The number of bytes that compose the length is encoded
                // in the marker
                // And then the length is just the number BE encoded

                let num_bytes = list as usize - 0xF7;
                let num = data
                    .get(1..)
                    .ok_or(Error::DataInvalid)?
                    .get(..num_bytes)
                    .ok_or(Error::DataInvalid)?;

                let mut array = [0; U64_SIZE];
                array[U64_SIZE - num_bytes..].copy_from_slice(num);

                let num = u64::from_be_bytes(array);
                Ok((read + 1 + num_bytes, num))
            }
            _ => Err(Error::DataInvalid),
        }
    }
}
use bolos::ApduError;
pub use utils::u256::{u256, BorrowedU256};
