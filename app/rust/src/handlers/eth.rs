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

pub mod get_app_configuration;
pub mod personal_msg;
pub mod provide_erc20;
pub mod provide_nft_info;
pub mod public_key;
pub mod set_plugin;
pub mod signing;

use bolos::crypto::bip32::BIP32Path;
use zemu_sys::{ViewError, Viewable};

use crate::constants::{ApduError as Error, BIP32_PATH_ROOT_0, BIP32_PATH_ROOT_COIN_ETH};
#[cfg(test)]
use crate::constants::BIP32_PATH_ROOT_1;

/// Verify that a BIP32 path is a valid Coreth / Ethereum-compatible root of
/// the form `m/44'/60'/account'` with optional non-hardened `change/index`
/// suffixes (full BIP44 for Ethereum).
///
/// Every ETH-side signing entry (transaction, personal message) and the
/// public-key/address handler derives its keys under this prefix. Accepting a
/// different prefix — for example `m/44'/9000'/0'` (AVAX native) or `m/0/0/0`
/// (unhardened) — lets a malicious host harvest or sign with keys from an
/// unrelated namespace while the UI displays a normal-looking Ethereum review.
///
/// The check enforces:
/// - depth in [3, 5] (account-only through full BIP44 address level)
/// - components 0 and 1 equal [`BIP32_PATH_ROOT_0`] (44') and
///   [`BIP32_PATH_ROOT_COIN_ETH`] (60') respectively
/// - the first three components (purpose / coin type / account) are hardened.
///   Change and index follow the standard BIP44-for-Ethereum convention and
///   are left flexible so MetaMask-style `m/44'/60'/0'/0/n` paths still work.
pub fn verify_coreth_root_path<const LEN: usize>(path: &BIP32Path<LEN>) -> Result<(), Error> {
    const HARDENED: u32 = 0x8000_0000;

    let components = path.components();
    if components.len() < 3 || components.len() > 5 {
        return Err(Error::WrongLength);
    }
    if components[0] != BIP32_PATH_ROOT_0 || components[1] != BIP32_PATH_ROOT_COIN_ETH {
        return Err(Error::DataInvalid);
    }
    if components[..3].iter().any(|c| c & HARDENED == 0) {
        return Err(Error::DataInvalid);
    }
    Ok(())
}

#[cfg(test)]
mod coreth_path_tests {
    use super::*;

    const P44H: u32 = BIP32_PATH_ROOT_0;
    const P60H: u32 = BIP32_PATH_ROOT_COIN_ETH;
    const P0H: u32 = 0x8000_0000;

    fn path<const LEN: usize>(components: &[u32]) -> BIP32Path<LEN> {
        BIP32Path::new(components.iter().copied()).unwrap()
    }

    #[test]
    fn accepts_account_only_root() {
        // m/44'/60'/0' — minimum accepted depth.
        assert!(verify_coreth_root_path(&path::<3>(&[P44H, P60H, P0H])).is_ok());
    }

    #[test]
    fn accepts_metamask_style_with_change_index() {
        // m/44'/60'/0'/0/5 — standard BIP44 for Ethereum (unhardened change/index).
        assert!(verify_coreth_root_path(&path::<5>(&[P44H, P60H, P0H, 0, 5])).is_ok());
    }

    #[test]
    fn accepts_four_component_zemu_path() {
        // m/44'/60'/0'/0' — the ETH_DERIVATION used by Zemu tests.
        assert!(verify_coreth_root_path(&path::<4>(&[P44H, P60H, P0H, P0H])).is_ok());
    }

    #[test]
    fn rejects_too_short() {
        assert!(verify_coreth_root_path(&path::<2>(&[P44H, P60H])).is_err());
    }

    #[test]
    fn rejects_too_long() {
        assert!(verify_coreth_root_path(&path::<6>(&[P44H, P60H, P0H, 0, 0, 0])).is_err());
    }

    #[test]
    fn rejects_avax_coin_type() {
        // m/44'/9000'/0' — AVAX native root, must not sign ETH-framed data.
        assert!(verify_coreth_root_path(&path::<3>(&[P44H, BIP32_PATH_ROOT_1, P0H])).is_err());
    }

    #[test]
    fn rejects_wrong_purpose() {
        // m/49'/60'/0' — BIP49 purpose.
        assert!(verify_coreth_root_path(&path::<3>(&[0x8000_0000 + 49, P60H, P0H])).is_err());
    }

    #[test]
    fn rejects_unhardened_purpose() {
        assert!(verify_coreth_root_path(&path::<3>(&[44, P60H, P0H])).is_err());
    }

    #[test]
    fn rejects_unhardened_coin_type() {
        assert!(verify_coreth_root_path(&path::<3>(&[P44H, 60, P0H])).is_err());
    }

    #[test]
    fn rejects_unhardened_account() {
        assert!(verify_coreth_root_path(&path::<3>(&[P44H, P60H, 0])).is_err());
    }
}

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
pub use utils::u256::{u256, BorrowedU256};
