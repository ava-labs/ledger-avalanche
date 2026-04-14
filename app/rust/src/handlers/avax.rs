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

pub mod message;
pub mod sign_hash;
pub mod signing;

use bolos::crypto::bip32::BIP32Path;

use crate::constants::{
    ApduError as Error, BIP32_PATH_PREFIX_DEPTH, BIP32_PATH_ROOT_0, BIP32_PATH_ROOT_1,
};

/// Verify that a BIP32 path is a valid AVAX signing root of the form
/// `m/44'/9000'/account'`.
///
/// Every AVAX-side signing entry (transaction, hash, personal message) derives
/// its keys from this prefix plus a 2-component non-hardened suffix. Accepting
/// a different prefix — for example `m/44'/60'/0'` (Ethereum) or `m/0/0/0`
/// (unhardened) — lets a malicious host show a normal-looking Avalanche
/// review while signing with a key from an unrelated namespace, so depth
/// alone is not a sufficient check.
///
/// The check enforces:
/// - depth == [`BIP32_PATH_PREFIX_DEPTH`] (3 components)
/// - components 0 and 1 equal [`BIP32_PATH_ROOT_0`] (44') and
///   [`BIP32_PATH_ROOT_1`] (9000') respectively
/// - every component is hardened
pub fn verify_avax_root_path<const LEN: usize>(path: &BIP32Path<LEN>) -> Result<(), Error> {
    const HARDENED: u32 = 0x8000_0000;

    let components = path.components();
    if components.len() != BIP32_PATH_PREFIX_DEPTH {
        return Err(Error::WrongLength);
    }
    if components[0] != BIP32_PATH_ROOT_0 || components[1] != BIP32_PATH_ROOT_1 {
        return Err(Error::DataInvalid);
    }
    if components.iter().any(|c| c & HARDENED == 0) {
        return Err(Error::DataInvalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const P44H: u32 = BIP32_PATH_ROOT_0;
    const P9000H: u32 = BIP32_PATH_ROOT_1;
    const P0H: u32 = 0x8000_0000;

    fn path<const LEN: usize>(components: &[u32]) -> BIP32Path<LEN> {
        BIP32Path::new(components.iter().copied()).unwrap()
    }

    #[test]
    fn accepts_canonical_root() {
        assert!(verify_avax_root_path(&path::<3>(&[P44H, P9000H, P0H])).is_ok());
    }

    #[test]
    fn rejects_too_short_prefix() {
        assert!(verify_avax_root_path(&path::<3>(&[P44H, P9000H])).is_err());
    }

    #[test]
    fn rejects_too_long_prefix() {
        assert!(verify_avax_root_path(&path::<5>(&[P44H, P9000H, P0H, P0H, P0H])).is_err());
    }

    #[test]
    fn rejects_wrong_coin_type() {
        // m/44'/60'/0' — Ethereum root, must not be accepted as AVAX.
        assert!(verify_avax_root_path(&path::<3>(&[P44H, 0x8000_0000 + 60, P0H])).is_err());
    }

    #[test]
    fn rejects_wrong_purpose() {
        // m/49'/9000'/0' — BIP49 purpose, wrong for AVAX.
        assert!(verify_avax_root_path(&path::<3>(&[0x8000_0000 + 49, P9000H, P0H])).is_err());
    }

    #[test]
    fn rejects_unhardened_account() {
        // m/44'/9000'/0 — account index must be hardened per BIP44.
        assert!(verify_avax_root_path(&path::<3>(&[P44H, P9000H, 0])).is_err());
    }

    #[test]
    fn rejects_unhardened_purpose() {
        // m/44/9000'/0' — purpose must be hardened.
        assert!(verify_avax_root_path(&path::<3>(&[44, P9000H, P0H])).is_err());
    }

    #[test]
    fn rejects_unhardened_coin_type() {
        // m/44'/9000/0' — coin type must be hardened.
        assert!(verify_avax_root_path(&path::<3>(&[P44H, 9000, P0H])).is_err());
    }
}
