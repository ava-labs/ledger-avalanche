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
    ApduError as Error, BIP32_PATH_PREFIX_DEPTH, BIP32_PATH_ROOT_0, BIP32_PATH_ROOT_COIN_ETH,
    BIP32_PATH_ROOT_1,
};

/// Verify that a BIP32 path is a valid AVAX signing root.
///
/// The AVAX signing INS carries Avalanche-native transactions whose payload
/// determines which chain owns the funds being moved:
///
/// - `AvmExport/Import` and `PvmExport/Import` move funds on X/P chain, where
///   the signing key lives under `m/44'/9000'/account'` ([`BIP32_PATH_ROOT_1`]).
/// - `EvmExport/Import` (CoreEth atomic transactions) move funds on C-chain,
///   where the signing key lives under `m/44'/60'/account'`
///   ([`BIP32_PATH_ROOT_COIN_ETH`]) — the same root used by the embedded ETH
///   handler for C-chain EVM transactions.
///
/// Both prefixes are legitimate at the root level; which one is required
/// depends on the parsed transaction type and is enforced at the call site
/// (see `signing.rs`). The helper here keeps the structural guarantees that
/// are always true regardless of tx type:
///
/// - depth == [`BIP32_PATH_PREFIX_DEPTH`] (3 components)
/// - component 0 equals [`BIP32_PATH_ROOT_0`] (44')
/// - component 1 equals one of [`BIP32_PATH_ROOT_1`] (9000') or
///   [`BIP32_PATH_ROOT_COIN_ETH`] (60')
/// - every component is hardened
pub fn verify_avax_root_path<const LEN: usize>(path: &BIP32Path<LEN>) -> Result<(), Error> {
    const HARDENED: u32 = 0x8000_0000;

    let components = path.components();
    if components.len() != BIP32_PATH_PREFIX_DEPTH {
        return Err(Error::WrongLength);
    }
    if components[0] != BIP32_PATH_ROOT_0 {
        return Err(Error::DataInvalid);
    }
    if components[1] != BIP32_PATH_ROOT_1 && components[1] != BIP32_PATH_ROOT_COIN_ETH {
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
    const P60H: u32 = BIP32_PATH_ROOT_COIN_ETH;
    const P0H: u32 = 0x8000_0000;

    fn path<const LEN: usize>(components: &[u32]) -> BIP32Path<LEN> {
        BIP32Path::new(components.iter().copied()).unwrap()
    }

    #[test]
    fn accepts_xp_root() {
        // m/44'/9000'/0' — canonical X/P-chain root.
        assert!(verify_avax_root_path(&path::<3>(&[P44H, P9000H, P0H])).is_ok());
    }

    #[test]
    fn accepts_coreth_atomic_root() {
        // m/44'/60'/0' — canonical C-chain root, used by EvmExport / EvmImport
        // CoreEth atomic transactions whose funds live in a C-chain account.
        assert!(verify_avax_root_path(&path::<3>(&[P44H, P60H, P0H])).is_ok());
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
    fn rejects_unrelated_coin_type() {
        // m/44'/61'/0' — neither X/P (9000') nor C-chain (60').
        assert!(verify_avax_root_path(&path::<3>(&[P44H, 0x8000_0000 + 61, P0H])).is_err());
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

    #[test]
    fn rejects_unhardened_coreth_coin_type() {
        // m/44'/60/0' — coin type must be hardened, even for the C-chain root.
        assert!(verify_avax_root_path(&path::<3>(&[P44H, 60, P0H])).is_err());
    }
}
