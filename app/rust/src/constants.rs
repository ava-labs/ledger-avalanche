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
// Based on ISO7816
#[repr(u16)]
#[derive(PartialEq, Eq)]
#[cfg_attr(any(test, miri, feature = "derive-debug"), derive(Debug))]
pub enum ApduError {
    ExecutionError = 0x6400,
    WrongLength = 0x6700,
    ApduCodeEmptyBuffer = 0x6982,
    OutputBufferTooSmall = 0x6983,
    DataInvalid = 0x6A80,
    ApduCodeConditionsNotSatisfied = 0x6985,
    CommandNotAllowed = 0x6986,
    BadKeyExample = 0x6A81, //unused
    InvalidP1P2 = 0x6B00,
    InsNotSupported = 0x6D00,
    ClaNotSupported = 0x6E00,
    Unknown = 0x6F00,
    SignVerifyError = 0x6F01, //unused
    Success = 0x9000,
    Busy = 0x9001,
}

#[cfg_attr(any(test, miri, feature = "derive-debug"), derive(Debug))]
pub enum ConvertApduError {
    Length { expected: usize, found: usize },
    Unknown(u16),
}

impl std::convert::TryFrom<&[u8]> for ApduError {
    type Error = ConvertApduError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() > 2 {
            return Err(Self::Error::Length {
                expected: 2,
                found: value.len(),
            });
        }

        let value = {
            let mut array = [0; 2];
            array.copy_from_slice(value);
            u16::from_be_bytes(array)
        };

        Self::try_from(value)
    }
}

impl std::convert::TryFrom<u16> for ApduError {
    type Error = ConvertApduError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x6400 => Ok(Self::ExecutionError),
            0x6700 => Ok(Self::WrongLength),
            0x6982 => Ok(Self::ApduCodeEmptyBuffer),
            0x6983 => Ok(Self::OutputBufferTooSmall),
            0x6A80 => Ok(Self::DataInvalid),
            0x6985 => Ok(Self::ApduCodeConditionsNotSatisfied),
            0x6986 => Ok(Self::CommandNotAllowed),
            0x6A81 => Ok(Self::BadKeyExample),
            0x6B00 => Ok(Self::InvalidP1P2),
            0x6D00 => Ok(Self::InsNotSupported),
            0x6E00 => Ok(Self::ClaNotSupported),
            0x6F00 => Ok(Self::Unknown),
            0x6F01 => Ok(Self::SignVerifyError),
            0x9000 => Ok(Self::Success),
            0x9001 => Ok(Self::Busy),
            err => Err(Self::Error::Unknown(err)),
        }
    }
}

pub const APDU_INDEX_CLA: usize = 0;
pub const APDU_INDEX_INS: usize = 1;
pub const APDU_INDEX_P1: usize = 2;
pub const APDU_INDEX_P2: usize = 3;
pub const APDU_INDEX_LEN: usize = 4;

pub const APDU_MIN_LENGTH: u32 = 5;

pub const SECP256_SIGN_BUFFER_MIN_LENGTH: usize = 100;

//Constants taken from obsidian app
pub const CHAIN_ID_LEN: usize = 32;
pub const CHAIN_ID_CHECKSUM_SIZE: usize = 4;
pub const DEFAULT_CHAIN_ID: &[u8; CHAIN_ID_LEN] = &[0; CHAIN_ID_LEN];
pub const ASCII_HRP_MAX_SIZE: usize = 24;
pub const WALLET_ID_LEN: usize = 6;
pub const WALLET_ID_HMAC_KEY: &str = "wallet-id";
pub const FIRST_MESSAGE: u8 = 0x01;
pub const NEXT_MESSAGE: u8 = 0x03;
pub const LAST_MESSAGE: u8 = 0x02;
pub const CURVE_SECP256K1: u8 = 0x00;
pub const CURVE_ED25519: u8 = 0x01;

pub const ED25519_ADDRESS_TO_HASH_LEN: usize = 37;

pub const SIGN_HASH_TX_SIZE: usize = 32 + MAX_BIP32_PATH_DEPTH * core::mem::size_of::<u32>();

pub(crate) mod instructions {
    pub const CLA: u8 = 0x80;

    pub const INS_GET_VERSION: u8 = 0x00;
    pub const INS_GET_WALLET_ID: u8 = 0x01;
    pub const INS_GET_PUBLIC_KEY: u8 = 0x02;
    pub const INS_GET_EXTENDED_PUBLIC_KEY: u8 = 0x03;
    pub const INS_SIGN_HASH: u8 = 0x04;
    pub const INS_SIGN: u8 = 0x05;
    pub const INS_SIGN_MSG: u8 = 0x06;
}

pub(crate) mod evm_instructions {
    pub const CLA_ETH: u8 = 0xE0;

    pub const INS_ETH_GET_PUBLIC_KEY: u8 = 0x02;
    pub const INS_ETH_SIGN: u8 = 0x04;
    pub const INS_ETH_GET_APP_CONFIGURATION: u8 = 0x06;
    pub const INS_SET_PLUGIN: u8 = 0x16;
    pub const INS_PROVIDE_NFT_INFORMATION: u8 = 0x14;
    pub const INS_ETH_PROVIDE_ERC20: u8 = 0x0A;
    pub const INS_SIGN_ETH_MSG: u8 = 0x08;
}

pub const BIP32_PATH_ROOT_0: u32 = 0x8000_0000 + 44;
pub const BIP32_PATH_ROOT_1: u32 = 0x8000_0000 + 9000;
pub const MAX_BIP32_PATH_DEPTH: usize = 6;
// path prefix for signer_list and change_path lists
// It is the same for both and has 3 components m/44'/9000'/0'/
pub const BIP32_PATH_PREFIX_DEPTH: usize = 3;
// path suffix components which contain the change/address
// This should be concatenated with the path_prefix to get a full
// signer/owner path.
pub const BIP32_PATH_SUFFIX_DEPTH: usize = 2;

#[cfg(test)]
pub use evm_instructions::*;
#[cfg(test)]
pub use instructions::*;

pub mod version {
    avalanche_app_derive::version!("../Makefile.version");
}

mod known_chains {
    use bolos::PIC;
    use zemu_sys::zemu_log_stack;

    avalanche_app_derive::unroll!("vendor/chainIDs.json");
}
pub use known_chains::chain_alias_lookup;
