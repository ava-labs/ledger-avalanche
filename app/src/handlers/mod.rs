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
pub mod avax;
pub mod public_key;
pub mod version;
pub mod wallet_id;

#[cfg(feature = "dev")]
pub mod dev;

pub mod eth;

mod utils;
pub use utils::*;

pub mod resources {
    use crate::constants::MAX_BIP32_PATH_DEPTH;

    use super::lock::Lock;
    use crate::parser::NftInfo;
    use bolos::{
        crypto::bip32::BIP32Path, hash::Sha256, lazy_static, new_swapping_buffer, pic::PIC,
        SwappingBuffer,
    };

    #[lazy_static]
    pub static mut BUFFER: Lock<SwappingBuffer<'static, 'static, 0xFF, 0x1FFF>, BUFFERAccessors> =
        Lock::new(new_swapping_buffer!(0xFF, 0x1FFF));

    #[lazy_static]
    pub static mut PATH: Lock<Option<BIP32Path<MAX_BIP32_PATH_DEPTH>>, PATHAccessors> =
        Lock::new(None);

    #[lazy_static]
    pub static mut HASH: Lock<Option<[u8; Sha256::DIGEST_LEN]>, HASHAccessors> = Lock::new(None);

    #[lazy_static]
    pub static mut NFT_INFO: Lock<Option<NftInfo>, NFTInfoAccessors> = Lock::new(None);

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum BUFFERAccessors {
        Sign,
        EthSign,
        SignHash,
        SignMsg,
        #[cfg(feature = "blind-sign")]
        BlindSign,
        #[cfg(feature = "blind-sign")]
        EthBlindSign,
        #[cfg(feature = "dev")]
        Debug,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum PATHAccessors {
        Sign,
        EthSign,
        SignHash,
        SignMsg,
        #[cfg(feature = "blind-sign")]
        BlindSign,
        #[cfg(feature = "blind-sign")]
        EthBlindSign,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum HASHAccessors {
        Sign,
        SignHash,
        SignMsg,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum NFTInfoAccessors {
        NftInfo,
        EthSign,
        // The subparser for ERC721 transactions
        ERC721Parser,
    }

    #[cfg(feature = "blind-sign")]
    impl From<super::avax::blind_signing::BlindSign> for BUFFERAccessors {
        fn from(_: super::avax::blind_signing::BlindSign) -> Self {
            Self::BlindSign
        }
    }

    impl From<super::avax::signing::Sign> for BUFFERAccessors {
        fn from(_: super::avax::signing::Sign) -> Self {
            Self::Sign
        }
    }

    impl From<super::avax::message::Sign> for BUFFERAccessors {
        fn from(_: super::avax::message::Sign) -> Self {
            Self::SignMsg
        }
    }

    impl From<super::avax::sign_hash::Sign> for BUFFERAccessors {
        fn from(_: super::avax::sign_hash::Sign) -> Self {
            Self::SignHash
        }
    }

    #[cfg(feature = "blind-sign")]
    impl From<super::eth::blind_signing::BlindSign> for BUFFERAccessors {
        fn from(_: super::eth::blind_signing::BlindSign) -> Self {
            Self::EthBlindSign
        }
    }

    impl From<super::eth::signing::Sign> for BUFFERAccessors {
        fn from(_: super::eth::signing::Sign) -> Self {
            Self::EthSign
        }
    }

    impl From<super::eth::provide_nft_info::Info> for NFTInfoAccessors {
        fn from(_: super::eth::provide_nft_info::Info) -> Self {
            Self::NftInfo
        }
    }

    impl From<super::eth::signing::Sign> for NFTInfoAccessors {
        fn from(_: super::eth::signing::Sign) -> Self {
            Self::EthSign
        }
    }

    // gives direct access to the ERC721 subparser, to
    // get the information it needs. otherwise we would
    // need to pass the NftInfo object all the way down
    // modifying the EthTransaction parser.
    impl From<crate::parser::ERC721Info> for NFTInfoAccessors {
        fn from(_: crate::parser::ERC721Info) -> Self {
            Self::ERC721Parser
        }
    }

    #[cfg(feature = "dev")]
    impl From<super::dev::Debug> for BUFFERAccessors {
        fn from(_: super::dev::Debug) -> Self {
            Self::Debug
        }
    }

    #[cfg(feature = "blind-sign")]
    impl From<super::avax::blind_signing::BlindSign> for PATHAccessors {
        fn from(_: super::avax::blind_signing::BlindSign) -> Self {
            Self::BlindSign
        }
    }

    impl From<super::avax::signing::Sign> for PATHAccessors {
        fn from(_: super::avax::signing::Sign) -> Self {
            Self::Sign
        }
    }

    impl From<super::avax::message::Sign> for PATHAccessors {
        fn from(_: super::avax::message::Sign) -> Self {
            Self::SignMsg
        }
    }

    #[cfg(feature = "blind-sign")]
    impl From<super::eth::blind_signing::BlindSign> for PATHAccessors {
        fn from(_: super::eth::blind_signing::BlindSign) -> Self {
            Self::EthBlindSign
        }
    }

    impl From<super::eth::signing::Sign> for PATHAccessors {
        fn from(_: super::eth::signing::Sign) -> Self {
            Self::EthSign
        }
    }

    impl From<super::avax::sign_hash::Sign> for PATHAccessors {
        fn from(_: super::avax::sign_hash::Sign) -> Self {
            Self::SignHash
        }
    }

    impl From<super::avax::signing::Sign> for HASHAccessors {
        fn from(_: super::avax::signing::Sign) -> Self {
            Self::Sign
        }
    }

    impl From<super::avax::message::Sign> for HASHAccessors {
        fn from(_: super::avax::message::Sign) -> Self {
            Self::SignMsg
        }
    }

    impl From<super::avax::sign_hash::Sign> for HASHAccessors {
        fn from(_: super::avax::sign_hash::Sign) -> Self {
            Self::SignHash
        }
    }
}

pub mod lock;
