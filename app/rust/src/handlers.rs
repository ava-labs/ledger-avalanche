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
pub mod avax;
pub mod public_key;
pub mod version;
pub mod wallet_id;

#[cfg(feature = "dev")]
pub mod dev;

pub mod eth;

mod utils;
pub use utils::*;

#[allow(static_mut_refs)]
pub mod resources {
    use crate::constants::MAX_BIP32_PATH_DEPTH;

    use super::{eth::EthUi, lock::Lock};
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

    #[cfg(feature = "erc721")]
    #[lazy_static]
    pub static mut NFT_INFO: Lock<Option<crate::parser::NftInfo>, NFTInfoAccessors> =
        Lock::new(None);

    #[lazy_static]
    pub static mut ETH_UI: Lock<Option<EthUi>, EthAccessors> = Lock::new(None);

    /// Streaming hash resources for large EVM transactions that don't fit in buffer
    /// When a transaction exceeds BUFFER_CAPACITY, it enters streaming mode
    /// where the transaction is hashed incrementally across multiple APDU packets
    /// Core streaming hasher - performs incremental Keccak256 hashing of transaction data
    /// Used in: parse() to update hash with each packet, finalize_streaming_hash() to get final hash
    #[lazy_static]
    pub static mut STREAMING_HASHER: Lock<Option<bolos::hash::Keccak<32>>, StreamingAccessors> =
        Lock::new(None);

    /// Flag indicating if we're currently in streaming mode
    /// Used in: parse() to check mode, finalize_streaming_hash() to clean up
    #[lazy_static]
    pub static mut STREAMING_MODE: Lock<bool, StreamingAccessors> = Lock::new(false);

    /// Total bytes expected for the transaction (from RLP length parsing)
    /// Used in: parse() initial packet to set total, subsequent packets to check completion
    #[lazy_static]
    pub static mut EXPECTED_BYTES: Lock<u64, StreamingAccessors> = Lock::new(0);

    /// Total bytes received so far across all packets
    /// Used in: parse() to track progress and determine when transaction is complete
    #[lazy_static]
    pub static mut RECEIVED_BYTES: Lock<u64, StreamingAccessors> = Lock::new(0);

    /// Flag to track if streaming mode was used for the current transaction
    /// Used in: rs_eth_was_streaming_mode_used() C function for external queries
    #[lazy_static]
    pub static mut STREAMING_MODE_USED: Lock<bool, StreamingAccessors> = Lock::new(false);

    /// Stores the final computed hash from streaming mode
    /// Used in: finalize_streaming_hash() to store result, rs_eth_get_streaming_hash() to retrieve for blind signing UI
    #[lazy_static]
    pub static mut STREAMING_HASH: Lock<Option<[u8; 32]>, StreamingAccessors> = Lock::new(None);

    /// Store chain ID and transaction type for correct V calculation in streaming mode
    /// Critical for EIP-155 signature compatibility between streaming and normal modes
    /// Chain ID bytes extracted from transaction for V component calculation
    /// Used in: parse() to store from first packet, finalize_streaming_hash() to use for V calculation
    #[lazy_static]
    pub static mut STREAMING_CHAIN_ID: Lock<Option<[u8; 8]>, StreamingAccessors> = Lock::new(None);

    /// Transaction type flag (true = EIP-1559/EIP-2930, false = Legacy)
    /// Used in: parse() to store type, finalize_streaming_hash() to determine V calculation method
    #[lazy_static]
    pub static mut STREAMING_TX_TYPE: Lock<bool, StreamingAccessors> = Lock::new(false);

    /// Packet buffering for legacy transaction chain ID extraction
    /// Legacy transactions store chain ID at the end, requiring buffering of last packets
    /// Last received packet [length_byte, data...] - used for legacy chain ID extraction
    /// Used in: parse() to buffer packets, finalize_streaming_hash() to extract chain ID from end
    #[lazy_static]
    pub static mut LAST_PACKET: Lock<Option<[u8; 255]>, StreamingAccessors> = Lock::new(None);

    /// Second-to-last packet [length_byte, data...] - for multi-packet legacy chain ID extraction
    /// Used in: parse() to rotate packet buffer, finalize_streaming_hash() to combine with last packet
    #[lazy_static]
    pub static mut SECOND_LAST_PACKET: Lock<Option<[u8; 255]>, StreamingAccessors> =
        Lock::new(None);

    /// Flag indicating if current transaction is legacy type (affects chain ID location)
    /// Used in: parse() to set based on transaction type, packet buffering, and chain ID extraction
    #[lazy_static]
    pub static mut IS_LEGACY_TX: Lock<bool, StreamingAccessors> = Lock::new(false);

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum BUFFERAccessors {
        Sign,
        EthSign,
        SignHash,
        SignMsg,
        EthSignMsg,
        #[cfg(feature = "dev")]
        Debug,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum PATHAccessors {
        Sign,
        EthSign,
        SignHash,
        SignMsg,
        EthSignMsg,
        Address,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum HASHAccessors {
        Sign,
        SignHash,
        SignMsg,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum EthAccessors {
        Tx,
        Msg,
        Address,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    #[cfg(feature = "erc721")]
    pub enum NFTInfoAccessors {
        NftInfo,
        EthSign,
        // The subparser for ERC721 transactions
        ERC721Parser,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum StreamingAccessors {
        EthSign,
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

    impl From<super::eth::signing::Sign> for BUFFERAccessors {
        fn from(_: super::eth::signing::Sign) -> Self {
            Self::EthSign
        }
    }

    impl From<super::eth::personal_msg::Sign> for BUFFERAccessors {
        fn from(_: super::eth::personal_msg::Sign) -> Self {
            Self::EthSignMsg
        }
    }

    // *********************** ETH accessors ***********************

    impl From<super::eth::signing::Sign> for EthAccessors {
        fn from(_: super::eth::signing::Sign) -> Self {
            Self::Tx
        }
    }

    impl From<super::eth::personal_msg::Sign> for EthAccessors {
        fn from(_: super::eth::personal_msg::Sign) -> Self {
            Self::Msg
        }
    }

    // *********************** Streaming accessor implementation ***********************

    impl From<super::eth::signing::Sign> for StreamingAccessors {
        fn from(_: super::eth::signing::Sign) -> Self {
            Self::EthSign
        }
    }

    // *********************** NfT accessors ***********************

    #[cfg(feature = "erc721")]
    impl From<super::eth::provide_nft_info::Info> for NFTInfoAccessors {
        fn from(_: super::eth::provide_nft_info::Info) -> Self {
            Self::NftInfo
        }
    }

    #[cfg(feature = "erc721")]
    impl From<super::eth::signing::Sign> for NFTInfoAccessors {
        fn from(_: super::eth::signing::Sign) -> Self {
            Self::EthSign
        }
    }

    // gives direct access to the ERC721 subparser, to
    // get the information it needs. otherwise we would
    // need to pass the NftInfo object all the way down
    // modifying the EthTransaction parser.
    #[cfg(feature = "erc721")]
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

    impl From<super::eth::signing::Sign> for PATHAccessors {
        fn from(_: super::eth::signing::Sign) -> Self {
            Self::EthSign
        }
    }

    impl From<super::eth::personal_msg::Sign> for PATHAccessors {
        fn from(_: super::eth::personal_msg::Sign) -> Self {
            Self::EthSignMsg
        }
    }

    impl From<super::avax::sign_hash::Sign> for PATHAccessors {
        fn from(_: super::avax::sign_hash::Sign) -> Self {
            Self::SignHash
        }
    }

    impl From<super::public_key::GetPublicKey> for PATHAccessors {
        fn from(_: super::public_key::GetPublicKey) -> Self {
            Self::Address
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
