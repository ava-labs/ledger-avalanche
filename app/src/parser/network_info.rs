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
use core::convert::TryFrom;

use crate::constants::chain_alias_lookup;
use crate::parser::constants::*;
use crate::parser::ParserError;

pub use crate::parser::{FromBytes, BLOCKCHAIN_ID_LEN};

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
#[cfg_attr(test, derive(Debug))]
pub enum NetworkId {
    Mainnet,
    Fuji,
    Local,
}

impl NetworkId {
    pub fn hrp(&self) -> &'static str {
        use bolos::PIC;

        match self {
            Self::Mainnet => PIC::new(HRP_MAINNET).into_inner(),
            Self::Fuji => PIC::new(HRP_TESTNET).into_inner(),
            Self::Local => PIC::new(HRP_LOCAL).into_inner(),
        }
    }
}

impl TryFrom<u32> for NetworkId {
    type Error = ParserError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            NETWORK_ID_MAINNET => Ok(Self::Mainnet),
            NETWORK_ID_FUJI => Ok(Self::Fuji),
            NETWORK_ID_LOCAL => Ok(Self::Local),
            _ => Err(ParserError::InvalidNetworkId),
        }
    }
}

// bellow type defines the ID of supported
// chains, although in the protocol there is room for
// local networks, the current avalanche wallet does
// not support transactios from/to it
#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
#[cfg_attr(test, derive(Debug))]
pub enum ChainId {
    PChain,
    XChain,
    CChain,
}

impl TryFrom<&[u8; BLOCKCHAIN_ID_LEN]> for ChainId {
    type Error = ParserError;

    fn try_from(value: &[u8; BLOCKCHAIN_ID_LEN]) -> Result<Self, Self::Error> {
        use bolos::{pic_str, PIC};

        match chain_alias_lookup(value).map(|a| a.as_bytes()) {
            Ok(b"X") => Ok(Self::XChain),
            Ok(b"P") => Ok(Self::PChain),
            Ok(b"C") => Ok(Self::CChain),
            _ => Err(ParserError::InvalidChainId),
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct NetworkInfo {
    pub network_id: NetworkId,
    pub chain_id: ChainId,
}

impl TryFrom<(u32, &[u8; BLOCKCHAIN_ID_LEN])> for NetworkInfo {
    type Error = ParserError;

    fn try_from(value: (u32, &[u8; BLOCKCHAIN_ID_LEN])) -> Result<Self, Self::Error> {
        let network_id = NetworkId::try_from(value.0)?;
        let chain_id = ChainId::try_from(value.1)?;
        Ok(Self {
            network_id,
            chain_id,
        })
    }
}
