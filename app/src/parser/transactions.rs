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

mod base_tx;
mod export_tx;
mod import_tx;

use core::convert::TryFrom;

use crate::parser::constants::*;
use crate::parser::ParserError;

pub use base_tx::{BaseTx, BLOCKCHAIN_ID_LEN};
pub use export_tx::ExportTx;
pub use import_tx::ImportTx;

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
#[cfg_attr(test, derive(Debug))]
pub enum PvmTransactionTypes {
    AddValidator,
    AddSubnetValidator,
    AddDelegator,
    CreateChain,
    CreateSubnet,
    Export,
    Import,
}

impl TryFrom<u32> for PvmTransactionTypes {
    type Error = ParserError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        let res = match value {
            PVM_CREATE_SUBNET => Self::CreateSubnet,
            PVM_EXPORT_TX => Self::Export,
            PVM_IMPORT_TX => Self::Import,
            PVM_ADD_VALIDATOR => Self::AddValidator,
            PVM_ADD_SUBNET_VALIDATOR => Self::AddSubnetValidator,
            PVM_ADD_DELEGATOR => Self::AddDelegator,
            PVM_CREATE_CHAIN => Self::CreateChain,
            _ => return Err(ParserError::InvalidNetworkId),
        };

        Ok(res)
    }
}

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
#[cfg_attr(test, derive(Debug))]
pub enum AvmTransactionTypes {
    CreateAsset,
    Operation,
    Export,
    Import,
}

impl TryFrom<u32> for AvmTransactionTypes {
    type Error = ParserError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        let res = match value {
            AVM_CREATE_ASSET_TX => Self::CreateAsset,
            AVM_OPERATION_TX => Self::Operation,
            AVM_IMPORT_TX => Self::Import,
            AVM_EXPORT_TX => Self::Export,
            _ => return Err(ParserError::InvalidNetworkId),
        };

        Ok(res)
    }
}

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
#[cfg_attr(test, derive(Debug))]
pub enum EvmTransactionTypes {
    Import,
    Export,
}

impl TryFrom<u32> for EvmTransactionTypes {
    type Error = ParserError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        let res = match value {
            EVM_IMPORT_TX => Self::Import,
            EVM_EXPORT_TX => Self::Export,
            _ => return Err(ParserError::InvalidNetworkId),
        };

        Ok(res)
    }
}

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
#[cfg_attr(test, derive(Debug))]
pub enum TransactionType {
    Avm(AvmTransactionTypes),
    Evm(EvmTransactionTypes),
    Pvm(PvmTransactionTypes),
}

impl TransactionType {
    pub fn is_pvm_tx(&self) -> bool {
        matches!(self, Self::Pvm(..))
    }

    pub fn is_avm_tx(&self) -> bool {
        matches!(self, Self::Avm(..))
    }

    pub fn is_evm_tx(&self) -> bool {
        matches!(self, Self::Evm(..))
    }
}

impl TryFrom<(&[u8; BLOCKCHAIN_ID_LEN], u32)> for TransactionType {
    type Error = ParserError;

    fn try_from(value: (&[u8; BLOCKCHAIN_ID_LEN], u32)) -> Result<Self, Self::Error> {
        todo!()
    }
}
