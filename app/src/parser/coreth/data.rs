/*******************************************************************************
*   (c) 2022 Zondax AG
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

use core::mem::MaybeUninit;

use zemu_sys::ViewError;

use crate::parser::{Address, DisplayableItem, ParserError};

mod asset_call;
mod contract_call;
mod deploy;

#[cfg(feature = "erc20")]
mod erc20;
#[cfg(feature = "erc20")]
pub use erc20::ERC20;

#[cfg(feature = "erc721")]
mod erc721;
#[cfg(feature = "erc721")]
pub use erc721::{ERC721Info, ERC721};

use super::native::parse_rlp_item;
pub use asset_call::AssetCall;
pub use contract_call::ContractCall;
pub use deploy::Deploy;

#[avalanche_app_derive::enum_init]
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "derive-debug"), derive(Debug))]
pub enum EthData<'b> {
    None, // empty data
    Deploy(Deploy<'b>),
    AssetCall(AssetCall<'b>),
    ContractCall(ContractCall<'b>),
    #[cfg(feature = "erc20")]
    Erc20(ERC20<'b>),
    #[cfg(feature = "erc721")]
    Erc721(ERC721<'b>),
}

impl<'b> EthData<'b> {
    pub fn parse_into(
        to: &Option<Address<'b>>,
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], ParserError> {
        // parse the rlp data
        let (rem, data) = parse_rlp_item(input)?;
        match (to, data.is_empty()) {
            (None, true) => {
                // invalid condition as no address means
                // the transaction is a contract deploy so
                // the data field should not be empty
                return Err(ParserError::InvalidTransactionType);
            }
            // the address is None, which means this is a
            // contract creation.
            (None, false) => Self::parse_deploy(data, out)?,
            (Some(..), true) => {
                // As data is empty, this is a transfer
                // transaction
                Self::parse_none(out);
            }
            // contract call
            (Some(to), false) => {
                if AssetCall::is_asset_call(to, data) {
                    Self::parse_asset_call(data, out)?
                } else {
                    // chain contract parsing, prioritizing ERC-721
                    // if it fails try ERC-20, otherwise default to
                    // a generic contract call
                    cfg_if::cfg_if! {
                        if #[cfg(all(feature = "erc721", feature = "erc20"))] {
                            Self::parse_erc721(to, data, out)
                                .or_else(|_| Self::parse_erc20(data, out))
                                .or_else(|_| Self::parse_contract_call(data, out))?;
                        } else if #[cfg(feature = "erc721")] {
                            Self::parse_erc721(to, data, out)
                                .or_else(|_| Self::parse_contract_call(data, out))?;
                        } else if #[cfg(feature = "erc20")] {
                            Self::parse_erc20(data, out)
                                .or_else(|_| Self::parse_contract_call(data, out))?;
                        } else {
                            Self::parse_contract_call(data, out)?;
                        }
                    }
                }
            }
        };
        Ok(rem)
    }

    fn parse_none(out: &mut MaybeUninit<Self>) {
        out.write(Self::None);
    }

    fn parse_deploy(data: &'b [u8], out: &mut MaybeUninit<Self>) -> Result<(), ParserError> {
        if data.is_empty() {
            return Err(ParserError::NoData);
        }

        // read all the data as the contract deployment
        // we do not have a way to verify this data. in the worst scenario
        // the transaction would be rejected, and for this reason
        // It is shown on the screen(partially) for the user to review.
        Self::init_as_deploy(|deploy| Deploy::parse_into(data, deploy), out)
    }

    fn parse_asset_call(data: &'b [u8], out: &mut MaybeUninit<Self>) -> Result<(), ParserError> {
        if data.is_empty() {
            return Err(ParserError::NoData);
        }

        Self::init_as_asset_call(|asset| AssetCall::parse_into(data, asset), out)
    }

    #[cfg(feature = "erc20")]
    fn parse_erc20(data: &'b [u8], out: &mut MaybeUninit<Self>) -> Result<(), ParserError> {
        if data.is_empty() {
            return Err(ParserError::NoData);
        }

        Self::init_as_erc_20(|erc20| ERC20::parse_into(data, erc20), out)
    }

    #[cfg(feature = "erc721")]
    fn parse_erc721(
        contract_address: &Address<'b>,
        data: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<(), ParserError> {
        if data.is_empty() {
            return Err(ParserError::NoData);
        }

        Self::init_as_erc_721(
            |erc721| ERC721::parse_into(contract_address, data, erc721),
            out,
        )
    }

    fn parse_contract_call(data: &'b [u8], out: &mut MaybeUninit<Self>) -> Result<(), ParserError> {
        if data.is_empty() {
            return Err(ParserError::NoData);
        }

        Self::init_as_contract_call(|cc| ContractCall::parse_into(data, cc), out)
    }
}

impl<'b> DisplayableItem for EthData<'b> {
    fn num_items(&self) -> Result<u8, ViewError> {
        match self {
            Self::None => Ok(0),
            Self::Deploy(d) => d.num_items(),
            Self::AssetCall(d) => d.num_items(),
            #[cfg(feature = "erc20")]
            Self::Erc20(d) => d.num_items(),
            #[cfg(feature = "erc721")]
            Self::Erc721(d) => d.num_items(),
            Self::ContractCall(d) => d.num_items(),
        }
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        match self {
            Self::None => Err(ViewError::NoData),
            Self::Deploy(d) => d.render_item(item_n, title, message, page),
            Self::AssetCall(d) => d.render_item(item_n, title, message, page),
            #[cfg(feature = "erc20")]
            Self::Erc20(d) => d.render_item(item_n, title, message, page),
            #[cfg(feature = "erc721")]
            Self::Erc721(d) => d.render_item(item_n, title, message, page),
            Self::ContractCall(d) => d.render_item(item_n, title, message, page),
        }
    }
}
