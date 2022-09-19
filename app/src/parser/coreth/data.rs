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

use core::{mem::MaybeUninit, ptr::addr_of_mut};

use zemu_sys::ViewError;

use crate::parser::{Address, DisplayableItem, ParserError};

mod asset_call;
mod contract_call;
mod deploy;

use super::native::parse_rlp_item;
pub use asset_call::AssetCall;
pub use contract_call::ContractCall;
pub use deploy::Deploy;

// Important: do not change the repr attribute,
// as this type is use as the tag field
// for the EthData enum which has the same representation
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
#[repr(u8)]
pub enum EthDataType {
    None,
    Deploy,
    AssetCall,
    ContractCall,
}

// EthData enum variants
#[repr(C)]
struct DeployVariant<'b>(EthDataType, Deploy<'b>);

#[repr(C)]
struct NoneVariant(EthDataType);

#[repr(C)]
struct AssetCallVariant<'b>(EthDataType, AssetCall<'b>);

#[repr(C)]
struct ContractCallVariant<'b>(EthDataType, ContractCall<'b>);

#[derive(Clone, Copy, PartialEq, Eq)]
// DO not change the representation
// as it would cause unalignment issues
// with the EthDataType tag
#[repr(u8)]
#[cfg_attr(test, derive(Debug))]
pub enum EthData<'b> {
    None, // empty data
    Deploy(Deploy<'b>),
    AssetCall(AssetCall<'b>),
    ContractCall(ContractCall<'b>),
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
                    Self::parse_contract_call(data, out)?
                }
            }
        };
        Ok(rem)
    }

    fn parse_none(out: &mut MaybeUninit<Self>) {
        let out = out.as_mut_ptr() as *mut DeployVariant;

        //pointer is valid
        unsafe {
            addr_of_mut!((*out).0).write(EthDataType::None);
        }
    }

    fn parse_deploy(data: &'b [u8], out: &mut MaybeUninit<Self>) -> Result<(), ParserError> {
        if data.is_empty() {
            return Err(ParserError::NoData);
        }

        let out = out.as_mut_ptr() as *mut DeployVariant;

        let deploy = unsafe { &mut *addr_of_mut!((*out).1).cast() };

        // read all the data as the contract deployment
        // we do not have a way to verify this data. in the worst scenario
        // the transaction would be rejected, and for this reason
        // It is shown on the screen(partially) for the user to review.
        _ = Deploy::parse_into(data, deploy)?;

        //pointer is valid
        unsafe {
            addr_of_mut!((*out).0).write(EthDataType::Deploy);
        }

        Ok(())
    }

    fn parse_asset_call(data: &'b [u8], out: &mut MaybeUninit<Self>) -> Result<(), ParserError> {
        if data.is_empty() {
            return Err(ParserError::NoData);
        }

        let out = out.as_mut_ptr() as *mut AssetCallVariant;

        let asset_call = unsafe { &mut *addr_of_mut!((*out).1).cast() };

        _ = AssetCall::parse_into(data, asset_call)?;

        //pointer is valid
        unsafe {
            addr_of_mut!((*out).0).write(EthDataType::AssetCall);
        }

        Ok(())
    }

    fn parse_contract_call(data: &'b [u8], out: &mut MaybeUninit<Self>) -> Result<(), ParserError> {
        if data.is_empty() {
            return Err(ParserError::NoData);
        }

        let out = out.as_mut_ptr() as *mut ContractCallVariant;

        let contract_call = unsafe { &mut *addr_of_mut!((*out).1).cast() };

        _ = ContractCall::parse_into(data, contract_call)?;

        //pointer is valid
        unsafe {
            addr_of_mut!((*out).0).write(EthDataType::ContractCall);
        }

        Ok(())
    }
}

impl<'b> DisplayableItem for EthData<'b> {
    fn num_items(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Deploy(d) => d.num_items(),
            Self::AssetCall(d) => d.num_items(),
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
            Self::ContractCall(d) => d.render_item(item_n, title, message, page),
        }
    }
}
