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

use bolos::{pic_str, PIC};
use nom::{bytes::complete::take, number::complete::be_u32};
use zemu_sys::ViewError;

use crate::{
    handlers::{handle_ui_message, resources::NFT_INFO},
    parser::{
        Address, AssetId, DisplayableItem, FromBytes, NftInfo, ParserError, ADDRESS_LEN,
        ETH_ARG_LEN,
    },
    utils::ApduPanic,
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct ERC721Info;

impl ERC721Info {
    pub fn get_nft_info() -> Result<&'static NftInfo, ParserError> {
        match unsafe { NFT_INFO.acquire(Self) } {
            Ok(Some(some)) => Ok(some),
            _ => Err(ParserError::NftInfoNotProvided),
        }
    }

    #[cfg(test)]
    pub fn set_info(info: NftInfo) -> Result<(), ParserError> {
        // store the information use to parse erc721 token
        unsafe {
            NFT_INFO
                .lock(Self)
                .map_err(|_| ParserError::UnexpectedError)?
                .replace(info);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "derive-debug"), derive(Debug))]
pub struct BaseTransfer<'b> {
    to: Address<'b>,
    from: Address<'b>,
    asset_id: AssetId<'b>,
}

impl<'b> DisplayableItem for BaseTransfer<'b> {
    fn num_items(&self) -> usize {
        3
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        // valid as at this point it was checked
        let nft_info = ERC721Info::get_nft_info().apdu_unwrap();

        match item_n {
            0 => {
                let label = pic_str!(b"To");
                title[..label.len()].copy_from_slice(label);

                // should not panic as address was check
                self.to.render_eth_address(message, page)
            }
            1 => {
                let label = pic_str!(b"Collection Name");
                title[..label.len()].copy_from_slice(label);

                nft_info.render_collection_name(message, page)
            }
            2 => {
                let label = pic_str!(b"TokenID");

                let res = self.asset_id.render_item(0, title, message, page);
                // Change title from Asse to Token
                title.iter_mut().for_each(|v| *v = 0);
                title[..label.len()].copy_from_slice(label);
                res
            }
            _ => Err(ViewError::NoData),
        }
    }
}

impl<'b> FromBytes<'b> for BaseTransfer<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        // get out pointer
        let out = out.as_mut_ptr();

        let from = unsafe { &mut *addr_of_mut!((*out).from).cast() };
        let (rem, address) = take(ETH_ARG_LEN)(input)?;

        //the first N bytes are for padding and are zeros
        let _ = Address::from_bytes_into(&address[ETH_ARG_LEN - ADDRESS_LEN..], from)?;

        let to = unsafe { &mut *addr_of_mut!((*out).to).cast() };
        let (rem, address) = take(ETH_ARG_LEN)(rem)?;

        //the first N bytes are for padding and are zeros
        let _ = Address::from_bytes_into(&address[ETH_ARG_LEN - ADDRESS_LEN..], to)?;

        // do not waste gas
        let to = unsafe { &*to.as_ptr() };
        let from = unsafe { &*from.as_ptr() };
        if to == from {
            return Err(ParserError::InvalidAddress.into());
        }

        // Asset/TOKEN id
        let asset_id = unsafe { &mut *addr_of_mut!((*out).asset_id).cast() };
        let rem = AssetId::from_bytes_into(rem, asset_id)?;

        Ok(rem)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "derive-debug"), derive(Debug))]
pub struct TransferFrom<'b> {
    base: BaseTransfer<'b>,
}

impl<'b> TransferFrom<'b> {
    pub const SELECTOR: u32 = u32::from_be_bytes([0x23, 0xb8, 0x72, 0xdd]);
}

impl<'b> FromBytes<'b> for TransferFrom<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("ERC721TransferFrom::from_bytes_into\x00");

        // get out pointer
        let out = out.as_mut_ptr();

        // base items
        let base = unsafe { &mut *addr_of_mut!((*out).base).cast() };
        let rem = BaseTransfer::from_bytes_into(input, base)?;

        Ok(rem)
    }
}

// SafeTrasnferFrom is an overloaded method,
// one variant holds a data field that is passed in the call.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "derive-debug"), derive(Debug))]
pub struct SafeTransferFrom<'b> {
    base: BaseTransfer<'b>,
    data: &'b [u8],
}

impl<'b> SafeTransferFrom<'b> {
    pub const SELECTOR: u32 = u32::from_be_bytes([0x42, 0x84, 0x2e, 0x0e]);
    pub const SELECTOR_DATA: u32 = u32::from_be_bytes([0xb8, 0x8d, 0x4f, 0xde]);
    const CALL_DATA_PREVIEW_LEN: usize = 15;
}

impl<'b> FromBytes<'b> for SafeTransferFrom<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("ERC721SafeTransferFrom::from_bytes_into\x00");

        // get out pointer
        let out = out.as_mut_ptr();

        // base items
        let base = unsafe { &mut *addr_of_mut!((*out).base).cast() };
        let rem = BaseTransfer::from_bytes_into(input, base)?;

        // data is the remaining bytes
        unsafe {
            addr_of_mut!((*out).data).write(rem);
        }

        Ok(&rem[rem.len()..])
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "derive-debug"), derive(Debug))]
pub struct Approve<'b> {
    controller: Address<'b>,
    asset_id: AssetId<'b>,
}

impl<'b> Approve<'b> {
    pub const SELECTOR: u32 = u32::from_be_bytes([0x09, 0x5e, 0xa7, 0xb3]);
}

impl<'b> FromBytes<'b> for Approve<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("ERC721Approve::from_bytes_into\x00");

        // get out pointer
        let out = out.as_mut_ptr();

        let spender = unsafe { &mut *addr_of_mut!((*out).controller).cast() };
        let (rem, address) = take(ETH_ARG_LEN)(input)?;
        //the first N bytes are for padding and are zeros
        let _ = Address::from_bytes_into(&address[ETH_ARG_LEN - ADDRESS_LEN..], spender)?;

        // Get the AssetID
        let asset = unsafe { &mut *addr_of_mut!((*out).asset_id).cast() };
        let (rem, raw_asset) = take(ETH_ARG_LEN)(rem)?;
        let _ = AssetId::from_bytes_into(raw_asset, asset);

        Ok(rem)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "derive-debug"), derive(Debug))]
pub struct ApprovalForAll<'b> {
    controller: Address<'b>,
    approve: bool,
}

impl<'b> ApprovalForAll<'b> {
    pub const SELECTOR: u32 = u32::from_be_bytes([0xa2, 0x2c, 0xb4, 0x65]);
}

impl<'b> FromBytes<'b> for ApprovalForAll<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("ERC721ApprovalForAll::from_bytes_into\x00");

        // get out pointer
        let out = out.as_mut_ptr();

        let spender = unsafe { &mut *addr_of_mut!((*out).controller).cast() };
        let (rem, address) = take(ETH_ARG_LEN)(input)?;
        //the first N bytes are for padding and are zeros
        let _ = Address::from_bytes_into(&address[ETH_ARG_LEN - ADDRESS_LEN..], spender)?;

        // Get approval
        let (rem, approval) = take(ETH_ARG_LEN)(rem)?;
        let approve = approval.iter().any(|v| *v == 1);

        unsafe {
            addr_of_mut!((*out).approve).write(approve);
        }

        Ok(rem)
    }
}

/// Represents a ERC721-like contract call
///
/// # ERC721-like
/// What we define as ERC721-like is when the selector (and arguments)
/// could be interpreted as being a call of the ERC721 specification
///
/// Namely, the following Solidity signatures are considered ERC721-like:
/**
```solidity
    event Transfer(address indexed _from, address indexed _to, uint256 indexed _tokenId);
    function safeSafeTransferFrom(address _from, address _to, uint256 _tokenId, bytes data) external payable;
    function safeSafeTransferFrom(address _from, address _to, uint256 _tokenId) external payable;
    function transferFrom(address _from, address _to, uint256 _tokenId) external payable;
    function approve(address _approved, uint256 _tokenId) external payable;
    function setApprovalForAll(address _operator, bool _approved) external;
    function getApproved(uint256 _tokenId) external view returns (address);
```
*/
/// # Exclusions
/// `public view` methods are excluded as those don't make sense to be called via a transaction
#[derive(Copy, Clone, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "derive-debug"), derive(Debug))]
#[avalanche_app_derive::enum_init]
pub enum ERC721<'b> {
    TransferFrom(TransferFrom<'b>),
    SafeTransferFrom(SafeTransferFrom<'b>),
    Approve(Approve<'b>),
    ApprovalForAll(ApprovalForAll<'b>),
}

impl ERC721__Type {
    pub fn from_selector(selector: u32) -> Option<Self> {
        match selector {
            TransferFrom::SELECTOR => Some(Self::TransferFrom),
            SafeTransferFrom::SELECTOR | SafeTransferFrom::SELECTOR_DATA => {
                Some(Self::SafeTransferFrom)
            }
            Approve::SELECTOR => Some(Self::Approve),
            ApprovalForAll::SELECTOR => Some(Self::ApprovalForAll),
            _ => None,
        }
    }
}

impl<'b> ERC721<'b> {
    pub fn method_name(&self) -> &'static [u8] {
        match self {
            ERC721::TransferFrom(_) => pic_str!(b"transferFrom"!),
            ERC721::SafeTransferFrom(_) => pic_str!(b"SafeTransferFrom"!),
            ERC721::Approve(_) => pic_str!(b"approve"!),
            ERC721::ApprovalForAll(_) => pic_str!(b"approvalForAll"!),
        }
    }

    pub fn parse_into(
        contract_address: &Address<'b>,
        data: &'b [u8],
        output: &mut MaybeUninit<Self>,
    ) -> Result<(), ParserError> {
        // a call data regarless the contract, consists of
        // - 4-bytes selector that are the first bytes
        // of the sha3("method_signature")
        // - a list or arguments, which can be empty,
        // each argument should be 32-bytes len.

        // Check the required information to parse this data was provided
        let nft_info = ERC721Info::get_nft_info()?;

        if contract_address != &nft_info.address() {
            return Err(ParserError::InvalidContractAddress);
        }

        // get selector
        let (rem, selector) = be_u32(data)?;

        let ty = ERC721__Type::from_selector(selector).ok_or(ParserError::InvalidEthSelector)?;

        match ty {
            ERC721__Type::TransferFrom => {
                let out = output.as_mut_ptr() as *mut TransferFrom__Variant;
                let item = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                _ = TransferFrom::from_bytes_into(rem, item)?;

                //no invalid ptrs
                unsafe {
                    addr_of_mut!((*out).0).write(ERC721__Type::TransferFrom);
                }
            }
            ERC721__Type::SafeTransferFrom => {
                let out = output.as_mut_ptr() as *mut SafeTransferFrom__Variant;
                let item = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                _ = SafeTransferFrom::from_bytes_into(rem, item)?;

                //no invalid ptrs
                unsafe {
                    addr_of_mut!((*out).0).write(ERC721__Type::SafeTransferFrom);
                }
            }
            ERC721__Type::Approve => {
                let out = output.as_mut_ptr() as *mut Approve__Variant;
                let item = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                _ = Approve::from_bytes_into(rem, item)?;

                //no invalid ptrs
                unsafe {
                    addr_of_mut!((*out).0).write(ERC721__Type::Approve);
                }
            }
            ERC721__Type::ApprovalForAll => {
                let out = output.as_mut_ptr() as *mut ApprovalForAll__Variant;
                let item = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                _ = ApprovalForAll::from_bytes_into(rem, item)?;

                //no invalid ptrs
                unsafe {
                    addr_of_mut!((*out).0).write(ERC721__Type::ApprovalForAll);
                }
            }
        }

        Ok(())
    }

    fn render_transfer_from(
        this: &TransferFrom<'_>,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        this.base.render_item(item_n, title, message, page)
    }

    fn render_safe_transfer_from(
        this: &SafeTransferFrom<'_>,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        match item_n {
            x @ 0.. if x < this.base.num_items() as u8 => {
                this.base.render_item(item_n, title, message, page)
            }
            _ => Err(ViewError::NoData),
        }
    }

    fn render_approve(
        this: &Approve<'_>,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        // this wont panic as it was checked at parsing
        let nft_info = ERC721Info::get_nft_info().apdu_unwrap();

        match item_n {
            0 => {
                let label = pic_str!(b"Allow");
                title[..label.len()].copy_from_slice(label);

                // should not panic as address was check
                this.controller.render_eth_address(message, page)
            }
            1 => {
                let label = pic_str!(b"To Manage your");
                title[..label.len()].copy_from_slice(label);
                nft_info.render_collection_name(message, page)
            }
            2 => {
                let res = this.asset_id.render_item(0, title, message, page);
                // Chanche title from Asse to Token
                let label = pic_str!(b"TokenID");
                title.iter_mut().for_each(|v| *v = 0);
                title[..label.len()].copy_from_slice(label);
                res
            }
            _ => Err(ViewError::NoData),
        }
    }

    fn render_approval_for_all(
        this: &ApprovalForAll<'_>,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        // valid as at this point it was checked
        let nft_info = ERC721Info::get_nft_info().apdu_unwrap();

        match item_n {
            0 => {
                let allow = pic_str!(b"Allow");
                let revoke = pic_str!(b"Revoke");
                if this.approve {
                    title[..allow.len()].copy_from_slice(allow);
                } else {
                    title[..revoke.len()].copy_from_slice(revoke);
                };

                // should not panic as address was check
                this.controller.render_eth_address(message, page)
            }
            1 => {
                let label = pic_str!(b"To Manage ALL");
                title[..label.len()].copy_from_slice(label);
                nft_info.render_collection_name(message, page)
            }
            _ => Err(ViewError::NoData),
        }
    }
}

impl<'b> DisplayableItem for ERC721<'b> {
    fn num_items(&self) -> usize {
        1 + match self {
            ERC721::TransferFrom(t) => t.base.num_items(),
            ERC721::SafeTransferFrom(t) => t.base.num_items(),
            ERC721::Approve(_) => 3,
            ERC721::ApprovalForAll(_) => 2,
        }
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        match item_n {
            0 => {
                let title_content = pic_str!(b"ERC-721");
                title[..title_content.len()].copy_from_slice(title_content);

                handle_ui_message(self.method_name(), message, page)
            }
            _x @ 1.. => match &self {
                ERC721::TransferFrom(call) => {
                    Self::render_transfer_from(call, item_n - 1, title, message, page)
                }
                ERC721::SafeTransferFrom(call) => {
                    Self::render_safe_transfer_from(call, item_n - 1, title, message, page)
                }
                ERC721::Approve(call) => {
                    Self::render_approve(call, item_n - 1, title, message, page)
                }
                ERC721::ApprovalForAll(call) => {
                    Self::render_approval_for_all(call, item_n - 1, title, message, page)
                }
            },
        }
    }
}
