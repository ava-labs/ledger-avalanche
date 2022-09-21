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
use nom::number::complete::be_u32;
use zemu_sys::ViewError;

use crate::{
    handlers::{
        eth::{u256, BorrowedU256},
        handle_ui_message,
    },
    parser::{coreth::parse_rlp_item, Address, DisplayableItem, FromBytes, ParserError},
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct Transfer<'b> {
    to: Address<'b>,
    value: BorrowedU256<'b>,
}

impl<'b> Transfer<'b> {
    pub const SELECTOR: u32 = 0xa9059cbb;
}

impl<'b> FromBytes<'b> for Transfer<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("ERC20Transfer::from_bytes_into\x00");

        // get out pointer
        let out = out.as_mut_ptr();

        let to = unsafe { &mut *addr_of_mut!((*out).to).cast() };
        let rem = Address::from_bytes_into(input, to)?;

        // value
        let (rem, value) = parse_rlp_item(rem)?;
        let value = BorrowedU256::new(value).ok_or(ParserError::InvalidEthMessage)?;

        unsafe {
            addr_of_mut!((*out).value).write(value);
        }

        Ok(rem)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct TransferFrom<'b> {
    from: Address<'b>,
    to: Address<'b>,
    value: BorrowedU256<'b>,
}

impl<'b> TransferFrom<'b> {
    pub const SELECTOR: u32 = 0x23b872dd;
}

impl<'b> FromBytes<'b> for TransferFrom<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("ERC20TransferFrom::from_bytes_into\x00");

        // get out pointer
        let out = out.as_mut_ptr();

        let from = unsafe { &mut *addr_of_mut!((*out).from).cast() };
        let rem = Address::from_bytes_into(input, from)?;

        let to = unsafe { &mut *addr_of_mut!((*out).to).cast() };
        let rem = Address::from_bytes_into(rem, to)?;

        // value
        let (rem, value) = parse_rlp_item(rem)?;
        let value = BorrowedU256::new(value).ok_or(ParserError::InvalidEthMessage)?;

        unsafe {
            addr_of_mut!((*out).value).write(value);
        }

        Ok(rem)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct Approve<'b> {
    spender: Address<'b>,
    value: BorrowedU256<'b>,
}

impl<'b> Approve<'b> {
    pub const SELECTOR: u32 = 0x095ea7b3;
}

impl<'b> FromBytes<'b> for Approve<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("ERC20Approve::from_bytes_into\x00");

        // get out pointer
        let out = out.as_mut_ptr();

        let spender = unsafe { &mut *addr_of_mut!((*out).spender).cast() };
        let rem = Address::from_bytes_into(input, spender)?;

        // value
        let (rem, value) = parse_rlp_item(rem)?;
        let value = BorrowedU256::new(value).ok_or(ParserError::InvalidEthMessage)?;

        unsafe {
            addr_of_mut!((*out).value).write(value);
        }

        Ok(rem)
    }
}

/// Represents a ERC20-like contract call
///
/// # ERC20-like
/// What we define as ERC20-like is when the selector (and arguments)
/// could be interpreted as being a call of the ERC20 specification
///
/// Namely, the following Solidity signatures are considered ERC20-like:
/**
```solidity
function name() public view returns (string)
function symbol() public view returns (string)
function decimals() public view returns (uint8)
function totalSupply() public view returns (uint256)
function balanceOf(address _owner) public view returns (uint256 balance)
function transfer(address _to, uint256 _value) public returns (bool success)
function transferFrom(address _from, address _to, uint256 _value) public returns (bool success)
function approve(address _spender, uint256 _value) public returns (bool success)
function allowance(address _owner, address _spender) public view returns (uint256 remaining)
```
*/
/// # Exclusions
/// `public view` methods are excluded as those don't make sense to be called via a transaction
#[derive(Copy, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
#[avalanche_app_derive::enum_init]
pub enum ERC20<'b> {
    Transfer(Transfer<'b>),
    TransferFrom(TransferFrom<'b>),
    Approve(Approve<'b>),
}

impl ERC20__Type {
    pub fn from_selector(selector: u32) -> Option<Self> {
        match selector {
            Transfer::SELECTOR => Some(Self::Transfer),
            TransferFrom::SELECTOR => Some(Self::TransferFrom),
            Approve::SELECTOR => Some(Self::Approve),
            _ => None,
        }
    }
}

impl<'b> ERC20<'b> {
    pub fn method_name(&self) -> &'static [u8] {
        match self {
            ERC20::Transfer(_) => pic_str!(b"transfer"!),
            ERC20::TransferFrom(_) => pic_str!(b"transferFrom"!),
            ERC20::Approve(_) => pic_str!(b"approve"!),
        }
    }

    pub fn parse_into(data: &'b [u8], output: &mut MaybeUninit<Self>) -> Result<(), ParserError> {
        // a call data regarless the contract, consists of
        // - 4-bytes selector that are the first bytes
        // of the sha3("method_signature")
        // - a list or arguments, which can be empty,
        // each argument should be 32-bytes len.

        // get selector
        let (rem, selector) = be_u32(data)?;
        let ty = ERC20__Type::from_selector(selector).ok_or(ParserError::InvalidEthSelector)?;

        match ty {
            ERC20__Type::Transfer => {
                let out = output.as_mut_ptr() as *mut Transfer__Variant;
                let item = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                _ = Transfer::from_bytes_into(rem, item)?;

                //no invalid ptrs
                unsafe {
                    addr_of_mut!((*out).0).write(ty);
                }
            }
            ERC20__Type::TransferFrom => {
                let out = output.as_mut_ptr() as *mut TransferFrom__Variant;
                let item = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                _ = TransferFrom::from_bytes_into(rem, item)?;

                //no invalid ptrs
                unsafe {
                    addr_of_mut!((*out).0).write(ty);
                }
            }
            ERC20__Type::Approve => {
                let out = output.as_mut_ptr() as *mut Approve__Variant;
                let item = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                _ = Approve::from_bytes_into(rem, item)?;

                //no invalid ptrs
                unsafe {
                    addr_of_mut!((*out).0).write(ty);
                }
            }
        }

        Ok(())
    }

    fn render_transfer(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        let this = match self {
            ERC20::Transfer(t) => t,
            ERC20::TransferFrom(_) | ERC20::Approve(_) => unsafe {
                core::hint::unreachable_unchecked()
            },
        };

        match item_n {
            0 => {
                let label = pic_str!(b"To");
                title[..label.len()].copy_from_slice(label);

                // should not panic as address was check
                this.to.render_eth_address(message, page)
            }
            1 => {
                let label = pic_str!(b"Amount");
                title[..label.len()].copy_from_slice(label);

                let mut bytes = [0; u256::FORMATTED_SIZE_DECIMAL + 1];
                let bytes = this.value.to_u256().to_lexical(&mut bytes);

                handle_ui_message(bytes, message, page)
            }
            _ => Err(ViewError::NoData),
        }
    }

    fn render_transfer_from(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        let this = match self {
            ERC20::TransferFrom(t) => t,
            _ => unsafe { core::hint::unreachable_unchecked() },
        };

        match item_n {
            0 => {
                let label = pic_str!(b"From");
                title[..label.len()].copy_from_slice(label);

                // should not panic as address was check
                this.from.render_eth_address(message, page)
            }
            1 => {
                let label = pic_str!(b"To");
                title[..label.len()].copy_from_slice(label);

                // should not panic as address was check
                this.to.render_eth_address(message, page)
            }
            2 => {
                let label = pic_str!(b"Amount");
                title[..label.len()].copy_from_slice(label);

                let mut bytes = [0; u256::FORMATTED_SIZE_DECIMAL + 1];
                let bytes = this.value.to_u256().to_lexical(&mut bytes);

                handle_ui_message(bytes, message, page)
            }
            _ => Err(ViewError::NoData),
        }
    }

    fn render_approve(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        let this = match self {
            ERC20::Approve(t) => t,
            _ => unsafe { core::hint::unreachable_unchecked() },
        };

        match item_n {
            0 => {
                let label = pic_str!(b"To");
                title[..label.len()].copy_from_slice(label);

                // should not panic as address was check
                this.spender.render_eth_address(message, page)
            }
            1 => {
                let label = pic_str!(b"Amount");
                title[..label.len()].copy_from_slice(label);

                let mut bytes = [0; u256::FORMATTED_SIZE_DECIMAL + 1];
                let bytes = this.value.to_u256().to_lexical(&mut bytes);

                handle_ui_message(bytes, message, page)
            }
            _ => Err(ViewError::NoData),
        }
    }
}

impl<'b> DisplayableItem for ERC20<'b> {
    fn num_items(&self) -> usize {
        1 + match self {
            ERC20::Transfer(_) => 2,
            ERC20::TransferFrom(_) => 3,
            ERC20::Approve(_) => 2,
        }
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        if item_n != 0 {
            return Err(ViewError::NoData);
        }

        match item_n {
            0 => {
                let title_content = pic_str!(b"ERC-20");
                title[..title_content.len()].copy_from_slice(title_content);

                handle_ui_message(self.method_name(), message, page)
            }
            x @ 1.. => match self {
                ERC20::Transfer(_) => self.render_transfer(item_n - 1, title, message, page),
                ERC20::TransferFrom(_) => {
                    self.render_transfer_from(item_n - 1, title, message, page)
                }
                ERC20::Approve(_) => self.render_approve(item_n - 1, title, message, page),
            },
        }
    }
}
