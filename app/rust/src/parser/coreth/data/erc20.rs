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
    handlers::{
        eth::{u256, BorrowedU256},
        handle_ui_message,
    },
    parser::{Address, DisplayableItem, FromBytes, ParserError, ADDRESS_LEN, ETH_ARG_LEN},
};

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
#[avalanche_app_derive::enum_init]
#[derive(Copy, Clone, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "derive-debug"), derive(Debug))]
pub enum ERC20<'b> {
    Transfer {
        contract_address: Address<'b>,
        to: Address<'b>,
        value: BorrowedU256<'b>,
    },
    TransferFrom {
        contract_address: Address<'b>,
        from: Address<'b>,
        to: Address<'b>,
        value: BorrowedU256<'b>,
    },
    Approve {
        contract_address: Address<'b>,
        spender: Address<'b>,
        value: BorrowedU256<'b>,
    },
}

impl Transfer<'_> {
    pub const SELECTOR: u32 = u32::from_be_bytes([0xa9, 0x05, 0x9c, 0xbb]);
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
        let (rem, address) = take(ETH_ARG_LEN)(input)?;
        //the first N bytes are for padding and are zeros
        let _ = Address::from_bytes_into(&address[ETH_ARG_LEN - ADDRESS_LEN..], to)?;

        // value
        let (rem, value) = take(ETH_ARG_LEN)(rem)?;
        let value = BorrowedU256::new(value).ok_or(ParserError::InvalidEthMessage)?;

        unsafe {
            addr_of_mut!((*out).value).write(value);
        }

        Ok(rem)
    }
}

impl TransferFrom<'_> {
    pub const SELECTOR: u32 = u32::from_be_bytes([0x23, 0xb8, 0x72, 0xdd]);
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

        // value
        let (rem, value) = take(ETH_ARG_LEN)(rem)?;
        let value = BorrowedU256::new(value).ok_or(ParserError::InvalidEthMessage)?;

        unsafe {
            addr_of_mut!((*out).value).write(value);
        }

        Ok(rem)
    }
}

impl Approve<'_> {
    pub const SELECTOR: u32 = u32::from_be_bytes([0x09, 0x5e, 0xa7, 0xb3]);
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
        let (rem, address) = take(ETH_ARG_LEN)(input)?;
        //the first N bytes are for padding and are zeros
        let _ = Address::from_bytes_into(&address[ETH_ARG_LEN - ADDRESS_LEN..], spender)?;

        // value
        let (rem, value) = take(ETH_ARG_LEN)(rem)?;
        let value = BorrowedU256::new(value).ok_or(ParserError::InvalidEthMessage)?;

        unsafe {
            addr_of_mut!((*out).value).write(value);
        }

        Ok(rem)
    }
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
            ERC20::Transfer { .. } => pic_str!(b"transfer"!),
            ERC20::TransferFrom { .. } => pic_str!(b"transferFrom"!),
            ERC20::Approve { .. } => pic_str!(b"approve"!),
        }
    }

    pub fn parse_into(
        contract_address: &Address<'b>,
        data: &'b [u8],
        output: &mut MaybeUninit<Self>
    ) -> Result<(), ParserError> {
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
                Self::init_as_transfer(|item| {
                    let out = item.as_mut_ptr();
                    
                    // Store contract address first
                    unsafe {
                        addr_of_mut!((*out).contract_address).write(*contract_address);
                    }
                    
                    // Parse transfer data
                    Transfer::from_bytes_into(rem, item)
                }, output)
            }
            ERC20__Type::TransferFrom => {
                Self::init_as_transfer_from(|item| {
                    let out = item.as_mut_ptr();
                    
                    // Store contract address first
                    unsafe {
                        addr_of_mut!((*out).contract_address).write(*contract_address);
                    }
                    
                    // Parse transfer_from data
                    TransferFrom::from_bytes_into(rem, item)
                }, output)
            }
            ERC20__Type::Approve => {
                Self::init_as_approve(|item| {
                    let out = item.as_mut_ptr();
                    
                    // Store contract address first
                    unsafe {
                        addr_of_mut!((*out).contract_address).write(*contract_address);
                    }
                    
                    // Parse approve data
                    Approve::from_bytes_into(rem, item)
                }, output)
            }
        }?;

        Ok(())
    }

    fn render_transfer(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        let (contract_address, to, value) = match &self {
            Self::Transfer { contract_address, to, value } => (contract_address, to, value),
            _ => unsafe { core::hint::unreachable_unchecked() },
        };

        match item_n {
            0 => {
                let label = pic_str!(b"To");
                title[..label.len()].copy_from_slice(label);

                // should not panic as address was check
                to.render_eth_address(message, page)
            }
            1 => {
                let label = pic_str!(b"Amount");
                title[..label.len()].copy_from_slice(label);

                format_token_amount(value, contract_address, message, page)
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
        let (contract_address, from, to, value) = match &self {
            Self::TransferFrom { contract_address, from, to, value } => (contract_address, from, to, value),
            _ => unsafe { core::hint::unreachable_unchecked() },
        };

        match item_n {
            0 => {
                let label = pic_str!(b"From");
                title[..label.len()].copy_from_slice(label);

                // should not panic as address was check
                from.render_eth_address(message, page)
            }
            1 => {
                let label = pic_str!(b"To");
                title[..label.len()].copy_from_slice(label);

                // should not panic as address was check
                to.render_eth_address(message, page)
            }
            2 => {
                let label = pic_str!(b"Amount");
                title[..label.len()].copy_from_slice(label);

                format_token_amount(value, contract_address, message, page)
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
        let (contract_address, spender, value) = match &self {
            Self::Approve { contract_address, spender, value } => (contract_address, spender, value),
            _ => unsafe { core::hint::unreachable_unchecked() },
        };

        match item_n {
            0 => {
                let label = pic_str!(b"To");
                title[..label.len()].copy_from_slice(label);

                // should not panic as address was check
                spender.render_eth_address(message, page)
            }
            1 => {
                let label = pic_str!(b"Amount");
                title[..label.len()].copy_from_slice(label);

                format_token_amount(value, contract_address, message, page)
            }
            _ => Err(ViewError::NoData),
        }
    }
}

impl DisplayableItem for ERC20<'_> {
    fn num_items(&self) -> Result<u8, ViewError> {
        let items = match self {
            ERC20::Transfer { .. } => 2,
            ERC20::TransferFrom { .. } => 3,
            ERC20::Approve { .. } => 2,
        };

        Ok(1 + items)
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
                let title_content = pic_str!(b"ERC-20");
                title[..title_content.len()].copy_from_slice(title_content);

                handle_ui_message(self.method_name(), message, page)
            }
            _x @ 1.. => match &self {
                ERC20::Transfer { .. } => self.render_transfer(item_n - 1, title, message, page),
                ERC20::TransferFrom { .. } => {
                    self.render_transfer_from(item_n - 1, title, message, page)
                }
                ERC20::Approve { .. } => self.render_approve(item_n - 1, title, message, page),
            },
        }
    }
}

fn get_token_info(contract_bytes: &[u8; ADDRESS_LEN]) -> Option<(&'static [u8], u8)> {
    match contract_bytes {
        // USDC
        [0xB9, 0x7E, 0xF9, 0xEf, 0x87, 0x34, 0xC7, 0x19, 0x04, 0xD8, 0x00, 0x2F, 0x8b, 0x6B, 0xc6, 0x6D, 0xd9, 0xc4, 0x8a, 0x6E] => Some((b"USDC", 6)),
        // USDC.e
        [0xA7, 0xD7, 0x07, 0x9b, 0x0F, 0xEa, 0xD9, 0x1F, 0x3e, 0x65, 0xf8, 0x6E, 0x89, 0x15, 0xCb, 0x59, 0xc1, 0xa4, 0xC6, 0x64] => Some((b"USDC.e", 6)),
        // EURC
        [0xC8, 0x91, 0xEB, 0x4c, 0xbd, 0xEf, 0xf6, 0xe0, 0x73, 0xe8, 0x59, 0xe9, 0x87, 0x81, 0x5E, 0xd1, 0x50, 0x5c, 0x2A, 0xCD] => Some((b"EURC", 18)),
        // USDT
        [0x97, 0x02, 0x23, 0x0A, 0x8E, 0xa5, 0x36, 0x01, 0xf5, 0xcD, 0x2d, 0xc0, 0x0f, 0xDB, 0xc1, 0x3d, 0x4d, 0xF4, 0xA8, 0xc7] => Some((b"USDT", 6)),
        // USDT.e
        [0xc7, 0x19, 0x84, 0x37, 0x98, 0x0c, 0x04, 0x1c, 0x80, 0x5A, 0x1E, 0xDc, 0xbA, 0x50, 0xc1, 0xCe, 0x5d, 0xb9, 0x51, 0x18] => Some((b"USDT.e", 6)),
        // 1INCH.e
        [0xd5, 0x01, 0x28, 0x15, 0x65, 0xbf, 0x77, 0x89, 0x22, 0x45, 0x23, 0x14, 0x4f, 0xe5, 0xd9, 0x8e, 0x8b, 0x28, 0xf2, 0x67] => Some((b"1INCH.e", 18)),
        // AAVE.e
        [0x63, 0xa7, 0x28, 0x06, 0x09, 0x8b, 0xd3, 0xd9, 0x52, 0x0c, 0xc4, 0x33, 0x56, 0xdd, 0x78, 0xaf, 0xe5, 0xd3, 0x86, 0xd9] => Some((b"AAVE.e", 18)),
        // ALPHA.e
        [0x21, 0x47, 0xef, 0xff, 0x67, 0x5e, 0x4a, 0x4e, 0xe1, 0xc2, 0xf9, 0x18, 0xd1, 0x81, 0xcd, 0xbd, 0x7a, 0x8e, 0x20, 0x8f] => Some((b"ALPHA.e", 18)),
        // BAT.e
        [0x98, 0x44, 0x3b, 0x96, 0xea, 0x4b, 0x08, 0x58, 0xfd, 0xf3, 0x21, 0x9c, 0xd1, 0x3e, 0x98, 0xc7, 0xa4, 0x69, 0x05, 0x88] => Some((b"BAT.e", 18)),
        // BUSD.e
        [0x19, 0x86, 0x0c, 0xcb, 0x0a, 0x68, 0xfd, 0x42, 0x13, 0xab, 0x9d, 0x82, 0x66, 0xf7, 0xbb, 0xf0, 0x5a, 0x8d, 0xde, 0x98] => Some((b"BUSD.e", 18)),
        // COMP.e
        [0xc3, 0x04, 0x8e, 0x19, 0xe7, 0x6c, 0xb9, 0xa3, 0xaa, 0x9d, 0x77, 0xd8, 0xc0, 0x3c, 0x29, 0xfc, 0x90, 0x6e, 0x24, 0x37] => Some((b"COMP.e", 18)),
        // CRV.e
        [0x24, 0x98, 0x48, 0xbe, 0xca, 0x43, 0xac, 0x40, 0x5b, 0x81, 0x02, 0xec, 0x90, 0xdd, 0x5f, 0x22, 0xca, 0x51, 0x3c, 0x06] => Some((b"CRV.e", 18)),
        // DAI.e
        [0xd5, 0x86, 0xe7, 0xf8, 0x44, 0xce, 0xa2, 0xf8, 0x7f, 0x50, 0x15, 0x26, 0x65, 0xbc, 0xbc, 0x2c, 0x27, 0x9d, 0x8d, 0x70] => Some((b"DAI.e", 18)),
        // GRT.e
        [0x8a, 0x0c, 0xac, 0x13, 0xc7, 0xda, 0x96, 0x5a, 0x31, 0x2f, 0x08, 0xea, 0x42, 0x29, 0xc3, 0x78, 0x69, 0xe8, 0x5c, 0xb9] => Some((b"GRT.e", 18)),
        // INFRA.e
        [0xa4, 0xfb, 0x4f, 0x0f, 0xf2, 0x43, 0x12, 0x62, 0xd2, 0x36, 0x77, 0x84, 0x95, 0x14, 0x5e, 0xcb, 0xc9, 0x75, 0xc3, 0x8b] => Some((b"INFRA.e", 18)),
        // LINK.e
        [0x59, 0x47, 0xbb, 0x27, 0x5c, 0x52, 0x10, 0x40, 0x05, 0x1d, 0x82, 0x39, 0x61, 0x92, 0x18, 0x1b, 0x41, 0x32, 0x27, 0xa3] => Some((b"LINK.e", 18)),
        // MKR.e
        [0x88, 0x12, 0x8f, 0xd4, 0xb2, 0x59, 0x55, 0x2a, 0x9a, 0x1d, 0x45, 0x7f, 0x43, 0x5a, 0x65, 0x27, 0xaa, 0xb7, 0x2d, 0x42] => Some((b"MKR.e", 18)),
        // SHIB.e
        [0x02, 0xd9, 0x80, 0xa0, 0xd7, 0xaf, 0x3f, 0xb7, 0xcf, 0x7d, 0xf8, 0xcb, 0x35, 0xd9, 0xed, 0xbc, 0xf3, 0x55, 0xf6, 0x65] => Some((b"SHIB.e", 18)),
        // SNX.e
        [0xbe, 0xc2, 0x43, 0xc9, 0x95, 0x40, 0x9e, 0x65, 0x20, 0xd7, 0xc4, 0x1e, 0x40, 0x4d, 0xa5, 0xde, 0xba, 0x4b, 0x20, 0x9b] => Some((b"SNX.e", 18)),
        // SUSHI.e
        [0x37, 0xb6, 0x08, 0x51, 0x9f, 0x91, 0xf7, 0x0f, 0x2e, 0xeb, 0x0e, 0x5e, 0xd9, 0xaf, 0x40, 0x61, 0x72, 0x2e, 0x4f, 0x76] => Some((b"SUSHI.e", 18)),
        // SWAP.e
        [0xc7, 0xb5, 0xd7, 0x2c, 0x83, 0x6e, 0x71, 0x8c, 0xda, 0x88, 0x88, 0xea, 0xf0, 0x37, 0x07, 0xfa, 0xef, 0x67, 0x50, 0x79] => Some((b"SWAP.e", 18)),
        // UMA.e
        [0x3b, 0xd2, 0xb1, 0xc7, 0xed, 0x8d, 0x39, 0x6d, 0xbb, 0x98, 0xde, 0xd3, 0xae, 0xbb, 0x41, 0x35, 0x0a, 0x5b, 0x23, 0x39] => Some((b"UMA.e", 18)),
        // UNI.e
        [0x8e, 0xba, 0xf2, 0x2b, 0x6f, 0x05, 0x3d, 0xff, 0xea, 0xf4, 0x6f, 0x4d, 0xd9, 0xef, 0xa9, 0x5d, 0x89, 0xba, 0x85, 0x80] => Some((b"UNI.e", 18)),
        // WBTC.e
        [0x50, 0xb7, 0x54, 0x56, 0x27, 0xa5, 0x16, 0x2f, 0x82, 0xa9, 0x92, 0xc3, 0x3b, 0x87, 0xad, 0xc7, 0x51, 0x87, 0xb2, 0x18] => Some((b"WBTC.e", 8)),
        // WETH.e
        [0x49, 0xd5, 0xc2, 0xbd, 0xff, 0xac, 0x6c, 0xe2, 0xbf, 0xdb, 0x66, 0x40, 0xf4, 0xf8, 0x0f, 0x22, 0x6b, 0xc1, 0x0b, 0xab] => Some((b"WETH.e", 18)),
        // WOO.e
        [0xab, 0xc9, 0x54, 0x7b, 0x53, 0x45, 0x19, 0xff, 0x73, 0x92, 0x1b, 0x1f, 0xba, 0x6e, 0x67, 0x2b, 0x5f, 0x58, 0xd0, 0x83] => Some((b"WOO.e", 18)),
        // YFI.e
        [0x9e, 0xaa, 0xc1, 0xb2, 0x3d, 0x93, 0x53, 0x65, 0xbd, 0x7b, 0x54, 0x2f, 0xe2, 0x2c, 0xee, 0xe2, 0x92, 0x2f, 0x52, 0xdc] => Some((b"YFI.e", 18)),
        // ZRX.e
        [0x59, 0x6f, 0xa4, 0x70, 0x43, 0xf9, 0x9a, 0x4e, 0x0f, 0x12, 0x22, 0x43, 0xb8, 0x41, 0xe5, 0x53, 0x75, 0xcd, 0xe0, 0xd2] => Some((b"ZRX.e", 18)),
        // WAVAX
        [0xB3, 0x1f, 0x66, 0xAA, 0x3C, 0x1e, 0x78, 0x53, 0x63, 0xF0, 0x87, 0x5A, 0x1B, 0x74, 0xE2, 0x7b, 0x85, 0xFD, 0x66, 0xc7] => Some((b"WAVAX", 18)),
        _ => None,
    }
}

const MAX_BUFFER_SIZE: usize = 64; // TODO : Review macro usage

// Helper function to format token amounts with decimals and symbols
pub fn format_token_amount(
    value: &BorrowedU256,
    contract_address: &Address,
    message: &mut [u8],
    page: u8,
) -> Result<u8, ViewError> {
    let contract_bytes = contract_address.raw_address();
    
    // Get token info directly
    if let Some((symbol, decimals)) = get_token_info(contract_bytes) {
        return format_amount_with_token(value, symbol, decimals, message, page);
    }
    
    // Fallback to raw value if token not found
    let mut bytes = [0; u256::FORMATTED_SIZE_DECIMAL + 1];
    let bytes = value.as_u256().to_lexical(&mut bytes);
    handle_ui_message(bytes, message, page)
}

fn format_amount_with_token(
    value: &BorrowedU256,
    symbol: &[u8],
    decimals: u8,
    message: &mut [u8],
    page: u8,
) -> Result<u8, ViewError> {
    // Use separate buffers to avoid borrowing conflicts
    let mut lexical_buffer = [0u8; u256::FORMATTED_SIZE_DECIMAL]; // TODO : Review macro usage
    let mut format_buffer = [0u8; MAX_BUFFER_SIZE]; // TODO : Review macro usage
    let mut final_buffer = [0u8; MAX_BUFFER_SIZE]; // TODO : Review macro usage
    
    // Convert to string
    let raw_str = value.as_u256().to_lexical(&mut lexical_buffer);
    
    // Apply decimal formatting
    let formatted = apply_decimals(raw_str, decimals, &mut format_buffer)?;
    
    // Add symbol
    let final_str = add_symbol(formatted, symbol, &mut final_buffer)?;
    
    handle_ui_message(final_str, message, page)
}

fn apply_decimals<'a>(input: &'a [u8], decimals: u8, buffer: &'a mut [u8]) -> Result<&'a [u8], ViewError> {
    if decimals == 0 {
        return Ok(input);
    }
    
    let input_len = input.len();
    let decimal_pos = decimals as usize;
    
    if input_len <= decimal_pos {
        // Add leading "0."
        let total_len = 2 + decimal_pos - input_len + input_len;
        if total_len >= buffer.len() { return Err(ViewError::Unknown); }
        
        buffer[0] = b'0';
        buffer[1] = b'.';
        
        // Add leading zeros
        for i in 0..(decimal_pos - input_len) {
            buffer[2 + i] = b'0';
        }
        
        // Copy original digits
        buffer[2 + decimal_pos - input_len..total_len].copy_from_slice(input);
        Ok(&buffer[..total_len])
    } else {
        // Insert decimal point
        let integer_len = input_len - decimal_pos;
        let total_len = input_len + 1;
        if total_len >= buffer.len() { return Err(ViewError::Unknown); }
        
        // Copy integer part
        buffer[..integer_len].copy_from_slice(&input[..integer_len]);
        buffer[integer_len] = b'.';
        buffer[integer_len + 1..total_len].copy_from_slice(&input[integer_len..]);
        
        Ok(&buffer[..total_len])
    }
}

fn add_symbol<'a>(formatted: &[u8], symbol: &[u8], buffer: &'a mut [u8]) -> Result<&'a [u8], ViewError> {
    let total_len = formatted.len() + 1 + symbol.len();
    if total_len >= buffer.len() { return Err(ViewError::Unknown); }
    
    // Copy formatted number to beginning
    buffer[..formatted.len()].copy_from_slice(formatted);
    buffer[formatted.len()] = b' ';
    buffer[formatted.len() + 1..total_len].copy_from_slice(symbol);
    
    Ok(&buffer[..total_len])
}
