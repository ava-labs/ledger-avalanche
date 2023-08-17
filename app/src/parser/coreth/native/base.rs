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

use bolos::{pic_str, PIC};
use core::{mem::MaybeUninit, ptr::addr_of_mut};
use zemu_sys::ViewError;

use super::parse_rlp_item;
use crate::{
    checked_add,
    handlers::{
        eth::{u256, BorrowedU256},
        handle_ui_message,
    },
    parser::{
        intstr_to_fpstr_inplace, Address, DisplayableItem, EthData, FromBytes, ParserError,
        ADDRESS_LEN, WEI_AVAX_DIGITS, WEI_NAVAX_DIGITS,
    },
    utils::ApduPanic,
};

use super::render_u256;

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct BaseLegacy<'b> {
    pub nonce: BorrowedU256<'b>,
    pub gas_price: BorrowedU256<'b>,
    pub gas_limit: BorrowedU256<'b>,
    pub to: Option<Address<'b>>,
    pub value: BorrowedU256<'b>,
    pub data: EthData<'b>,
}
impl<'b> BaseLegacy<'b> {
    #[inline(never)]
    fn fee(&self) -> Result<u256, ParserError> {
        let f = u256::pic_from_big_endian();
        let gas_price = f(&self.gas_price);
        let gas_limit = f(&self.gas_limit);

        gas_price
            .checked_mul(gas_limit)
            .ok_or(ParserError::OperationOverflows)
    }

    #[inline(never)]
    fn render_transfer(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        match item_n {
            0 => {
                let label = pic_str!(b"Transfer");
                title[..label.len()].copy_from_slice(label);

                let curr = pic_str!(b"AVAX "!);
                let (prefix, message) = message.split_at_mut(curr.len());
                prefix.copy_from_slice(curr);

                render_u256(&self.value, WEI_AVAX_DIGITS, message, page)
            }

            1 => {
                let label = pic_str!(b"To");
                title[..label.len()].copy_from_slice(label);

                // should not panic as address was check
                self.to
                    .as_ref()
                    .apdu_unwrap()
                    .render_eth_address(message, page)
            }
            2 => {
                let label = pic_str!(b"Fee(GWEI)");
                title[..label.len()].copy_from_slice(label);

                self.render_fee(message, page)
            }

            _ => Err(ViewError::NoData),
        }
    }

    #[inline(never)]
    fn render_deploy(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        let render_funding = !self.value.is_empty();
        match item_n {
            0 => {
                let label = pic_str!(b"Contract");
                title[..label.len()].copy_from_slice(label);

                let content = pic_str!(b"Creation");
                handle_ui_message(&content[..], message, page)
            }

            1 => {
                let label = pic_str!(b"Gas Limit");
                title[..label.len()].copy_from_slice(label);

                render_u256(&self.gas_limit, 0, message, page)
            }

            2 if render_funding => {
                let label = pic_str!(b"Funding Contract");
                title[..label.len()].copy_from_slice(label);

                render_u256(&self.value, WEI_NAVAX_DIGITS, message, page)
            }
            x @ 2.. if !render_funding && x == 2 || render_funding && x == 3 => {
                self.data.render_item(0, title, message, page)
            }
            x @ 3.. if x == self.num_items()? - 1 => {
                let label = pic_str!(b"Maximum Fee(GWEI)");
                title[..label.len()].copy_from_slice(label);

                self.render_fee(message, page)
            }

            _ => Err(ViewError::NoData),
        }
    }

    fn render_asset_call(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        let render_fee = self.num_items()? - 1;

        match item_n {
            x @ 0.. if x < render_fee => self.data.render_item(item_n, title, message, page),
            x if x == render_fee => {
                let label = pic_str!(b"Maximum Fee");
                title[..label.len()].copy_from_slice(label);

                self.render_fee(message, page)
            }

            _ => Err(ViewError::NoData),
        }
    }

    #[inline(never)]
    fn render_contract_call(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        match item_n {
            0 => {
                let label = pic_str!(b"Contract");
                title[..label.len()].copy_from_slice(label);
                let content = pic_str!(b"Call");

                handle_ui_message(content, message, page)
            }
            1 => {
                let label = pic_str!(b"Transfer");
                title[..label.len()].copy_from_slice(label);

                let curr = pic_str!(b"AVAX "!);
                let (prefix, message) = message.split_at_mut(curr.len());
                prefix.copy_from_slice(curr);

                render_u256(&self.value, WEI_AVAX_DIGITS, message, page)
            }
            2 => {
                let label = pic_str!(b"To");
                title[..label.len()].copy_from_slice(label);

                // should not panic as address was check
                self.to
                    .as_ref()
                    .apdu_unwrap()
                    .render_eth_address(message, page)
            }
            3 => self.data.render_item(0, title, message, page),
            4 => {
                let label = pic_str!(b"Maximun Fee(GWEI)");
                title[..label.len()].copy_from_slice(label);

                self.render_fee(message, page)
            }

            _ => Err(ViewError::NoData),
        }
    }

    #[inline(never)]
    #[cfg(feature = "erc20")]
    fn render_erc20_call(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        let erc20 = match self.data {
            EthData::Erc20(erc20) => erc20,
            _ => unsafe { core::hint::unreachable_unchecked() },
        };

        let num_items = erc20.num_items()?;

        match item_n {
            item_n @ 0.. if item_n < num_items => erc20.render_item(item_n, title, message, page),
            x @ 0.. if x == num_items => {
                let label = pic_str!(b"Contract");
                title[..label.len()].copy_from_slice(label);

                // should not panic as address was check
                self.to
                    .as_ref()
                    .apdu_unwrap()
                    .render_eth_address(message, page)
            }
            x @ 0.. if x == num_items + 1 => {
                let label = pic_str!(b"Maximun Fee(GWEI)");
                title[..label.len()].copy_from_slice(label);

                self.render_fee(message, page)
            }

            _ => Err(ViewError::NoData),
        }
    }

    #[inline(never)]
    #[cfg(feature = "erc721")]
    fn render_erc721_call(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        let erc721 = match self.data {
            EthData::Erc721(erc721) => erc721,
            _ => unsafe { core::hint::unreachable_unchecked() },
        };

        let num_items = erc721.num_items()?;

        match item_n {
            item_n @ 0.. if item_n < num_items => erc721.render_item(item_n, title, message, page),
            x @ 0.. if x == num_items => {
                let label = pic_str!(b"Contract");
                title[..label.len()].copy_from_slice(label);

                // should not panic as address was check
                self.to
                    .as_ref()
                    .apdu_unwrap()
                    .render_eth_address(message, page)
            }
            x @ 0.. if x == num_items + 1 => {
                let label = pic_str!(b"Maximun Fee(GWEI)");
                title[..label.len()].copy_from_slice(label);

                self.render_fee(message, page)
            }

            _ => Err(ViewError::NoData),
        }
    }

    #[inline(never)]
    fn render_fee(&self, message: &mut [u8], page: u8) -> Result<u8, ViewError> {
        let mut bytes = [0; u256::FORMATTED_SIZE_DECIMAL + 2];

        let fee = self.fee().map_err(|_| ViewError::Unknown)?;
        fee.to_lexical(&mut bytes);

        let out = intstr_to_fpstr_inplace(&mut bytes, WEI_NAVAX_DIGITS)
            .map_err(|_| ViewError::Unknown)?;

        handle_ui_message(out, message, page)
    }
}

impl<'b> FromBytes<'b> for BaseLegacy<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("EthBase::from_bytes_into\x00");

        // get out pointer
        let out = out.as_mut_ptr();

        // nonce
        let (rem, nonce) = parse_rlp_item(input)?;
        let nonce = BorrowedU256::new(nonce).ok_or(ParserError::InvalidEthMessage)?;

        // gas price"
        let (rem, gas_price) = parse_rlp_item(rem)?;
        let gas_price = BorrowedU256::new(gas_price).ok_or(ParserError::InvalidEthMessage)?;

        // gase limit
        let (rem, gas_limit) = parse_rlp_item(rem)?;
        let gas_limit = BorrowedU256::new(gas_limit).ok_or(ParserError::InvalidEthMessage)?;

        // to
        let (rem, raw_address) = parse_rlp_item(rem)?;

        let address = match raw_address.len() {
            0 => None,
            x if x == ADDRESS_LEN => {
                let mut addr = MaybeUninit::uninit();
                _ = Address::from_bytes_into(raw_address, &mut addr)?;
                Some(unsafe { addr.assume_init() })
            }
            _ => return Err(ParserError::InvalidAddress.into()),
        };

        // value
        let (rem, value_bytes) = parse_rlp_item(rem)?;
        let value = BorrowedU256::new(value_bytes).ok_or(ParserError::InvalidEthMessage)?;

        let data_out = unsafe { &mut *addr_of_mut!((*out).data).cast() };
        let rem = EthData::parse_into(&address, rem, data_out)?;

        // If this is an asset call transaction, checks that there is not
        // value being sent, which would be definately loss
        let eth_data = unsafe { &*data_out.as_ptr() };
        if matches!(eth_data, EthData::AssetCall(..)) && !value.is_zero() {
            return Err(ParserError::InvalidAssetCall.into());
        }

        unsafe {
            addr_of_mut!((*out).nonce).write(nonce);
            addr_of_mut!((*out).gas_price).write(gas_price);
            addr_of_mut!((*out).gas_limit).write(gas_limit);
            addr_of_mut!((*out).to).write(address);
            addr_of_mut!((*out).value).write(value);
        }

        Ok(rem)
    }
}

impl<'b> DisplayableItem for BaseLegacy<'b> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // The type of the data field defines how a transaction
        // info is displayed.
        let items = match self.data {
            // description, gas limit, funding contract(if value != zero), maximun fee and data.items
            EthData::Deploy(d) => checked_add!(
                ViewError::Unknown,
                3u8,
                d.num_items()?,
                !self.value.is_empty() as u8
            )?,
            // render a simple Transfer, to, fee
            EthData::None => 1 + 1 + 1,
            // asset items + fee
            EthData::AssetCall(d) => d.num_items()?.checked_add(1).ok_or(ViewError::Unknown)?,
            // description amount, address, fee and contract_data
            EthData::ContractCall(d) => d.num_items()?.checked_add(4).ok_or(ViewError::Unknown)?,
            // address, fee
            #[cfg(feature = "erc20")]
            EthData::Erc20(d) => d.num_items()?.checked_add(2).ok_or(ViewError::Unknown)?,
            // contract address, fee
            #[cfg(feature = "erc721")]
            EthData::Erc721(d) => d.num_items()?.checked_add(2).ok_or(ViewError::Unknown)?,
        };

        Ok(items)
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        match self.data {
            EthData::None => self.render_transfer(item_n, title, message, page),
            EthData::Deploy(..) => self.render_deploy(item_n, title, message, page),
            EthData::AssetCall(..) => self.render_asset_call(item_n, title, message, page),
            EthData::ContractCall(..) => self.render_contract_call(item_n, title, message, page),
            #[cfg(feature = "erc20")]
            EthData::Erc20(..) => self.render_erc20_call(item_n, title, message, page),
            #[cfg(feature = "erc721")]
            EthData::Erc721(..) => self.render_erc721_call(item_n, title, message, page),
        }
    }
}
