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
    handlers::{eth::u256, handle_ui_message},
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
    pub nonce: &'b [u8],
    pub gas_price: &'b [u8],
    pub gas_limit: &'b [u8],
    pub to: Option<Address<'b>>,
    pub value: &'b [u8],
    pub data: EthData<'b>,
}
impl<'b> BaseLegacy<'b> {
    #[inline(never)]
    fn fee(&self) -> Result<u256, ParserError> {
        let gas_price = u256::from_big_endian(self.gas_price);
        let gas_limit = u256::from_big_endian(self.gas_limit);

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
                let label = pic_str!(b"Transfer(AVAX)");
                title[..label.len()].copy_from_slice(label);

                render_u256(self.value, WEI_AVAX_DIGITS, message, page)
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

                render_u256(self.gas_limit, 0, message, page)
            }

            2 if render_funding => {
                let label = pic_str!(b"Funding Contract");
                title[..label.len()].copy_from_slice(label);

                render_u256(self.value, WEI_NAVAX_DIGITS, message, page)
            }
            x @ 2.. if !render_funding && x == 2 || render_funding && x == 3 => {
                self.data.render_item(0, title, message, page)
            }
            x @ 3.. if x as usize == self.num_items() - 1 => {
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
        let render_fee = self.num_items() as u8 - 1;

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
                let label = pic_str!(b"Transfer(AVAX)");
                title[..label.len()].copy_from_slice(label);

                render_u256(self.value, WEI_AVAX_DIGITS, message, page)
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
            2 => self.data.render_item(0, title, message, page),
            3 => {
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

        // gas price"
        let (rem, gas_price) = parse_rlp_item(rem)?;

        // gase limit
        let (rem, gas_limit) = parse_rlp_item(rem)?;

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

        let data_out = unsafe { &mut *addr_of_mut!((*out).data).cast() };
        let rem = EthData::parse_into(&address, rem, data_out)?;

        // If this is an asset call transaction, checks that there is not
        // value being sent, which would be definately loss
        let eth_data = unsafe { &*data_out.as_ptr() };
        if matches!(eth_data, EthData::AssetCall(..)) && value_bytes.iter().any(|v| *v != 0) {
            return Err(ParserError::InvalidAssetCall.into());
        }

        unsafe {
            addr_of_mut!((*out).nonce).write(nonce);
            addr_of_mut!((*out).gas_price).write(gas_price);
            addr_of_mut!((*out).gas_limit).write(gas_limit);
            addr_of_mut!((*out).to).write(address);
            addr_of_mut!((*out).value).write(value_bytes);
        }

        Ok(rem)
    }
}

impl<'b> DisplayableItem for BaseLegacy<'b> {
    fn num_items(&self) -> usize {
        // The type of the data field defines how a transaction
        // info is displayed.
        match self.data {
            // description, gas limit, funding contract(if value != zero), maximun fee and data.items
            EthData::Deploy(d) => 1 + 1 + 1 + d.num_items() + !self.value.is_empty() as usize,
            // render a simple Transfer, to, fee
            EthData::None => 1 + 1 + 1,
            // asset items + fee
            EthData::AssetCall(d) => d.num_items() + 1,
            // amount, address, fee and contract_data
            EthData::ContractCall(d) => 1 + 1 + 1 + d.num_items(),
        }
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
        }
    }
}
