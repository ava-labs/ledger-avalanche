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

use super::{parse_rlp_item, render_u256};
use crate::{
    handlers::{
        eth::{u256, BorrowedU256},
        handle_ui_message,
    },
    parser::{
        intstr_to_fpstr_inplace, Address, DisplayableItem, ERC721Info, EthData, FromBytes,
        ParserError, ADDRESS_LEN, WEI_AVAX_DIGITS, WEI_NAVAX_DIGITS,
    },
    utils::ApduPanic,
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct Eip1559<'b> {
    chain_id: &'b [u8],
    pub nonce: BorrowedU256<'b>,
    pub priority_fee: BorrowedU256<'b>,
    pub max_fee: BorrowedU256<'b>,
    pub gas_limit: BorrowedU256<'b>,
    // this transaction can deploy a contract too
    to: Option<Address<'b>>,
    pub value: BorrowedU256<'b>,
    data: EthData<'b>,
    access_list: &'b [u8],
    // R and S must be empty
    // so do not put and empty
    // field here, it is just to indicate
    // that they are expected
}

impl<'b> Eip1559<'b> {
    pub fn chain_id_low_byte(&self) -> u8 {
        self.chain_id.last().copied().apdu_unwrap()
    }
}

impl<'b> FromBytes<'b> for Eip1559<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("Eip1559::from_bytes_into\x00");

        // get out pointer
        let out = out.as_mut_ptr();

        // chainID
        let (rem, id_bytes) = parse_rlp_item(input)?;
        if id_bytes.len() < 1 {
            return Err(ParserError::InvalidChainId.into());
        }

        // nonce
        let (rem, nonce) = parse_rlp_item(rem)?;
        let nonce = BorrowedU256::new(nonce).ok_or(ParserError::InvalidEthMessage)?;

        // max_priority_fee
        let (rem, priority_fee) = parse_rlp_item(rem)?;
        let priority_fee = BorrowedU256::new(priority_fee).ok_or(ParserError::InvalidEthMessage)?;

        // max_fee
        let (rem, max_fee) = parse_rlp_item(rem)?;
        let max_fee = BorrowedU256::new(max_fee).ok_or(ParserError::InvalidEthMessage)?;

        // gas limit
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

        // EthData
        let data_out = unsafe { &mut *addr_of_mut!((*out).data).cast() };
        let rem = EthData::parse_into(&address, rem, data_out)?;

        // If this is an asset call transaction, checks that there is not
        // value being sent, which would be definately loss
        let eth_data = unsafe { &*data_out.as_ptr() };
        if matches!(eth_data, EthData::AssetCall(..)) && !value.is_zero() {
            return Err(ParserError::InvalidAssetCall.into());
        }

        // check for erc721 call and chainID
        let data = unsafe { &*data_out.as_ptr() };
        if matches!(data, EthData::Erc721(..)) {
            let chain_id = super::bytes_to_u64(id_bytes)?;
            let contract_chain_id = ERC721Info::get_nft_info()?.chain_id;
            if chain_id != contract_chain_id {
                return Err(ParserError::InvalidAssetCall.into());
            }
        }

        // access list
        let (rem, access_list) = parse_rlp_item(rem)?;

        if !rem.is_empty() {
            return Err(ParserError::UnexpectedData.into());
        }

        unsafe {
            addr_of_mut!((*out).nonce).write(nonce);
            addr_of_mut!((*out).priority_fee).write(priority_fee);
            addr_of_mut!((*out).max_fee).write(max_fee);
            addr_of_mut!((*out).gas_limit).write(gas_limit);
            addr_of_mut!((*out).to).write(address);
            addr_of_mut!((*out).value).write(value);
            addr_of_mut!((*out).chain_id).write(id_bytes);
            addr_of_mut!((*out).access_list).write(access_list);
        }

        Ok(rem)
    }
}

impl<'b> Eip1559<'b> {
    #[inline(never)]
    fn fee(&self) -> Result<u256, ParserError> {
        let f = u256::pic_from_big_endian();

        let priority_fee = f(&*self.priority_fee);
        let max_fee = f(&*self.max_fee);
        let gas_limit = f(&*self.gas_limit);

        let fee = priority_fee
            .checked_add(max_fee)
            .ok_or(ParserError::OperationOverflows)?;

        fee.checked_mul(gas_limit)
            .ok_or(ParserError::OperationOverflows)
    }

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

                render_u256(&self.value, WEI_AVAX_DIGITS, message, page)
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
                let label = pic_str!(b"Contract");
                title[..label.len()].copy_from_slice(label);
                let content = pic_str!(b"Call");

                handle_ui_message(content, message, page)
            }
            1 => {
                let label = pic_str!(b"Transfer(AVAX)");
                title[..label.len()].copy_from_slice(label);

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

        let num_items = erc20.num_items() as u8;

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

        let num_items = erc721.num_items() as u8;

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

    fn render_fee(&self, message: &mut [u8], page: u8) -> Result<u8, ViewError> {
        let mut bytes = [0; u256::FORMATTED_SIZE_DECIMAL + 2];

        let fee = self.fee().map_err(|_| ViewError::Unknown)?;
        fee.to_lexical(&mut bytes);

        let out = intstr_to_fpstr_inplace(&mut bytes, WEI_NAVAX_DIGITS)
            .map_err(|_| ViewError::Unknown)?;

        handle_ui_message(out, message, page)
    }
}

impl<'b> DisplayableItem for Eip1559<'b> {
    fn num_items(&self) -> usize {
        // The type of the data field defines how a transaction
        // info is displayed.
        match self.data {
            // render a simple Transfer, to, fee
            EthData::None => 1 + 1 + 1,
            // description, gas limit, funding contract(if value != zero), maximun fee and data.items
            EthData::Deploy(d) => 1 + 1 + 1 + d.num_items() + !self.value.is_empty() as usize,
            // asset items + fee
            EthData::AssetCall(d) => d.num_items() + 1,
            // description amount, address, fee and contract_data
            EthData::ContractCall(d) => 1 + 1 + 1 + 1 + d.num_items(),
            // address, fee
            EthData::Erc20(d) => 1 + 1 + d.num_items(),
            // address, fee
            EthData::Erc721(d) => 1 + 1 + d.num_items(),
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
            EthData::Erc20(..) => self.render_erc20_call(item_n, title, message, page),
            EthData::Erc721(..) => self.render_erc721_call(item_n, title, message, page),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_eip1559() {
        // market..
        let data = "02f871018347eae184773594008517bfac7c008303291894dac17f958d2ee523a2206206994597c13d831ec780b844a9059cbb000000000000000000000000bb98f2a83d78310342da3e63278ce7515d52619d00000000000000000000000000000000000000000000000000000006e0456cd0c0";
        let data = hex::decode(data).unwrap();

        // remove the transaction type and get the transaction bytes as
        // data = 2 + rlp([tx_bytes])
        let (_, tx_bytes) = parse_rlp_item(&data[1..]).unwrap();

        let (_, tx) = Eip1559::from_bytes(tx_bytes).unwrap();

        assert_eq!(&[3, 41, 24], &*tx.gas_limit);
        assert_eq!(&[23, 191, 172, 124, 0], &*tx.max_fee);
        assert_eq!(&[119, 53, 148, 0], &*tx.priority_fee);

        assert_eq!(0, tx.value.len());
    }
}
