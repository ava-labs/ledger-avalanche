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
    handlers::{eth::u256, handle_ui_message},
    parser::{
        intstr_to_fpstr_inplace, Address, DisplayableItem, EthData, FromBytes, ParserError,
        ADDRESS_LEN, WEI_AVAX_DIGITS, WEI_NAVAX_DIGITS,
    },
    utils::ApduPanic,
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct Eip1559<'b> {
    pub chain_id: &'b [u8],
    pub nonce: &'b [u8],
    pub priority_fee: &'b [u8],
    pub max_fee: &'b [u8],
    pub gas_limit: &'b [u8],
    // this transaction can deploy a contract too
    to: Option<Address<'b>>,
    pub value: &'b [u8],
    data: EthData<'b>,
    access_list: &'b [u8],
    // R and S must be empty
    // so do not put and empty
    // field here, it is just to indicate
    // that they are expected
}

impl<'b> Eip1559<'b> {
    pub fn chain_id_low_byte(&self) -> u8 {
        self.chain_id[self.chain_id.len() - 1]
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

        // nonce
        let (rem, nonce) = parse_rlp_item(rem)?;

        // max_priority_fee
        let (rem, priority_fee) = parse_rlp_item(rem)?;

        // max_fee
        let (rem, max_fee) = parse_rlp_item(rem)?;

        // gas limit
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

        // EthData
        let data_out = unsafe { &mut *addr_of_mut!((*out).data).cast() };
        let rem = EthData::parse_into(&address, rem, data_out)?;

        // If this is an asset call transaction, checks that there is not
        // value being sent, which would be definately loss
        let eth_data = unsafe { &*data_out.as_ptr() };
        if matches!(eth_data, EthData::AssetCall(..)) && value_bytes.iter().any(|v| *v != 0) {
            return Err(ParserError::InvalidAssetCall.into());
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
            addr_of_mut!((*out).value).write(value_bytes);
            addr_of_mut!((*out).chain_id).write(id_bytes);
            addr_of_mut!((*out).access_list).write(access_list);
        }

        Ok(rem)
    }
}

impl<'b> Eip1559<'b> {
    #[inline(never)]
    fn fee(&self) -> Result<u256, ParserError> {
        let priority_fee = u256::from_big_endian(self.priority_fee);
        let max_fee = u256::from_big_endian(self.max_fee);
        let gas_limit = u256::from_big_endian(self.gas_limit);
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

                render_u256(self.value, WEI_AVAX_DIGITS, message, page)
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
            EthData::None => 0,
            // description, gas limit, funding contract(if value != zero), maximun fee and data.items
            EthData::Deploy(d) => 1 + 1 + 1 + d.num_items() + !self.value.is_empty() as usize,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_eip1559() {
        // market..
        let data = "02f9018a82a868808506fc23ac008506fc23ac008316e3608080b90170608060405234801561001057600080fd5b50610150806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c80632e64cec11461003b5780636057361d14610059575b600080fd5b610043610075565b60405161005091906100d9565b60405180910390f35b610073600480360381019061006e919061009d565b61007e565b005b60008054905090565b8060008190555050565b60008135905061009781610103565b92915050565b6000602082840312156100b3576100b26100fe565b5b60006100c184828501610088565b91505092915050565b6100d3816100f4565b82525050565b60006020820190506100ee60008301846100ca565b92915050565b6000819050919050565b600080fd5b61010c816100f4565b811461011757600080fd5b5056fea2646970667358221220404e37f487a89a932dca5e77faaf6ca2de3b991f93d230604b1b8daaef64766264736f6c63430008070033c0";
        let data = hex::decode(data).unwrap();

        // remove the transaction type and get the transaction bytes as
        // data = 2 + rlp([tx_bytes])
        let (_, tx_bytes) = parse_rlp_item(&data[1..]).unwrap();

        let (_, tx) = Eip1559::from_bytes(&tx_bytes).unwrap();

        assert!(tx.to.is_none());

        assert!(tx.nonce.is_empty());
        assert_eq!(
            &1500000u64.to_be_bytes()[8 - tx.gas_limit.len()..],
            tx.gas_limit
        );
        assert_eq!(
            &30000000000u64.to_be_bytes()[8 - tx.max_fee.len()..],
            tx.max_fee
        );
        assert_eq!(
            &30000000000u64.to_be_bytes()[8 - tx.priority_fee.len()..],
            tx.priority_fee
        );

        assert_eq!(0, tx.value.len());
    }
}
