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

use super::parse_rlp_item;
use super::BaseLegacy;
use crate::parser::U64_SIZE;
use crate::parser::{DisplayableItem, FromBytes, ParserError};

const MAX_CHAIN_LEN: usize = U64_SIZE;

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct Legacy<'b> {
    pub base: BaseLegacy<'b>,
    chain_id: &'b [u8],
    // R and S must be empty
    // so do not put and empty
    // field here, it is just to indicate
    // that they are expected
}

impl<'b> Legacy<'b> {
    pub fn chain_id(&self) -> &'b [u8] {
        self.chain_id
    }
}

impl<'b> FromBytes<'b> for Legacy<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("Legacy::from_bytes_into\x00");

        // get out pointer
        let out = out.as_mut_ptr();

        let data_out = unsafe { &mut *addr_of_mut!((*out).base).cast() };
        let rem = BaseLegacy::from_bytes_into(input, data_out)?;

        // two cases:
        // - legacy no EIP155 compliant which should be supported
        // - legacy EIP155 in which case should come with empty r and s values
        if rem.is_empty() {
            unsafe {
                // write an empty chain-id as it is used to compute the right V component
                // when transaction is signed
                addr_of_mut!((*out).chain_id).write(&[]);
            }

            return Ok(&[]);
        }

        // Transaction comes with a chainID so it is EIP155 compliant
        let (rem, id_bytes) = parse_rlp_item(rem)?;
        if id_bytes.is_empty() {
            return Err(ParserError::InvalidChainId.into());
        }

        let (rem, r) = parse_rlp_item(rem)?;
        let (rem, s) = parse_rlp_item(rem)?;

        // check for erc721 call and chainID
        #[cfg(feature = "erc721")]
        {
            let base = unsafe { &*data_out.as_ptr() };
            if matches!(base.data, crate::parser::EthData::Erc721(..)) {
                let chain_id = super::bytes_to_u64(id_bytes)?;
                let contract_chain_id = crate::parser::ERC721Info::get_nft_info()?.chain_id;
                if chain_id != contract_chain_id {
                    return Err(ParserError::InvalidAssetCall.into());
                }
            }
        }

        // r and s if not empty, should contain only one value
        // which must be zero.
        if !r.is_empty() && !s.is_empty() {
            let no_zero = r.iter().any(|v| *v != 0) && s.iter().any(|v| *v != 0);
            if no_zero || r.len() != 1 || s.len() != 1 {
                crate::sys::zemu_log_stack("Legacy::invalid_r_s\x00");
                return Err(ParserError::UnexpectedData.into());
            }
        }

        // to align with ledger's original ethereum app
        if id_bytes.len() > MAX_CHAIN_LEN {
            return Err(ParserError::InvalidChainId.into());
        }

        unsafe {
            addr_of_mut!((*out).chain_id).write(id_bytes);
        }

        Ok(rem)
    }
}

impl<'b> DisplayableItem for Legacy<'b> {
    fn num_items(&self) -> Result<u8, ViewError> {
        self.base.num_items()
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        self.base.render_item(item_n, title, message, page)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{handlers::eth::u256, parser::EthData};

    #[test]
    fn parse_legacy_tx() {
        let data = "ed018504e3b292008252089428ee52a8f3d6e5d15f8b131996950d7f296c7952872bd72a248740008082a86a8080";
        let data = hex::decode(data).unwrap();

        let (_, bytes) = parse_rlp_item(&data).unwrap();
        let (_, _tx) = Legacy::from_bytes(bytes).unwrap();
    }

    #[test]
    fn parse_legacy_deploy() {
        let deploy = "f5808609184e72a0008227108080a47f7465737432000000000000000000000000000000000000000000000000000000600057018080";
        let bytes = hex::decode(deploy).unwrap();

        // get transaction bytes
        let (_, bytes) = parse_rlp_item(&bytes).unwrap();
        let (_, tx) = Legacy::from_bytes(bytes).unwrap();

        assert!(tx.base.to.is_none());
        assert!(matches!(tx.base.data, EthData::Deploy(..)));
        assert!(tx.base.value.len() == 0);
    }

    #[test]
    fn parse_legacy_asset_transfer() {
        let deploy = "f87c01856d6e2edc00830186a094010000000000000000000000000000000000000280b85441c9cc6fd27e26e70f951869fb09da685a696f0a79d338394f709c6d776d1318765981e69c09f0aa49864d8cc35699545b5e73a00000000000000000000000000000000000000000000000000123456789abcdef82a8688080";
        let bytes = hex::decode(deploy).unwrap();
        let address = hex::decode("41c9cc6fd27e26e70f951869fb09da685a696f0a").unwrap();
        let amount = hex::decode("0123456789abcdef").unwrap();
        let amount = u256::pic_from_big_endian()(&amount);

        // get transaction bytes
        let (_, bytes) = parse_rlp_item(&bytes).unwrap();
        let (_, tx) = Legacy::from_bytes(bytes).unwrap();

        if let EthData::AssetCall(c) = tx.base.data {
            assert_eq!(&address[..], c.address.raw_address());
            let parsed_amount = u256::pic_from_big_endian()(c.amount);
            assert_eq!(amount, parsed_amount);
        } else {
            panic!("Expected an AssetCall transaction!");
        }
    }

    #[test]
    fn parse_legacy_asset_deposit() {
        let deploy = "f88001856d6e2edc00830186a094010000000000000000000000000000000000000280b85841c9cc6fd27e26e70f951869fb09da685a696f0a79d338394f709c6d776d1318765981e69c09f0aa49864d8cc35699545b5e73a00000000000000000000000000000000000000000000000000000000000000000d0e30db082a8688080";
        let bytes = hex::decode(deploy).unwrap();

        let address = hex::decode("41c9cc6fd27e26e70f951869fb09da685a696f0a").unwrap();

        // get transaction bytes
        let (_, bytes) = parse_rlp_item(&bytes).unwrap();
        let (_, tx) = Legacy::from_bytes(bytes).unwrap();

        if let EthData::AssetCall(c) = tx.base.data {
            assert_eq!(&address[..], c.address.raw_address());
            let amount = u256::pic_from_big_endian()(c.amount);
            assert!(amount.is_zero());
        } else {
            panic!("Expected an AssetCall transaction!");
        }
    }

    #[test]
    fn parse_legacy_bad_asset_call() {
        let deploy = "f83880856d6e2edc00832dc6c0940100000000000000000000000000000000000002019190000102030405060708090a0b0c0d0e0f82a8688080";
        let bytes = hex::decode(deploy).unwrap();

        let tx = Legacy::from_bytes(&bytes);
        assert!(tx.is_err());
    }
}
