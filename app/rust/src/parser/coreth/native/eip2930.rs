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
use crate::parser::{DisplayableItem, FromBytes, ParserError};

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct Eip2930<'b> {
    // it is not clear if chainID
    // is an u32, u8, u64
    // considering this might
    // come from an avax C-Chain
    chain_id: &'b [u8],
    pub base: BaseLegacy<'b>,
    access_list: &'b [u8],
    // R and S must be empty
    // so do not put and empty
    // field here, it is just to indicate
    // that they are expected
}

impl<'b> Eip2930<'b> {
    pub fn chain_id(&self) -> &'b [u8] {
        self.chain_id
    }
}

impl<'b> FromBytes<'b> for Eip2930<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("Eip2930::from_bytes_into\x00");

        // get out pointer
        let out = out.as_mut_ptr();

        // chainID
        let (rem, id_bytes) = parse_rlp_item(input)?;
        if id_bytes.is_empty() {
            return Err(ParserError::InvalidChainId.into());
        }

        let data_out = unsafe { &mut *addr_of_mut!((*out).base).cast() };
        let rem = BaseLegacy::from_bytes_into(rem, data_out)?;

        // access list
        let (rem, access_list) = parse_rlp_item(rem)?;

        let chain_id = super::bytes_to_u64(id_bytes)?;

        // check for erc721 call and chainID
        #[cfg(feature = "erc721")]
        {
            let base = unsafe { &*data_out.as_ptr() };
            if matches!(base.data, crate::parser::EthData::Erc721(..)) {
                let contract_chain_id = crate::parser::ERC721Info::get_nft_info()?.chain_id;
                if chain_id != contract_chain_id {
                    return Err(ParserError::InvalidAssetCall.into());
                }
            }
        }

        unsafe {
            addr_of_mut!((*out).chain_id).write(id_bytes);
            addr_of_mut!((*out).access_list).write(access_list);
        }

        Ok(rem)
    }
}

impl<'b> DisplayableItem for Eip2930<'b> {
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
    use crate::parser::EthData;

    use super::*;

    #[test]
    fn parse_eip2930() {
        let data = "01f901b10180018402625a0080830186a0b901447f74657374320000000000000000000000000000000000000000000000000000006000577f74657374320000000000000000000000000000000000000000000000000000006000577f74657374320000000000000000000000000000000000000000000000000000006000577f74657374320000000000000000000000000000000000000000000000000000006000577f74657374320000000000000000000000000000000000000000000000000000006000577f74657374320000000000000000000000000000000000000000000000000000006000577f74657374320000000000000000000000000000000000000000000000000000006000577f74657374320000000000000000000000000000000000000000000000000000006000577f7465737432000000000000000000000000000000000000000000000000000000600057f85bf859940000000000000000000000000000000000000101f842a00000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000060a7";
        let data = hex::decode(data).unwrap();

        // remove transaction version, which is the first bytes
        let (_, bytes) = parse_rlp_item(&data[1..]).unwrap();

        _ = Eip2930::from_bytes(bytes).unwrap().1;
    }

    #[test]
    fn parse_eip2930_contract_call() {
        let data = "01f901c60181e0018402625a0094cccccccccccccccccccccccccccccccccccccccc830186a0b901447f74657374320000000000000000000000000000000000000000000000000000006000577f74657374320000000000000000000000000000000000000000000000000000006000577f74657374320000000000000000000000000000000000000000000000000000006000577f74657374320000000000000000000000000000000000000000000000000000006000577f74657374320000000000000000000000000000000000000000000000000000006000577f74657374320000000000000000000000000000000000000000000000000000006000577f74657374320000000000000000000000000000000000000000000000000000006000577f74657374320000000000000000000000000000000000000000000000000000006000577f7465737432000000000000000000000000000000000000000000000000000000600057f85bf859940000000000000000000000000000000000000101f842a00000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000060a7";
        let data = hex::decode(data).unwrap();

        let address = hex::decode("cccccccccccccccccccccccccccccccccccccccc").unwrap();

        // remove transaction version, which is the first bytes
        let (_, bytes) = parse_rlp_item(&data[1..]).unwrap();

        let tx = Eip2930::from_bytes(bytes).unwrap().1;

        assert_eq!(tx.base.value[0], 1u8);
        assert_eq!(tx.base.nonce[0], 0xe0);

        assert!(matches!(tx.base.data, EthData::ContractCall(..)));
        assert_eq!(&tx.base.to.unwrap().raw_address()[..], &address);
    }
}
