/*******************************************************************************
*   (c) 2022 zondax ag
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

use nom::bytes::complete::take;
use zemu_sys::ViewError;

use crate::{
    handlers::{eth::u256, handle_ui_message},
    parser::{Address, AssetId, DisplayableItem, FromBytes, ParserError},
};
use bolos::PIC;

const DEPOSIT_SELECTOR: &[u8] = &[0xd0, 0xe3, 0x0d, 0xb0];
const ASSETCALL_FIXED_DATA_WIDTH: usize = 20 + 32 + 32;

const AMOUNT_SIZE: usize = u256::BITS as usize / 8;

/// An asset call according to the documentation
/// in https://docs.avax.network/specs/coreth-arc20s
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "derive-debug"), derive(Debug))]
pub struct AssetCall<'b> {
    pub address: Address<'b>,
    pub asset_id: AssetId<'b>,
    pub amount: &'b [u8],
    call_data: &'b [u8],
}

impl<'b> AssetCall<'b> {
    pub fn is_asset_call(to: &Address<'_>, data: &[u8]) -> bool {
        // lets not use pic as check is simple
        let address = to.raw_address();
        address[0] == 0x1
            && address[19] == 0x2
            && !address[1..19].iter().any(|v| *v != 0)
            // this data can contain either just the fixed items 
            // or a call data for the call which means it could be 
            // a deposit call
            && data.len() >= ASSETCALL_FIXED_DATA_WIDTH
    }

    pub fn parse_into(data: &'b [u8], output: &mut MaybeUninit<Self>) -> Result<(), ParserError> {
        crate::sys::zemu_log_stack("AssetCall::parse_into\x00");
        // get out pointer
        let out = output.as_mut_ptr();

        // An asset call is structured as follows:
        // nativeAssetCall(address addr, uint256 assetID, uint256 assetAmount, bytes memory
        // callData)
        // where callData has to be parsed as well to define if it
        // is a deposit or something else.
        // we only support deposits for now

        // sender
        let address = unsafe { &mut *addr_of_mut!((*out).address).cast() };
        let rem = Address::from_bytes_into(data, address)?;

        // asset_id
        let asset_id = unsafe { &mut *addr_of_mut!((*out).asset_id).cast() };
        let rem = AssetId::from_bytes_into(rem, asset_id)?;

        // amount
        let (rem, amount) = take(AMOUNT_SIZE)(rem)?;

        let selector = PIC::new(DEPOSIT_SELECTOR).into_inner();

        // Supports an Asset transfer in which case rem is
        // empty. otherwise, check that it contains the deposit_selector
        // if not returns an error.
        if !rem.is_empty() && rem.len() != selector.len() {
            return Err(ParserError::UnexpectedData);
        }

        if !rem.is_empty() && rem != selector {
            return Err(ParserError::InvalidEthSelector);
        }

        // safe writes
        unsafe {
            addr_of_mut!((*out).amount).write(amount);
            addr_of_mut!((*out).call_data).write(rem);
        }

        Ok(())
    }

    fn is_deposit(&self) -> bool {
        self.call_data.len() == DEPOSIT_SELECTOR.len()
    }
}

impl<'b> DisplayableItem for AssetCall<'b> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // transfer/deposit, asset_id and address
        Ok(1 + 1 + 1)
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::pic_str;

        let of = pic_str!(b" of");
        let mut buffer = [0; u256::FORMATTED_SIZE_DECIMAL + 4];

        match item_n {
            0 => {
                let deposit = pic_str!(b"Deposit");
                let transfer = pic_str!(b"Transfer");

                if self.is_deposit() {
                    title[..deposit.len()].copy_from_slice(deposit);
                } else {
                    title[..transfer.len()].copy_from_slice(transfer);
                }

                let amount = u256::pic_from_big_endian()(self.amount);
                let s = amount.to_lexical(&mut buffer[..u256::FORMATTED_SIZE_DECIMAL]);

                let mut size = s.len();

                buffer[size..size + of.len()].copy_from_slice(&of[..]);

                size += of.len();

                handle_ui_message(&buffer[..size], message, page)
            }
            1 => self.asset_id.render_item(0, title, message, page),
            2 => {
                let label = pic_str!(b"To");
                title[..label.len()].copy_from_slice(label);

                self.address.render_eth_address(message, page)
            }

            _ => Err(ViewError::NoData),
        }
    }
}
