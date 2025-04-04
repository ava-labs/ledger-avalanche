/*******************************************************************************
*   (c) 2018-2024 Zondax AG
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
use nom::{
    bytes::complete::{tag, take},
    number::complete::{be_u16, be_u32},
};
use zemu_sys::ViewError;

use crate::{
    handlers::handle_ui_message,
    parser::{
        cb58_output_len, nano_avax_to_fp_str, BaseTxFields, DisplayableItem, FromBytes, Header,
        ParserError, PvmOutput, SubnetAuth, SubnetId, CB58_CHECKSUM_LEN, PVM_CREATE_CHAIN, U64_FORMATTED_SIZE
    },
    utils::{bs58_encode, hex_encode, ApduPanic},
};

pub const VM_ID_LEN: usize = 32;
pub const FX_ID_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct CreateChainTx<'b> {
    pub tx_header: Header<'b>,
    pub base_tx: BaseTxFields<'b, PvmOutput<'b>>,
    pub subnet_id: SubnetId<'b>,
    pub chain_name: &'b [u8],
    pub vm_id: &'b [u8; VM_ID_LEN],
    pub fx_id: &'b [[u8; FX_ID_LEN]],
    pub genesis_data: &'b [u8],
    pub subnet_auth: SubnetAuth<'b>,
}

impl<'b> CreateChainTx<'b> {
    fn fee(&'b self) -> Result<u64, ParserError> {
        let sum_inputs = self.base_tx.sum_inputs_amount()?;

        let base_outputs = self.base_tx.sum_outputs_amount()?;

        let fee = sum_inputs
            .checked_sub(base_outputs)
            .ok_or(ParserError::OperationOverflows)?;
        Ok(fee)
    }
}

impl<'b> FromBytes<'b> for CreateChainTx<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("CreateChainTx::from_bytes_into\x00");

        let (rem, _) = tag(PVM_CREATE_CHAIN.to_be_bytes())(input)?;

        let out = out.as_mut_ptr();

        // tx header
        let tx_header = unsafe { &mut *addr_of_mut!((*out).tx_header).cast() };
        let rem = Header::from_bytes_into(rem, tx_header)?;

        // base_tx
        let base_tx = unsafe { &mut *addr_of_mut!((*out).base_tx).cast() };
        let rem = BaseTxFields::<PvmOutput>::from_bytes_into(rem, base_tx)?;

        // SubnetId
        let subnet_id = unsafe { &mut *addr_of_mut!((*out).subnet_id).cast() };
        let rem = SubnetId::from_bytes_into(rem, subnet_id)?;

        // The len is define as a u16 for chain_name
        let (rem, chain_name_len) = be_u16(rem)?;
        let (rem, chain_name) = take(chain_name_len as usize)(rem)?;
        // chain name is a valid utf8 string according
        // to avalanche's docs
        // double check for ascii bytes
        if !chain_name.is_ascii() {
            return Err(ParserError::InvalidAsciiValue.into());
        }

        let (rem, vm_id) = take(VM_ID_LEN)(rem)?;
        let vm_id = arrayref::array_ref!(vm_id, 0, VM_ID_LEN);

        let (rem, num_fx_id) = be_u32(rem)?;
        let (rem, fx_id) = take(num_fx_id as usize * FX_ID_LEN)(rem)?;

        // This would not fail as previous line ensures we take
        // the right amount of bytes, also the alignemnt is correct
        let fx_id = bytemuck::try_cast_slice(fx_id).apdu_unwrap();

        let (rem, genesis_data_len) = be_u32(rem)?;
        let (rem, genesis_data) = take(genesis_data_len as usize)(rem)?;

        let subnet_auth = unsafe { &mut *addr_of_mut!((*out).subnet_auth).cast() };
        let rem = SubnetAuth::from_bytes_into(rem, subnet_auth)?;

        //good ptr and no uninit reads
        unsafe {
            addr_of_mut!((*out).chain_name).write(chain_name);
            addr_of_mut!((*out).vm_id).write(vm_id);
            addr_of_mut!((*out).fx_id).write(fx_id);
            addr_of_mut!((*out).genesis_data).write(genesis_data);
        }

        Ok(rem)
    }
}

impl DisplayableItem for CreateChainTx<'_> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // we need to show:
        // tx description, SubnetID, ChainName, VMID, GenesisDataHash
        // and fee
        Ok(1 + 4 + 1)
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        use bolos::{
            hash::{Hasher, Sha256},
            pic_str, PIC,
        };

        let mut hex_buf = [0; Sha256::DIGEST_LEN * 2];
        match item_n {
            0 => {
                let label = pic_str!(b"CreateChain");
                title[..label.len()].copy_from_slice(label);
                let content = pic_str!(b"transaction");
                handle_ui_message(content, message, page)
            }
            1 => self.subnet_id.render_item(0, title, message, page),
            2 => {
                let label = pic_str!(b"ChainName");
                title[..label.len()].copy_from_slice(label);
                handle_ui_message(self.chain_name, message, page)
            }
            3 => {
                let label = pic_str!(b"VMID");
                title[..label.len()].copy_from_slice(label);

                let checksum = Sha256::digest(self.vm_id).map_err(|_| ViewError::Unknown)?;
                // prepare the data to be encoded by appending last 4-byte
                let mut data = [0; VM_ID_LEN + CB58_CHECKSUM_LEN];
                data[..VM_ID_LEN].copy_from_slice(&self.vm_id[..]);
                data[VM_ID_LEN..]
                    .copy_from_slice(&checksum[(Sha256::DIGEST_LEN - CB58_CHECKSUM_LEN)..]);

                const MAX_SIZE: usize = cb58_output_len::<VM_ID_LEN>();
                let mut encoded = [0; MAX_SIZE];

                let len = bs58_encode(data, &mut encoded[..]).map_err(|_| ViewError::Unknown)?;
                handle_ui_message(&encoded[..len], message, page)
            }
            4 => {
                let label = pic_str!(b"GenesisData");
                title[..label.len()].copy_from_slice(label);
                let sha = Sha256::digest(self.genesis_data).map_err(|_| ViewError::Unknown)?;
                hex_encode(&sha[..], &mut hex_buf).map_err(|_| ViewError::Unknown)?;
                handle_ui_message(&hex_buf, message, page)
            }
            5 => {
                let label = pic_str!(b"Fee(AVAX)");
                title[..label.len()].copy_from_slice(label);

                let mut buffer = [0; U64_FORMATTED_SIZE + 2];
                let fee = self.fee().map_err(|_| ViewError::Unknown)?;
                let fee_buff =
                    nano_avax_to_fp_str(fee, &mut buffer[..]).map_err(|_| ViewError::Unknown)?;

                handle_ui_message(fee_buff, message, page)
            }

            _ => Err(ViewError::NoData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &[u8] = &[
        0, 0, 0, 15, 0, 0, 0, 1, 237, 95, 56, 52, 30, 67, 110, 93, 70, 226, 187, 0, 180, 93, 98,
        174, 151, 209, 176, 80, 198, 75, 198, 52, 174, 16, 98, 103, 57, 227, 92, 75, 0, 0, 0, 1, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 39, 16, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 1,
        157, 31, 52, 188, 58, 111, 35, 6, 202, 7, 144, 22, 174, 248, 92, 19, 23, 103, 242, 56, 0,
        0, 0, 1, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 0, 0, 0, 2, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 31, 64, 0, 0, 0, 10, 0, 0,
        0, 4, 0, 0, 0, 5, 0, 0, 0, 58, 0, 0, 0, 1, 0, 0, 0, 79, 0, 0, 0, 65, 0, 0, 0, 87, 0, 0, 0,
        94, 0, 0, 0, 125, 0, 0, 1, 122, 0, 0, 0, 4, 109, 101, 109, 111, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 0, 6, 122, 111, 110,
        100, 97, 120, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
        5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 0, 0, 0, 12, 103, 101, 110, 101, 115, 105, 115, 32,
        100, 97, 116, 97, 0, 0, 0, 10, 0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3,
    ];

    #[test]
    fn parse_create_chain() {
        let (_, tx) = CreateChainTx::from_bytes(DATA).unwrap();
        assert_eq!(tx.chain_name, b"zondax");
        assert_eq!(tx.fx_id.len(), 1);
    }
}
