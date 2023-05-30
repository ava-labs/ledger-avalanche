/*******************************************************************************
*   (c) 2023 Zondax AG
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

use bolos::{pic::PIC, pic_str};
use nom::{bytes::complete::take, number::complete::be_u32};
use zemu_sys::ViewError;

use crate::{handlers::handle_ui_message, utils::hex_encode};

use super::{DisplayableItem, FromBytes, ParserError};

pub const BLS_PUBKEY_LEN: usize = 48;
pub const BLS_SIGNATURE_LEN: usize = 96;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct ProofOfPossession<'b> {
    public_key: &'b [u8; BLS_PUBKEY_LEN],
    signature: &'b [u8; BLS_SIGNATURE_LEN],
}

impl<'b> ProofOfPossession<'b> {
    pub fn render_address(&self, message: &mut [u8], page: u8) -> Result<u8, ViewError> {
        let prefix = pic_str!(b"0x"!);
        // prefix
        let mut out = [0; BLS_PUBKEY_LEN * 2 + 2];
        let mut sz = prefix.len();
        out[..prefix.len()].copy_from_slice(&prefix[..]);

        sz += hex_encode(self.public_key, &mut out[prefix.len()..])
            .map_err(|_| ViewError::Unknown)?;

        handle_ui_message(&out[..sz], message, page)
    }
}

impl<'b> FromBytes<'b> for ProofOfPossession<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        let (rem, public_key) = take(BLS_PUBKEY_LEN)(input)?;
        let public_key = arrayref::array_ref![public_key, 0, BLS_PUBKEY_LEN];

        let (rem, signature) = take(BLS_SIGNATURE_LEN)(rem)?;
        let signature = arrayref::array_ref![signature, 0, BLS_SIGNATURE_LEN];

        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).public_key).write(public_key);
            addr_of_mut!((*out).signature).write(signature);
        }

        Ok(rem)
    }
}

#[avalanche_app_derive::enum_init]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub enum BLSSigner<'b> {
    EmptyProof,
    Proof(ProofOfPossession<'b>),
}

impl<'b> BLSSigner<'b> {
    const EMPTY_TYTPE_ID: u32 = 0x1B;
    const SIGNER_TYTPE_ID: u32 = 0x1C;
}

impl BLSSigner__Type {
    pub fn from_type_id(type_id: u32) -> Option<Self> {
        match type_id {
            BLSSigner::EMPTY_TYTPE_ID => Some(Self::EmptyProof),
            BLSSigner::SIGNER_TYTPE_ID => Some(Self::Proof),
            _ => None,
        }
    }
}

impl<'b> FromBytes<'b> for BLSSigner<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        let (rem, type_id) = be_u32(input)?;
        let type_id = BLSSigner__Type::from_type_id(type_id).ok_or(ParserError::InvalidTypeId)?;

        match type_id {
            BLSSigner__Type::EmptyProof => {
                let out = out.as_mut_ptr();
                unsafe {
                    out.write(Self::EmptyProof);
                }
                Ok(rem)
            }
            BLSSigner__Type::Proof => {
                Self::init_as_proof(|out| ProofOfPossession::from_bytes_into(rem, out), out)
            }
        }
    }
}

impl<'b> DisplayableItem for BLSSigner<'b> {
    fn num_items(&self) -> usize {
        match &self {
            BLSSigner::EmptyProof => 0,
            BLSSigner::Proof(_) => 1,
        }
    }

    fn render_item(
        &self,
        _: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        match &self {
            BLSSigner::EmptyProof => Err(ViewError::NoData),
            BLSSigner::Proof(proof) => {
                let label = pic_str!(b"Signer");
                title[..label.len()].copy_from_slice(label);

                proof.render_address(message, page)
            }
        }
    }
}
