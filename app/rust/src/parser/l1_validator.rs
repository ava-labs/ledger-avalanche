/*******************************************************************************
*   (c) 2021 Zondax GmbH
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
use super::{pchain_owner::PchainOwner, proof_of_possession::ProofOfPossession, NodeId};
use crate::parser::{FromBytes, ParserError};
use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::{bytes::complete::take, number::complete::be_u64};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct L1Validator<'b> {
    pub node_id: NodeId<'b>,
    pub weight: u64,
    pub balance: u64,
    pub signer: ProofOfPossession<'b>,
    pub remaining_balance_owner: PchainOwner<'b>,
    pub deactivation_owner: PchainOwner<'b>,
}

impl<'b> FromBytes<'b> for L1Validator<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("L1Validator::from_bytes_into\x00");

        let (rem, _unused_value) = take(4usize)(input)?;

        let out = out.as_mut_ptr();
        let node_id = unsafe { &mut *addr_of_mut!((*out).node_id).cast() };
        let rem = NodeId::from_bytes_into(rem, node_id)?;

        let (rem, weight) = be_u64(rem)?;
        let (rem, balance) = be_u64(rem)?;

        let signer = unsafe { &mut *addr_of_mut!((*out).signer).cast() };
        let rem = ProofOfPossession::from_bytes_into(rem, signer)?;

        let remaining_balance_owner =
            unsafe { &mut *addr_of_mut!((*out).remaining_balance_owner).cast() };
        let rem = PchainOwner::from_bytes_into(rem, remaining_balance_owner)?;

        let deactivation_owner = unsafe { &mut *addr_of_mut!((*out).deactivation_owner).cast() };
        let rem = PchainOwner::from_bytes_into(rem, deactivation_owner)?;

        unsafe {
            addr_of_mut!((*out).weight).write(weight);
            addr_of_mut!((*out).balance).write(balance);
        }

        Ok(rem)
    }
}
