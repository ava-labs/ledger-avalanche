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

use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::{bytes::complete::take, number::complete::be_u32, sequence::tuple};

use crate::parser::{FromBytes, ParserError, TransferableInput, TransferableOutput};

use super::object_list::ObjectList;

const BLOCKCHAIN_ID_LEN: usize = 32;
const MAX_MEMO_LEN: usize = 256;

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct BaseTx<'b> {
    pub type_id: u32,
    pub network_id: u32,
    pub blockchain_id: &'b [u8; BLOCKCHAIN_ID_LEN],
    // lazy parsing of inputs/outpus
    pub outputs: ObjectList<'b>,
    pub inputs: ObjectList<'b>,
    pub memo: &'b [u8],
}

impl<'b> FromBytes<'b> for BaseTx<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("BaseTx::from_bytes_into\x00");

        let (mut rem, (type_id, network_id, blockchain_id)) =
            tuple((be_u32, be_u32, take(BLOCKCHAIN_ID_LEN)))(input)?;
        let blockchain_id = arrayref::array_ref!(blockchain_id, 0, BLOCKCHAIN_ID_LEN);

        let out = out.as_mut_ptr();
        let outputs = unsafe { &mut *addr_of_mut!((*out).outputs).cast() };
        let inputs = unsafe { &mut *addr_of_mut!((*out).inputs).cast() };
        rem = ObjectList::new_into::<TransferableOutput>(rem, outputs)?;
        rem = ObjectList::new_into::<TransferableInput>(rem, inputs)?;
        let (rem, memo_len) = be_u32(rem)?;

        if memo_len as usize > MAX_MEMO_LEN {
            return Err(ParserError::ValueOutOfRange.into());
        }

        let (rem, memo) = take(memo_len as usize)(rem)?;

        //good ptr and no uninit reads
        unsafe {
            addr_of_mut!((*out).type_id).write(type_id);
            addr_of_mut!((*out).network_id).write(network_id);
            addr_of_mut!((*out).blockchain_id).write(blockchain_id);
            addr_of_mut!((*out).memo).write(memo);
        }

        Ok(rem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{TransferableInput, TransferableOutput};

    const DATA: &[u8] = &[
        0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 1, 244, 0, 0,
        0, 0, 0, 0, 0, 12, 0, 0, 0, 2, 0, 0, 0, 2, 22, 54, 119, 75, 103, 131, 141, 236, 22, 225,
        106, 182, 207, 172, 178, 27, 136, 195, 168, 97, 157, 31, 52, 188, 58, 111, 35, 6, 202, 7,
        144, 22, 174, 248, 92, 19, 23, 103, 242, 56, 0, 0, 0, 1, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 0, 0, 2, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 0, 0, 0,
        5, 0, 0, 0, 0, 0, 0, 0, 186, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 58, 0, 0, 0, 1,
        0, 0, 0, 79, 0, 0, 0, 65, 0, 0, 0, 87, 0, 0, 0, 94, 0, 0, 0, 125, 0, 0, 1, 122, 0, 0, 0,
        17, 109, 101, 109, 111, 95, 97, 118, 97, 108, 97, 110, 99, 104, 101, 95, 116, 120,
    ];

    #[test]
    fn parse_base_tx() {
        let mut base = BaseTx::from_bytes(DATA).unwrap().1;
        assert_eq!(base.network_id, 256);
        assert_eq!(base.blockchain_id, &[1; 32]);
        let mut output = MaybeUninit::uninit();
        let mut input = MaybeUninit::uninit();
        let mut rem = base
            .outputs
            .parse_next::<TransferableOutput>(&mut output)
            .unwrap();
        assert_eq!(rem, Some(()));
        rem = base
            .inputs
            .parse_next::<TransferableInput>(&mut input)
            .unwrap();
        assert_eq!(rem, Some(()));
    }
}
