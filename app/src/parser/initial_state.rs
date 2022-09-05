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
use core::{convert::TryFrom, mem::MaybeUninit, ptr::addr_of_mut};
use nom::number::complete::be_u32;


use crate::{
    handlers::handle_ui_message,
    parser::{AvmOutput, DisplayableItem, FromBytes, ObjectList, ParserError},
};

use zemu_sys::ViewError;

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
#[repr(C)]
pub enum FxId {
    SECP256KAsset,
    NftAsse,
}

impl TryFrom<u32> for FxId {
    type Error = ParserError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(FxId::SECP256KAsset),
            1 => Ok(FxId::NftAsset),
            _ => Err(ParserError::UnexpectedType),
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
#[repr(C)]
pub struct InitialState<'b> {
    id: FxId,
    outputs: ObjectList<'b, AvmOutput<'b>>,
}

impl<'b> FromBytes<'b> for InitialState<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("InitialState::from_bytes_into\x00");

        let output = out.as_mut_ptr();
        // get FxId
        let (rem, id) = be_u32(input)?;
        let id = FxId::try_from(id)?;

        // get outputs
        let mut outputs = unsafe { &mut *addr_of_mut!((*output).outputs).cast() };
        let rem = ObjectList::<AvmOutput>::new_into(rem, &mut outputs)?;

        //good ptr and no uninit reads
        unsafe {
            addr_of_mut!((*output).id).write(id);
        }

        Ok(rem)
    }
}
