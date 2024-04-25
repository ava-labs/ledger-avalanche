/*******************************************************************************
*   (c) 2024 Zondax AG
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

use crate::parser::DisplayableItem;
use crate::parser::{FromBytes, ParserError, Transaction};

#[repr(u8)]
pub enum Instruction {
    SignAvaxTx = 0x00,
    SignEthTx,
    SignAvaxMsg,
    SignEthMsg,
    SignAvaxHash,
}

impl TryFrom<u8> for Instruction {
    type Error = ParserError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Instruction::SignAvaxTx),
            0x01 => Ok(Instruction::SignEthTx),
            0x02 => Ok(Instruction::SignAvaxMsg),
            0x03 => Ok(Instruction::SignEthMsg),
            0x04 => Ok(Instruction::SignAvaxHash),
            _ => Err(ParserError::InvalidTransactionType),
        }
    }
}

#[repr(C)]
pub struct parser_context_t {
    pub buffer: *const u8,
    pub bufferLen: u16,
    pub offset: u16,
    pub ins: u8,
    pub tx_obj: parse_tx_t,
}

#[repr(C)]
pub struct parse_tx_t {
    state: *mut u8,
    len: u16,
}

/// Cast a *mut u8 to a *mut Transaction
macro_rules! avax_obj_from_state {
    // *addr_of_mut!((*out).0).cast()
    ($ptr:expr) => {
        unsafe { &mut (*addr_of_mut!((*$ptr).state).cast::<MaybeUninit<Transaction>>()) }
    };
}

/// #Safety
/// Enough space was allocated to store an Avalanche Transaction
// unsafe fn parse_obj_from_state<'a>(tx: *mut parse_tx_t) -> Option<&'a mut Transaction<'a>> {
//     ((*tx).state as *const u8 as *mut Transaction).as_mut()
// }

#[no_mangle]
pub unsafe extern "C" fn _parser_init(
    ctx: *mut parser_context_t,
    buffer: *const u8,
    len: u16,
    alloc_size: *mut u16,
) -> u32 {
    if ctx.is_null() || alloc_size.is_null() {
        return ParserError::ParserInitContextEmpty as u32;
    }

    let tx_type = (*ctx).ins;

    let Ok(ins) = Instruction::try_from(tx_type) else {
        return ParserError::InvalidTransactionType as u32;
    };

    // Lets the caller know how much memory we need for allocating
    // our global state
    let size = match ins {
        Instruction::SignAvaxTx => core::mem::size_of::<MaybeUninit<Transaction>>() as u16,
        Instruction::SignEthTx => {
            unimplemented!()
        }
        Instruction::SignAvaxMsg => {
            unimplemented!()
        }
        Instruction::SignEthMsg => {
            unimplemented!()
        }
        Instruction::SignAvaxHash => {
            unimplemented!()
        }
    };

    *alloc_size = size;

    parser_init_context(ctx, buffer, len) as u32
}

/// #Safety
/// Called after zb_allocate assign memory
/// to store the Transaction. This memory outlives
/// the parsed and is deallocated before signing
/// at such point the rust-parser is not used anymore
unsafe fn parser_init_context(
    ctx: *mut parser_context_t,
    buffer: *const u8,
    len: u16,
) -> ParserError {
    (*ctx).offset = 0;

    if len == 0 || buffer.is_null() {
        (*ctx).buffer = core::ptr::null_mut();
        (*ctx).bufferLen = 0;
        return ParserError::ParserInitContextEmpty;
    }

    (*ctx).buffer = buffer;
    (*ctx).bufferLen = len;

    ParserError::ParserOk
}

#[no_mangle]
pub unsafe extern "C" fn _parser_read(
    context: *const parser_context_t,
    tx_t: *mut parse_tx_t,
) -> u32 {
    zemu_sys::zemu_log_stack("********read_avax_tx\x00");
    let data = core::slice::from_raw_parts((*context).buffer, (*context).bufferLen as _);
    let state = tx_t;

    if tx_t.is_null() || context.is_null() {
        return ParserError::ParserContextMismatch as u32;
    };

    let Ok(tx_type) = Instruction::try_from((*context).ins) else {
        return ParserError::InvalidTransactionType as u32;
    };

    match tx_type {
        Instruction::SignAvaxTx => {
            let tx = avax_obj_from_state!(state);
            match Transaction::new_into(data, tx) {
                Ok(_) => ParserError::ParserOk as u32,
                Err(e) => e as u32,
            }
        }

        _ => todo!(),
    };

    ParserError::ParserOk as u32
}

#[no_mangle]
pub unsafe extern "C" fn _getNumItems(
    ctx: *const parser_context_t,
    tx_t: *const parse_tx_t,
    num_items: *mut u8,
) -> u32 {
    if tx_t.is_null() || (*tx_t).state.is_null() || num_items.is_null() || ctx.is_null() {
        return ParserError::NoData as u32;
    }

    let state = tx_t as *mut parse_tx_t;

    let Ok(tx_type) = Instruction::try_from((*ctx).ins) else {
        return ParserError::InvalidTransactionType as u32;
    };

    match tx_type {
        Instruction::SignAvaxTx => {
            let tx = avax_obj_from_state!(state);
            let obj = tx.assume_init_mut();
            match obj.num_items() {
                Ok(n) => {
                    *num_items = n;
                    ParserError::ParserOk as u32
                }
                Err(e) => e as u32,
            }
        }

        _ => todo!(),
    };

    ParserError::ParserOk as u32
}

#[no_mangle]
pub unsafe extern "C" fn _getItem(
    ctx: *const parser_context_t,
    display_idx: u8,
    out_key: *mut i8,
    key_len: u16,
    out_value: *mut i8,
    out_len: u16,
    page_idx: u8,
    page_count: *mut u8,
    tx_t: *const parse_tx_t,
) -> u32 {
    *page_count = 0u8;

    let page_count = &mut *page_count;

    let key = core::slice::from_raw_parts_mut(out_key as *mut u8, key_len as usize);
    let value = core::slice::from_raw_parts_mut(out_value as *mut u8, out_len as usize);

    if tx_t.is_null() || (*tx_t).state.is_null() || ctx.is_null() {
        return ParserError::ParserContextMismatch as _;
    }

    let Ok(tx_type) = Instruction::try_from((*ctx).ins) else {
        return ParserError::InvalidTransactionType as u32;
    };

    let state = tx_t as *mut parse_tx_t;

    match tx_type {
        Instruction::SignAvaxTx => {
            let tx = avax_obj_from_state!(state);
            let obj = tx.assume_init_mut();
            match obj.render_item(display_idx, key, value, page_idx) {
                Ok(page) => {
                    *page_count = page;
                    ParserError::ParserOk as _
                }
                Err(e) => e as _,
            }
        }

        _ => todo!(),
    }
}
