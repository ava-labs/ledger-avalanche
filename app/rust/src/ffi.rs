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

#[repr(C)]
pub struct parser_context_t {
    pub buffer: *const u8,
    pub bufferLen: u16,
    pub offset: u16,
}

#[repr(C)]
pub struct parse_tx_t {
    state: *mut u8,
    len: u16,
}

macro_rules! get_obj_from_state {
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
pub unsafe extern "C" fn _init_avax_tx(
    ctx: *mut parser_context_t,
    buffer: *const u8,
    bufferSize: u16,
    alloc_size: *mut u16,
) -> u32 {
    // Lets the caller know how much memory we need for allocating
    // our global state
    if alloc_size.is_null() {
        return ParserError::ParserInitContextEmpty as u32;
    }
    // *alloc_size = core::mem::size_of::<Transaction>() as u16;
    // Lets use Uninit memory abstraction in rust
    *alloc_size = core::mem::size_of::<MaybeUninit<Transaction>>() as u16;
    parser_init_context(ctx, buffer, bufferSize) as u32
}

/// #Safety
/// Called after zb_allocate assign memory
/// to store the Transaction. This memory outlives
/// the parsed and is deallocated before signing
/// at such point the rust-parser is not used anymore
unsafe fn parser_init_context(
    ctx: *mut parser_context_t,
    buffer: *const u8,
    bufferSize: u16,
) -> ParserError {
    (*ctx).offset = 0;

    if bufferSize == 0 || buffer.is_null() {
        (*ctx).buffer = core::ptr::null_mut();
        (*ctx).bufferLen = 0;
        return ParserError::ParserInitContextEmpty;
    }

    (*ctx).buffer = buffer;
    (*ctx).bufferLen = bufferSize;
    ParserError::ParserOk
}

#[no_mangle]
pub unsafe extern "C" fn _read_avax_tx(
    context: *const parser_context_t,
    tx_t: *mut parse_tx_t,
) -> u32 {
    zemu_sys::zemu_log_stack("********read_avax_tx\x00");
    let data = core::slice::from_raw_parts((*context).buffer, (*context).bufferLen as _);
    let state = tx_t as *mut parse_tx_t;

    if tx_t.is_null() {
        return ParserError::ParserContextMismatch as u32;
    }

    let tx = get_obj_from_state!(state);

    match Transaction::new_into(data, tx) {
        Ok(_) => ParserError::ParserOk as u32,
        Err(e) => e as u32,
    }
}

#[no_mangle]
pub unsafe extern "C" fn _getNumItems(
    _ctx: *const parser_context_t,
    tx_t: *const parse_tx_t,
    num_items: *mut u8,
) -> u32 {
    if tx_t.is_null() || (*tx_t).state.is_null() || num_items.is_null() {
        return ParserError::NoData as u32;
    }

    let state = tx_t as *mut parse_tx_t;
    let tx = get_obj_from_state!(state);

    let obj = tx.assume_init_mut();

    match obj.num_items() {
        Ok(n) => {
            *num_items = n;
            ParserError::ParserOk as u32
        }
        Err(e) => e as u32,
    }
}

#[no_mangle]
pub unsafe extern "C" fn _getItem(
    _ctx: *const parser_context_t,
    displayIdx: u8,
    outKey: *mut i8,
    outKeyLen: u16,
    outValue: *mut i8,
    outValueLen: u16,
    pageIdx: u8,
    pageCount: *mut u8,
    tx_t: *const parse_tx_t,
) -> u32 {
    *pageCount = 0u8;
    let page_count = &mut *pageCount;
    let key = core::slice::from_raw_parts_mut(outKey as *mut u8, outKeyLen as usize);
    let value = core::slice::from_raw_parts_mut(outValue as *mut u8, outValueLen as usize);
    if tx_t.is_null() || (*tx_t).state.is_null() {
        return ParserError::ParserContextMismatch as _;
    }
    let state = tx_t as *mut parse_tx_t;
    let tx = get_obj_from_state!(state);
    let obj = tx.assume_init_mut();

    match obj.render_item(displayIdx, key, value, pageIdx) {
        Ok(page) => {
            *page_count = page;
            ParserError::ParserOk as _
        }
        Err(e) => e as _,
    }
}
