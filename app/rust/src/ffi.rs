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

use crate::constants::{BIP32_PATH_SUFFIX_DEPTH, SIGN_HASH_TX_SIZE};
use crate::handlers::avax::sign_hash::{Sign as SignHash, SignUI};
use crate::handlers::avax::signing::Sign;
use crate::handlers::resources::{EthAccessors, ETH_UI};
use crate::parser::{parse_path_list, AvaxMessage, DisplayableItem, ObjectList, PathWrapper};
use crate::parser::{FromBytes, ParserError, Transaction};
use crate::ZxError;

pub mod context;
pub mod ext_public_key;
pub mod nft_info;
pub mod public_key;
pub mod sign_hash;
pub mod wallet_id;
use bolos::ApduError;
use context::{parser_context_t, Instruction};
use zemu_sys::Viewable;

/// Cast a *mut u8 to a *mut Transaction
macro_rules! avax_tx_from_state {
    ($ptr:expr) => {
        unsafe { &mut (*addr_of_mut!((*$ptr).tx_obj.state).cast::<MaybeUninit<Transaction>>()) }
    };
}

/// Cast a *mut u8 to a *mut AvaxMessage
macro_rules! avax_msg_from_state {
    ($ptr:expr) => {
        unsafe { &mut (*addr_of_mut!((*$ptr).tx_obj.state).cast::<MaybeUninit<AvaxMessage>>()) }
    };
}

// Innitialize internals for transaction processing
#[no_mangle]
pub unsafe extern "C" fn _parser_init(
    ctx: *mut parser_context_t,
    buffer: *const u8,
    len: usize,
    alloc_size: *mut u32,
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
        Instruction::SignAvaxTx => core::mem::size_of::<MaybeUninit<Transaction>>() as u32,
        // Instruction::SignEthTx => core::mem::size_of::<MaybeUninit<EthTransaction>>() as u32,
        Instruction::SignAvaxMsg => core::mem::size_of::<MaybeUninit<AvaxMessage>>() as u32,
        // Instruction::SignEthMsg => core::mem::size_of::<MaybeUninit<PersonalMsg>>() as u32,
        Instruction::SignAvaxHash => SIGN_HASH_TX_SIZE as u32,
        // Ingnore eth transactions as they would be handled by
        // either the app-ethereum application or full rust handler.
        _ => return ParserError::InvalidTransactionType as u32,
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
    len: usize,
) -> ParserError {
    (*ctx).offset = 0;

    if len == 0 || buffer.is_null() {
        (*ctx).buffer = core::ptr::null_mut();
        (*ctx).buffer_len = 0;
        return ParserError::ParserInitContextEmpty;
    }

    (*ctx).buffer = buffer;
    // we are sure that len is less than u16::MAX
    (*ctx).buffer_len = len as u16;

    ParserError::ParserOk
}

/// Parses the transaction data from the provided context.
///
/// It interprets the transaction data based on the instruction type specified in the context
/// and performs the corresponding parsing operation.
///
/// # Safety
///
/// This function is unsafe because it performs raw pointer dereferencing and assumes the provided context pointer is valid.
/// The caller must ensure the context is properly initialized and that the memory pointed to remains valid for the duration of the function call.
///
/// # Arguments
///
/// * `ctx` - A pointer to the `parser_context_t` structure that contains the buffer and instruction type.
///
/// # Returns
///
/// Returns a `u32` indicating the result of the parse operation. The return value corresponds to values from the `ParserError` enum,
/// encoded as `u32`.
///
/// # Errors
///
/// Returns an error if:
/// * The context pointer is null.
/// * The instruction type is invalid or unsupported.
/// * Parsing the transaction type or specific transaction components fails.
#[no_mangle]
pub unsafe extern "C" fn _parser_read(ctx: *const parser_context_t) -> u32 {
    if ctx.is_null() {
        return ParserError::ParserContextMismatch as u32;
    };

    let data = core::slice::from_raw_parts((*ctx).buffer, (*ctx).buffer_len as _);

    let Ok(tx_type) = Instruction::try_from((*ctx).ins) else {
        return ParserError::InvalidTransactionType as u32;
    };

    match tx_type {
        Instruction::SignAvaxTx => {
            // then, get the change_path list.
            let mut path_list: MaybeUninit<ObjectList<PathWrapper<BIP32_PATH_SUFFIX_DEPTH>>> =
                MaybeUninit::uninit();

            let Ok(rem) = parse_path_list(&mut path_list, data) else {
                return ParserError::InvalidPath as u32;
            };

            let mut path_list = path_list.assume_init();

            let tx = avax_tx_from_state!(ctx as *mut parser_context_t);
            match Transaction::new_into(rem, tx) {
                Ok(_) => {
                    // now disable transaction outputs that match
                    // the change paths
                    let tx = tx.assume_init_mut();
                    // important to use the handlers::avax::signing::Sign module
                    let Ok(_) = Sign::disable_outputs(&mut path_list, tx) else {
                        return ParserError::InvalidPath as u32;
                    };

                    ParserError::ParserOk as u32
                }
                Err(e) => e as u32,
            }
        }

        Instruction::SignAvaxHash => {
            if let Err(e) = SignHash::parse_hash(data) {
                return e as u32;
            }
            ParserError::ParserOk as u32
        }

        Instruction::SignAvaxMsg => {
            let tx = avax_msg_from_state!(ctx as *mut parser_context_t);
            match AvaxMessage::from_bytes_into(data, tx) {
                Ok(_) => ParserError::ParserOk as u32,
                Err(_) => ParserError::InvalidAvaxMessage as u32,
            }
        }
        // Ingnore eth transactions as they would be handled by
        // the app-ethereum application.
        _ => ParserError::InvalidTransactionType as u32,
    }
}

#[no_mangle]
pub unsafe extern "C" fn _getNumItems(ctx: *const parser_context_t, num_items: *mut u8) -> u32 {
    if num_items.is_null() || ctx.is_null() {
        return ParserError::NoData as u32;
    }

    let Ok(tx_type) = Instruction::try_from((*ctx).ins) else {
        return ParserError::InvalidTransactionType as u32;
    };

    let num_items = &mut *num_items;

    if tx_type.is_avax() {
        num_items_avax(ctx, num_items)
    } else {
        num_items_eth(ctx, num_items)
    }
}

#[inline(never)]
unsafe fn num_items_avax(ctx: *const parser_context_t, num_items: &mut u8) -> u32 {
    let Ok(tx_type) = Instruction::try_from((*ctx).ins) else {
        return ParserError::InvalidTransactionType as u32;
    };

    match tx_type {
        Instruction::SignAvaxTx => {
            let state = (*ctx).tx_obj.state;

            if state.is_null() {
                return ParserError::NoData as u32;
            }

            let tx = avax_tx_from_state!(ctx as *mut parser_context_t);
            let obj = tx.assume_init_mut();
            match obj.num_items() {
                Ok(n) => {
                    *num_items = n;
                    ParserError::ParserOk as u32
                }
                Err(e) => e as u32,
            }
        }

        Instruction::SignAvaxHash => {
            *num_items = 1;
            ParserError::ParserOk as u32
        }

        Instruction::SignAvaxMsg => {
            *num_items = 1;
            ParserError::ParserOk as u32
        }
        _ => ParserError::InvalidTransactionType as u32,
    };

    ParserError::ParserOk as u32
}

#[inline(never)]
unsafe fn num_items_eth(ctx: *const parser_context_t, num_items: &mut u8) -> u32 {
    let Ok(tx_type) = Instruction::try_from((*ctx).ins) else {
        return ParserError::InvalidTransactionType as u32;
    };

    if tx_type.is_avax() {
        return ParserError::InvalidTransactionType as u32;
    }

    if let Some(obj) = ETH_UI.lock(EthAccessors::Tx) {
        match obj.num_items() {
            Ok(n) => {
                *num_items = n;
                ParserError::ParserOk as _
            }
            Err(e) => e as _,
        }
    } else {
        ParserError::NoData as _
    }
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
) -> u32 {
    *page_count = 0u8;

    let page_count = &mut *page_count;

    let key = core::slice::from_raw_parts_mut(out_key as *mut u8, key_len as usize);
    let value = core::slice::from_raw_parts_mut(out_value as *mut u8, out_len as usize);

    if ctx.is_null() {
        return ParserError::ParserContextMismatch as _;
    }

    let Ok(tx_type) = Instruction::try_from((*ctx).ins) else {
        return ParserError::InvalidTransactionType as u32;
    };

    if tx_type.is_avax() {
        get_avax_item(ctx, display_idx, key, value, page_idx, page_count)
    } else {
        get_eth_item(ctx, display_idx, key, value, page_idx, page_count)
    }
}

#[inline(never)]
unsafe fn get_avax_item(
    ctx: *const parser_context_t,
    display_idx: u8,
    key: &mut [u8],
    value: &mut [u8],
    page_idx: u8,
    page_count: &mut u8,
) -> u32 {
    *page_count = 0u8;

    let page_count = &mut *page_count;

    if ctx.is_null() {
        return ParserError::ParserContextMismatch as _;
    }

    let Ok(tx_type) = Instruction::try_from((*ctx).ins) else {
        return ParserError::InvalidTransactionType as u32;
    };

    match tx_type {
        Instruction::SignAvaxTx => {
            let state = (*ctx).tx_obj.state;

            if state.is_null() {
                return ParserError::NoData as u32;
            }

            let tx = avax_tx_from_state!(ctx as *mut parser_context_t);
            let obj = tx.assume_init_mut();
            match obj.render_item(display_idx, key, value, page_idx) {
                Ok(page) => {
                    *page_count = page;
                    ParserError::ParserOk as _
                }
                Err(e) => e as _,
            }
        }

        Instruction::SignAvaxHash => {
            let state = (*ctx).tx_obj.state;

            if state.is_null() {
                return ParserError::NoData as u32;
            }

            let Ok(hash) = SignHash::get_hash() else {
                return ParserError::NoData as _;
            };
            let mut ui = SignUI::new(*hash);
            match zemu_sys::Viewable::render_item(&mut ui, display_idx, key, value, page_idx) {
                Ok(page) => {
                    *page_count = page;
                    ParserError::ParserOk as _
                }
                Err(e) => e as _,
            }
        }

        Instruction::SignAvaxMsg => {
            let state = (*ctx).tx_obj.state;

            if state.is_null() {
                return ParserError::NoData as u32;
            }

            let msg = avax_msg_from_state!(ctx as *mut parser_context_t);
            let obj = msg.assume_init_mut();
            match obj.render_item(display_idx, key, value, page_idx) {
                Ok(page) => {
                    *page_count = page;
                    ParserError::ParserOk as _
                }
                Err(e) => e as _,
            }
        }
        _ => ParserError::NoData as _,
    }
}

#[inline(never)]
unsafe fn get_eth_item(
    ctx: *const parser_context_t,
    display_idx: u8,
    key: &mut [u8],
    value: &mut [u8],
    page_idx: u8,
    page_count: &mut u8,
) -> u32 {
    *page_count = 0u8;

    let page_count = &mut *page_count;

    if ctx.is_null() {
        return ParserError::ParserContextMismatch as _;
    }

    let Ok(tx_type) = Instruction::try_from((*ctx).ins) else {
        return ParserError::InvalidTransactionType as u32;
    };

    if tx_type.is_avax() {
        return ParserError::InvalidTransactionType as _;
    }

    if let Some(obj) = ETH_UI.lock(EthAccessors::Tx) {
        match obj.render_item(display_idx, key, value, page_idx) {
            Ok(page) => {
                *page_count = page;
                ParserError::ParserOk as _
            }
            Err(e) => e as _,
        }
    } else {
        ParserError::NoData as _
    }
}

// Returns the offset at which transaction data starts.
// remember that this instruction comes with a list of change_path at the
// begining of the buffer. those paths needs to be ignored when
// computing transaction hash for signing.
// this is useful for avax transactions that takes a list of change paths.
#[no_mangle]
pub unsafe extern "C" fn _tx_data_offset(
    buffer: *const u8,
    buffer_len: u16,
    offset: *mut u16,
) -> u16 {
    if buffer.is_null() || offset.is_null() || buffer_len == 0 {
        return ZxError::NoData as _;
    }

    let data = core::slice::from_raw_parts(buffer, buffer_len as _);

    let mut path_list: MaybeUninit<ObjectList<PathWrapper<BIP32_PATH_SUFFIX_DEPTH>>> =
        MaybeUninit::uninit();

    let Ok(rem) = parse_path_list(&mut path_list, data) else {
        return ZxError::NoData as _;
    };

    if buffer_len < rem.len() as u16 {
        return ZxError::BufferTooSmall as _;
    }

    *offset = buffer_len - rem.len() as u16;

    ZxError::Ok as _
}

#[no_mangle]
unsafe extern "C" fn _accept_eth_tx(tx: *mut u16, buffer: *mut u8, buffer_len: u32) -> u16 {
    if tx.is_null() || buffer.is_null() || buffer_len == 0 {
        return ApduError::DataInvalid as u16;
    }

    let data = std::slice::from_raw_parts_mut(buffer, buffer_len as usize);

    let code = if let Some(obj) = ETH_UI.lock(EthAccessors::Tx) {
        let (_tx, code) = obj.accept(data);
        *tx = _tx as u16;
        code
    } else {
        // No ethereum transaction has been processed yet
        ApduError::DataInvalid as u16
    };

    code
}
