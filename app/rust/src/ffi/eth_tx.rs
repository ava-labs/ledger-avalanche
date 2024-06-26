use zemu_sys::Viewable;

use crate::{
    constants::ApduError,
    handlers::resources::{EthAccessors, ETH_UI},
    parser::ParserError,
};

use super::context::{parser_context_t, Instruction};

#[inline(never)]
pub unsafe fn num_items_eth(ctx: *const parser_context_t, num_items: &mut u8) -> u32 {
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

#[inline(never)]
pub unsafe fn get_eth_item(
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
