use core::mem::MaybeUninit;

use zemu_sys::Viewable;

use crate::{
    handlers::wallet_id::{WalletId, WalletIdUI},
    utils::ApduBufferRead,
    ZxError,
};

#[no_mangle]
pub unsafe extern "C" fn _app_fill_wallet(
    tx: *mut u32,
    rx: u32,
    buffer: *mut u8,
    buffer_len: u16,
    wallet_ui: *mut u8,
    wallet_ui_len: u16,
) -> u16 {
    let Some(tx) = tx.as_mut() else {
        return ZxError::NoData as u16;
    };
    let data = std::slice::from_raw_parts_mut(buffer, buffer_len as usize);

    let Ok(apdu_buffer) = ApduBufferRead::new(data, rx) else {
        return ZxError::OutOfBounds as u16;
    };

    match WalletId::fill(tx, apdu_buffer, wallet_ui, wallet_ui_len) {
        Ok(_) => ZxError::Ok as u16,
        Err(e) => e as u16,
    }
}

#[no_mangle]
pub unsafe extern "C" fn _wallet_ui_size() -> u16 {
    core::mem::size_of::<MaybeUninit<WalletIdUI>>() as u16
}

#[no_mangle]
pub unsafe extern "C" fn _wallet_num_items(addr_obj: *mut u8, num_items: *mut u8) -> u16 {
    if addr_obj.is_null() || num_items.is_null() {
        return ZxError::NoData as u16;
    }

    let ui = &mut *addr_obj.cast::<MaybeUninit<WalletIdUI>>();
    let ui = ui.assume_init_mut();

    let Ok(items) = ui.num_items() else {
        return ZxError::NoData as u16;
    };

    *num_items = items;

    ZxError::Ok as u16
}

#[no_mangle]
pub unsafe extern "C" fn _wallet_get_item(
    addr_obj: *mut u8,
    display_idx: u8,
    out_key: *mut u8,
    key_len: u16,
    out_value: *mut u8,
    out_len: u16,
    page_idx: u8,
    page_count: *mut u8,
) -> u16 {
    if addr_obj.is_null()
        || out_value.is_null()
        || page_count.is_null()
        || key_len == 0
        || out_key.is_null()
    {
        return ZxError::NoData as u16;
    }

    let (ui, out_key, out_value) = {
        let ui = &mut *addr_obj.cast::<MaybeUninit<WalletIdUI>>();
        let out_value = core::slice::from_raw_parts_mut(out_value, out_len as usize);
        let out_key = core::slice::from_raw_parts_mut(out_key, key_len as usize);
        (ui.assume_init_mut(), out_key, out_value)
    };

    let Ok(page) = ui.render_item(display_idx, out_key, out_value, page_idx) else {
        return ZxError::NoData as u16;
    };

    *page_count = page;

    ZxError::Ok as u16
}
