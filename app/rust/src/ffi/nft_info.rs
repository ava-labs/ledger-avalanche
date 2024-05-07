use crate::ZxError;

use crate::handlers::eth::provide_nft_info::Info;

#[no_mangle]
pub unsafe extern "C" fn _process_nft_info(buffer: *mut u8, buffer_len: u16) -> u16 {
    if buffer.is_null() {
        return ZxError::NoData as u16;
    };
    let data = std::slice::from_raw_parts_mut(buffer, buffer_len as usize);

    match Info::process(data) {
        Ok(_) => ZxError::Ok as u16,
        Err(e) => e as u16,
    }
}
