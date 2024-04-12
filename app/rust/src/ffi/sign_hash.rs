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

use crate::{
    constants::MAX_BIP32_PATH_DEPTH, handlers::avax::sign_hash::Sign, parser::ParserError, ZxError,
};

#[no_mangle]
pub unsafe extern "C" fn _get_hash(out: *mut u8, len: u16) -> u16 {
    if out.is_null() || len != Sign::SIGN_HASH_SIZE as u16 {
        return ZxError::BufferTooSmall as _;
    }

    let output = core::slice::from_raw_parts_mut(out, len as _);

    let Ok(hash) = Sign::get_hash() else {
        return ZxError::NoData as _;
    };

    output.copy_from_slice(&hash[..]);

    ZxError::Ok as _
}

#[no_mangle]
pub unsafe extern "C" fn _get_signing_info(
    out: *mut u32,
    len: u16,
    input: *const u8,
    in_len: u16,
) -> u16 {
    if out.is_null() || len > MAX_BIP32_PATH_DEPTH as u16 || input.is_null() {
        return ZxError::BufferTooSmall as _;
    }

    let raw_path_suffix = core::slice::from_raw_parts(input, in_len as _);

    // our output path, the one to use for signing this hash
    let output = core::slice::from_raw_parts_mut(out, len as _);

    let Ok(path) = Sign::get_signing_info(raw_path_suffix) else {
        return ZxError::NoData as _;
    };

    let components = path.components();

    output[..components.len()].copy_from_slice(components);

    ZxError::Ok as _
}

#[no_mangle]
pub unsafe extern "C" fn _clean_up_hash() {
    _ = crate::handlers::avax::sign_hash::cleanup_globals();
}

#[no_mangle]
pub unsafe extern "C" fn _parse_sign_hash_tx(input: *const u8, len: u16) -> u32 {
    let data = core::slice::from_raw_parts(input, len as _);
    if let Err(e) = Sign::parse_hash(data) {
        return e as _;
    }
    ParserError::ParserOk as _
}
