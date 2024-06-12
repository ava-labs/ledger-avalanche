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
