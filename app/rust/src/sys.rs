/*******************************************************************************
*   (c) 2018-2024 Zondax AG
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
#![allow(dead_code)]

pub use bolos::*;
pub use zemu_sys::*;

// extern "C" {
//     pub fn zemu_log_stack(buffer: *const u8);
// }

// #[cfg(not(test))]
// pub fn zlog_stack<S: AsRef<[u8]>>(s: S) {
//     unsafe { zemu_log_stack(s.as_ref().as_ptr()) }
// }
// #[cfg(test)]
// pub fn zlog_stack<S: AsRef<[u8]>>(_s: S) {}
