/*******************************************************************************
*   (c) 2022 Zondax GmbH
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
use cfg_if::cfg_if;

#[cfg(feature = "blind-sign-toggle")]
mod impls {
    #[repr(C)]
    pub struct BlindSignToggle {
        pub toggle: bool,
        pub message: [i8; 9],
    }

    cfg_if::cfg_if! {
        if #[cfg(any(unix, windows))] {
            /// Provide a mock for tests
            #[allow(non_upper_case_globals)]
            pub static mut blind_sign: BlindSignToggle = BlindSignToggle {
                toggle: true,
                message: [0; 9],
            };
        } else {
            extern "C" {
                ///Link to the C code
                pub static mut blind_sign: BlindSignToggle;
            }
        }
    }
}

/// Returns if blind signing is enabled in this execution
pub fn blind_sign_enabled() -> bool {
    cfg_if! {
        if #[cfg(feature = "blind-sign-toggle")] {
            //safe: guaranteed no data races
            unsafe { impls::blind_sign.toggle }
        } else {
            false
        }
    }
}
