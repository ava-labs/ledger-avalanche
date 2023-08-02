/*******************************************************************************
*   (c) 2022 Zondax AG
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
    constants::{version::*, ApduError as Error},
    dispatcher::ApduHandler,
    sys,
    utils::ApduBufferRead,
};

/// Return the app configuration flags
///
/// This is described by the Ethereum app docs
///
/// The response is constructed by 4 bytes, where the first
/// is a set of flags, while the other 3 are the app's
/// MAJOR, MINOR and PATCH version values
/// [----zsxy][MAJOR][MINOR][PATCH]
///
/// `z` is set when Stark V2 is supported
/// `s` is set when Stark is supported
/// `x` is set when the app needs external data for ERC20 tokens
/// `z` is set when the app can sign arbitrary data
pub struct GetAppConfiguration;

impl ApduHandler for GetAppConfiguration {
    #[inline(never)]
    fn handle(
        _: &mut u32,
        tx: &mut u32,
        buffer: ApduBufferRead<'_>,
    ) -> Result<(), Error> {
        sys::zemu_log_stack("GetAppConfig::handle\x00");

        //ignore any input, we don't care
        let buffer = buffer.write();
        buffer[0] = 0x02; //needs external data for ERC20 tokens
        buffer[1] = APPVERSION_M;
        buffer[2] = APPVERSION_N;
        buffer[3] = APPVERSION_P;

        *tx = 4;

        Ok(())
    }
}
