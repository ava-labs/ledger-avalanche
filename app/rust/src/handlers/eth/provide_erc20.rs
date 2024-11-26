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
use crate::{constants::ApduError as Error, dispatcher::ApduHandler, sys, utils::ApduBufferRead};

pub struct ProvideERC20;

impl ApduHandler for ProvideERC20 {
    #[inline(never)]
    fn handle(_: &mut u32, tx: &mut u32, _: ApduBufferRead<'_>) -> Result<(), Error> {
        sys::zemu_log_stack("ProvideERC20::handle\x00");

        *tx = 0;

        Ok(())
    }
}
