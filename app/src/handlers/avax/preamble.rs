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
use std::convert::TryFrom;

use bolos::crypto::bip32::BIP32Path;

use crate::{
    constants::{ApduError as Error, MAX_BIP32_PATH_DEPTH},
    crypto::Curve,
    dispatcher::ApduHandler,
    handlers::resources::PATH,
    sys,
    utils::ApduBufferRead,
};

pub struct Preamble;

impl ApduHandler for Preamble {
    #[inline(never)]
    fn handle<'apdu>(
        _flags: &mut u32,
        tx: &mut u32,
        buffer: ApduBufferRead<'apdu>,
    ) -> Result<(), Error> {
        sys::zemu_log_stack("Preample::handle\x00");

        *tx = 0;
        let curve = Curve::try_from(buffer.p2()).map_err(|_| Error::InvalidP1P2)?;

        let cdata = buffer.payload().map_err(|_| Error::DataInvalid)?;
        let path =
            BIP32Path::<MAX_BIP32_PATH_DEPTH>::read(cdata).map_err(|_| Error::DataInvalid)?;

        // store the root path, it is not a full path though
        unsafe {
            PATH.lock(Self)?.replace((path, curve));
        }
        Ok(())
    }
}
