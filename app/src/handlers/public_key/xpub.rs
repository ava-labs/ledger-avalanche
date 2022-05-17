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
use core::{convert::TryFrom, mem::MaybeUninit};

use zemu_sys::{Show, Viewable};

use crate::{
    constants::ApduError as Error, crypto, dispatcher::ApduHandler, sys, utils::ApduBufferRead,
};

use super::GetPublicKey;

pub struct GetExtendedPublicKey;

impl ApduHandler for GetExtendedPublicKey {
    #[inline(never)]
    fn handle<'apdu>(
        flags: &mut u32,
        tx: &mut u32,
        buffer: ApduBufferRead<'apdu>,
    ) -> Result<(), Error> {
        sys::zemu_log_stack("GetExtendedPublicKey::handle\x00");

        *tx = 0;

        let req_confirmation = buffer.p1() >= 1;
        let curve = crypto::Curve::try_from(buffer.p2()).map_err(|_| Error::InvalidP1P2)?;

        let mut cdata = buffer.payload().map_err(|_| Error::DataInvalid)?;

        let hrp = GetPublicKey::get_hrp(&mut cdata)?;
        let chainid = GetPublicKey::get_chainid(&mut cdata)?;

        let bip32_path =
            sys::crypto::bip32::BIP32Path::<6>::read(cdata).map_err(|_| Error::DataInvalid)?;

        let mut ui = MaybeUninit::uninit();
        GetPublicKey::initialize_ui(
            req_confirmation,
            curve,
            hrp,
            chainid,
            bip32_path,
            true,
            &mut ui,
        )?;

        //safe since it's all initialized now
        let mut ui = unsafe { ui.assume_init() };

        if req_confirmation {
            unsafe { ui.show(flags) }.map_err(|_| Error::ExecutionError)
        } else {
            //we don't need to show so we execute the "accept" already
            // this way the "formatting" to `buffer` is all in the ui code
            let (sz, code) = ui.accept(buffer.write());

            if code != Error::Success as u16 {
                Err(Error::try_from(code).map_err(|_| Error::ExecutionError)?)
            } else {
                *tx = sz as u32;
                Ok(())
            }
        }
    }
}
