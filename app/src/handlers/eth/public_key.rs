/*******************************************************************************
*   (c) 2021 Zondax GmbH
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
use core::mem::MaybeUninit;
use std::convert::TryFrom;

use bolos::crypto::bip32::BIP32Path;
use zemu_sys::{Show, Viewable};

mod xpub;
pub use xpub::GetExtendedPublicKey;

mod ui;
pub use ui::{AddrUI, AddrUIInitError, AddrUIInitializer};

use crate::{
    constants::{ApduError as Error, MAX_BIP32_PATH_DEPTH},
    crypto,
    dispatcher::ApduHandler,
    sys::{self, Error as SysError},
    utils::{ApduBufferRead, ApduPanic},
};

use super::utils::parse_bip32_eth;

pub struct GetPublicKey;

impl GetPublicKey {
    /// Retrieve the public key with the given curve and bip32 path
    #[inline(never)]
    pub fn new_key_into<const B: usize>(
        path: &sys::crypto::bip32::BIP32Path<B>,
        out: &mut MaybeUninit<crypto::PublicKey>,
        chaincode: Option<&mut [u8; 32]>,
    ) -> Result<(), SysError> {
        sys::zemu_log_stack("GetEthAddres::new_key\x00");
        crypto::Curve::Secp256K1
            .to_secret(path)
            .into_public_into(chaincode, out)?;

        //we don't compress the public key for ethereum
        Ok(())
    }

    /// Handles the request according to the parameters given
    pub fn initialize_ui(
        path: BIP32Path<MAX_BIP32_PATH_DEPTH>,
        ui: &mut MaybeUninit<AddrUI>,
    ) -> Result<(), Error> {
        let mut ui_initializer = AddrUIInitializer::new(ui);

        ui_initializer.with_path(path);

        ui_initializer.finalize().map_err(|(_, err)| err)?;

        Ok(())
    }
}

impl ApduHandler for GetPublicKey {
    #[inline(never)]
    fn handle<'apdu>(
        flags: &mut u32,
        tx: &mut u32,
        buffer: ApduBufferRead<'apdu>,
    ) -> Result<(), Error> {
        sys::zemu_log_stack("GetPublicKey::handle\x00");

        *tx = 0;

        let req_confirmation = buffer.p1() >= 1;
        let cdata = buffer.payload().map_err(|_| Error::DataInvalid)?;

        let (_, bip32_path) = parse_bip32_eth(cdata).map_err(|_| Error::DataInvalid)?;

        let mut ui = MaybeUninit::uninit();
        Self::initialize_ui(bip32_path, &mut ui)?;

        //safe since it's all initialized now
        let mut ui = unsafe { ui.assume_init() };

        if req_confirmation {
            crate::show_ui!(ui.show(flags), tx)
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
