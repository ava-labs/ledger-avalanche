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
use zemu_sys::Viewable;

mod ui;
pub use ui::{AddrUI, AddrUIInitializer};

use crate::{
    constants::{ApduError as Error, MAX_BIP32_PATH_DEPTH},
    crypto,
    dispatcher::ApduHandler,
    handlers::resources::EthAccessors,
    parser::ParserError,
    sys::{self, Error as SysError},
    utils::ApduBufferRead,
};

use super::utils::parse_bip32_eth;

pub struct GetPublicKey;

impl GetPublicKey {
    /// Retrieve the public key with the given bip32 path
    #[inline(never)]
    pub fn new_key_into<const B: usize>(
        path: &sys::crypto::bip32::BIP32Path<B>,
        out: &mut MaybeUninit<crypto::PublicKey>,
        chaincode: Option<&mut [u8; 32]>,
    ) -> Result<(), SysError> {
        sys::zemu_log_stack("GetEthAddres::new_key\x00");
        crypto::Curve
            .to_secret(path)
            .into_public_into(chaincode, out)?;

        //we don't compress the public key for ethereum
        Ok(())
    }

    /// Handles the request according to the parameters given
    pub fn initialize_ui(
        path: BIP32Path<MAX_BIP32_PATH_DEPTH>,
        with_cc: bool,
        ui: &mut MaybeUninit<AddrUI>,
    ) -> Result<(), Error> {
        let mut ui_initializer = AddrUIInitializer::new(ui);

        ui_initializer.with_path(path).with_chaincode(with_cc);

        ui_initializer.finalize().map_err(|(_, err)| err)?;

        Ok(())
    }

    pub fn fill(tx: &mut u32, buffer: ApduBufferRead<'_>) -> Result<bool, ParserError> {
        crate::zlog("EthGetPublicKey::fill_address\x00");

        let req_chaincode = buffer.p2() >= 1;
        let cdata = buffer.payload().map_err(|_| ParserError::NoData)?;

        let (_, bip32_path) = parse_bip32_eth(cdata).map_err(|_| ParserError::InvalidPath)?;

        // In this step we initialized and store in memory(allocated from C) our
        // UI object for later address visualization
        let mut ui = MaybeUninit::uninit();
        Self::initialize_ui(bip32_path, req_chaincode, &mut ui).map_err(|_| ParserError::NoData)?;

        //safe since it's all initialized now
        let ui = unsafe { ui.assume_init() };
        let mut ui = super::EthUi::Addr(ui);

        //we don't need to show so we execute the "accept" already
        // this way the "formatting" to `buffer` is all in the ui code
        let (sz, code) = ui.accept(buffer.write());

        if code != Error::Success as u16 {
            Err(ParserError::UnexpectedError)
        } else {
            unsafe {
                crate::handlers::resources::ETH_UI
                    .lock(EthAccessors::Tx)
                    .replace(ui);
            }

            *tx = sz as u32;
            Ok(true)
        }
    }
}

impl ApduHandler for GetPublicKey {
    #[inline(never)]
    fn handle(flags: &mut u32, tx: &mut u32, buffer: ApduBufferRead<'_>) -> Result<(), Error> {
        sys::zemu_log_stack("GetPublicKey::handle\x00");

        *tx = 0;

        let req_confirmation = buffer.p1() >= 1;
        let req_chaincode = buffer.p2() >= 1;
        let cdata = buffer.payload().map_err(|_| Error::DataInvalid)?;

        let (_, bip32_path) = parse_bip32_eth(cdata).map_err(|_| Error::DataInvalid)?;

        let mut ui = MaybeUninit::uninit();
        Self::initialize_ui(bip32_path, req_chaincode, &mut ui)?;

        //safe since it's all initialized now
        let mut ui = unsafe { ui.assume_init() };

        if req_confirmation {
            // crate::show_ui!(ui.show(flags), tx)
            Ok(())
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
