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
use core::mem::MaybeUninit;
use std::convert::TryFrom;

use bolos::{crypto::bip32::BIP32Path, PIC};
use zemu_sys::{Show, Viewable};

mod xpub;
pub use xpub::{ExtendedPubkeyUI, GetExtendedPublicKey};

mod ui;
pub use ui::{AddrUI, AddrUIInitError, AddrUIInitializer};

use crate::{
    constants::{ApduError as Error, ASCII_HRP_MAX_SIZE, DEFAULT_CHAIN_ID, MAX_BIP32_PATH_DEPTH},
    crypto,
    dispatcher::ApduHandler,
    sys::{self, Error as SysError},
    utils::{read_slice, ApduBufferRead, ApduPanic},
};

pub struct GetPublicKey;

impl GetPublicKey {
    pub const DEFAULT_CHAIN_ID: &'static [u8; 32] = DEFAULT_CHAIN_ID;

    pub const DEFAULT_HRP: &'static [u8; 4] = b"avax";

    pub fn default_hrp() -> &'static [u8; 4] {
        PIC::new(Self::DEFAULT_HRP).into_inner()
    }

    pub fn default_chainid() -> &'static [u8; 32] {
        PIC::new(Self::DEFAULT_CHAIN_ID).into_inner()
    }

    /// Retrieve the public key with the given bip32 path
    #[inline(never)]
    pub fn new_key_into<const B: usize>(
        path: &sys::crypto::bip32::BIP32Path<B>,
        out: &mut MaybeUninit<crypto::PublicKey>,
        chaincode: Option<&mut [u8; 32]>,
        curve_type: u8,
    ) -> Result<(), SysError> {
        sys::zemu_log_stack("GetAddres::new_key\x00");

        if curve_type == 0 {
            crypto::Curve::Secp256K1
                .to_secret(path)
                .into_public_into(chaincode, out)?;
        } else {
            crypto::Curve::Ed25519
                .to_secret(path)
                .into_public_into(chaincode, out)?;
        }
        

        //this is safe because it's initialized
        // also unwrapping is fine because the ptr is valid
        let pkey = unsafe { out.as_mut_ptr().as_mut().apdu_unwrap() };
        pkey.compress()
    }

    /// Attempts to read a hrp in the slice, advancing the slice and returning the HRP (or default)
    pub fn get_hrp<'a>(cdata: &mut &'a [u8]) -> Result<&'a [u8], Error> {
        let (bytes_read, hrp) = read_slice(cdata).ok_or(Error::DataInvalid)?;
        *cdata = &cdata[bytes_read..];

        match hrp.len() {
            0 => Ok(Self::default_hrp().as_slice()),
            len if len > ASCII_HRP_MAX_SIZE => Err(Error::DataInvalid),
            _ => Ok(hrp),
        }
    }

    /// Attempts to read a chainid in the slice,
    /// advancing the slice and returning the ChainID (or default)
    pub fn get_chainid<'a>(cdata: &mut &'a [u8]) -> Result<&'a [u8], Error> {
        let (bytes_read, chainid) = read_slice(cdata).ok_or(Error::DataInvalid)?;
        *cdata = &cdata[bytes_read..];

        match chainid.len() {
            0 => Ok(Self::default_chainid().as_slice()),
            32 => Ok(chainid),
            _ => Err(Error::DataInvalid),
        }
    }

    /// Handles the request according to the parameters given
    pub fn initialize_ui(
        hrp: &[u8],
        chain_id: &[u8],
        path: BIP32Path<MAX_BIP32_PATH_DEPTH>,
        ui: &mut MaybeUninit<AddrUI>,
        curve_type: u8,
    ) -> Result<(), Error> {
        let mut ui_initializer = AddrUIInitializer::new(ui);

        if curve_type == 0 {
            ui_initializer
                .with_path(path)
                .with_chain(chain_id)?
                .with_hrp(hrp)?
                .with_curve(0);
        } else {
            ui_initializer
                .with_path(path)
                .with_curve(1);
        }

        ui_initializer.finalize().map_err(|(_, err)| err)?;

        Ok(())
    }

    pub fn fill(
        tx: &mut u32,
        buffer: ApduBufferRead<'_>,
        addr_ui: *mut u8,
        addr_ui_len: u16,
    ) -> Result<(), Error> {
        crate::zlog("GetPublicKey::fill_address\n\x00");

        if addr_ui.is_null() || addr_ui_len != core::mem::size_of::<MaybeUninit<AddrUI>>() as u16 {
            return Err(Error::DataInvalid);
        }

        *tx = 0;

        let mut cdata = buffer.payload().map_err(|_| Error::DataInvalid)?;

        let hrp = Self::get_hrp(&mut cdata)?;
        let chainid = Self::get_chainid(&mut cdata)?;

        let bip32_path = sys::crypto::bip32::BIP32Path::<MAX_BIP32_PATH_DEPTH>::read(cdata)
            .map_err(|_| Error::DataInvalid)?;

        // In this step we initialized and store in memory(allocated from C) our
        // UI object for later address visualization
        let ui = unsafe { &mut *addr_ui.cast::<MaybeUninit<AddrUI>>() };
        Self::initialize_ui(hrp, chainid, bip32_path, ui, 0)?;

        //safe since it's all initialized now
        let ui = unsafe { ui.assume_init_mut() };

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

impl ApduHandler for GetPublicKey {
    #[inline(never)]
    fn handle(flags: &mut u32, tx: &mut u32, buffer: ApduBufferRead<'_>) -> Result<(), Error> {
        sys::zemu_log_stack("GetPublicKey::handle\x00");

        *tx = 0;

        let req_confirmation = buffer.p1() >= 1;

        let mut cdata = buffer.payload().map_err(|_| Error::DataInvalid)?;

        let hrp = Self::get_hrp(&mut cdata)?;
        let chainid = Self::get_chainid(&mut cdata)?;

        let bip32_path = sys::crypto::bip32::BIP32Path::<MAX_BIP32_PATH_DEPTH>::read(cdata)
            .map_err(|_| Error::DataInvalid)?;

        let mut ui = MaybeUninit::uninit();
        Self::initialize_ui(hrp, chainid, bip32_path, &mut ui, 0)?;

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
