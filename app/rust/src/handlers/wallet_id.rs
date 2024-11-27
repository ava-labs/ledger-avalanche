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
use core::{mem::MaybeUninit, ptr::addr_of_mut};
use std::convert::TryFrom;

use bolos::hmac::Sha256HMAC;
use zemu_sys::{Show, ViewError, Viewable};

use crate::{
    constants::{
        ApduError as Error, BIP32_PATH_ROOT_0, BIP32_PATH_ROOT_1, WALLET_ID_HMAC_KEY, WALLET_ID_LEN,
    },
    crypto,
    dispatcher::ApduHandler,
    handlers::handle_ui_message,
    sys::{self, PIC},
    utils::{hex_encode, ApduBufferRead, ApduPanic},
};

pub struct WalletId;

impl WalletId {
    pub const LEN: usize = WALLET_ID_LEN;
    pub const HMAC_KEY: &'static str = WALLET_ID_HMAC_KEY;

    pub fn hmac_key() -> &'static str {
        PIC::new(Self::HMAC_KEY).into_inner()
    }

    pub fn fill(
        tx: &mut u32,
        buffer: ApduBufferRead<'_>,
        ui: *mut u8,
        ui_len: u16,
    ) -> Result<(), Error> {
        sys::zemu_log_stack("WalletId::handle\x00");

        if ui.is_null() || ui_len != core::mem::size_of::<MaybeUninit<WalletIdUI>>() as u16 {
            return Err(Error::DataInvalid);
        }

        *tx = 0;

        //ok to unwrap as we have control over the input
        let bip32_path =
            sys::crypto::bip32::BIP32Path::<2>::new([BIP32_PATH_ROOT_0, BIP32_PATH_ROOT_1])
                .apdu_unwrap();

        //compute public key Sha256HMAC with path "44'/9000'"
        // and key 'wallet-id'
        // the hmac is truncated so the public key is not recoverable
        // since the hmac is done with a known key
        let hmac = {
            let mut digest =
                Sha256HMAC::new(Self::hmac_key().as_bytes()).map_err(|_| Error::ExecutionError)?;

            let mut pkey = MaybeUninit::uninit();
            crypto::Curve
                .to_secret(&bip32_path)
                .into_public_into(None, &mut pkey)
                .map_err(|_| Error::ExecutionError)?;
            //this is safe since we initialized it just now
            let pkey = unsafe { pkey.assume_init() };

            //we hmac the entire UNCOMPRESSED public key
            digest
                .update(pkey.as_ref())
                .map_err(|_| Error::ExecutionError)?;

            digest.finalize_hmac().map_err(|_| Error::ExecutionError)?
        };

        let ui = unsafe { &mut *ui.cast::<MaybeUninit<WalletIdUI>>() };
        //we can ignore the error safely as we pass the right slice lenght
        let _ = WalletIdUI::init_with_id(ui, &hmac[..WalletId::LEN]);

        //safe because it's all initialized now
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

impl ApduHandler for WalletId {
    #[inline(never)]
    fn handle(flags: &mut u32, tx: &mut u32, buffer: ApduBufferRead<'_>) -> Result<(), Error> {
        sys::zemu_log_stack("WalletId::handle\x00");

        *tx = 0;

        let req_confirmation = buffer.p1() >= 1;

        //ok to unwrap as we have control over the input
        let bip32_path =
            sys::crypto::bip32::BIP32Path::<2>::new([BIP32_PATH_ROOT_0, BIP32_PATH_ROOT_1])
                .apdu_unwrap();

        //compute public key Sha256HMAC with path "44'/9000'"
        // and key 'wallet-id'
        // the hmac is truncated so the public key is not recoverable
        // since the hmac is done with a known key
        let hmac = {
            let mut digest =
                Sha256HMAC::new(Self::hmac_key().as_bytes()).map_err(|_| Error::ExecutionError)?;

            let mut pkey = MaybeUninit::uninit();
            crypto::Curve
                .to_secret(&bip32_path)
                .into_public_into(None, &mut pkey)
                .map_err(|_| Error::ExecutionError)?;
            //this is safe since we initialized it just now
            let pkey = unsafe { pkey.assume_init() };

            //we hmac the entire UNCOMPRESSED public key
            digest
                .update(pkey.as_ref())
                .map_err(|_| Error::ExecutionError)?;

            digest.finalize_hmac().map_err(|_| Error::ExecutionError)?
        };

        let mut ui = MaybeUninit::<WalletIdUI>::uninit();
        //we can ignore the error safely as we pass the right slice lenght
        let _ = WalletIdUI::init_with_id(&mut ui, &hmac[..WalletId::LEN]);

        //safe because it's all initialized now
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

pub struct WalletIdUI {
    id: [u8; WalletId::LEN],
}

pub enum WalletIdUIError {
    InvalidIdLen,
}

impl WalletIdUI {
    pub fn init_with_id(loc: &mut MaybeUninit<Self>, id: &[u8]) -> Result<(), WalletIdUIError> {
        if id.len() != WalletId::LEN {
            Err(WalletIdUIError::InvalidIdLen)
        } else {
            //get `id` &mut
            // SAFE: `as_mut` it to &mut [u8; ...] this is okay as there's no invalid value of u8
            // and we'll be writing on it now regardless
            // unwrap is fine since it's a valid pointer
            let loc_id = unsafe { addr_of_mut!((*loc.as_mut_ptr()).id).as_mut().apdu_unwrap() };
            loc_id.copy_from_slice(id);

            Ok(())
        }
    }
}

impl Viewable for WalletIdUI {
    fn num_items(&mut self) -> Result<u8, ViewError> {
        Ok(1)
    }

    fn render_item(
        &mut self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::pic_str;

        if let 0 = item_n {
            let title_content = pic_str!(b"Wallet ID");
            title[..title_content.len()].copy_from_slice(title_content);

            let mut mex = [0; WalletId::LEN * 2];
            let len = hex_encode(self.id, &mut mex).map_err(|_| ViewError::Unknown)?;

            handle_ui_message(&mex[..len], message, page)
        } else {
            Err(ViewError::NoData)
        }
    }

    fn accept(&mut self, out: &mut [u8]) -> (usize, u16) {
        let mut tx = 0;

        out[tx..][..self.id.len()].copy_from_slice(&self.id);
        tx += self.id.len();

        (tx, Error::Success as _)
    }

    fn reject(&mut self, _: &mut [u8]) -> (usize, u16) {
        (0, Error::CommandNotAllowed as _)
    }
}
