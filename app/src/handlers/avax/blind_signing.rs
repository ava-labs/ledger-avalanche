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

use bolos::{
    crypto::bip32::BIP32Path,
    hash::{Hasher, Sha256},
    pic_str, PIC,
};
use zemu_sys::{Show, ViewError, Viewable};

use crate::{
    constants::{ApduError as Error, MAX_BIP32_PATH_DEPTH},
    crypto::Curve,
    dispatcher::ApduHandler,
    handlers::{handle_ui_message, resources::PATH},
    sys,
    utils::{blind_sign_toggle, hex_encode, ApduBufferRead, ApduPanic, Uploader},
};

pub struct BlindSign;

impl BlindSign {
    pub const SIGN_HASH_SIZE: usize = 32;

    fn get_derivation_info() -> Result<&'static BIP32Path<MAX_BIP32_PATH_DEPTH>, Error> {
        match unsafe { PATH.acquire(Self) } {
            Ok(Some(some)) => Ok(some),
            _ => Err(Error::ApduCodeConditionsNotSatisfied),
        }
    }

    //(actual_size, [u8; MAX_SIGNATURE_SIZE])
    #[inline(never)]
    pub fn sign<const LEN: usize>(
        path: &BIP32Path<LEN>,
        data: &[u8],
    ) -> Result<(usize, [u8; 100]), Error> {
        let sk = Curve.to_secret(path);

        let mut out = [0; 100];
        let sz = sk
            .sign(data, &mut out[..])
            .map_err(|_| Error::ExecutionError)?;

        Ok((sz, out))
    }

    #[inline(never)]
    fn sha256_digest(buffer: &[u8]) -> Result<[u8; Self::SIGN_HASH_SIZE], Error> {
        Sha256::digest(buffer).map_err(|_| Error::ExecutionError)
    }

    #[inline(never)]
    pub fn start_sign(
        send_hash: bool,
        init_data: &[u8],
        data: &'static [u8],
        flags: &mut u32,
    ) -> Result<u32, Error> {
        let path = BIP32Path::read(init_data).map_err(|_| Error::DataInvalid)?;

        unsafe {
            PATH.lock(Self)?.replace(path);
        }

        let unsigned_hash = Self::sha256_digest(data)?;

        let ui = SignUI {
            hash: unsigned_hash,
            send_hash,
        };

        crate::show_ui!(ui.show(flags))
    }
}

impl ApduHandler for BlindSign {
    #[inline(never)]
    fn handle<'apdu>(
        flags: &mut u32,
        tx: &mut u32,
        buffer: ApduBufferRead<'apdu>,
    ) -> Result<(), Error> {
        sys::zemu_log_stack("AvaxBlindSign::handle\x00");

        *tx = 0;

        //blind signing not enabled
        if !blind_sign_toggle::blind_sign_enabled() {
            return Err(Error::ApduCodeConditionsNotSatisfied);
        }

        if let Some(upload) = Uploader::new(Self).upload(&buffer)? {
            *tx = Self::start_sign(true, upload.first, upload.data, flags)?;
        }

        Ok(())
    }
}

pub(crate) struct SignUI {
    hash: [u8; BlindSign::SIGN_HASH_SIZE],
    send_hash: bool,
}

impl Viewable for SignUI {
    fn num_items(&mut self) -> Result<u8, ViewError> {
        Ok(1)
    }

    #[inline(never)]
    fn render_item(
        &mut self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        match item_n {
            0 => {
                let title_content = pic_str!(b"Sign");
                title[..title_content.len()].copy_from_slice(title_content);

                let mut hex_buf = [0; BlindSign::SIGN_HASH_SIZE * 2];
                //this is impossible that will error since the sizes are all checked
                let len = hex_encode(&self.hash[..], &mut hex_buf).apdu_unwrap();

                handle_ui_message(&hex_buf[..len], message, page)
            }
            _ => Err(ViewError::NoData),
        }
    }

    fn accept(&mut self, out: &mut [u8]) -> (usize, u16) {
        let path = match BlindSign::get_derivation_info() {
            Err(e) => return (0, e as _),
            Ok(k) => k,
        };

        let (sig_size, sig) = match BlindSign::sign(path, &self.hash[..]) {
            Err(e) => return (0, e as _),
            Ok(k) => k,
        };

        let mut tx = 0;

        //reset globals to avoid skipping `Init`
        if let Err(e) = cleanup_globals() {
            return (0, e as _);
        }

        //write unsigned_hash to buffer
        if self.send_hash {
            out[tx..tx + BlindSign::SIGN_HASH_SIZE].copy_from_slice(&self.hash[..]);
            tx += BlindSign::SIGN_HASH_SIZE;
        }

        //wrte signature to buffer
        out[tx..tx + sig_size].copy_from_slice(&sig[..sig_size]);
        tx += sig_size;

        (tx, Error::Success as _)
    }

    fn reject(&mut self, _: &mut [u8]) -> (usize, u16) {
        let _ = cleanup_globals();
        (0, Error::CommandNotAllowed as _)
    }
}

fn cleanup_globals() -> Result<(), Error> {
    unsafe {
        if let Ok(path) = PATH.acquire(BlindSign) {
            path.take();

            //let's release the lock for the future
            let _ = PATH.release(BlindSign);
        }
    }
    //if we failed to aquire then someone else is using it anyways

    Ok(())
}
