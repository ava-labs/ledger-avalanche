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

use bolos::{
    crypto::bip32::BIP32Path,
    hash::{Hasher, Sha256},
};
use zemu_sys::{Show, ViewError, Viewable};

use crate::{
    constants::{ApduError as Error, MAX_BIP32_PATH_DEPTH},
    crypto::Curve,
    dispatcher::ApduHandler,
    handlers::resources::PATH,
    parser::{DisplayableItem, Transaction},
    sys,
    utils::{ApduBufferRead, Uploader},
};

pub struct Sign;

impl Sign {
    fn get_derivation_info() -> Result<&'static (BIP32Path<MAX_BIP32_PATH_DEPTH>, Curve), Error> {
        match unsafe { PATH.acquire(Self) } {
            Ok(Some(some)) => Ok(some),
            _ => Err(Error::ApduCodeConditionsNotSatisfied),
        }
    }

    //(actual_size, [u8; MAX_SIGNATURE_SIZE])
    #[inline(never)]
    pub fn sign<const LEN: usize>(
        curve: Curve,
        path: &BIP32Path<LEN>,
        data: &[u8],
    ) -> Result<(usize, [u8; 100]), Error> {
        let sk = curve.to_secret(path);

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
        p2: u8,
        init_data: &[u8],
        data: &'static [u8],
        flags: &mut u32,
    ) -> Result<u32, Error> {
        let curve = Curve::try_from(p2).map_err(|_| Error::InvalidP1P2)?;
        let path = BIP32Path::read(init_data).map_err(|_| Error::DataInvalid)?;

        unsafe {
            PATH.lock(Self)?.replace((path, curve));
        }

        let unsigned_hash = Self::sha256_digest(data)?;

        let transaction = Transaction::new(data).map_err(|_| Error::DataInvalid)?;

        let ui = SignUI {
            hash: unsigned_hash,
            send_hash,
            transaction,
        };

        crate::show_ui!(ui.show(flags))
    }
}

impl ApduHandler for Sign {
    #[inline(never)]
    fn handle<'apdu>(
        flags: &mut u32,
        tx: &mut u32,
        buffer: ApduBufferRead<'apdu>,
    ) -> Result<(), Error> {
        sys::zemu_log_stack("AvaxSign::handle\x00");

        *tx = 0;

        if let Some(upload) = Uploader::new(Self).upload(&buffer)? {
            // Do not return the unsigned hash. It can be compute by the caller
            // giving us more space to wrtie the signature in the output buffer
            *tx = Self::start_sign(false, upload.p2, upload.first, upload.data, flags)?;
        }

        Ok(())
    }
}

pub(crate) struct SignUI {
    hash: [u8; Sign::SIGN_HASH_SIZE],
    send_hash: bool,
    transaction: Transaction<'static>,
}

impl Viewable for SignUI {
    fn num_items(&mut self) -> Result<u8, ViewError> {
        Ok(self.transaction.num_items() as _)
    }

    #[inline(never)]
    fn render_item(
        &mut self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        self.transaction.render_item(item_n, title, message, page)
    }

    fn accept(&mut self, out: &mut [u8]) -> (usize, u16) {
        let (path, curve) = match Sign::get_derivation_info() {
            Err(e) => return (0, e as _),
            Ok(k) => k,
        };

        let (sig_size, sig) = match Sign::sign(*curve, path, &self.hash[..]) {
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
            out[tx..tx + Sign::SIGN_HASH_SIZE].copy_from_slice(&self.hash[..]);
            tx += Sign::SIGN_HASH_SIZE;
        }

        // check that output buffer size is big enough
        if out.len() < (tx + sig_size) {
            sys::zemu_log_stack("AvaxSign::output_buffer_too_small\x00");
            return (0, Error::OutputBufferTooSmall as u16);
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
        if let Ok(path) = PATH.acquire(Sign) {
            path.take();

            //let's release the lock for the future
            let _ = PATH.release(Sign);
        }
    }
    //if we failed to aquire then someone else is using it anyways

    Ok(())
}
