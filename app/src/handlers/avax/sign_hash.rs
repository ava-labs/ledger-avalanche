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
use bolos::{crypto::bip32::BIP32Path, hash::Sha256};

use crate::{
    constants::{
        ApduError as Error, BIP32_PATH_SUFFIX_DEPTH, FIRST_MESSAGE, LAST_MESSAGE,
        MAX_BIP32_PATH_DEPTH,
    },
    crypto::Curve,
    dispatcher::ApduHandler,
    handlers::resources::{HASH, PATH},
    sys,
    utils::ApduBufferRead,
};

pub struct Sign;

impl Sign {
    // For avax transactions which includes P, C, X chains,
    // sha256 is used
    pub const SIGN_HASH_SIZE: usize = Sha256::DIGEST_LEN;

    fn get_derivation_info() -> Result<&'static (BIP32Path<MAX_BIP32_PATH_DEPTH>, Curve), Error> {
        match unsafe { PATH.acquire(Self) } {
            Ok(Some(some)) => Ok(some),
            _ => Err(Error::ApduCodeConditionsNotSatisfied),
        }
    }

    fn get_hash() -> Result<&'static [u8; Self::SIGN_HASH_SIZE], Error> {
        match unsafe { HASH.acquire(Self) } {
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
    pub fn start_sign(data: &[u8], flags: &mut u32) -> Result<(usize, [u8; 100]), Error> {
        let (path_prefix, curve) = Self::get_derivation_info()?;
        let hash = Self::get_hash()?;

        //We expect a path prefix of the form x'/x'/x'
        if path_prefix.components().len() > 4 {
            return Err(Error::WrongLength);
        }

        let suffix: BIP32Path<BIP32_PATH_SUFFIX_DEPTH> =
            BIP32Path::read(data).map_err(|_| Error::DataInvalid)?;

        let path_iter = path_prefix
            .components()
            .iter()
            .chain(suffix.components().iter())
            .copied();

        let full_path: BIP32Path<MAX_BIP32_PATH_DEPTH> =
            BIP32Path::new(path_iter).map_err(|_| Error::DataInvalid)?;

        Self::sign(*curve, &full_path, hash)
    }
}

impl ApduHandler for Sign {
    #[inline(never)]
    fn handle<'apdu>(
        flags: &mut u32,
        tx: &mut u32,
        buffer: ApduBufferRead<'apdu>,
    ) -> Result<(), Error> {
        sys::zemu_log_stack("SignHash::handle\x00");

        *tx = 0;
        let p1 = buffer.p1();

        let cdata = buffer.payload().map_err(|_| Error::DataInvalid)?;

        //
        if p1 == FIRST_MESSAGE {
            if cdata.len() != Self::SIGN_HASH_SIZE {
                return Err(Error::WrongLength);
            }

            let mut unsigned_hash = [0; Self::SIGN_HASH_SIZE];
            unsigned_hash.copy_from_slice(cdata);

            unsafe {
                HASH.lock(Self)?.replace(unsigned_hash);
            }
            return Ok(());
        }

        let (sz, sig) = Sign::start_sign(cdata, flags)?;
        buffer.write()[..sz].copy_from_slice(&sig[..sz]);

        if p1 == LAST_MESSAGE {
            let _ = cleanup_globals();
        }

        *tx = sz as _;
        Ok(())
    }
}

fn cleanup_globals() -> Result<(), Error> {
    unsafe {
        if let Ok(path) = PATH.acquire(Sign) {
            path.take();

            //let's release the lock for the future
            let _ = PATH.release(Sign);
        }

        if let Ok(hash) = HASH.acquire(Sign) {
            hash.take();

            //let's release the lock for the future
            let _ = HASH.release(Sign);
        }
    }
    //if we failed to aquire then someone else is using it anyways

    Ok(())
}
