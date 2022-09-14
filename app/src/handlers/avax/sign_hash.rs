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
use core::mem::MaybeUninit;

use crate::{
    constants::{
        ApduError as Error, BIP32_PATH_PREFIX_DEPTH, BIP32_PATH_SUFFIX_DEPTH, FIRST_MESSAGE,
        LAST_MESSAGE, MAX_BIP32_PATH_DEPTH,
    },
    crypto::Curve,
    dispatcher::ApduHandler,
    handlers::resources::{HASH, PATH},
    parser::{FromBytes, PathWrapper},
    sys,
    utils::{convert_der_to_rs, ApduBufferRead},
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
    pub fn sign(
        path: &BIP32Path<MAX_BIP32_PATH_DEPTH>,
        curve: Curve,
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
    pub fn start_sign(data: &[u8]) -> Result<(), Error> {
        // the data contains root_path + 32-byte hash
        let mut path = MaybeUninit::uninit();
        let rem = PathWrapper::from_bytes_into(data, &mut path).map_err(|_| Error::Unknown)?;
        let root_path = unsafe { path.assume_init().path() };
        // this path should be a root path of the form x/x/x
        if root_path.components().len() != BIP32_PATH_PREFIX_DEPTH {
            return Err(Error::WrongLength);
        }

        let curve = Curve::Secp256K1;

        unsafe {
            PATH.lock(Self)?.replace((root_path, curve));
        }

        if rem.len() != Self::SIGN_HASH_SIZE {
            return Err(Error::WrongLength);
        }

        let mut unsigned_hash = [0; Self::SIGN_HASH_SIZE];
        unsigned_hash.copy_from_slice(rem);

        unsafe {
            HASH.lock(Self)?.replace(unsigned_hash);
        }

        Ok(())
    }

    fn get_signing_info(data: &[u8]) -> Result<(BIP32Path<MAX_BIP32_PATH_DEPTH>, Curve), Error> {
        //We expect a path prefix of the form x'/x'/x'
        let (path_prefix, curve) = Self::get_derivation_info()?;
        if path_prefix.components().len() != BIP32_PATH_PREFIX_DEPTH {
            return Err(Error::WrongLength);
        }

        let suffix: BIP32Path<BIP32_PATH_SUFFIX_DEPTH> =
            BIP32Path::read(data).map_err(|_| Error::DataInvalid)?;

        //We expect a path suffix of the form x/x
        if suffix.components().len() != BIP32_PATH_SUFFIX_DEPTH {
            return Err(Error::WrongLength);
        }

        let path_iter = path_prefix
            .components()
            .iter()
            .chain(suffix.components().iter())
            .copied();

        let full_path: BIP32Path<MAX_BIP32_PATH_DEPTH> =
            BIP32Path::new(path_iter).map_err(|_| Error::DataInvalid)?;
        Ok((full_path, *curve))
    }
}

impl ApduHandler for Sign {
    #[inline(never)]
    fn handle<'apdu>(
        _flags: &mut u32,
        tx: &mut u32,
        buffer: ApduBufferRead<'apdu>,
    ) -> Result<(), Error> {
        sys::zemu_log_stack("SignHash::handle\x00");

        *tx = 0;
        let mut offset = 0;

        let p1 = buffer.p1();
        let cdata = buffer.payload().map_err(|_| Error::DataInvalid)?;

        if p1 == FIRST_MESSAGE {
            return Self::start_sign(cdata);
        }

        // retrieve signing info
        let (path_prefix, curve) = Sign::get_signing_info(cdata)?;
        let hash = Self::get_hash()?;

        let (sig_size, mut sig) = Sign::sign(&path_prefix, curve, hash)?;
        let out = buffer.write();

        //write signature as RSV
        //write V, which is the LSB of the firsts byte
        let v = sig[0] & 0x01;

        //reset to 0x30 for the conversion
        sig[0] = 0x30;
        {
            let mut r = [0; 33];
            let mut s = [0; 33];

            //write as R S (V written earlier)
            // this will write directly to buffer
            match convert_der_to_rs(&sig[..sig_size], &mut r, &mut s) {
                Ok((written_r, written_s)) => {
                    //format R and S by only having 32 bytes each,
                    // skipping the first byte if necessary
                    let r = if written_r == 33 { &r[1..] } else { &r[..32] };
                    let s = if written_s == 33 { &s[1..] } else { &s[..32] };

                    out[offset..][..32].copy_from_slice(r);
                    offset += 32;

                    out[offset..][..32].copy_from_slice(s);
                    offset += 32;
                }
                Err(_) => return Err(Error::ExecutionError as _),
            }
        }
        // write V at the end
        out[offset] = v;
        offset += 1;

        if p1 == LAST_MESSAGE {
            let _ = cleanup_globals();
        }

        *tx = offset as _;
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
