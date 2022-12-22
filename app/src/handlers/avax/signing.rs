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
use core::mem::MaybeUninit;
use nom::number::complete::be_u8;

use bolos::{
    crypto::bip32::BIP32Path,
    hash::{Hasher, Ripemd160, Sha256},
};
use zemu_sys::{Show, ViewError, Viewable};

use crate::{
    constants::{
        ApduError as Error, BIP32_PATH_PREFIX_DEPTH, BIP32_PATH_SUFFIX_DEPTH, MAX_BIP32_PATH_DEPTH,
    },
    dispatcher::ApduHandler,
    handlers::{
        avax::sign_hash::Sign as SignHash,
        resources::{HASH, PATH},
    },
    parser::{DisplayableItem, ObjectList, ParserError, PathWrapper, Transaction},
    sys,
    utils::{ApduBufferRead, Uploader},
};

pub struct Sign;

impl Sign {
    // For avax transactions which includes P, C, X chains,
    // sha256 is used
    pub const SIGN_HASH_SIZE: usize = Sha256::DIGEST_LEN;

    fn get_derivation_info() -> Result<&'static BIP32Path<MAX_BIP32_PATH_DEPTH>, Error> {
        match unsafe { PATH.acquire(Self) } {
            Ok(Some(some)) => Ok(some),
            _ => Err(Error::ApduCodeConditionsNotSatisfied),
        }
    }

    #[inline(never)]
    fn sha256_digest(buffer: &[u8]) -> Result<[u8; Self::SIGN_HASH_SIZE], Error> {
        Sha256::digest(buffer).map_err(|_| Error::ExecutionError)
    }

    #[inline(never)]
    pub fn compute_keyhash(
        path: &BIP32Path<MAX_BIP32_PATH_DEPTH>,
        out_hash: &mut [u8; Ripemd160::DIGEST_LEN],
    ) -> Result<(), Error> {
        use crate::handlers::public_key::GetPublicKey;

        let mut out = MaybeUninit::uninit();
        GetPublicKey::new_key_into(path, &mut out, None).map_err(|_| Error::ExecutionError)?;

        // get the uncompressed pubkey for the provided path
        let pkey = unsafe { out.assume_init() };

        let mut tmp = [0; Sha256::DIGEST_LEN];

        Sha256::digest_into(pkey.as_ref(), &mut tmp)
            .and_then(|_| Ripemd160::digest_into(&tmp, out_hash))
            .map_err(|_| Error::DataInvalid)?;

        Ok(())
    }

    fn disable_outputs(
        list: &mut ObjectList<PathWrapper<BIP32_PATH_SUFFIX_DEPTH>>,
        tx: &mut Transaction,
    ) -> Result<(), Error> {
        // get root path
        let path_root = Self::get_derivation_info()?;

        //We expect a path prefix of the form x'/x'/x'
        if path_root.components().len() != BIP32_PATH_PREFIX_DEPTH {
            return Err(Error::WrongLength);
        }

        let mut path_wrapper: MaybeUninit<PathWrapper<BIP32_PATH_SUFFIX_DEPTH>> =
            MaybeUninit::uninit();

        let mut address = [0; Ripemd160::DIGEST_LEN];
        while let Some(()) = list.parse_next(&mut path_wrapper) {
            let path_ptr = path_wrapper.as_mut_ptr();
            let suffix = unsafe { &(*path_ptr).path() };

            //We expect a path suffix of the form x/x
            if suffix.components().len() != BIP32_PATH_SUFFIX_DEPTH {
                return Err(Error::WrongLength);
            }

            let path_iter = path_root
                .components()
                .iter()
                .chain(suffix.components())
                .copied();

            let full_path: BIP32Path<MAX_BIP32_PATH_DEPTH> =
                BIP32Path::new(path_iter).map_err(|_| Error::DataInvalid)?;

            Self::compute_keyhash(&full_path, &mut address)?;

            tx.disable_output_if(&address[..]);
        }
        Ok(())
    }

    #[inline(never)]
    pub fn start_sign(
        init_data: &[u8],
        data: &'static [u8],
        flags: &mut u32,
    ) -> Result<u32, Error> {
        // read root path and store it in ram as during the
        // signing process and diseabling outputs we use it
        // to get a full path: root_path + path_suffix
        let root_path = BIP32Path::read(init_data).map_err(|_| Error::DataInvalid)?;
        //We expect a path prefix of the form x'/x'/x'
        if root_path.components().len() != BIP32_PATH_PREFIX_DEPTH {
            return Err(Error::WrongLength);
        }

        unsafe {
            PATH.lock(Self)?.replace(root_path);
        }

        // then, get the change_path list.
        let mut path_list: MaybeUninit<ObjectList<PathWrapper<BIP32_PATH_SUFFIX_DEPTH>>> =
            MaybeUninit::uninit();
        let (rem, num_paths) = be_u8::<_, ParserError>(data).map_err(|_| Error::ExecutionError)?;
        let rem = ObjectList::new_into_with_len(rem, &mut path_list, num_paths as _)
            .map_err(|_| Error::DataInvalid)?;
        let mut path_list = unsafe { path_list.assume_init() };

        let unsigned_hash = Self::sha256_digest(rem)?;

        // parse transaction
        let mut tx = MaybeUninit::uninit();
        Transaction::new_into(rem, &mut tx).map_err(|_| Error::DataInvalid)?;
        let mut transaction = unsafe { tx.assume_init() };

        Self::disable_outputs(&mut path_list, &mut transaction)?;

        let ui = SignUI {
            hash: unsigned_hash,
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
            *tx = Self::start_sign(upload.first, upload.data, flags)?;
        }

        Ok(())
    }
}

pub(crate) struct SignUI {
    hash: [u8; Sign::SIGN_HASH_SIZE],
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

    fn accept(&mut self, _out: &mut [u8]) -> (usize, u16) {
        let tx = 0;

        // In this step the transaction has not been signed
        // so store the hash for the next steps
        unsafe {
            match HASH.lock(Sign) {
                Ok(hash) => {
                    hash.replace(self.hash);
                }
                Err(_) => return (0, Error::ExecutionError as _),
            }

            // next step requires SignHash handler to have
            // access to the path and hash resources that this handler just updated
            let _ = PATH.lock(SignHash);
            let _ = HASH.lock(SignHash);
        }

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
