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
};
use zemu_sys::{Show, ViewError, Viewable};

use crate::{
    constants::{ApduError as Error, BIP32_PATH_PREFIX_DEPTH},
    dispatcher::ApduHandler,
    handlers::{
        avax::sign_hash::Sign as SignHash,
        resources::{HASH, PATH},
    },
    parser::{AvaxMessage, DisplayableItem},
    sys,
    utils::{ApduBufferRead, Uploader},
};

pub struct Sign;

impl Sign {
    // For avax signing which includes P, C, X chains,
    // sha256 is used
    pub const SIGN_HASH_SIZE: usize = Sha256::DIGEST_LEN;

    #[inline(never)]
    fn sha256_digest(buffer: &[u8]) -> Result<[u8; Self::SIGN_HASH_SIZE], Error> {
        Sha256::digest(buffer).map_err(|_| Error::ExecutionError)
    }

    #[inline(never)]
    pub fn start_sign(
        init_data: &[u8],
        data: &'static [u8],
        flags: &mut u32,
    ) -> Result<u32, Error> {
        let root_path = BIP32Path::read(init_data).map_err(|_| Error::DataInvalid)?;
        // this path should be a root path of the form x/x/x
        if root_path.components().len() != BIP32_PATH_PREFIX_DEPTH {
            return Err(Error::WrongLength);
        }

        unsafe {
            PATH.lock(Self).replace(root_path);
        }

        let digest = Self::sha256_digest(data)?;
        // parse message
        let msg = AvaxMessage::new(data).map_err(|_| Error::DataInvalid)?;

        let ui = SignUI { hash: digest, msg };

        crate::show_ui!(ui.show(flags))
    }
}

impl ApduHandler for Sign {
    #[inline(never)]
    fn handle(flags: &mut u32, tx: &mut u32, buffer: ApduBufferRead<'_>) -> Result<(), Error> {
        sys::zemu_log_stack("AvaxSignMsg::handle\x00");

        *tx = 0;

        if let Some(upload) = Uploader::new(Self).upload(&buffer)? {
            *tx = Self::start_sign(upload.first, upload.data, flags)?;
        }

        Ok(())
    }
}

pub(crate) struct SignUI {
    hash: [u8; Sign::SIGN_HASH_SIZE],
    msg: AvaxMessage<'static>,
}

impl Viewable for SignUI {
    fn num_items(&mut self) -> Result<u8, ViewError> {
        self.msg.num_items()
    }

    #[inline(never)]
    fn render_item(
        &mut self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        self.msg.render_item(item_n, title, message, page)
    }

    fn accept(&mut self, _out: &mut [u8]) -> (usize, u16) {
        let tx = 0;

        // In this step the msg has not been signed
        // so store the hash for the next steps
        unsafe {
            HASH.lock(Sign).replace(self.hash);

            // next step requires SignHash handler to have
            // access to the path and hash resources that this handler just updated
            PATH.lock(SignHash);
            HASH.lock(SignHash);
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

        if let Ok(hash) = HASH.acquire(Sign) {
            hash.take();

            //let's release the lock for the future
            let _ = HASH.release(Sign);
        }
    }
    //if we failed to aquire then someone else is using it anyways

    Ok(())
}
