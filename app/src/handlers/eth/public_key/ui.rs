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

use arrayref::array_mut_ref;

use crate::{
    constants::{ApduError as Error, MAX_BIP32_PATH_DEPTH},
    crypto,
    handlers::handle_ui_message,
    sys::{
        crypto::{bip32::BIP32Path, CHAIN_CODE_LEN},
        ViewError, Viewable, PIC,
    },
    utils::{hex_encode, KHasher, Keccak},
};

use core::{mem::MaybeUninit, ptr::addr_of_mut};

use super::GetPublicKey;

/// This is a utility struct to initialize the [`AddrUI`]
/// in a given [`MaybeUninit`] correctly
pub struct AddrUIInitializer<'ui> {
    ui: &'ui mut MaybeUninit<AddrUI>,
    path_init: bool,
    cc: bool,
}

#[cfg_attr(test, derive(Debug))]
pub enum AddrUIInitError {
    KeyInitError,
    PathNotInitialized,
    HashInitError,
}

impl From<AddrUIInitError> for Error {
    fn from(_: AddrUIInitError) -> Self {
        Self::ExecutionError
    }
}

impl<'ui> AddrUIInitializer<'ui> {
    /// Create a new `AddrUI` initialized
    pub fn new(ui: &'ui mut MaybeUninit<AddrUI>) -> Self {
        Self {
            ui,
            path_init: false,
            cc: false,
        }
    }

    /// Produce the closure to initialize a key
    pub fn key_initializer<const B: usize>(
        path: &BIP32Path<B>,
    ) -> impl FnOnce(
        &mut MaybeUninit<crypto::PublicKey>,
        Option<&mut [u8; CHAIN_CODE_LEN]>,
    ) -> Result<(), AddrUIInitError>
           + '_ {
        move |key, cc| {
            GetPublicKey::new_key_into(path, key, cc).map_err(|_| AddrUIInitError::KeyInitError)
        }
    }

    /// Produce the closure to initialize the pubkey hash
    pub fn hash_initializer() -> impl FnOnce(
        &crypto::PublicKey,
        &mut [u8; Keccak::<32>::DIGEST_LEN],
    ) -> Result<(), AddrUIInitError> {
        |key, hash| {
            let mut k = Keccak::<32>::new();

            //for eth the hash of the pkey
            // is the hash of the uncompressed pbkey (64 bytes)
            // so with ledger we need to skip the first byte
            //
            // the key was never compressed so it's uncompressed
            let key = key
                .as_ref()
                .get(1..)
                .ok_or(AddrUIInitError::HashInitError)?;
            k.update(key);
            k.finalize(&mut hash[..]);
            Ok(())
        }
    }

    /// Initialie the path with the given one
    pub fn with_path(&mut self, path: BIP32Path<MAX_BIP32_PATH_DEPTH>) -> &mut Self {
        //get ui *mut
        let ui = self.ui.as_mut_ptr();

        //SAFETY: pointers are all valid since they are coming from rust
        unsafe {
            let ui_path = addr_of_mut!((*ui).path);
            ui_path.write(path);
        }

        self.path_init = true;
        self
    }

    /// Write the `with_chaincode` field of the UI
    fn write_cc(&mut self) {
        let ui = self.ui.as_mut_ptr();

        unsafe {
            let ui_cc = addr_of_mut!((*ui).with_chaincode);
            ui_cc.write(self.cc);
        }
    }

    /// Set the chain code requirement to the given one
    pub fn with_chaincode(&mut self, with: bool) -> &mut Self {
        self.cc = with;

        self
    }

    /// Finalize the initialization, performing any necessary checks to ensure everything is initialized
    pub fn finalize(mut self) -> Result<(), (Self, AddrUIInitError)> {
        if !self.path_init {
            Err((self, AddrUIInitError::PathNotInitialized))
        } else {
            self.write_cc();
            Ok(())
        }
    }
}

pub struct AddrUI {
    path: BIP32Path<MAX_BIP32_PATH_DEPTH>,
    with_chaincode: bool,
}

impl AddrUI {
    /// Compute the public key from the path
    pub fn pkey(
        &self,
        chain_code: Option<&mut [u8; CHAIN_CODE_LEN]>,
    ) -> Result<crypto::PublicKey, Error> {
        let mut out = MaybeUninit::uninit();

        AddrUIInitializer::key_initializer(&self.path)(&mut out, chain_code)
            .map_err(|_| Error::ExecutionError)?;

        //SAFETY: out has been initialized by the call above
        // note, this isn't done in .map since it would also be executed in case of an error
        Ok(unsafe { out.assume_init() })
    }

    /// Compute the pkey hash
    pub fn hash(&self, key: &crypto::PublicKey) -> Result<[u8; Keccak::<32>::DIGEST_LEN], Error> {
        let mut out = [0; Keccak::<32>::DIGEST_LEN];

        AddrUIInitializer::hash_initializer()(key, &mut out)
            .map_err(|_| Error::ExecutionError)
            .map(|_| out)
    }

    /// Compute the address
    ///
    /// The ethereum address is the hex encoded string
    /// of the last 20 bytes
    /// of the Keccak256 hash of the public key
    pub fn address(&self, key: &crypto::PublicKey, out: &mut [u8; 20 * 2]) -> Result<(), Error> {
        let hash = self.hash(key)?;

        hex_encode(&hash[hash.len() - 20..], out).map_err(|_| Error::ExecutionError)?;

        Ok(())
    }
}

impl Viewable for AddrUI {
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
            let title_content = if self.with_chaincode {
                pic_str!(b"Ext Address").as_slice()
            } else {
                pic_str!(b"Address").as_slice()
            };
            title[..title_content.len()].copy_from_slice(title_content);

            let mut mex = [0; 2 + 40];
            mex[0] = b'0';
            mex[1] = b'x';

            let len = 2;
            self.pkey(None)
                .and_then(|pkey| self.address(&pkey, array_mut_ref![mex, len, 40]))
                .map_err(|_| ViewError::Unknown)?;

            handle_ui_message(&mex[..], message, page)
        } else {
            Err(ViewError::NoData)
        }
    }

    fn accept(&mut self, out: &mut [u8]) -> (usize, u16) {
        let mut cc = [0; CHAIN_CODE_LEN];

        let pkey = match self.pkey(Some(&mut cc)) {
            Ok(pkey) => pkey,
            Err(e) => return (0, e as _),
        };

        let pkey_bytes = pkey.as_ref();
        let mut tx = 0;

        out[tx] = pkey_bytes.len() as u8;
        tx += 1;
        out[tx..][..pkey_bytes.len()].copy_from_slice(pkey_bytes);
        tx += pkey_bytes.len();

        //etereum address is 40 bytes
        out[tx] = 40;
        tx += 1;

        match self.address(&pkey, array_mut_ref![out, tx, 40]) {
            Ok(_) => tx += 40,
            Err(e) => return (0, e as _),
        }

        if self.with_chaincode {
            out[tx..][..CHAIN_CODE_LEN].copy_from_slice(&cc);
            tx += CHAIN_CODE_LEN;
        }

        (tx, Error::Success as _)
    }

    fn reject(&mut self, _: &mut [u8]) -> (usize, u16) {
        (0, Error::CommandNotAllowed as _)
    }
}

#[cfg(test)]
mod tests {
    use bolos::crypto::bip32::BIP32Path;
    use zuit::{MockDriver, Page};

    use crate::{
        crypto::{PublicKey, SecretKey},
        utils::strlen,
    };

    use super::*;

    impl AddrUI {
        pub fn new(path: BIP32Path<MAX_BIP32_PATH_DEPTH>) -> Self {
            let mut loc = MaybeUninit::uninit();

            let mut builder = AddrUIInitializer::new(&mut loc);
            let _ = builder.with_path(path);
            let _ = builder.finalize();

            unsafe { loc.assume_init() }
        }
    }

    fn path() -> BIP32Path<MAX_BIP32_PATH_DEPTH> {
        BIP32Path::new([44]).unwrap()
    }

    fn keypair() -> (SecretKey<MAX_BIP32_PATH_DEPTH>, PublicKey) {
        let secret = crypto::SecretKey::new(crypto::Curve, path());

        let public = secret.public().unwrap();
        (secret, public)
    }

    #[test]
    pub fn eth_addr_ui() {
        let ui = AddrUI::new(path());

        //construct the expected message
        let mut expected_message = std::string::String::new();
        expected_message.push_str("0x");
        {
            let mut addr = [0; 40];
            ui.address(&ui.pkey(None).unwrap(), &mut addr).unwrap();
            expected_message.push_str(std::str::from_utf8(&addr).unwrap());
        }

        let mut driver = MockDriver::<_, 18, 4096>::new(ui);
        driver.with_print(true);
        driver.drive();

        let produced_ui = driver.out_ui();
        let produced_pages = &produced_ui[0];

        //mockdriver is big enough to only need 1 page
        let &Page { title, message } = &produced_pages[0];
        //ignore pagination at the end of the title,
        // even tho with MockDriver there shouldn't be any anyways
        assert!(title.starts_with(b"Address"));

        //avoid trailing zeros
        let message = {
            let len = strlen(&message);
            std::str::from_utf8(&message[..len]).unwrap()
        };
        //verify that the address message computed by the UI
        // and the one computed in the test are the same

        assert_eq!(message, &expected_message)
    }
}
