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
use core::{
    mem::MaybeUninit,
    ptr::{addr_of, addr_of_mut},
};
use std::convert::TryFrom;

use zemu_sys::{Show, ViewError, Viewable};

use crate::{
    constants::{ApduError as Error, ASCII_HRP_MAX_SIZE, DEFAULT_CHAIN_CODE},
    crypto,
    dispatcher::ApduHandler,
    handlers::handle_ui_message,
    sys::{
        self, bech32,
        hash::{Hasher, Ripemd160, Sha256},
        Error as SysError,
    },
    utils::{rs_strlen, ApduBufferRead, ApduPanic},
};

pub struct GetPublicKey;

impl GetPublicKey {
    pub const DEFAULT_CHAIN_CODE: &'static [u8; 32] = DEFAULT_CHAIN_CODE;

    pub fn chain_code() -> &'static [u8; 32] {
        bolos::PIC::new(Self::DEFAULT_CHAIN_CODE).into_inner()
    }

    /// Retrieve the public key with the given curve and bip32 path
    #[inline(never)]
    pub fn new_key_into<const B: usize>(
        curve: crypto::Curve,
        path: &sys::crypto::bip32::BIP32Path<B>,
        out: &mut MaybeUninit<crypto::PublicKey>,
    ) -> Result<(), SysError> {
        sys::zemu_log_stack("GetAddres::new_key\x00");
        curve
            .to_secret(path, Self::chain_code())
            .into_public_into(out)?;

        //this is safe because it's initialized
        // also unwrapping is fine because the ptr is valid
        let pkey = unsafe { out.as_mut_ptr().as_mut().apdu_unwrap() };
        pkey.compress()
    }
}

impl ApduHandler for GetPublicKey {
    #[inline(never)]
    fn handle<'apdu>(
        flags: &mut u32,
        tx: &mut u32,
        buffer: ApduBufferRead<'apdu>,
    ) -> Result<(), Error> {
        sys::zemu_log_stack("GetPublicKey::handle\x00");

        *tx = 0;

        let req_confirmation = buffer.p1() >= 1;
        let curve = crypto::Curve::try_from(buffer.p2()).map_err(|_| Error::InvalidP1P2)?;

        let mut cdata = buffer.payload().map_err(|_| Error::DataInvalid)?;

        let hrp = {
            let hrp_len = match cdata.get(0) {
                Some(&len) => len as usize,
                None => return Err(Error::DataInvalid),
            };
            if hrp_len > ASCII_HRP_MAX_SIZE {
                return Err(Error::DataInvalid);
            }

            //skip hrp_len
            cdata = &cdata[1..];

            if hrp_len == 0 {
                //default
                bolos::PIC::new(b"avax").into_inner()
            } else {
                match cdata.get(..hrp_len) {
                    None => return Err(Error::DataInvalid),
                    Some(hrp) => {
                        cdata = &cdata[hrp_len..];
                        hrp
                    }
                }
            }
        };

        let bip32_path =
            sys::crypto::bip32::BIP32Path::<6>::read(cdata).map_err(|_| Error::DataInvalid)?;

        let mut ui = MaybeUninit::<AddrUI>::uninit();

        //initialize UI
        {
            let mut ui_initializer = AddrUIInitializer::new(&mut ui);
            ui_initializer
                .init_pkey(|key| {
                    Self::new_key_into(curve, &bip32_path, key)
                        .map_err(|_| AddrUIInitError::KeyInitError)
                })?
                .init_hash(|key, hash| {
                    let mut tmp = [0; Sha256::DIGEST_LEN];
                    Sha256::digest_into(key.as_ref(), &mut tmp)
                        .and_then(|_| Ripemd160::digest_into(&tmp, hash))
                        .map_err(|_| AddrUIInitError::HashInitError)
                })?
                .with_hrp(hrp)?;
            ui_initializer.finalize().map_err(|(_, err)| err)?;
        }

        //safe because it's all initialized now
        let mut ui = unsafe { ui.assume_init() };

        if req_confirmation {
            unsafe { ui.show(flags) }.map_err(|_| Error::ExecutionError)
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

pub struct AddrUIInitializer<'ui> {
    ui: &'ui mut MaybeUninit<AddrUI>,
    hash_init: bool,
    pkey_init: bool,
    hrp_init: bool,
}

pub enum AddrUIInitError {
    KeyInitError,
    KeyNotInitialized,
    HashInitError,
    HashNotInitialized,
    HrpNotInitialized,
    FieldsNotInitialized,
    HRPTooLong,
    NonASCIIHrp,
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
            hash_init: false,
            pkey_init: false,
            hrp_init: false,
        }
    }

    /// Initialize the public key with the given closure
    pub fn init_pkey<
        F: FnOnce(&mut MaybeUninit<crypto::PublicKey>) -> Result<(), AddrUIInitError>,
    >(
        &mut self,
        init: F,
    ) -> Result<&mut Self, AddrUIInitError> {
        //get ui *mut
        let ui = self.ui.as_mut_ptr();
        //get `pkey` *mut,
        // cast to MaybeUninit *mut
        //SAFE: `as_mut` it to &mut MaybeUninit (safe because it's MaybeUninit)
        // unwrap the option as it's guarantee valid pointer
        let key =
            unsafe { addr_of_mut!((*ui).pkey).cast::<MaybeUninit<_>>().as_mut() }.apdu_unwrap();

        init(key).map(|_| {
            self.pkey_init = true;
            self
        })
    }

    /// Initialie the HRP with the given slice
    pub fn with_hrp(&mut self, hrp: &[u8]) -> Result<&mut Self, AddrUIInitError> {
        if hrp.len() > ASCII_HRP_MAX_SIZE {
            return Err(AddrUIInitError::HRPTooLong);
        }
        match core::str::from_utf8(hrp) {
            Ok(s) if !s.is_ascii() => Err(AddrUIInitError::NonASCIIHrp),
            Err(_) => Err(AddrUIInitError::NonASCIIHrp),
            Ok(_) => {
                //get ui *mut
                let ui = self.ui.as_mut_ptr();
                //get `hrp` *mut,
                //SAFE: `as_mut` it to &mut [u8; ...]. this is okay as there's not invalid value for u8
                // and we'll be writing on it now
                // unwrap is fine since it's valid pointer
                let ui_hrp = unsafe { addr_of_mut!((*ui).hrp).as_mut() }.apdu_unwrap();
                ui_hrp[..hrp.len()].copy_from_slice(hrp);
                ui_hrp[hrp.len()] = 0; //null terminate
                self.hrp_init = true;
                Ok(self)
            }
        }
    }

    /// Initialize the pubkey hash in the given hash output
    pub fn init_hash<
        F: FnOnce(&crypto::PublicKey, &mut [u8; Ripemd160::DIGEST_LEN]) -> Result<(), AddrUIInitError>,
    >(
        &mut self,
        init: F,
    ) -> Result<&mut Self, AddrUIInitError> {
        if !self.pkey_init {
            return Err(AddrUIInitError::KeyNotInitialized);
        }
        //get ui *mut
        let ui = self.ui.as_mut_ptr();

        //gey &pkey
        // SAFE: `as_ref` is fine since we checked that it's initialized
        // the unwrap is also fine as the pointer is guaranteed valid
        let key = unsafe { addr_of!((*ui).pkey).as_ref() }.apdu_unwrap();

        //get `hrp` *mut,
        //SAFE: `as_mut` it to &mut [u8; ...]. this is okay as there's not invalid value for u8
        // and we'll be writing on it now
        // unwrap is fine since it's valid pointer
        let hash = unsafe { addr_of_mut!((*ui).hash).as_mut() }.apdu_unwrap();

        init(key, hash).map(|_| {
            self.hash_init = true;
            self
        })
    }

    /// Finalize the initialization, performing any necessary checks to ensure everything is initialized
    pub fn finalize(self) -> Result<(), (Self, AddrUIInitError)> {
        if !self.hash_init {
            Err((self, AddrUIInitError::HashNotInitialized))
        } else if !self.pkey_init {
            Err((self, AddrUIInitError::KeyNotInitialized))
        } else if !self.hrp_init {
            Err((self, AddrUIInitError::HrpNotInitialized))
        } else {
            Ok(())
        }
    }
}

pub struct AddrUI {
    pub pkey: crypto::PublicKey,
    hash: [u8; Ripemd160::DIGEST_LEN],
    hrp: [u8; ASCII_HRP_MAX_SIZE + 1], //+1 to null terminate just in case
}

impl AddrUI {
    fn hrp_as_str(&self) -> &str {
        //this is okey since it's checked when a new instance is made
        let len = rs_strlen(&self.hrp);
        unsafe { core::str::from_utf8_unchecked(&self.hrp[..len]) }
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
        use bolos::{pic_str, PIC};

        if let 0 = item_n {
            let title_content = pic_str!(b"Address");
            title[..title_content.len()].copy_from_slice(title_content);

            let mut mex = [0; bech32::estimate_size(ASCII_HRP_MAX_SIZE, Ripemd160::DIGEST_LEN)];
            let len = bech32::encode(self.hrp_as_str(), &self.hash, &mut mex)
                .map_err(|_| ViewError::Unknown)?;

            handle_ui_message(&mex[..len], message, page)
        } else {
            Err(ViewError::NoData)
        }
    }

    fn accept(&mut self, out: &mut [u8]) -> (usize, u16) {
        let pkey = self.pkey.as_ref();
        let mut tx = 0;

        out[tx] = pkey.len() as u8;
        tx += 1;
        out[tx..tx + pkey.len()].copy_from_slice(pkey);
        tx += pkey.len();

        out[tx..tx + self.hash.len()].copy_from_slice(&self.hash[..]);
        tx += self.hash.len();

        (tx, Error::Success as _)
    }

    fn reject(&mut self, _: &mut [u8]) -> (usize, u16) {
        (0, Error::CommandNotAllowed as _)
    }
}
