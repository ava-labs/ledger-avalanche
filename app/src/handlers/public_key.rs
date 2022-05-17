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

use bolos::{
    crypto::{bip32::BIP32Path, CHAIN_CODE_LEN},
    PIC,
};
use zemu_sys::{Show, ViewError, Viewable};

mod xpub;
pub use xpub::GetExtendedPublicKey;

use crate::{
    constants::{
        chain_alias_lookup, ApduError as Error, ASCII_HRP_MAX_SIZE, BIP32_PATH_ROOT_1,
        CHAIN_ID_CHECKSUM_SIZE, CHAIN_ID_LEN, DEFAULT_CHAIN_ID,
    },
    crypto,
    dispatcher::ApduHandler,
    handlers::handle_ui_message,
    sys::{
        self, bech32,
        hash::{Hasher, Ripemd160, Sha256},
        Error as SysError,
    },
    utils::{bs58_encode, read_slice, rs_strlen, ApduBufferRead, ApduPanic},
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

    /// Retrieve the public key with the given curve and bip32 path
    #[inline(never)]
    pub fn new_key_into<const B: usize>(
        curve: crypto::Curve,
        path: &sys::crypto::bip32::BIP32Path<B>,
        out: &mut MaybeUninit<crypto::PublicKey>,
        chaincode: Option<&mut [u8; 32]>,
    ) -> Result<(), SysError> {
        sys::zemu_log_stack("GetAddres::new_key\x00");
        curve.to_secret(path).into_public_into(chaincode, out)?;

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
    pub fn initialize_ui<const B: usize>(
        confirmation: bool,
        curve: crypto::Curve,
        hrp: &[u8],
        chain_id: &[u8],
        path: BIP32Path<B>,
        extended: bool,
        ui: &mut MaybeUninit<AddrUI>,
    ) -> Result<(), Error> {
        let path_component_1 = *path.components().get(1).ok_or(Error::DataInvalid)?;

        let mut ui_initializer = AddrUIInitializer::new(ui);

        ui_initializer
            .init_pkey(|key, cc| {
                if extended {
                    *cc = Some(*PIC::new(&[0; 32]).into_inner());
                };

                Self::new_key_into(curve, &path, key, cc.as_mut())
                    .map_err(|_| AddrUIInitError::KeyInitError)
            })?
            .init_hash(|key, hash| {
                let mut tmp = [0; Sha256::DIGEST_LEN];
                Sha256::digest_into(key.as_ref(), &mut tmp)
                    .and_then(|_| Ripemd160::digest_into(&tmp, hash))
                    .map_err(|_| AddrUIInitError::HashInitError)
            })?
            .with_chain(chain_id)?
            .with_hrp(hrp)?
            .set_is_avm(path_component_1 == BIP32_PATH_ROOT_1);

        ui_initializer.finalize().map_err(|(_, err)| err)?;

        Ok(())
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

        let hrp = Self::get_hrp(&mut cdata)?;
        let chainid = Self::get_chainid(&mut cdata)?;

        let bip32_path =
            sys::crypto::bip32::BIP32Path::<6>::read(cdata).map_err(|_| Error::DataInvalid)?;

        let mut ui = MaybeUninit::uninit();
        Self::initialize_ui(
            req_confirmation,
            curve,
            hrp,
            chainid,
            bip32_path,
            false,
            &mut ui,
        )?;

        //safe since it's all initialized now
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

/// This is a utility struct to initialize the [`AddrUI`]
/// in a given [`MaybeUninit`] correctly
pub struct AddrUIInitializer<'ui> {
    ui: &'ui mut MaybeUninit<AddrUI>,
    chain_init: bool,
    hash_init: bool,
    pkey_init: bool,
    hrp_init: bool,
}

#[cfg_attr(test, derive(Debug))]
pub enum AddrUIInitError {
    KeyInitError,
    KeyNotInitialized,
    HashInitError,
    HashNotInitialized,
    HrpNotInitialized,
    InvalidChainCode,
    ChainCodeNotInitialized,
    ChainCodeInitError,
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
        unsafe {
            let ui = ui.as_mut_ptr();
            addr_of_mut!((*ui).is_avm).write(true);
        }

        Self {
            ui,
            hash_init: false,
            pkey_init: false,
            hrp_init: false,
            chain_init: false,
        }
    }

    /// Override type of AddrUI between EVM or AVM
    pub fn set_is_avm(&mut self, is_avm: bool) -> &mut Self {
        unsafe {
            let ui = self.ui.as_mut_ptr();
            addr_of_mut!((*ui).is_avm).write(is_avm);
        }

        self
    }

    /// Initialize the public key with the given closure,
    /// also providing access to chain_code, initialized to `None` already
    pub fn init_pkey<
        F: FnOnce(
            &mut MaybeUninit<crypto::PublicKey>,
            &mut Option<[u8; CHAIN_CODE_LEN]>,
        ) -> Result<(), AddrUIInitError>,
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

        //get `chain_code` &mut,
        // cast to MaybeUninit *mut
        //SAFE: `as_mut` it to &mut MaybeUninit (safe because it's MaybeUninit)
        // unwrap the option as it's guarantee valid pointer
        // then initialize to a default, and pass the &mut of it
        let chain_code: &mut Option<[u8; CHAIN_CODE_LEN]> = unsafe {
            let cc = addr_of_mut!((*ui).chain_code)
                .cast::<MaybeUninit<_>>()
                .as_mut()
                .apdu_unwrap();
            cc.write(None);
            cc.assume_init_mut()
        };

        init(key, chain_code).map(|_| {
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

                //SAFETY: pointers are all valid since they are coming from rust
                // they are guaranteed non overlapping and we don't do any reads on uninit memory
                unsafe {
                    let ui_hrp = addr_of_mut!((*ui).hrp).cast::<u8>();
                    //copy hrp into the array
                    ui_hrp.copy_from_nonoverlapping(hrp.as_ptr(), hrp.len());
                    //null terminate
                    ui_hrp
                        .add(hrp.len())
                        .write_bytes(0, ASCII_HRP_MAX_SIZE + 1 - hrp.len());
                }

                self.hrp_init = true;
                Ok(self)
            }
        }
    }

    pub fn with_chain(&mut self, chainid: &[u8]) -> Result<&mut Self, AddrUIInitError> {
        if chainid.len() != CHAIN_ID_LEN {
            return Err(AddrUIInitError::InvalidChainCode);
        }
        let checksum = Sha256::digest(chainid).map_err(|_| AddrUIInitError::ChainCodeInitError)?;

        let ui = self.ui.as_mut_ptr();
        //SAFE: pointers come from rust so they are valid
        // any write happens with `.write` so we don't read the uninitialized memory
        unsafe {
            //get `chain_code` *mut,
            let chain = addr_of_mut!((*ui).chain_id_with_checksum).cast::<u8>();
            //write chainid in the array
            chain.copy_from_nonoverlapping(chainid.as_ptr(), CHAIN_ID_LEN);
            //offset by CHAIN_ID_LEN bytes and write the checksum
            // which is the last 4 bytes of sha256(chain_code)
            chain
                .add(CHAIN_ID_LEN) //should be same chainid.len()
                .copy_from_nonoverlapping(
                    checksum
                        .as_ptr()
                        .add(checksum.len() - CHAIN_ID_CHECKSUM_SIZE),
                    CHAIN_ID_CHECKSUM_SIZE,
                );
        }

        self.chain_init = true;
        Ok(self)
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
        let hash = unsafe {
            let hash = addr_of_mut!((*ui).hash);
            //initialize to default to avoid UB
            hash.write(*PIC::new(&[0; Ripemd160::DIGEST_LEN]).into_inner());
            hash.as_mut()
        }
        .apdu_unwrap();

        init(key, hash).map(|_| {
            self.hash_init = true;
            self
        })
    }

    #[cfg(test)]
    pub fn compute_hash(&mut self) -> &mut Self {
        let ui = self.ui.as_mut_ptr();
        let key = unsafe { addr_of!((*ui).pkey).as_ref() }.apdu_unwrap();

        let tmp = Sha256::digest(key.as_ref()).unwrap();
        let hash = Ripemd160::digest(&tmp).unwrap();

        unsafe { addr_of_mut!((*ui).hash).write(hash) };

        self
    }

    /// Finalize the initialization, performing any necessary checks to ensure everything is initialized
    pub fn finalize(self) -> Result<(), (Self, AddrUIInitError)> {
        if !self.hash_init {
            Err((self, AddrUIInitError::HashNotInitialized))
        } else if !self.pkey_init {
            Err((self, AddrUIInitError::KeyNotInitialized))
        } else if !self.hrp_init {
            Err((self, AddrUIInitError::HrpNotInitialized))
        } else if !self.chain_init {
            Err((self, AddrUIInitError::ChainCodeNotInitialized))
        } else {
            Ok(())
        }
    }
}

pub struct AddrUI {
    pub pkey: crypto::PublicKey,
    chain_code: Option<[u8; CHAIN_CODE_LEN]>,
    is_avm: bool,
    //includes checksum
    chain_id_with_checksum: [u8; CHAIN_ID_LEN + CHAIN_ID_CHECKSUM_SIZE],
    hash: [u8; Ripemd160::DIGEST_LEN],
    hrp: [u8; ASCII_HRP_MAX_SIZE + 1], //+1 to null terminate just in case
}

impl AddrUI {
    //36 (32 + 4 checksum) * log(2, 256) / log(2, 58) ~ 49.1
    // so we round up to 50
    pub const MAX_CHAIN_CB58_LEN: usize = 50;

    fn hrp_as_str(&self) -> &str {
        //this is okey since it's checked when a new instance is made
        let len = rs_strlen(&self.hrp);
        unsafe { core::str::from_utf8_unchecked(&self.hrp[..len]) }
    }

    /// Returns the CB58 representation (or alias) of the chain_id inside self
    ///
    /// The return is the total number of bytes written
    pub fn chain_id_into(&self, out: &mut [u8; Self::MAX_CHAIN_CB58_LEN]) -> usize {
        let chain_code = arrayref::array_ref!(self.chain_id_with_checksum, 0, CHAIN_ID_LEN);
        match chain_alias_lookup(chain_code) {
            Ok(alias) => {
                let alias = alias.as_bytes();
                let len = alias.len();
                out[..len].copy_from_slice(alias);
                len
            }
            Err(_) => {
                //not found in alias list, compute CB58 representation
                bs58_encode(&self.chain_id_with_checksum, &mut out[..])
                    .apdu_expect("encoded in base58 is not of the right length")
            }
        }
    }
}

impl Viewable for AddrUI {
    fn num_items(&mut self) -> Result<u8, ViewError> {
        Ok(1 + self.chain_code.is_some() as u8)
    }

    fn render_item(
        &mut self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::pic_str;

        match item_n {
            0 => {
                let title_content = pic_str!(b"Address");
                title[..title_content.len()].copy_from_slice(title_content);

                const MEX_MAX_SIZE: usize = AddrUI::MAX_CHAIN_CB58_LEN
                + 1 // the '-' separator
                + bech32::estimate_size(ASCII_HRP_MAX_SIZE, Ripemd160::DIGEST_LEN);

                let mut mex = [0; MEX_MAX_SIZE];
                let mut len = self.chain_id_into(arrayref::array_mut_ref![
                    mex,
                    0,
                    AddrUI::MAX_CHAIN_CB58_LEN
                ]);
                mex[len] = b'-';
                len += 1;

                len += bech32::encode(self.hrp_as_str(), &self.hash, &mut mex[len..])
                    .map_err(|_| ViewError::Unknown)?;

                handle_ui_message(&mex[..len], message, page)
            }
            1 if self.chain_code.is_some() => {
                let title_content = pic_str!(b"Path");
                title[..title_content.len()].copy_from_slice(title_content);

                let path = if self.is_avm {
                    pic_str!("m/44'/9000'/0'")
                } else {
                    pic_str!("m/44'/60'/0'")
                };

                handle_ui_message(path.as_bytes(), message, page)
            }
            _ => Err(ViewError::NoData),
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

#[cfg(test)]
mod tests {
    use arrayref::array_ref;
    use bolos::crypto::bip32::BIP32Path;
    use zuit::{MockDriver, Page};

    use crate::{
        crypto::{PublicKey, SecretKey},
        utils::strlen,
    };

    use super::*;

    impl AddrUI {
        pub fn new(pkey: &crypto::PublicKey, chain_code: &[u8], hrp: &[u8]) -> Self {
            let mut loc = MaybeUninit::uninit();

            let mut builder = AddrUIInitializer::new(&mut loc);
            let _ = builder
                .init_pkey(|key, _| {
                    key.write(*pkey);
                    Ok(())
                })
                .unwrap()
                .compute_hash()
                .with_chain(chain_code)
                .unwrap()
                .with_hrp(hrp);
            let _ = builder.finalize();

            unsafe { loc.assume_init() }
        }
    }

    fn keypair() -> (SecretKey<1>, PublicKey) {
        let secret =
            crypto::SecretKey::new(crypto::Curve::Secp256K1, BIP32Path::<1>::new([44]).unwrap());

        let public = secret.public().unwrap();
        (secret, public)
    }

    fn test_chain_alias(alias: Option<&str>, chain_code: Option<&[u8; 32]>) {
        let (_, pk) = keypair();
        let chain_code = chain_code.unwrap_or(GetPublicKey::default_chainid());
        let ui = AddrUI::new(&pk, chain_code, GetPublicKey::DEFAULT_HRP);

        //construct the expected message
        // chainID-bech32(HRP, pkey)
        let mut expected_message = std::string::String::new();
        match alias {
            None => {
                //calculate CB58 of the chain_code
                let chain_id = zbs58::encode(chain_code).as_cb58(None).into_string();
                expected_message.push_str(&chain_id);
            }
            Some(alias) => {
                expected_message.push_str(alias);
            }
        }
        expected_message.push('-');
        expected_message.push_str(&{
            let hrp = std::string::String::from_utf8(GetPublicKey::DEFAULT_HRP.to_vec()).unwrap();
            let mut tmp = [0; bech32::estimate_size(ASCII_HRP_MAX_SIZE, Ripemd160::DIGEST_LEN)];
            let len = bech32::encode(&hrp, &ui.hash, &mut tmp).unwrap();

            std::string::String::from_utf8(tmp[..len].to_vec()).unwrap()
        });

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

    #[test]
    pub fn p_chain() {
        test_chain_alias(Some("P"), None)
    }

    #[test]
    pub fn x_chain() {
        let id = hex::decode("ab68eb1ee142a05cfe768c36e11f0b596db5a3c6c77aabe665dad9e638ca94f7")
            .unwrap();
        let chain_code = array_ref![id, 0, 32];
        test_chain_alias(Some("X"), Some(chain_code))
    }

    #[test]
    pub fn c_chain() {
        let id = hex::decode("7fc93d85c6d62c5b2ac0b519c87010ea5294012d1e407030d6acd0021cac10d5")
            .unwrap();
        let chain_code = array_ref![id, 0, 32];
        test_chain_alias(Some("C"), Some(chain_code))
    }

    #[test]
    pub fn unknown_chain() {
        let id = hex::decode("2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a")
            .unwrap();
        let chain_code = array_ref![id, 0, 32];
        test_chain_alias(None, Some(chain_code))
    }
}
