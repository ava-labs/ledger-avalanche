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

use crate::{
    constants::{
        chain_alias_lookup, ApduError as Error, ASCII_HRP_MAX_SIZE, CHAIN_ID_CHECKSUM_SIZE, CHAIN_ID_LEN, CURVE_SECP256K1, MAX_BIP32_PATH_DEPTH
    },
    crypto,
    handlers::{handle_ui_message, resources::PATH},
    sys::{bech32, crypto::{bip32::BIP32Path, CHAIN_CODE_LEN}, hash::{Hasher, Ripemd160, Sha256}, ViewError, Viewable, PIC
    },
    utils::{bs58_encode, hex_encode, rs_strlen, ApduPanic},
};

use core::{mem::MaybeUninit, ptr::addr_of_mut};

use super::GetPublicKey;

/// This is a utility struct to initialize the [`AddrUI`]
/// in a given [`MaybeUninit`] correctly
pub struct AddrUIInitializer<'ui> {
    ui: &'ui mut MaybeUninit<AddrUI>,
    chain_init: bool,
    path_init: bool,
    hrp_init: bool,
    curve_init: bool,
}

#[cfg_attr(test, derive(Debug))]
pub enum AddrUIInitError {
    KeyInitError,
    PathNotInitialized,
    HashInitError,
    HrpNotInitialized,
    InvalidChainCode,
    ChainCodeNotInitialized,
    ChainCodeInitError,
    HRPTooLong,
    NonASCIIHrp,
    CurveNotInitialized,
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
            hrp_init: false,
            chain_init: false,
            curve_init: false,
        }
    }

    /// Produce the closure to initialize a key
    pub fn key_initializer<const B: usize>(
        path: &'_ BIP32Path<B>,
        curve_type: u8,
    ) -> impl FnOnce(
        &mut MaybeUninit<crypto::PublicKey>,
        Option<&mut [u8; CHAIN_CODE_LEN]>,
    ) -> Result<(), AddrUIInitError>
           + '_ {
        move |key, cc| {
            GetPublicKey::new_key_into(path, key, cc, curve_type).map_err(|_| AddrUIInitError::KeyInitError)
        }
    }

    /// Produce the closure to initialize the pubkey hash
    pub fn hash_initializer(
    ) -> impl FnOnce(&crypto::PublicKey, &mut [u8; Ripemd160::DIGEST_LEN]) -> Result<(), AddrUIInitError>
    {
        |key, hash| {
            let mut tmp = [0; Sha256::DIGEST_LEN];

            Sha256::digest_into(key.as_ref(), &mut tmp)
                .and_then(|_| Ripemd160::digest_into(&tmp, hash))
                .map_err(|_| AddrUIInitError::HashInitError)
        }
    }

    /// Initialie the path with the given one
    pub fn with_path(&mut self, path: BIP32Path<MAX_BIP32_PATH_DEPTH>) -> &mut Self {
        unsafe {
            PATH.lock(super::GetPublicKey).replace(path);
        }

        self.path_init = true;
        self
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
            chain.copy_from_nonoverlapping(chainid.as_ptr(), CHAIN_CODE_LEN);
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

    pub fn with_curve(&mut self, curve_type: u8) -> &mut Self {
        //get ui *mut
        let ui = self.ui.as_mut_ptr();

        //SAFETY: pointers are all valid since they are coming from rust
        unsafe {
            (*ui).curve_type = curve_type;
        }

        self.curve_init = true;
        self
    }

    /// Finalize the initialization, performing any necessary checks to ensure everything is initialized
    pub fn finalize(self) -> Result<(), (Self, AddrUIInitError)> {
        if !self.path_init {
            Err((self, AddrUIInitError::PathNotInitialized))
        } else if !self.curve_init {
            Err((self, AddrUIInitError::CurveNotInitialized))
        } else {
            // SAFETY: curve_type is initialized since we checked curve_init
            let curve_type = unsafe { (*self.ui.as_ptr()).curve_type };
            
            if curve_type == 0 {
                // Only check hrp and chain when curve_type is 0
                if !self.hrp_init {
                    Err((self, AddrUIInitError::HrpNotInitialized))
                } else if !self.chain_init {
                    Err((self, AddrUIInitError::ChainCodeNotInitialized))
                } else {
                    Ok(())
                }
            } else {
                Ok(())
            }
        }
    }
}

#[repr(C)]
pub struct AddrUI {
    //includes checksum
    chain_id_with_checksum: [u8; CHAIN_ID_LEN + CHAIN_ID_CHECKSUM_SIZE],
    hrp: [u8; ASCII_HRP_MAX_SIZE + 1], //+1 to null terminate just in case
    curve_type: u8,
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
                bs58_encode(self.chain_id_with_checksum, &mut out[..])
                    .apdu_expect("encoded in base58 is not of the right length")
            }
        }
    }

    /// Compute the public key from the path
    pub fn pkey(
        &self,
        chain_code: Option<&mut [u8; CHAIN_CODE_LEN]>,
    ) -> Result<crypto::PublicKey, Error> {
        crate::zlog("AddrUI::pkey\n\x00");
        let mut out = MaybeUninit::uninit();

        let path = unsafe { PATH.acquire(super::GetPublicKey) }?
            .as_ref()
            .ok_or(Error::ExecutionError)?;

        AddrUIInitializer::key_initializer(path, self.curve_type)(&mut out, chain_code)
            .map_err(|_| Error::ExecutionError)?;

        //SAFETY: out has been initialized by the call above
        // note, this isn't done in .map since it would also be executed in case of an error
        Ok(unsafe { out.assume_init() })
    }

    /// Compute the pkey hash
    pub fn hash(&self, key: &crypto::PublicKey) -> Result<[u8; Ripemd160::DIGEST_LEN], Error> {
        let mut out = [0; Ripemd160::DIGEST_LEN];

        AddrUIInitializer::hash_initializer()(key, &mut out)
            .map_err(|_| Error::ExecutionError)
            .map(|_| out)
    }

    pub const MAX_ADDR_SIZE: usize = Self::MAX_CHAIN_CB58_LEN
        + 1
        + bech32::estimate_size(ASCII_HRP_MAX_SIZE, Ripemd160::DIGEST_LEN);

    /// Will write the formatted address to `out` and return the length written
    pub fn addr(&self, out: &mut [u8; AddrUI::MAX_ADDR_SIZE]) -> Result<usize, Error> {
        if self.curve_type == CURVE_SECP256K1 {
            crate::zlog("addr - secp256k1\n\x00");

        let mut len =
            self.chain_id_into(arrayref::array_mut_ref![out, 0, AddrUI::MAX_CHAIN_CB58_LEN]);

        out[len] = b'-';
        len += 1;

        let hash = self.pkey(None).and_then(|pk| self.hash(&pk))?;
        len += bech32::encode(
            self.hrp_as_str(),
            &hash[..],
            &mut out[len..],
            bech32::Variant::Bech32,
        )
        .apdu_unwrap();

            Ok(len)
        } else {
            crate::zlog("addr - ed25519\n\x00");

            // ED25519 HVM address format
            const ED25519_AUTH_ID: u8 = 0x00;
            
            let pkey = self.pkey(None)?;
            let pkey_bytes = pkey.as_ref();
            
            // Create address bytes: [auth_id, sha256(pubkey)]
            let mut addr_bytes = [0u8; 37]; // Temporary buffer for raw address
            addr_bytes[0] = ED25519_AUTH_ID;
            let mut sha256_hash = [0u8; 32];
            Sha256::digest_into(&pkey_bytes[..32], &mut sha256_hash)
                .map_err(|_| Error::ExecutionError)?;
            addr_bytes[1..33].copy_from_slice(&sha256_hash);
            
            // Calculate checksum (last 4 bytes of sha256(address_bytes))
            let mut checksum = [0u8; 32];
            Sha256::digest_into(&addr_bytes[..33], &mut checksum)
                .map_err(|_| Error::ExecutionError)?;
            addr_bytes[33..37].copy_from_slice(&checksum[28..32]);
            
            // Hex encode the address bytes
            let hex_len = hex_encode(&addr_bytes, out)
                .map_err(|_| Error::ExecutionError)?;
            
            Ok(hex_len) // Length of hex encoded string
        }
    }
}

impl Viewable for AddrUI {
    const IS_ADDRESS: bool = true;

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
            let title_content = pic_str!(b"Address");
            title[..title_content.len()].copy_from_slice(title_content);

            let mut mex = [0; Self::MAX_ADDR_SIZE];
            let len = self.addr(&mut mex).map_err(|_| ViewError::Unknown)?;

            handle_ui_message(&mex[..len], message, page)
        } else {
            Err(ViewError::NoData)
        }
    }

    fn accept(&mut self, out: &mut [u8]) -> (usize, u16) {
        let pkey = match self.pkey(None) {
            Ok(pkey) => pkey,
            Err(e) => return (0, e as _),
        };

        let pkey_bytes = pkey.as_ref();
        let mut tx = 0;

        if self.curve_type == CURVE_SECP256K1 {
            out[tx] = pkey_bytes.len() as u8;
            tx += 1;
            out[tx..][..pkey_bytes.len()].copy_from_slice(pkey_bytes);
            tx += pkey_bytes.len();
        } else {
            out[tx] = 32;
            tx += 1;
            out[tx..][..32].copy_from_slice(&pkey_bytes[..32]);
            tx += 32;
        }

        match self.hash(&pkey) {
            Ok(hash) => {
                out[tx..][..hash.len()].copy_from_slice(&hash[..]);
                tx += hash.len();
            }
            Err(e) => return (0, e as _),
        }

        let addr = arrayref::array_mut_ref![out, tx, AddrUI::MAX_ADDR_SIZE];
        match self.addr(addr) {
            Ok(len) => tx += len,
            Err(e) => return (0, e as _),
        }

        (tx, Error::Success as _)
    }

    fn reject(&mut self, _: &mut [u8]) -> (usize, u16) {
        (0, Error::CommandNotAllowed as _)
    }
}

#[cfg(test)]
mod tests {
    use arrayref::array_ref;
    use bolos::{bech32, crypto::bip32::BIP32Path};
    use serial_test::file_serial;
    use zuit::{MockDriver, Page};

    use crate::{handlers::public_key::GetPublicKey, utils::strlen};

    use super::*;

    impl AddrUI {
        pub fn new(path: BIP32Path<MAX_BIP32_PATH_DEPTH>, chain_code: &[u8], hrp: &[u8]) -> Self {
            let mut loc = MaybeUninit::uninit();

            let mut builder = AddrUIInitializer::new(&mut loc);
            let _ = builder
                .with_path(path)
                .with_chain(chain_code)
                .unwrap()
                .with_hrp(hrp)
                .unwrap()
                .with_curve(0);
            let _ = builder.finalize();

            unsafe { loc.assume_init() }
        }
    }

    fn path() -> BIP32Path<MAX_BIP32_PATH_DEPTH> {
        BIP32Path::new([0x8000_0000 + 44, 0x8000_0000 + 9000]).unwrap()
    }

    fn test_chain_alias(alias: Option<&str>, chain_code: Option<&[u8; 32]>) {
        let chain_code = chain_code.unwrap_or_else(|| GetPublicKey::default_chainid());
        let ui = AddrUI::new(path(), chain_code, GetPublicKey::DEFAULT_HRP);

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
            let len = bech32::encode(
                &hrp,
                ui.hash(&ui.pkey(None).unwrap()).unwrap(),
                &mut tmp,
                bech32::Variant::Bech32,
            )
            .unwrap();

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
    #[cfg_attr(not(miri), file_serial(path))]
    pub fn p_chain() {
        test_chain_alias(Some("P"), None)
    }

    #[test]
    #[cfg_attr(not(miri), file_serial(path))]
    pub fn x_chain() {
        let id = hex::decode("ab68eb1ee142a05cfe768c36e11f0b596db5a3c6c77aabe665dad9e638ca94f7")
            .unwrap();
        let chain_code = array_ref![id, 0, 32];
        test_chain_alias(Some("X"), Some(chain_code))
    }

    #[test]
    #[cfg_attr(not(miri), file_serial(path))]
    pub fn c_chain() {
        let id = hex::decode("7fc93d85c6d62c5b2ac0b519c87010ea5294012d1e407030d6acd0021cac10d5")
            .unwrap();
        let chain_code = array_ref![id, 0, 32];
        test_chain_alias(Some("C"), Some(chain_code))
    }

    #[test]
    #[cfg_attr(not(miri), file_serial(path))]
    pub fn unknown_chain() {
        let id = hex::decode("2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a")
            .unwrap();
        let chain_code = array_ref![id, 0, 32];
        test_chain_alias(None, Some(chain_code))
    }
}
