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
use core::{convert::TryFrom, mem::MaybeUninit, ptr::addr_of_mut};

use zemu_sys::{Show, ViewError, Viewable};

use crate::{
    constants::{ApduError as Error, BIP32_PATH_ROOT_1, MAX_BIP32_PATH_DEPTH},
    crypto,
    dispatcher::ApduHandler,
    handlers::handle_ui_message,
    sys::{
        self,
        crypto::{bip32::BIP32Path, CHAIN_CODE_LEN},
        PIC,
    },
    utils::{ApduBufferRead, ApduPanic},
};

use super::{AddrUI, AddrUIInitError, AddrUIInitializer, GetPublicKey};

pub struct GetExtendedPublicKey;

impl GetExtendedPublicKey {
    pub fn initialize_ui(
        hrp: &[u8],
        chain_id: &[u8],
        path: BIP32Path<MAX_BIP32_PATH_DEPTH>,
        ui: &mut MaybeUninit<ExtendedPubkeyUI>,
    ) -> Result<(), Error> {
        let path_component_1 = *path.components().get(1).ok_or(Error::DataInvalid)?;

        let mut initializer = ExtendedPubkeyUIInitializer::new(ui);
        initializer.set_is_avm(path_component_1 == BIP32_PATH_ROOT_1);

        initializer.initialize_inner(path, chain_id, hrp)?;

        initializer.finalize().map_err(|_| Error::ExecutionError)
    }
}

impl ApduHandler for GetExtendedPublicKey {
    #[inline(never)]
    fn handle(
        flags: &mut u32,
        tx: &mut u32,
        buffer: ApduBufferRead<'_>,
    ) -> Result<(), Error> {
        sys::zemu_log_stack("GetExtendedPublicKey::handle\x00");

        *tx = 0;

        let req_confirmation = buffer.p1() >= 1;

        let mut cdata = buffer.payload().map_err(|_| Error::DataInvalid)?;

        let hrp = GetPublicKey::get_hrp(&mut cdata)?;
        let chainid = GetPublicKey::get_chainid(&mut cdata)?;

        let bip32_path = sys::crypto::bip32::BIP32Path::<MAX_BIP32_PATH_DEPTH>::read(cdata)
            .map_err(|_| Error::DataInvalid)?;

        let mut ui = MaybeUninit::uninit();
        Self::initialize_ui(hrp, chainid, bip32_path, &mut ui)?;

        //safe since it's all initialized now
        let mut ui = unsafe { ui.assume_init() };

        if req_confirmation {
            crate::show_ui!(ui.show(flags), tx)
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

pub struct ExtendedPubkeyUI {
    addr_ui: AddrUI,
    is_avm: bool,
}

impl ExtendedPubkeyUI {
    pub fn key_with_chain_code(&self) -> Result<(crypto::PublicKey, [u8; CHAIN_CODE_LEN]), Error> {
        let mut out = [0; CHAIN_CODE_LEN];
        self.addr_ui.pkey(Some(&mut out)).map(|key| (key, out))
    }
}

pub struct ExtendedPubkeyUIInitializer<'ui> {
    ui: &'ui mut MaybeUninit<ExtendedPubkeyUI>,
    inner_ui_init: bool,
    // chain_code_init: bool,
}

impl<'ui> ExtendedPubkeyUIInitializer<'ui> {
    pub fn new(ui: &'ui mut MaybeUninit<ExtendedPubkeyUI>) -> Self {
        unsafe {
            let ui = ui.as_mut_ptr();
            addr_of_mut!((*ui).is_avm).write(true);
        }

        Self {
            ui,
            inner_ui_init: false,
            // chain_code_init: false,
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

    fn addr_ui_initializer(&mut self) -> AddrUIInitializer<'ui> {
        let ui = self.ui.as_mut_ptr();

        //get `addr_ui` *mut,
        // cast to MaybeUninit *mut
        //SAFE: `as_mut` it to &mut MaybeUninit (safe because it's MaybeUninit)
        // unwrap the option as it's guarantee valid pointer
        let inner_ui = unsafe {
            addr_of_mut!((*ui).addr_ui)
                .cast::<MaybeUninit<AddrUI>>()
                .as_mut()
        }
        .apdu_unwrap();

        AddrUIInitializer::new(inner_ui)
    }

    pub fn initialize_inner(
        &mut self,
        path: BIP32Path<MAX_BIP32_PATH_DEPTH>,
        chain_id: &[u8],
        hrp: &[u8],
    ) -> Result<&mut Self, AddrUIInitError> {
        let mut initializer = self.addr_ui_initializer();
        initializer
            .with_path(path)
            .with_chain(chain_id)?
            .with_hrp(hrp)?;
        initializer.finalize().map_err(|(_, err)| err)?;

        self.inner_ui_init = true;
        Ok(self)
    }

    pub fn finalize(self) -> Result<(), Self> {
        if self.inner_ui_init {
            Ok(())
        } else {
            Err(self)
        }
    }
}

impl Viewable for ExtendedPubkeyUI {
    const IS_ADDRESS: bool = true;

    fn num_items(&mut self) -> Result<u8, ViewError> {
        Ok(2)
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
            0 => self.addr_ui.render_item(0, title, message, page),
            1 => {
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
        let (pkey, cc) = match self.key_with_chain_code() {
            Ok(ok) => ok,
            Err(e) => return (0, e as _),
        };

        let pkey_bytes = pkey.as_ref();
        let mut tx = 0;

        out[tx] = pkey_bytes.len() as u8;
        tx += 1;

        out[tx..][..pkey_bytes.len()].copy_from_slice(pkey_bytes);
        tx += pkey_bytes.len();

        out[tx..][..cc.len()].copy_from_slice(&cc);
        tx += cc.len();

        (tx, Error::Success as _)
    }

    fn reject(&mut self, _: &mut [u8]) -> (usize, u16) {
        (0, Error::CommandNotAllowed as _)
    }
}
