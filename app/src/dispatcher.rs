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

use core::hint::unreachable_unchecked;

use crate::constants::{evm_instructions::*, instructions::*, ApduError};

use crate::handlers::{
    eth::{
        get_app_configuration::GetAppConfiguration as EthGetAppConfig, provide_erc20::ProvideERC20,
        provide_nft_info::Info as NftProvider, public_key::GetPublicKey as GetEthPublicKey,
        set_plugin::SetPlugin, signing::Sign as EthSign,
    },
    public_key::{GetExtendedPublicKey, GetPublicKey},
    version::GetVersion,
    wallet_id::WalletId,
};

#[cfg(feature = "blind-sign")]
use crate::handlers::{
    avax::blind_signing::BlindSign as AvaxBlindSign, eth::blind_signing::BlindSign as EthBlindSign,
};

use crate::handlers::avax::{
    message::Sign as AvaxSignMsg, sign_hash::Sign as SignHash, signing::Sign as AvaxSign,
};

#[cfg(feature = "dev")]
use crate::handlers::dev::*;

use crate::utils::{ApduBufferRead, ApduPanic};

pub trait ApduHandler {
    fn handle<'apdu>(
        flags: &mut u32,
        tx: &mut u32,
        apdu_buffer: ApduBufferRead<'apdu>,
    ) -> Result<(), ApduError>;
}

#[inline(never)]
pub fn apdu_dispatch<'apdu>(
    flags: &mut u32,
    tx: &mut u32,
    apdu_buffer: ApduBufferRead<'apdu>,
) -> Result<(), ApduError> {
    crate::sys::zemu_log_stack("apdu_dispatch\x00");
    *flags = 0;
    *tx = 0;

    let cla = apdu_buffer.cla();
    if cla != CLA && cla != CLA_ETH {
        return Err(ApduError::ClaNotSupported);
    }

    let ins = apdu_buffer.ins();

    //common instructions
    match (cla, ins) {
        (CLA, INS_GET_VERSION) => GetVersion::handle(flags, tx, apdu_buffer),
        (CLA, INS_GET_PUBLIC_KEY) => GetPublicKey::handle(flags, tx, apdu_buffer),
        (CLA, INS_GET_EXTENDED_PUBLIC_KEY) => GetExtendedPublicKey::handle(flags, tx, apdu_buffer),
        #[cfg(feature = "blind-sign")]
        (CLA, INS_BLIND_SIGN) => AvaxBlindSign::handle(flags, tx, apdu_buffer),
        (CLA, INS_GET_WALLET_ID) => WalletId::handle(flags, tx, apdu_buffer),
        (CLA, INS_SIGN) => AvaxSign::handle(flags, tx, apdu_buffer),
        (CLA, INS_SIGN_HASH) => SignHash::handle(flags, tx, apdu_buffer),
        (CLA, INS_SIGN_MSG) => AvaxSignMsg::handle(flags, tx, apdu_buffer),

        (CLA_ETH, INS_ETH_GET_PUBLIC_KEY) => GetEthPublicKey::handle(flags, tx, apdu_buffer),
        (CLA_ETH, INS_SET_PLUGIN) => SetPlugin::handle(flags, tx, apdu_buffer),
        (CLA_ETH, INS_ETH_PROVIDE_ERC20) => ProvideERC20::handle(flags, tx, apdu_buffer),
        (CLA_ETH, INS_PROVIDE_NFT_INFORMATION) => NftProvider::handle(flags, tx, apdu_buffer),
        (CLA_ETH, INS_ETH_GET_APP_CONFIGURATION) => EthGetAppConfig::handle(flags, tx, apdu_buffer),
        #[cfg(feature = "blind-sign")]
        (CLA_ETH, INS_ETH_BLIND_SIGN) => EthBlindSign::handle(flags, tx, apdu_buffer),
        (CLA_ETH, INS_ETH_SIGN) => EthSign::handle(flags, tx, apdu_buffer),

        #[cfg(feature = "dev")]
        _ => Debug::handle(flags, tx, apdu_buffer),
        #[allow(unreachable_patterns)] //not unrechable for all feature configurations
        _ => Err(ApduError::CommandNotAllowed),
    }
}

pub fn handle_apdu(flags: &mut u32, tx: &mut u32, rx: u32, apdu_buffer: &mut [u8]) {
    crate::sys::zemu_log_stack("handle_apdu\x00");

    //construct reader
    let status_word = match ApduBufferRead::new(apdu_buffer, rx) {
        Ok(reader) => match apdu_dispatch(flags, tx, reader)
            .and(Err::<(), _>(ApduError::Success))
            .map_err(|e| e as u16)
        {
            Err(e) => e,
            Ok(_) => unsafe { unreachable_unchecked() },
        },
        Err(_) => ApduError::WrongLength as u16,
    };

    let txu = *tx as usize;
    apdu_buffer
        .get_mut(txu..txu + 2)
        .apdu_unwrap()
        .copy_from_slice(status_word.to_be_bytes().as_ref());

    *tx += 2;
}

#[cfg(test)]
mod tests {
    use crate::assert_error_code;
    use crate::constants::ApduError;
    use crate::dispatcher::handle_apdu;
    use std::convert::TryInto;

    #[test]
    fn apdu_too_short() {
        let flags = &mut 0u32;
        let tx = &mut 0u32;
        let rx = 0u32;
        let buffer = &mut [0u8; 260];

        handle_apdu(flags, tx, rx, buffer);
        assert_eq!(*tx, 2u32);
        assert_error_code!(*tx, buffer, ApduError::WrongLength);
    }

    #[test]
    fn apdu_invalid_cla() {
        let flags = &mut 0u32;
        let tx = &mut 0u32;
        let rx = 5u32;
        let buffer = &mut [0u8; 260];

        handle_apdu(flags, tx, rx, buffer);
        assert_eq!(*tx, 2u32);
    }
}
