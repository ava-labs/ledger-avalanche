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
    constants::{evm_instructions::*, instructions::*, ApduError},
    parser::ParserError,
};

#[cfg(feature = "erc20")]
use crate::handlers::eth::provide_erc20::ProvideERC20;
use crate::handlers::eth::{
    get_app_configuration::GetAppConfiguration as EthGetAppConfig,
    personal_msg::Sign as EthSignMsg, public_key::GetPublicKey as GetEthPublicKey,
    set_plugin::SetPlugin, signing::Sign as EthSign,
};
#[cfg(test)]
use crate::handlers::{
    public_key::{GetExtendedPublicKey, GetPublicKey},
    version::GetVersion,
    wallet_id::WalletId,
};

#[cfg(feature = "erc721")]
use crate::handlers::eth::provide_nft_info::Info as NftProvider;

#[cfg(test)]
use crate::handlers::avax::{
    message::Sign as AvaxSignMsg, sign_hash::Sign as SignHash, signing::Sign as AvaxSign,
};

#[cfg(feature = "dev")]
use crate::handlers::dev::*;

use crate::utils::{ApduBufferRead, ApduPanic};

pub trait ApduHandler {
    fn handle(
        flags: &mut u32,
        tx: &mut u32,
        apdu_buffer: ApduBufferRead<'_>,
    ) -> Result<(), ApduError>;
}

#[inline(never)]
pub fn apdu_dispatch(
    flags: &mut u32,
    tx: &mut u32,
    apdu_buffer: ApduBufferRead<'_>,
) -> Result<(), ApduError> {
    crate::zlog("apdu_dispatch\x00");
    *flags = 0;
    *tx = 0;

    let cla = apdu_buffer.cla();
    if cla != CLA && cla != CLA_ETH {
        return Err(ApduError::ClaNotSupported);
    }

    let ins = apdu_buffer.ins();

    //common instructions
    match (cla, ins) {
        #[cfg(test)]
        (CLA, _) => handle_avax_apdu(flags, tx, apdu_buffer),

        // only for nanos as other targets will use app-ethereum
        (CLA_ETH, INS_ETH_GET_PUBLIC_KEY) => GetEthPublicKey::handle(flags, tx, apdu_buffer),
        (CLA_ETH, INS_SET_PLUGIN) => SetPlugin::handle(flags, tx, apdu_buffer),
        #[cfg(feature = "erc20")]
        (CLA_ETH, INS_ETH_PROVIDE_ERC20) => ProvideERC20::handle(flags, tx, apdu_buffer),
        #[cfg(feature = "erc721")]
        (CLA_ETH, INS_PROVIDE_NFT_INFORMATION) => NftProvider::handle(flags, tx, apdu_buffer),
        (CLA_ETH, INS_ETH_GET_APP_CONFIGURATION) => EthGetAppConfig::handle(flags, tx, apdu_buffer),
        (CLA_ETH, INS_ETH_SIGN) => EthSign::handle(flags, tx, apdu_buffer),
        (CLA_ETH, INS_SIGN_ETH_MSG) => EthSignMsg::handle(flags, tx, apdu_buffer),

        #[cfg(feature = "dev")]
        _ => Debug::handle(flags, tx, apdu_buffer),
        #[allow(unreachable_patterns)] //not unrechable for all feature configurations
        _ => Err(ApduError::CommandNotAllowed),
    }
}

#[inline(never)]
pub fn eth_dispatch(
    flags: &mut u32,
    tx: &mut u32,
    apdu_buffer: ApduBufferRead<'_>,
) -> Result<bool, ParserError> {
    crate::zlog("eth_dispatch\x00");
    *flags = 0;
    *tx = 0;

    let cla = apdu_buffer.cla();
    if cla != CLA_ETH {
        return Err(ParserError::UnexpectedData);
    }

    let ins = apdu_buffer.ins();

    //common instructions
    match (cla, ins) {
        // only for nanos as other targets will use app-ethereum
        (CLA_ETH, INS_ETH_GET_PUBLIC_KEY) => GetEthPublicKey::fill(tx, apdu_buffer),
        (CLA_ETH, INS_ETH_SIGN) => EthSign::parse(apdu_buffer),
        (CLA_ETH, INS_SIGN_ETH_MSG) => EthSignMsg::parse(apdu_buffer),
        _ => Err(ParserError::InvalidTransactionType),
    }
}

#[cfg(test)]
fn handle_avax_apdu(
    flags: &mut u32,
    tx: &mut u32,
    apdu_buffer: ApduBufferRead<'_>,
) -> Result<(), ApduError> {
    crate::zlog("handle_avax_apdu\x00");
    *flags = 0;
    *tx = 0;

    let cla = apdu_buffer.cla();
    if cla != CLA {
        return Err(ApduError::ClaNotSupported);
    }

    let ins = apdu_buffer.ins();

    //common instructions
    match (cla, ins) {
        (CLA, INS_GET_VERSION) => GetVersion::handle(flags, tx, apdu_buffer),
        (CLA, INS_GET_PUBLIC_KEY) => GetPublicKey::handle(flags, tx, apdu_buffer),
        (CLA, INS_GET_EXTENDED_PUBLIC_KEY) => GetExtendedPublicKey::handle(flags, tx, apdu_buffer),
        (CLA, INS_GET_WALLET_ID) => WalletId::handle(flags, tx, apdu_buffer),
        (CLA, INS_SIGN) => AvaxSign::handle(flags, tx, apdu_buffer),
        (CLA, INS_SIGN_HASH) => SignHash::handle(flags, tx, apdu_buffer),
        (CLA, INS_SIGN_MSG) => AvaxSignMsg::handle(flags, tx, apdu_buffer),
        _ => Err(ApduError::CommandNotAllowed),
    }
}

pub fn handle_apdu(flags: &mut u32, tx: &mut u32, rx: u32, apdu_buffer: &mut [u8]) {
    crate::zlog("handle_apdu\x00");

    //construct reader
    let status_word = match ApduBufferRead::new(apdu_buffer, rx) {
        Ok(reader) => match apdu_dispatch(flags, tx, reader)
            .and(Err::<(), _>(ApduError::Success))
            .map_err(|e| e as u16)
        {
            Err(_) if (*tx + 2) as usize >= apdu_buffer.len() => {
                //sw won't fit in the buffer
                // set tx to 0 and override error
                *tx = 0;
                ApduError::OutputBufferTooSmall as u16
            }
            Err(e) => e,
            Ok(_) => unsafe { core::hint::unreachable_unchecked() },
        },
        Err(_) => ApduError::WrongLength as u16,
    };

    let txu = *tx as usize;
    apdu_buffer
        .get_mut(txu..txu + 2)
        .apdu_unwrap()
        .copy_from_slice(&status_word.to_be_bytes());

    *tx += 2;
}

pub fn handle_eth_apdu(
    flags: &mut u32,
    tx: &mut u32,
    rx: u32,
    apdu_buffer: &mut [u8],
    done: &mut bool,
) -> u32 {
    crate::zlog("handle_eth_apdu\x00");

    //construct reader
    let Ok(reader) = ApduBufferRead::new(apdu_buffer, rx) else {
        return crate::parser::ParserError::NoData as u32;
    };

    match eth_dispatch(flags, tx, reader) {
        Ok(ready) => {
            *done = ready;
            crate::parser::ParserError::ParserOk as u32
        }
        Err(e) => e as u32,
    }
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
