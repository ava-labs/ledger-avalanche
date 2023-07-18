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
use crate::{constants::ApduError as Error, dispatcher::ApduHandler, sys, utils::ApduBufferRead};

pub struct Info;

#[cfg(feature = "erc721")]
impl Info {
    fn process(input: &[u8]) -> Result<(), Error> {
        // skip type and version
        let mut nft_info = core::mem::MaybeUninit::uninit();

        _ = crate::parser::FromBytes::from_bytes_into(input, &mut nft_info)
            .map_err(|_| Error::DataInvalid)?;

        let nft_info = unsafe { nft_info.assume_init() };

        // store the information use to parse erc721 token
        unsafe {
            crate::handlers::resources::NFT_INFO
                .lock(super::signing::Sign)
                .replace(nft_info);
        }

        Ok(())
    }
}

#[cfg(not(feature = "erc721"))]
impl Info {
    fn process(_: &[u8]) -> Result<(), Error> {
        Ok(())
    }
}

impl ApduHandler for Info {
    #[inline(never)]
    fn handle<'apdu>(
        _flags: &mut u32,
        tx: &mut u32,
        buffer: ApduBufferRead<'apdu>,
    ) -> Result<(), Error> {
        sys::zemu_log_stack("NftInfoProvider::handle\x00");

        *tx = 0;

        // the hw-app-eth sends all the data that is required for this.
        // it is arount 90 bytes length so It should error in case It received
        // less than that
        let payload = buffer.payload().map_err(|_| Error::WrongLength)?;

        Info::process(payload)?;

        Ok(())
    }
}
