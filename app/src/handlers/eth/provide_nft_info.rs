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

use crate::{
    constants::{ApduError as Error, APDU_MIN_LENGTH, MAX_BIP32_PATH_DEPTH},
    dispatcher::ApduHandler,
    handlers::resources::NFT_INFO,
    parser::{FromBytes, NftInfo},
    sys,
    utils::ApduBufferRead,
};

// taken from app-ethereum implementation
const TYPE_SIZE: usize = 1;
const VERSION_SIZE: usize = 1;
const NAME_LENGTH_SIZE: usize = 1;
const HEADER_SIZE: usize = TYPE_SIZE + VERSION_SIZE + NAME_LENGTH_SIZE;
const CHAIN_ID_SIZE: usize = 8;
const KEY_ID_SIZE: usize = 1;
const ALGORITHM_ID_SIZE: usize = 1;
const SIGNATURE_LENGTH_SIZE: usize = 1;
const MIN_DER_SIG_SIZE: usize = 67;
const MAX_DER_SIG_SIZE: usize = 72;
const TEST_NFT_METADATA_KEY: usize = 0;
const PROD_NFT_METADATA_KEY: usize = 1;
const ALGORITHM_ID_1: usize = 1;
const TYPE_1: usize = 1;
const VERSION_1: usize = 1;

pub struct Info;

impl Info {
    fn process(input: &[u8]) -> Result<(), Error> {
        // skip type and version
        let mut nft_info = MaybeUninit::uninit();

        _ = NftInfo::from_bytes_into(&input[2..], &mut nft_info).map_err(|_| Error::DataInvalid)?;

        let nft_info = unsafe { nft_info.assume_init() };

        // store the information use to parse erc721 token
        unsafe {
            NFT_INFO.lock(Self)?.replace(nft_info);
        }

        Ok(())
    }
}

impl ApduHandler for Info {
    #[inline(never)]
    fn handle<'apdu>(
        flags: &mut u32,
        tx: &mut u32,
        buffer: ApduBufferRead<'apdu>,
    ) -> Result<(), Error> {
        sys::zemu_log_stack("EthSign::handle\x00");

        *tx = 0;

        // the hw-app-eth sends all the data that is required for this.
        // it is arount 90 bytes length so It should error in case It received
        // less than that
        let payload = buffer.payload().map_err(|_| Error::WrongLength)?;

        if payload.len() <= HEADER_SIZE {
            return Err(Error::WrongLength);
        }

        Info::process(payload)?;

        Ok(())
    }
}
