/*******************************************************************************
*   (c) 2024 Zondax AG
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

use bolos_common::bip32::BIP32Path;

use crate::{
    constants::BIP32_PATH_PREFIX_DEPTH,
    handlers::{
        avax::{sign_hash::Sign as SignHash, signing::Sign},
        resources::{HASH, PATH},
    },
    parser::ParserError,
    ZxError,
};
// typedef struct {
//     const uint8_t *buffer;
//     uint16_t bufferLen;
//     uint16_t offset;
//     instruction_t ins;
//     parser_tx_t tx_obj;
// } parser_context_t;
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct parser_context_t {
    pub buffer: *const u8,
    pub buffer_len: u16,
    pub offset: u16,
    pub ins: u8,
    pub tx_obj: parse_tx_t,
}

// typedef struct {
//     uint8_t *state;
//     uint32_t len;
// } parser_tx_t;
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct parse_tx_t {
    pub state: *mut u8,
    pub len: u32,
}

// typedef enum {
//     SignAvaxTx = 0x00,
//     SignEthTx,
//     SignAvaxMsg,
//     SignEthMsg,
//     SignAvaxHash
// } instruction_t;
#[repr(C)]
pub enum Instruction {
    SignAvaxTx = 0x00,
    SignEthTx,
    SignAvaxMsg,
    SignEthMsg,
    SignAvaxHash,
}

impl TryFrom<u8> for Instruction {
    type Error = ParserError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Instruction::SignAvaxTx),
            1 => Ok(Instruction::SignEthTx),
            2 => Ok(Instruction::SignAvaxMsg),
            3 => Ok(Instruction::SignEthMsg),
            4 => Ok(Instruction::SignAvaxHash),
            _ => Err(ParserError::InvalidTransactionType),
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn _set_root_path(raw_path: *const u8, path_len_bytes: u16) -> u32 {
    let path = core::slice::from_raw_parts(raw_path, path_len_bytes as usize);
    // read root path and store it in ram as during the
    // signing process and diseabling outputs we use it
    // to get a full path: root_path + path_suffix
    let Ok(root_path) = BIP32Path::read(path) else {
        return ParserError::InvalidPath as u32;
    };
    //We expect a path prefix of the form x'/x'/x'
    if root_path.components().len() != BIP32_PATH_PREFIX_DEPTH {
        return ParserError::InvalidPath as u32;
    }

    // important to use avax::signing::Sign
    PATH.lock(Sign).replace(root_path);
    ParserError::ParserOk as u32
}

#[no_mangle]
pub unsafe extern "C" fn _set_tx_hash(hash: *const u8, hash_len_bytes: u16) -> u16 {
    if hash_len_bytes != Sign::SIGN_HASH_SIZE as u16 {
        return ZxError::OutOfBounds as u16;
    }

    let Ok(hash) = core::slice::from_raw_parts(hash, hash_len_bytes as usize).try_into() else {
        return ZxError::Unknown as u16;
    };

    // In this step the transaction has not been signed
    // so store the hash for the next steps
    HASH.lock(Sign).replace(hash);

    // next step requires SignHash handler to have
    // access to the path and hash resources that this handler just updated
    PATH.lock(SignHash);
    HASH.lock(SignHash);
    ZxError::Ok as u16
}
