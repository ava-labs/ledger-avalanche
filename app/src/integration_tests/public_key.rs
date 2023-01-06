/*******************************************************************************
*   (c) 2022 Zondax AG
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
use super::prelude::*;

use constants::INS_GET_PUBLIC_KEY as INS;

fn addr_len(hrp: Option<&[u8]>, chain_id: Option<&[u8]>) -> usize {
    use crate::handlers::public_key::{AddrUI, GetPublicKey};
    use bolos::{bech32, hash::Ripemd160};

    let chain_id = chain_id.unwrap_or(GetPublicKey::DEFAULT_CHAIN_ID);
    let chain_id_len =
        match chain_alias_lookup(chain_id.try_into().expect("chain id to be 32 bytes long")) {
            Ok(alias) => alias.len(),
            //not found, so needs to be cb58 encoded
            Err(_) => AddrUI::MAX_CHAIN_CB58_LEN,
        };

    //chain id + '-' separator + bech32 address
    chain_id_len
        + 1
        + bech32::estimate_size(
            hrp.unwrap_or(GetPublicKey::DEFAULT_HRP).len(),
            Ripemd160::DIGEST_LEN,
        )
}

#[test]
fn public_key() {
    let mut flags = 0u32;
    let mut tx = 0u32;
    let rx = 5;
    let mut buffer = [0u8; 260];

    buffer[..3].copy_from_slice(&[CLA, INS, 0]);
    prepare_buffer::<4>(&mut buffer, &[44, 9000, 0, 0], Some(&[]), Some(&[]));

    let out = handle_apdu(&mut flags, &mut tx, rx, &mut buffer);
    assert_error_code!(tx, out, ApduError::Success);

    let pk_len = out[0] as usize;
    //secp256k1 pubkey and 20 bytes for hash + address + 2 for response code
    assert_eq!(tx as usize, 1 + pk_len + 20 + addr_len(None, None) + 2);
}

#[test]
fn public_key_with_hrp() {
    let mut flags = 0u32;
    let mut tx = 0u32;
    let rx = 5;
    let mut buffer = [0u8; 260];

    let hrp = b"address";

    buffer[..3].copy_from_slice(&[CLA, INS, 0]);
    prepare_buffer::<4>(&mut buffer, &[44, 9000, 0, 0], Some(hrp), Some(&[]));

    let out = handle_apdu(&mut flags, &mut tx, rx, &mut buffer);
    assert_error_code!(tx, out, ApduError::Success);

    let pk_len = out[0] as usize;
    //secp256k1 pubkey and 20 bytes for hash + address + 2 for response code
    assert_eq!(tx as usize, 1 + pk_len + 20 + addr_len(Some(hrp), None) + 2);
}

#[test]
#[should_panic = "DataInvalid"]
fn public_key_with_too_long_hrp() {
    let mut flags = 0u32;
    let mut tx = 0u32;
    let rx = 5;
    let mut buffer = [0u8; 260];

    let hrp = b"averylonghrpmaybetoolongeven";

    buffer[..3].copy_from_slice(&[CLA, INS, 0]);
    prepare_buffer::<4>(&mut buffer, &[44, 9000, 0, 0], Some(hrp), Some(&[]));

    let out = handle_apdu(&mut flags, &mut tx, rx, &mut buffer);
    assert_error_code!(tx, out, ApduError::Success);

    let pk_len = out[0] as usize;
    //secp256k1 pubkey and 20 bytes for hash + addres + 2 for response code
    assert_eq!(tx as usize, 1 + pk_len + 20 + addr_len(Some(hrp), None) + 2);
}

#[test]
fn public_key_with_long_hrp() {
    let mut flags = 0u32;
    let mut tx = 0u32;
    let rx = 5;
    let mut buffer = [0u8; 260];

    let hrp = b"exactly24characterlong!";

    buffer[..3].copy_from_slice(&[CLA, INS, 0]);
    prepare_buffer::<4>(&mut buffer, &[44, 9000, 0, 0], Some(hrp), Some(&[]));

    let out = handle_apdu(&mut flags, &mut tx, rx, &mut buffer);
    assert_error_code!(tx, out, ApduError::Success);

    let pk_len = out[0] as usize;
    //secp256k1 pubkey and 20 bytes for hash + addr + 2 for response code
    assert_eq!(tx as usize, 1 + pk_len + 20 + addr_len(Some(hrp), None) + 2);
}

#[test]
fn public_key_with_chainid() {
    let mut flags = 0u32;
    let mut tx = 0u32;
    let rx = 5;
    let mut buffer = [0u8; 260];

    let chain_id = [42u8; 32];

    buffer[..3].copy_from_slice(&[CLA, INS, 0]);
    prepare_buffer::<4>(&mut buffer, &[44, 9000, 0, 0], Some(&[]), Some(&chain_id));

    let out = handle_apdu(&mut flags, &mut tx, rx, &mut buffer);
    assert_error_code!(tx, out, ApduError::Success);

    let pk_len = out[0] as usize;
    //secp256k1 pubkey and 20 bytes for hash + addr + 2 for response code
    assert_eq!(
        tx as usize,
        1 + pk_len + 20 + addr_len(None, Some(&chain_id)) + 2
    );
}

#[test]
#[should_panic = "DataInvalid"]
fn public_key_with_bad_chainid() {
    let mut flags = 0u32;
    let mut tx = 0u32;
    let rx = 5;
    let mut buffer = [0u8; 260];

    let chain_id = [42u8; 10];

    buffer[..3].copy_from_slice(&[CLA, INS, 0]);
    prepare_buffer::<4>(&mut buffer, &[44, 9000, 0, 0], Some(&[]), Some(&chain_id));

    let out = handle_apdu(&mut flags, &mut tx, rx, &mut buffer);
    assert_error_code!(tx, out, ApduError::Success);

    let pk_len = out[0] as usize;
    //secp256k1 pubkey and 20 bytes for hash + addr + 2 for response code
    assert_eq!(
        tx as usize,
        1 + pk_len + 20 + addr_len(None, Some(&chain_id)) + 2
    );
}
