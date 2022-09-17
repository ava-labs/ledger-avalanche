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
mod prelude;
use bolos::hash::{Hasher, Keccak};
use prelude::*;

use constants::INS_ETH_GET_PUBLIC_KEY as INS;

#[test]
fn eth_public_key() {
    let mut flags = 0u32;
    let mut tx = 0u32;
    let rx = 5;
    let mut buffer = [0u8; 260];

    buffer[..3].copy_from_slice(&[CLA_ETH, INS, 0]);
    prepare_buffer::<4>(&mut buffer, &[44, 60, 0, 0], None, None);
    buffer[3] = 0;

    let out = handle_apdu(&mut flags, &mut tx, rx, &mut buffer);
    assert_error_code!(tx, out, ApduError::Success);

    let pk_len = out[0] as usize;
    let pk = &out[1..][..pk_len];
    let pk_hash = Keccak::<32>::digest(&pk[1..]).expect("unable to hash pk");

    let addr_len = out[1 + pk_len] as usize;
    assert_eq!(addr_len, 40);

    let addr = &out[1 + pk_len + 1..][..addr_len];

    let addr_decoded = hex::decode(addr).expect("addr not hex");

    //secp256k1 pubkey and hex encoded addr + 2 for response code
    assert_eq!(tx as usize, 1 + pk_len + 1 + addr_len + 2);
    assert_eq!(&pk_hash[32 - 20..], addr_decoded.as_slice());
}
