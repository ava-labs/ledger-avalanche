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
use std::convert::TryFrom;

use k256::ecdsa::{self, recoverable, signature::Verifier};
use prelude::*;

use bolos::crypto::bip32::BIP32Path;
#[cfg(feature = "blind-sign")]
use constants::INS_ETH_BLIND_SIGN as INS;

const MSG_HEX: &str = "02f878018402a8af41843b9aca00850d8c7b50e68303d090944a2962ac08962819a8a17661970e3c0db765565e8817addd0864728ae780c080a01e514f7fc78197c66589083cc8fd06376bae627a4080f5fb58d52d90c0df340da049b048717f215e622c93722ff5b1e38e1d1a4ab9e26a39183969a34a5f8dea75";

#[cfg(feature = "blind-sign")]
#[test]
fn eth_sign() {
    let mut flags = 0;
    let mut tx = 0;
    let mut buffer = [0; 260];

    let data = hex::decode(MSG_HEX).unwrap();
    let path = BIP32Path::<4>::new([44, 60, 0, 0].iter().map(|n| 0x8000_0000 + n))
        .unwrap()
        .serialize();

    buffer[0] = CLA_ETH;
    buffer[1] = INS;
    buffer[2] = 0x00;
    buffer[3] = 0x00;
    buffer[4] = path.len() as u8;
    buffer[5..][..path.len()].copy_from_slice(&path);
    buffer[5 + path.len()..][..data.len()].copy_from_slice(&data);

    let out = handle_apdu(
        &mut flags,
        &mut tx,
        4 + path.len() as u32 + data.len() as u32,
        &mut buffer,
    );
    println!("{}:{}", tx, hex::encode(&out));
    assert_error_code!(tx, out, ApduError::Success);

    let sig = ecdsa::Signature::try_from(&out[1..][..64]).expect("signature was not RS encoded");
    let sig = recoverable::Signature::new(
        &sig,
        recoverable::Id::new(out[0] & 0x01).expect("invalid V"),
    )
    .expect("not a recoverable signature");

    let key = sig
        .recover_verify_key(&data)
        .expect("unable to retrieve verifying key");
    assert!(key.verify(&data, &sig).is_ok())
}
