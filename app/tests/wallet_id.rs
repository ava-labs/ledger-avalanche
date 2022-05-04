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
use prelude::*;

use constants::{INS_GET_WALLET_ID as INS, WALLET_ID_LEN};

#[test]
fn wallet_id() {
    let mut flags = 0u32;
    let mut tx = 0u32;
    let rx = 5;
    let mut buffer = [0u8; 260];

    buffer[..5].copy_from_slice(&[CLA, INS, 0, Curve::Secp256K1.into(), 0]);

    handle_apdu(&mut flags, &mut tx, rx, &mut buffer);

    assert_error_code!(tx, buffer, ApduError::Success);

    //secp256k1 pubkey and 20 bytes for hash + 2 for response code
    assert_eq!(tx as usize, WALLET_ID_LEN + 2);
}
