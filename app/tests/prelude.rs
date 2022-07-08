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
#![allow(unused_imports)]

pub use rslib::{
    constants::{self, ApduError, CLA, CLA_ETH},
    crypto::{self, Curve},
    rs_handle_apdu, PacketType,
};

pub use std::convert::TryInto;

use bolos::crypto::bip32::BIP32Path;

pub fn handle_apdu(flags: &mut u32, tx: &mut u32, rx: u32, buffer: &mut [u8]) -> Vec<u8> {
    unsafe { rs_handle_apdu(flags, tx, rx, buffer.as_mut_ptr(), buffer.len() as u16) }

    //attempt to retrieve the ui output
    // if none is returned then the show UI was never invoked
    // so all the data is in the apdu buffer
    // otherwise the data is in this buffer
    match zemu_sys::get_out() {
        Some((sz, buf)) => Vec::from(&buf[..sz]),
        None => Vec::from(&buffer[..*tx as usize]),
    }
}

#[allow(dead_code)]
pub fn prepare_buffer<const LEN: usize>(
    buffer: &mut [u8; 260],
    path: &[u32],
    curve: Curve,
    hrp: Option<&[u8]>,
    chainid: Option<&[u8]>,
) -> usize {
    let crv: u8 = curve.into();
    let path = BIP32Path::<LEN>::new(path.iter().map(|n| 0x8000_0000 + n))
        .unwrap()
        .serialize();

    buffer[3] = crv;
    buffer[4] = 0;

    let mut tx = 5;

    if let Some(hrp) = hrp {
        buffer[4] += 1 + hrp.len() as u8;
        buffer[tx] = hrp.len() as u8;
        tx += 1;

        buffer[tx..tx + hrp.len()].copy_from_slice(hrp);
        tx += hrp.len();
    }

    if let Some(chainid) = chainid {
        buffer[4] += 1 + chainid.len() as u8;
        buffer[tx] = chainid.len() as u8;
        tx += 1;

        buffer[tx..tx + chainid.len()].copy_from_slice(chainid);
        tx += chainid.len();
    }

    buffer[4] += path.len() as u8;

    buffer[tx..tx + path.len()].copy_from_slice(path.as_slice());
    tx += path.len();

    5 + tx
}

#[macro_export]
macro_rules! assert_error_code {
    ($tx:expr, $buffer:ident, $expected:expr) => {
        let pos: usize = $tx as _;
        let actual: ApduError = (&$buffer[pos - 2..pos]).try_into().unwrap();
        assert_eq!(actual, $expected);
    };
}
