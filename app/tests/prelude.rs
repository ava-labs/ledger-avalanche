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

use rslib::constants::{
    APDU_INDEX_CLA, APDU_INDEX_INS, APDU_INDEX_LEN, APDU_INDEX_P1, APDU_INDEX_P2,
};
pub use rslib::{
    constants::{self, ApduError, CLA, CLA_ETH},
    crypto, rs_handle_apdu, PacketType,
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

/// Split message in chunks ready to send to the handler
pub fn chunk(ins: u8, p2: u8, init_data: &[u8], msg: &[u8]) -> Vec<[u8; 260]> {
    let mut buffer = [0; 260];
    buffer[APDU_INDEX_CLA] = CLA;
    buffer[APDU_INDEX_INS] = ins;
    buffer[APDU_INDEX_P2] = p2;
    let buffer = buffer; //make immutable

    let mut first_buffer = buffer;
    first_buffer[APDU_INDEX_P1] = PacketType::Init as u8;

    first_buffer[APDU_INDEX_LEN] = init_data.len() as u8;
    first_buffer[APDU_INDEX_LEN + 1..][..init_data.len()].copy_from_slice(init_data);
    let first_buffer = first_buffer; //make immutable

    //split message in chunks of 255
    let chunks_iter = msg.chunks(255).map(|data| {
        let mut buf = buffer;
        buf[APDU_INDEX_P1] = PacketType::Add as u8;
        buf[APDU_INDEX_LEN] = data.len() as u8;
        buf[APDU_INDEX_LEN + 1..][..data.len()].copy_from_slice(data);

        buf
    });

    let mut chunks = Vec::with_capacity(1 + chunks_iter.len());
    chunks.push(first_buffer);
    chunks.extend(chunks_iter);

    //set last message to Last
    chunks.last_mut().unwrap()[APDU_INDEX_P1] = PacketType::Last as u8;

    chunks
}

#[allow(dead_code)]
pub fn prepare_buffer<const LEN: usize>(
    buffer: &mut [u8; 260],
    path: &[u32],
    hrp: Option<&[u8]>,
    chainid: Option<&[u8]>,
) -> usize {
    let path = BIP32Path::<LEN>::new(path.iter().map(|n| 0x8000_0000 + n))
        .unwrap()
        .serialize();

    buffer[3] = 0;
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
