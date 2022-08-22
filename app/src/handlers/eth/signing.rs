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
use arrayref::array_mut_ref;
use bolos::{
    crypto::bip32::BIP32Path,
    hash::{Hasher, Keccak},
    pic_str, PIC,
};
use zemu_sys::{Show, ViewError, Viewable};

use crate::{
    constants::{ApduError as Error, APDU_MIN_LENGTH, MAX_BIP32_PATH_DEPTH},
    crypto::Curve,
    dispatcher::ApduHandler,
    handlers::{
        handle_ui_message,
        resources::{BUFFER, PATH},
    },
    sys,
    utils::{blind_sign_toggle, hex_encode, ApduBufferRead, ApduPanic, Uploader},
};

use super::utils::{convert_der_to_rs, parse_bip32_eth};

pub struct BlindSign;

impl BlindSign {
    pub const SIGN_HASH_SIZE: usize = Keccak::<32>::DIGEST_LEN;

    fn get_derivation_info() -> Result<&'static (BIP32Path<MAX_BIP32_PATH_DEPTH>, Curve), Error> {
        match unsafe { PATH.acquire(Self) } {
            Ok(Some(some)) => Ok(some),
            _ => Err(Error::ApduCodeConditionsNotSatisfied),
        }
    }

    //(actual_size, [u8; MAX_SIGNATURE_SIZE])
    #[inline(never)]
    pub fn sign<const LEN: usize>(
        curve: Curve,
        path: &BIP32Path<LEN>,
        data: &[u8],
    ) -> Result<(usize, [u8; 100]), Error> {
        let sk = curve.to_secret(path);

        let mut out = [0; 100];
        let sz = sk
            .sign(data, &mut out[..])
            .map_err(|_| Error::ExecutionError)?;

        Ok((sz, out))
    }

    #[inline(never)]
    fn digest(buffer: &[u8]) -> Result<[u8; Self::SIGN_HASH_SIZE], Error> {
        Keccak::<32>::digest(buffer).map_err(|_| Error::ExecutionError)
    }

    #[inline(never)]
    pub fn start_sign(txdata: &'static [u8], flags: &mut u32) -> Result<u32, Error> {
        let unsigned_hash = Self::digest(txdata)?;

        let ui = SignUI {
            hash: unsigned_hash,
        };

        crate::show_ui!(ui.show(flags))
    }

    /// Return the number of bytes of the ethereum tx
    ///
    /// Note: the tx version is expected
    ///
    /// Returns the number of bytes read and the number of bytes to read
    fn get_tx_rlp_len(mut data: &[u8]) -> Result<(usize, u64), Error> {
        const U64_SIZE: usize = core::mem::size_of::<u64>();

        let mut read = 0;

        //skip version if present/recognized
        // otherwise tx is probably legacy so no version, just rlp data
        let version = *data.get(0).ok_or(Error::DataInvalid)?;
        match version {
            0x01 | 0x02 => {
                data = data.get(1..).ok_or(Error::DataInvalid)?;
                read += 1;
            }
            _ => {}
        }

        let marker = *data.get(0).ok_or(Error::DataInvalid)?;

        match marker {
            _num @ 0..=0x7F => Ok((read + 1, 0)),
            sstring @ 0x80..=0xB7 => Ok((read + 1, sstring as u64 - 0x7F)),
            string @ 0xB8..=0xBF => {
                // For strings longer than 55 bytes the length is encoded
                // differently.
                // The number of bytes that compose the length is encoded
                // in the marker
                // And then the length is just the number BE encoded
                let num_bytes = string as usize - 0xB7;
                let num = data
                    .get(1..)
                    .ok_or(Error::DataInvalid)?
                    .get(..num_bytes)
                    .ok_or(Error::DataInvalid)?;

                let mut array = [0; U64_SIZE];
                array[U64_SIZE - num_bytes..].copy_from_slice(num);

                let num = u64::from_be_bytes(array);
                Ok((read + 1 + num_bytes, num))
            }
            slist @ 0xC0..=0xF7 => Ok((read + 1, slist as u64 - 0xBF)),
            list @ 0xF8.. => {
                // For lists longer than 55 bytes the length is encoded
                // differently.
                // The number of bytes that compose the length is encoded
                // in the marker
                // And then the length is just the number BE encoded

                let num_bytes = list as usize - 0xF7;
                let num = data
                    .get(1..)
                    .ok_or(Error::DataInvalid)?
                    .get(..num_bytes)
                    .ok_or(Error::DataInvalid)?;

                let mut array = [0; U64_SIZE];
                array[U64_SIZE - num_bytes..].copy_from_slice(num);

                let num = u64::from_be_bytes(array);
                Ok((read + 1 + num_bytes, num))
            }
        }
    }
}

impl ApduHandler for BlindSign {
    #[inline(never)]
    fn handle<'apdu>(
        flags: &mut u32,
        tx: &mut u32,
        buffer: ApduBufferRead<'apdu>,
    ) -> Result<(), Error> {
        sys::zemu_log_stack("EthSign::handle\x00");

        *tx = 0;

        //blind signing not enabled
        if !blind_sign_toggle::blind_sign_enabled() {
            return Err(Error::ApduCodeConditionsNotSatisfied);
        }

        // hw-app-eth encodes the packet type in p1
        // with 0x00 being init and 0x80 being next
        //
        // the end of the transmission is implicit based on the received data
        // an eth transaction is RLP encoded (https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/#definition)
        // with the first byte being the version (0x01 EIP2930 or 0x02 EIP1559 or legacy if neither/missing)
        // and then a RLP list
        //
        // therefore, the data received self-describes how many bytes the app can expect and
        // when all data has been received

        let packet_type = buffer.p1();

        match packet_type {
            //init
            0x00 => {
                //we can't use .payload here since it's not prefixed with the length
                // of the payload
                let apdu_buffer = buffer.write();
                let payload = &apdu_buffer
                    .get(APDU_MIN_LENGTH as usize..)
                    .ok_or(Error::DataInvalid)?;

                //parse path to verify it's the data we expect
                let (rest, bip32_path) =
                    parse_bip32_eth(payload).map_err(|_| Error::DataInvalid)?;

                unsafe {
                    PATH.lock(Self)?.replace((bip32_path, Curve::Secp256K1));
                }

                //parse the length of the RLP message
                let (read, to_read) = Self::get_tx_rlp_len(rest)?;

                let len = core::cmp::min(to_read as usize + read, rest.len());

                //write the rest to the swapping buffer so we persist this data
                let buffer = unsafe { BUFFER.lock(Self)? };
                buffer.reset();

                buffer
                    .write(&rest[..len])
                    .map_err(|_| Error::ExecutionError)?;

                //if the number of bytes read and the number of bytes to read
                // is the same as what we read...
                if to_read as usize + read - len == 0 {
                    //then we actually had all bytes in this tx!
                    // we should sign directly
                    *tx = Self::start_sign(buffer.read_exact(), flags)?;
                }

                Ok(())
            }
            //next
            0x80 => {
                //we can't use .payload here since it's not prefixed with the length
                // of the payload
                let apdu_buffer = buffer.write();
                let payload = &apdu_buffer
                    .get(APDU_MIN_LENGTH as usize..)
                    .ok_or(Error::DataInvalid)?;

                let buffer = unsafe { BUFFER.acquire(Self)? };

                //we could unwrap here as this data should be guaranteed correct
                // we read back what we wrote to see how many bytes we expect
                // to have to collect
                let (read, to_read) = Self::get_tx_rlp_len(buffer.read_exact())?;

                // let's ignore the little header at the start
                let rlp_read = buffer.read_exact().len() - read;

                //either the entire buffer of the remaining bytes we expect
                let missing = to_read as usize - rlp_read;
                let len = core::cmp::min(missing, payload.len());

                buffer
                    .write(&payload[..len])
                    .map_err(|_| Error::ExecutionError)?;

                if missing - len == 0 {
                    //we read all the missing bytes so we can proceed with the signature
                    // nwo
                    *tx = Self::start_sign(buffer.read_exact(), flags)?;
                }

                Ok(())
            }
            _ => Err(Error::InvalidP1P2),
        }
    }
}

pub(crate) struct SignUI {
    hash: [u8; BlindSign::SIGN_HASH_SIZE],
}

impl Viewable for SignUI {
    fn num_items(&mut self) -> Result<u8, ViewError> {
        Ok(1)
    }

    #[inline(never)]
    fn render_item(
        &mut self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        match item_n {
            0 => {
                let title_content = pic_str!(b"Ethereum Sign");
                title[..title_content.len()].copy_from_slice(title_content);

                let mut hex_buf = [0; BlindSign::SIGN_HASH_SIZE * 2];
                //this is impossible that will error since the sizes are all checked
                let len = hex_encode(&self.hash[..], &mut hex_buf).apdu_unwrap();

                handle_ui_message(&hex_buf[..len], message, page)
            }
            _ => Err(ViewError::NoData),
        }
    }

    fn accept(&mut self, out: &mut [u8]) -> (usize, u16) {
        let (path, curve) = match BlindSign::get_derivation_info() {
            Err(e) => return (0, e as _),
            Ok(k) => k,
        };

        let (sig_size, mut sig) = match BlindSign::sign(*curve, path, &self.hash[..]) {
            Err(e) => return (0, e as _),
            Ok(k) => k,
        };

        //reset globals to avoid skipping `Init`
        if let Err(e) = cleanup_globals() {
            return (0, e as _);
        }

        let mut tx = 0;

        //write signature as VRS
        //write V, which is the LSB of the firsts byte
        out[tx] = sig[0] & 0x01;
        tx += 1;

        //reset to 0x30 for the conversion
        sig[0] = 0x30;
        {
            let mut r = [0; 33];
            let mut s = [0; 33];

            //write as R S (V written earlier)
            // this will write directly to buffer
            match convert_der_to_rs(&sig[..sig_size], &mut r, &mut s) {
                Ok((written_r, written_s)) => {
                    //format R and S by only having 32 bytes each,
                    // skipping the first byte if necessary
                    let r = if written_r == 33 { &r[1..] } else { &r[..32] };
                    let s = if written_s == 33 { &s[1..] } else { &s[..32] };

                    out[tx..][..32].copy_from_slice(r);
                    tx += 32;

                    out[tx..][..32].copy_from_slice(s);
                    tx += 32;
                }
                Err(_) => return (0, Error::ExecutionError as _),
            }
        }

        (tx, Error::Success as _)
    }

    fn reject(&mut self, _: &mut [u8]) -> (usize, u16) {
        let _ = cleanup_globals();
        (0, Error::CommandNotAllowed as _)
    }
}

fn cleanup_globals() -> Result<(), Error> {
    unsafe {
        if let Ok(path) = PATH.acquire(BlindSign) {
            path.take();

            //let's release the lock for the future
            let _ = PATH.release(BlindSign);
        }

        if let Ok(buffer) = BUFFER.acquire(BlindSign) {
            buffer.reset();

            //let's release the lock for the future
            let _ = BUFFER.release(BlindSign);
        }
    }

    //if we failed to aquire then someone else is using it anyways
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rlp_decoder() {
        let data = hex::decode("02f878018402a8af41843b9aca00850d8c7b50e68303d090944a2962ac08962819a8a17661970e3c0db765565e8817addd0864728ae780c080a01e514f7fc78197c66589083cc8fd06376bae627a4080f5fb58d52d90c0df340da049b048717f215e622c93722ff5b1e38e1d1a4ab9e26a39183969a34a5f8dea75").unwrap();

        let (read, to_read) =
            BlindSign::get_tx_rlp_len(&data).expect("unable to minimally parse tx data");

        assert_eq!(read, 3);
        assert_eq!(to_read, 0x78);
    }
}
