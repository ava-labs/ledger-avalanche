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

use crate::handlers::eth::EthUi;
use crate::handlers::resources::{EthAccessors, ETH_UI};
use bolos::{
    crypto::{bip32::BIP32Path, ecfp256::ECCInfo},
    hash::{Hasher, Keccak},
    pic_str, PIC,
};
use nom::number::complete::be_u32;
use zemu_sys::{Show, ViewError, Viewable};

use crate::{
    constants::{ApduError as Error, MAX_BIP32_PATH_DEPTH},
    crypto::{Curve, ECCInfoFlags},
    dispatcher::ApduHandler,
    handlers::resources::{BUFFER, PATH},
    parser::{DisplayableItem, FromBytes, ParserError, PersonalMsg},
    sys,
    utils::ApduBufferRead,
};

use super::utils::parse_bip32_eth;
use crate::utils::convert_der_to_rs;

pub struct Sign;

impl Sign {
    pub const SIGN_HASH_SIZE: usize = Keccak::<32>::DIGEST_LEN;

    fn get_derivation_info() -> Result<&'static BIP32Path<MAX_BIP32_PATH_DEPTH>, Error> {
        match unsafe { PATH.acquire(Self) } {
            Ok(Some(some)) => Ok(some),
            _ => Err(Error::ApduCodeConditionsNotSatisfied),
        }
    }

    //(actual_size, [u8; MAX_SIGNATURE_SIZE])
    #[inline(never)]
    pub fn sign<const LEN: usize>(
        path: &BIP32Path<LEN>,
        // data: &[u8],
    ) -> Result<(ECCInfoFlags, usize, [u8; 100]), Error> {
        let sk = Curve.to_secret(path);
        let buffer = unsafe { BUFFER.acquire(Self)? };

        let data = Self::digest(buffer.read_exact())?;

        let mut out = [0; 100];
        let (flags, sz) = sk
            .sign(&data, &mut out[..])
            .map_err(|_| Error::ExecutionError)?;

        Ok((flags, sz, out))
    }

    #[inline(never)]
    fn digest(buffer: &[u8]) -> Result<[u8; Self::SIGN_HASH_SIZE], Error> {
        let mut hasher = {
            let mut k = MaybeUninit::uninit();
            Keccak::<32>::new_gce(&mut k).map_err(|_| Error::Unknown)?;

            //safe: initialized
            unsafe { k.assume_init() }
        };
        // The ethereum app does not expect the "header" as part of the apdu
        // instruction as it is prepended when hashing, that is why the hw-app-eth
        // sends only the msg size and the msg itself.
        let header = pic_str!(b"\x19Ethereum Signed Message:\n"!);
        hasher.update(&header[..]).map_err(|_| Error::Unknown)?;
        hasher.update(buffer).map_err(|_| Error::Unknown)?;

        hasher.finalize().map_err(|_| Error::Unknown)
    }

    #[inline(never)]
    pub fn start_sign(txdata: &'static [u8], flags: &mut u32) -> Result<u32, Error> {
        let mut tx = MaybeUninit::uninit();
        _ = PersonalMsg::from_bytes_into(txdata, &mut tx).map_err(|_| Error::DataInvalid)?;

        // let unsigned_hash = Self::digest(txdata)?;

        let tx = unsafe { tx.assume_init() };

        let ui = SignUI {
            // hash: unsigned_hash,
            tx,
        };

        crate::show_ui!(ui.show(flags))
    }

    #[inline(never)]
    pub fn start_parse(txdata: &'static [u8]) -> Result<(), ParserError> {
        let mut tx = MaybeUninit::uninit();
        _ = PersonalMsg::from_bytes_into(txdata, &mut tx)?;

        // let unsigned_hash = Self::digest(txdata).map_err(|_| ParserError::UnexpectedError)?;

        let tx = unsafe { tx.assume_init() };

        let ui = EthUi::Msg(SignUI {
            // hash: unsigned_hash,
            tx,
        });

        unsafe {
            ETH_UI.lock(EthAccessors::Msg).replace(ui);
        }
        Ok(())
    }

    #[inline(never)]
    pub fn parse(buffer: ApduBufferRead<'_>) -> Result<bool, ParserError> {
        crate::zlog("EthSignMessage::parse\x00");

        // hw-app-eth encodes the packet type in p1
        // with 0x00 being init and 0x80 being next
        //
        // moreover, it does not prepend the ethereum header
        // for personal messages, it just structures the message as:
        // path | msg.len() as 4-bytes big-indian integer | msg

        let packet_type = buffer.p1();

        match packet_type {
            //init
            0x00 => {
                let payload = buffer
                    .payload()
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;

                //parse path to verify it's the data we expect
                let (rest, bip32_path) =
                    parse_bip32_eth(payload).map_err(|_| ParserError::InvalidPath)?;

                unsafe {
                    PATH.lock(Self).replace(bip32_path);
                }

                let (msg, len) =
                    be_u32::<_, ParserError>(rest).map_err(|_| ParserError::UnexpectedBufferEnd)?;

                //write( msg.len and msg) to the swapping buffer so we persist this data
                let buffer = unsafe { BUFFER.lock(Self) };
                buffer.reset();

                buffer
                    .write(rest)
                    .map_err(|_| ParserError::UnexpectedError)?;

                if len as usize == msg.len() {
                    // The message is completed so we can proceed with the signature
                    Self::start_parse(buffer.read_exact())?;
                    return Ok(true);
                }

                Ok(false)
            }
            //next
            0x80 => {
                let payload = buffer
                    .payload()
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;

                let buffer = unsafe { BUFFER.acquire(Self).map_err(|_| ParserError::NoData)? };

                buffer
                    .write(payload)
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;

                let (msg, len) = be_u32::<_, ParserError>(buffer.read_exact())
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;

                if msg.len() == len as usize {
                    Self::start_parse(buffer.read_exact())?;
                    return Ok(true);
                }

                Ok(false)
            }
            _ => Err(ParserError::UnexpectedData),
        }
    }
}

impl ApduHandler for Sign {
    #[inline(never)]
    fn handle(flags: &mut u32, tx: &mut u32, buffer: ApduBufferRead<'_>) -> Result<(), Error> {
        sys::zemu_log_stack("EthSignMessage::handle\x00");

        *tx = 0;

        // hw-app-eth encodes the packet type in p1
        // with 0x00 being init and 0x80 being next
        //
        // moreover, it does not prepend the ethereum header
        // for personal messages, it just structures the message as:
        // path | msg.len() as 4-bytes big-indian integer | msg

        let packet_type = buffer.p1();

        match packet_type {
            //init
            0x00 => {
                let payload = buffer.payload().map_err(|_| Error::WrongLength)?;

                //parse path to verify it's the data we expect
                let (rest, bip32_path) =
                    parse_bip32_eth(payload).map_err(|_| Error::DataInvalid)?;

                unsafe {
                    PATH.lock(Self).replace(bip32_path);
                }

                let (msg, len) = be_u32::<_, ParserError>(rest).map_err(|_| Error::WrongLength)?;

                //write( msg.len and msg) to the swapping buffer so we persist this data
                let buffer = unsafe { BUFFER.lock(Self) };
                buffer.reset();

                buffer.write(rest).map_err(|_| Error::ExecutionError)?;

                if len as usize == msg.len() {
                    // The message is completed so we can proceed with the signature
                    *tx = Self::start_sign(buffer.read_exact(), flags)?;
                }

                Ok(())
            }
            //next
            0x80 => {
                let payload = buffer.payload().map_err(|_| Error::WrongLength)?;

                let buffer = unsafe { BUFFER.acquire(Self)? };

                buffer.write(payload).map_err(|_| Error::ExecutionError)?;

                let (msg, len) = be_u32::<_, ParserError>(buffer.read_exact())
                    .map_err(|_| Error::WrongLength)?;

                if msg.len() == len as usize {
                    //we read all the missing bytes so we can proceed with the signature
                    *tx = Self::start_sign(buffer.read_exact(), flags)?;
                }

                Ok(())
            }
            _ => Err(Error::InvalidP1P2),
        }
    }
}

pub(crate) struct SignUI {
    // hash: [u8; Sign::SIGN_HASH_SIZE],
    tx: PersonalMsg<'static>,
}

impl Viewable for SignUI {
    fn num_items(&mut self) -> Result<u8, ViewError> {
        self.tx.num_items()
    }

    #[inline(never)]
    fn render_item(
        &mut self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        self.tx.render_item(item_n, title, message, page)
    }

    fn accept(&mut self, out: &mut [u8]) -> (usize, u16) {
        let path = match Sign::get_derivation_info() {
            Err(e) => return (0, e as _),
            Ok(k) => k,
        };

        // let (flags, sig_size, mut sig) = match Sign::sign(path, &self.hash[..]) {
        let (flags, sig_size, mut sig) = match Sign::sign(path) {
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
        // follow app-ethereum
        out[tx] = 27;
        if flags.contains(ECCInfo::ParityOdd) {
            out[tx] += 1;
        }

        if flags.contains(ECCInfo::XGTn) {
            out[tx] += 2;
        }

        tx += 1;

        //set to 0x30 for the conversion
        sig[0] = 0x30;
        {
            let mut r = [0; 33];
            let mut s = [0; 33];

            //write as R S (V written earlier)
            // this will write directly to buffer
            match convert_der_to_rs(&sig[..sig_size], &mut r, &mut s) {
                Ok(_) => {
                    //format R and S by only having 32 bytes each,
                    // skipping the first byte if necessary
                    // if we have less than 32 bytes we just have 0s at the start
                    // this is consistent with the fact that in `convert_der_to_rs`
                    // we put the bytes at the end of the buffer first
                    let r = &r[1..];
                    let s = &s[1..];

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
        if let Ok(path) = PATH.acquire(Sign) {
            path.take();

            //let's release the lock for the future
            let _ = PATH.release(Sign);
        }

        if let Ok(buffer) = BUFFER.acquire(Sign) {
            buffer.reset();

            //let's release the lock for the future
            let _ = BUFFER.release(Sign);
        }
    }

    //if we failed to aquire then someone else is using it anyways
    Ok(())
}
