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

use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::{bytes::complete::tag, number::complete::be_u32};
use zemu_sys::ViewError;

use crate::{
    handlers::handle_ui_message,
    parser::{error::ParserError, DisplayableItem, FromBytes},
};
use bolos::{pic_str, PIC};

// eth app truncates an ascii
// message to around this size.
const MAX_ASCII_LEN: usize = 103;

#[derive(Clone, Copy, PartialEq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct AvaxMessage<'b> {
    data: &'b [u8],
    msg_at: usize,
}
impl<'b> AvaxMessage<'b> {
    pub fn new(data: &'b [u8]) -> Result<Self, ParserError> {
        let mut this = MaybeUninit::uninit();
        let _ = Self::from_bytes_into(data, &mut this)?;
        Ok(unsafe { this.assume_init() })
    }

    pub fn msg(&self) -> &'b [u8] {
        &self.data[self.msg_at..]
    }

    fn render_msg(&self, message: &mut [u8], page: u8) -> Result<u8, ViewError> {
        let suffix = pic_str!(b"...");
        let mut render_msg = [0u8; MAX_ASCII_LEN + 4]; // plus suffix
        let msg = self.msg();

        // look for special characters [\b..=\r]
        // which the eth app maps to a space b' '
        let msg_iter = msg.iter().map(|c| {
            if (*c >= 0x08) && (*c <= b'\r') {
                b' '
            } else {
                *c
            }
        });

        let copy_len = if msg.len() > MAX_ASCII_LEN {
            render_msg[MAX_ASCII_LEN..].copy_from_slice(&suffix[..]);
            MAX_ASCII_LEN
        } else {
            msg.len()
        };

        render_msg
            .iter_mut()
            .take(copy_len)
            .zip(msg_iter)
            .for_each(|(r, m)| *r = m);

        handle_ui_message(&render_msg[..], message, page)
    }
}

impl<'b> FromBytes<'b> for AvaxMessage<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        // Avax message structure: Header + 4-byte msg_len + msg
        // according to:
        // https://docs.avax.network/community/tutorials-contest/2021/red-dev-sig-verify-tutorial#1-hash-the-message
        let header = pic_str!(b"\x1AAvalanche Signed Message:\n"!);

        let (rem, _) = tag(header)(input)?;

        // read message len
        let (rem, msg_len) = be_u32(rem)?;

        if rem.len() != msg_len as usize {
            return Err(ParserError::InvalidAvaxMessage.into());
        }

        if !rem.is_ascii() {
            return Err(ParserError::InvalidAvaxMessage.into());
        }

        let at = input.len() - rem.len();

        //good ptr and no uninit reads
        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).data).write(input);
            addr_of_mut!((*out).msg_at).write(at);
        }

        Ok(input)
    }
}

impl<'b> DisplayableItem for AvaxMessage<'b> {
    fn num_items(&self) -> usize {
        // Description + message
        1 + 1
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        match item_n {
            0 => {
                let label = pic_str!(b"Sign");
                title[..label.len()].copy_from_slice(label);
                let content = pic_str!("Avax Message");
                handle_ui_message(content.as_bytes(), message, page)
            }
            1 => {
                let label = pic_str!(b"Message");
                title[..label.len()].copy_from_slice(label);
                self.render_msg(message, page)
            }

            _ => Err(ViewError::NoData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &str = "An AvalancheMessage to sign";
    const HEADER: &str = "\x1AAvalanche Signed Message:\n";

    fn construct_msg(msg: &str) -> std::vec::Vec<u8> {
        let mut vec = std::vec![];
        let msg_len = (DATA.len() as u32).to_be_bytes();
        vec.extend_from_slice(HEADER.as_bytes());
        vec.extend_from_slice(&msg_len[..]);
        vec.extend_from_slice(msg.as_bytes());
        vec
    }

    #[test]
    fn parse_avax_msg() {
        let msg = construct_msg(DATA);
        let (_, tx) = AvaxMessage::from_bytes(&msg).unwrap();
        let m = std::str::from_utf8(tx.msg()).unwrap();
        assert_eq!(m, DATA);
    }
}
