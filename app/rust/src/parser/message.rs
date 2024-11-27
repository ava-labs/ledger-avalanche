/*******************************************************************************
*   (c) 2018-2024 Zondax AG
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
use nom::{
    bytes::complete::{tag, take},
    number::complete::be_u32,
};
use zemu_sys::ViewError;

use crate::{
    handlers::handle_ui_message,
    parser::{error::ParserError, DisplayableItem, FromBytes},
    utils::ApduPanic,
};
use bolos::{pic_str, PIC};

// eth app truncates an ascii
// message to around this size.
const MAX_ASCII_LEN: usize = 103;

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct Message<'b>(&'b [u8]);

impl<'b> Message<'b> {
    pub fn msg(&self) -> &[u8] {
        // wont panic as this check was done when parsing
        be_u32::<_, ParserError>(self.0)
            .map(|(msg, _)| msg)
            .apdu_unwrap()
    }

    fn render_msg(&self, message: &mut [u8], page: u8) -> Result<u8, ViewError> {
        let suffix = pic_str!(b"...");
        // message plus suffix and
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

        let mut copy_len = if msg.len() > MAX_ASCII_LEN {
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

        if copy_len >= MAX_ASCII_LEN {
            copy_len += suffix.len()
        }

        handle_ui_message(&render_msg[..copy_len], message, page)
    }
}

impl<'b> FromBytes<'b> for Message<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<crate::parser::ParserError>> {
        crate::sys::zemu_log_stack("Message::from_bytes_into\x00");

        if input.is_empty() || !input.is_ascii() {
            return Err(ParserError::InvalidEthMessage.into());
        }

        let (msg, len) = be_u32(input)?;

        if msg.len() != len as usize {
            return Err(ParserError::InvalidEthMessage.into());
        }

        let (rem, msg) = take(super::U32_SIZE + len as usize)(input)?;

        let out = out.as_mut_ptr();

        unsafe {
            addr_of_mut!((*out).0).write(msg);
        }

        Ok(rem)
    }
}

impl<'b> DisplayableItem for Message<'b> {
    fn num_items(&self) -> Result<u8, ViewError> {
        Ok(1)
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        if item_n != 0 {
            return Err(ViewError::NoData);
        }
        let label = pic_str!(b"Message");
        title[..label.len()].copy_from_slice(label);
        self.render_msg(message, page)
    }
}

#[derive(Clone, Copy, PartialEq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct AvaxMessage<'b> {
    data: Message<'b>,
}

impl<'b> AvaxMessage<'b> {
    pub fn new(data: &'b [u8]) -> Result<Self, ParserError> {
        let mut this = MaybeUninit::uninit();
        let _ = Self::from_bytes_into(data, &mut this)?;
        Ok(unsafe { this.assume_init() })
    }

    pub fn msg(&self) -> &[u8] {
        self.data.msg()
    }

    /// Returns the len of the received message including the header
    pub fn msg_len(data: &'b [u8]) -> Result<u32, ParserError> {
        let mut uninit = MaybeUninit::uninit();
        let rem = Self::from_bytes_into(data, &mut uninit)?;
        Ok((data.len() - rem.len()) as u32)
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
        let out = out.as_mut_ptr();

        let msg = unsafe { &mut *addr_of_mut!((*out).data).cast() };
        let rem = Message::from_bytes_into(rem, msg)?;

        Ok(rem)
    }
}

impl<'b> DisplayableItem for AvaxMessage<'b> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // Description + message
        let items = self.data.num_items()?;
        items.checked_add(1).ok_or(ViewError::Unknown)
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
            x @ 1.. => {
                let idx = x - 1;
                self.data.render_item(idx, title, message, page)
            }
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
