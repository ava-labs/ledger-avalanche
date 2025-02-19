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
    zlog,
};
use bolos::{pic_str, PIC};

use super::MSG_MAX_CHUNK_LEN;

const HEX_REPR_LEN: usize = 4;

#[inline(never)]
fn u8_to_hex_array(value: u8) -> [u8; 4] {
    let mut result = *b"\\x00";

    let high_nibble = value >> 4;
    let low_nibble = value & 0x0F;

    result[2] = match high_nibble {
        0..=9 => b'0' + high_nibble,
        10..=15 => b'a' + (high_nibble - 10),
        _ => unreachable!(),
    };

    result[3] = match low_nibble {
        0..=9 => b'0' + low_nibble,
        10..=15 => b'a' + (low_nibble - 10),
        _ => unreachable!(),
    };

    result
}

#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct Message<'b> {
    data: &'b [u8],
    chunk_count: u8,
}

impl<'b> Message<'b> {
    pub fn msg(&self) -> &[u8] {
        // wont panic as this check was done when parsing
        be_u32::<_, ParserError>(self.data)
            .map(|(msg, _)| msg)
            .apdu_unwrap()
    }

    fn get_chunk(&self, chunk_idx: usize, chunk: &mut [u8]) -> usize {
        if chunk.len() < MSG_MAX_CHUNK_LEN {
            return 0;
        }
        let msg = self.msg();
        let mut chunk_len = 0;

        // Calculate starting point for reading
        let mut cumulative_chunk_len = 0;
        let mut start_byte = 0;

        for _ in 0..chunk_idx {
            while cumulative_chunk_len < MSG_MAX_CHUNK_LEN && start_byte < msg.len() {
                let byte = msg[start_byte];
                cumulative_chunk_len += if byte.is_ascii() { 1 } else { HEX_REPR_LEN };
                start_byte += 1;
            }
            cumulative_chunk_len = 0;
        }

        // We must do the same as app-ethereum where, It has an auxiliary buffer where
        // data to be rendered is copied, this data is "modified" from the original
        // as follows:
        // 1. process the message character per character
        // 2. Printable ascii characters are displayed as it is.
        // 3. Whitespace characters are displayed as they are
        // 4. non printable ascii characters are displayed as hex codes: \x00
        // for example for the null character
        //
        // so we are going to do this for every current chunk of data
        // and for either eth PersonalMessage eip-191 or avax personal messages
        for &byte in msg.iter().skip(start_byte) {
            let bytes_to_add = if byte.is_ascii_whitespace() {
                chunk[chunk_len] = b' ';
                1
            } else if byte.is_ascii() {
                chunk[chunk_len] = byte;
                1
            } else {
                // check if current chunk has space for this hex character
                // which requires 4-bytes
                let hex = u8_to_hex_array(byte);
                if chunk_len + HEX_REPR_LEN > MSG_MAX_CHUNK_LEN {
                    break;
                }
                chunk[chunk_len..chunk_len + HEX_REPR_LEN].copy_from_slice(&hex);
                HEX_REPR_LEN
            };

            chunk_len += bytes_to_add;

            if chunk_len >= MSG_MAX_CHUNK_LEN {
                break;
            }
        }

        chunk_len
    }

    fn render_msg(&self, message: &mut [u8], item_n: u8, page: u8) -> Result<u8, ViewError> {
        let mut chunk = [0u8; MSG_MAX_CHUNK_LEN];
        let len = self.get_chunk(item_n as usize, &mut chunk);

        handle_ui_message(&chunk[..len], message, page)
    }

    pub fn is_ascii(&self) -> bool {
        self.data.iter().all(|c| c.is_ascii())
    }

    fn calculate_chunk_count(msg: &[u8]) -> u8 {
        let mut total_len = 0;
        for &byte in msg {
            total_len += if byte.is_ascii() { 1 } else { HEX_REPR_LEN };
        }
        ((total_len + MSG_MAX_CHUNK_LEN - 1) / MSG_MAX_CHUNK_LEN).min(255) as u8
    }
}

impl<'b> FromBytes<'b> for Message<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<crate::parser::ParserError>> {
        zlog("Message::from_bytes_into\x00");

        if input.is_empty() {
            return Err(ParserError::InvalidEthMessage.into());
        }

        let (msg, len) = be_u32(input)?;

        if msg.len() != len as usize {
            return Err(ParserError::InvalidEthMessage.into());
        }

        let (rem, msg) = take(super::U32_SIZE + len as usize)(input)?;

        let out = out.as_mut_ptr();
        // omit the first 4-bytes which are use for the len
        let chunk_count = Self::calculate_chunk_count(&msg[4..]);

        unsafe {
            addr_of_mut!((*out).data).write(msg);
            addr_of_mut!((*out).chunk_count).write(chunk_count);
        }

        Ok(rem)
    }
}

impl<'b> DisplayableItem for Message<'b> {
    fn num_items(&self) -> Result<u8, ViewError> {
        Ok(self.chunk_count)
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        zlog("Message::render_item\x00");
        let label = pic_str!(b"Message");
        title[..label.len()].copy_from_slice(label);
        self.render_msg(message, item_n, page)
    }
}

#[derive(Clone, PartialEq)]
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

#[cfg(test)]
mod tests_message_render {
    use std::vec;

    use super::*;
    use std::vec::Vec;

    fn create_message(content: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + content.len());
        data.extend_from_slice(&(content.len() as u32).to_be_bytes());
        data.extend_from_slice(content);
        data
    }

    fn msg_test1(chunk: &mut [u8]) {
        // Test Vector 1: Fits in two items exactly
        let msg1 = create_message(&[b'A'; 200]);
        let msg1 = Message::from_bytes(msg1.as_slice()).unwrap().1;
        // We expect three chunks
        assert_eq!(msg1.num_items().unwrap(), 2);

        let len1 = msg1.get_chunk(0, chunk);
        assert_eq!(len1, MSG_MAX_CHUNK_LEN);
        assert_eq!(&chunk[..len1], &[b'A'; MSG_MAX_CHUNK_LEN]);

        let len2 = msg1.get_chunk(1, chunk);
        assert_eq!(len2, MSG_MAX_CHUNK_LEN);
        assert_eq!(&chunk[..len2], &[b'A'; MSG_MAX_CHUNK_LEN]);
    }

    fn msg_test2(chunk: &mut [u8]) {
        // Test Vector 2: Uses 3 items, last one half full
        let msg2 = create_message(&[b'B'; 250]);
        let msg2 = Message::from_bytes(msg2.as_slice()).unwrap().1;
        assert_eq!(msg2.num_items().unwrap(), 3);

        let len1 = msg2.get_chunk(0, chunk);
        assert_eq!(len1, MSG_MAX_CHUNK_LEN);
        assert_eq!(&chunk[..len1], &[b'B'; MSG_MAX_CHUNK_LEN]);

        let len2 = msg2.get_chunk(1, chunk);
        assert_eq!(len2, MSG_MAX_CHUNK_LEN);
        assert_eq!(&chunk[..len2], &[b'B'; MSG_MAX_CHUNK_LEN]);

        let len3 = msg2.get_chunk(2, chunk);
        assert_eq!(len3, 50);
        assert_eq!(&chunk[..len3], &[b'B'; 50]);
    }

    fn msg_test3(chunk: &mut [u8]) {
        // Test Vector 3: Non-ASCII characters in the middle
        let mut msg3_content = vec![b'C'; 180];
        msg3_content.extend_from_slice(&[0x80, 0x81, 0x82, 0x83, 0x84]); // 5 non-ASCII chars
        msg3_content.extend_from_slice(&[b'D'; 15]);
        std::println!("msg3_content: {}", msg3_content.len());
        let msg3 = create_message(&msg3_content);
        std::println!("vec_len: {}", msg3.len());
        let msg3 = Message::from_bytes(msg3.as_slice()).unwrap().1;
        assert_eq!(msg3.num_items().unwrap(), 3);

        let len1 = msg3.get_chunk(0, chunk);
        assert_eq!(len1, MSG_MAX_CHUNK_LEN);
        assert_eq!(&chunk[..len1], &[b'C'; MSG_MAX_CHUNK_LEN]);

        let len2 = msg3.get_chunk(1, chunk);
        assert_eq!(len2, MSG_MAX_CHUNK_LEN);
        assert_eq!(&chunk[..80], &[b'C'; 80]);
        assert_eq!(&chunk[80..84], b"\\x80");
        assert_eq!(&chunk[84..88], b"\\x81");
        assert_eq!(&chunk[88..92], b"\\x82");
        assert_eq!(&chunk[92..96], b"\\x83");
        assert_eq!(&chunk[96..100], b"\\x84");

        let len3 = msg3.get_chunk(2, chunk);
        assert_eq!(len3, 15);
        assert_eq!(&chunk[..len3], &[b'D'; 15]);
    }

    fn msg_test4(chunk: &mut [u8]) {
        // Create a complex message with 236 bytes
        let mut msg_content = Vec::with_capacity(236);
        msg_content.extend_from_slice(b"Hello, ");
        msg_content.push(0x80); // non-ASCII
        msg_content.extend_from_slice(b"World! ");
        msg_content.push(0x81); // non-ASCII
        msg_content.extend_from_slice(b"This is a ");
        msg_content.push(0x82); // non-ASCII
        msg_content.extend_from_slice(b"complex ");
        msg_content.push(0x83); // non-ASCII
        msg_content.extend_from_slice(b"test ");
        msg_content.push(0x84); // non-ASCII
        msg_content.extend_from_slice(b"vector with ");
        msg_content.extend_from_slice(&[0x85, 0x86, 0x87]); // 3 non-ASCII
        msg_content.extend_from_slice(b" multiple non-ASCII ");
        msg_content.extend_from_slice(&[0x88, 0x89]); // 2 non-ASCII
        msg_content.extend_from_slice(b" characters ");
        msg_content.push(0x8A); // non-ASCII
        msg_content.extend_from_slice(b"scattered ");
        msg_content.push(0x8B); // non-ASCII
        msg_content.extend_from_slice(b"throughout. ");
        msg_content.extend_from_slice(&[0x8C, 0x8D, 0x8E, 0x8F]); // 4 non-ASCII
        msg_content.extend_from_slice(b"It should ");
        msg_content.push(0x90); // non-ASCII
        msg_content.extend_from_slice(b"properly ");
        msg_content.push(0x91); // non-ASCII
        msg_content.extend_from_slice(b"chunk ");
        msg_content.push(0x92); // non-ASCII
        msg_content.extend_from_slice(b"and format.");

        assert_eq!(msg_content.len(), 158);

        let msg = create_message(&msg_content);
        let msg = Message::from_bytes(msg.as_slice()).unwrap().1;

        // We expect 4 chunks due to the expansion of non-ASCII characters
        assert_eq!(msg.num_items().unwrap(), 3);

        // Check each chunk
        for i in 0..3 {
            let len = msg.get_chunk(i, chunk);
            let chunk_str = std::str::from_utf8(&chunk[..len]).unwrap();
            std::println!("Chunk {}: '{}'\nLength: {}", i + 1, chunk_str, len);

            // Verify that each chunk is not longer than MSG_MAX_CHUNK_LEN
            assert!(len <= MSG_MAX_CHUNK_LEN);

            // Verify that non-ASCII characters are properly formatted
            for j in 0..len {
                if chunk[j] == b'\\' && j + 3 < len {
                    assert_eq!(&chunk[j..j + 2], b"\\x");
                    assert!(chunk[j + 2].is_ascii_hexdigit());
                    assert!(chunk[j + 3].is_ascii_hexdigit());
                }
            }
        }

        // Verify the content of the last chunk
        let last_chunk_len = msg.get_chunk(1, chunk);
        assert!(std::str::from_utf8(&chunk[..last_chunk_len])
            .unwrap()
            .ends_with("91chunk "));

        let last_chunk_len = msg.get_chunk(2, chunk);
        assert!(std::str::from_utf8(&chunk[..last_chunk_len])
            .unwrap()
            .ends_with("and format."));
    }

    fn msg_test5(chunk: &mut [u8]) {
        // Test Vector 1: Fits in two items exactly
        let msg = b"Hello World";
        let msg1 = create_message(msg.as_ref());
        let msg1 = Message::from_bytes(msg1.as_slice()).unwrap().1;
        // We expect three chunks
        assert_eq!(msg1.num_items().unwrap(), 1);
        assert_eq!(msg1.chunk_count, 1);

        let len1 = msg1.get_chunk(0, chunk);
        assert_eq!(len1, msg.len());
        assert_eq!(&chunk[..len1], msg.as_ref());
    }

    #[test]
    fn test_message_chunking() {
        let mut chunk = [0u8; MSG_MAX_CHUNK_LEN + 1];

        msg_test1(&mut chunk);
        msg_test2(&mut chunk);
        msg_test3(&mut chunk);
        msg_test4(&mut chunk);
        msg_test5(&mut chunk);
    }
}
