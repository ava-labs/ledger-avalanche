/*******************************************************************************
*   (c) 2022 Zondax AG
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

use crate::{
    checked_add,
    handlers::handle_ui_message,
    parser::{DisplayableItem, FromBytes, Message},
    zlog,
};
use bolos::{pic_str, PIC};
use zemu_sys::ViewError;

const MAX_ETH_MESSAGE_SIZE: usize = 100;

#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct PersonalMsg<'b>(Message<'b>);

impl PersonalMsg<'_> {
    pub fn msg(&self) -> &[u8] {
        self.0.msg()
    }
}

impl<'b> FromBytes<'b> for PersonalMsg<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<crate::parser::ParserError>> {
        zlog("PersonalMessage::from_bytes_into\x00");
        // read message len
        let out = out.as_mut_ptr();

        let msg = unsafe { &mut *addr_of_mut!((*out).0).cast() };
        let rem = Message::from_bytes_into(input, msg)?;

        Ok(rem)
    }
}

impl DisplayableItem for PersonalMsg<'_> {
    fn num_items(&self) -> Result<u8, ViewError> {
        checked_add!(ViewError::Unknown, 1u8, self.0.num_items()?)
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        if item_n == 0 {
            let label = pic_str!(b"Sign");
            title[..label.len()].copy_from_slice(label);
            let content = pic_str!("PersonalMessage");
            handle_ui_message(content.as_bytes(), message, page)
        } else {
            let idx = item_n - 1;
            self.0.render_item(idx, title, message, page)
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn parse_eth_msg() {
        let msg = "hello_world";
        let msg_len = (msg.len() as u32).to_be_bytes();

        let mut data = std::vec![];
        data.extend_from_slice(&msg_len);
        data.extend_from_slice(msg.as_bytes());

        let tx = PersonalMsg::from_bytes(&data).unwrap().1;

        assert_eq!(tx.msg(), msg.as_bytes());
    }
}
