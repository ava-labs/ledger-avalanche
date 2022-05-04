use nom::{bytes::complete::take, error::ErrorKind, IResult};

use crate::handlers::parser_common::ParserError;

pub const ADDRESS_LEN: usize = 20;

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct Address<'b>(&'b [u8; ADDRESS_LEN]);

impl<'b> Address<'b> {
    #[inline(never)]
    pub fn from_bytes(input: &'b [u8]) -> IResult<&[u8], Self, ParserError> {
        let (left, addr) = take(ADDRESS_LEN)(input)?;
        let addr = arrayref::array_ref!(addr, 0, ADDRESS_LEN);
        Ok((left, Self(addr)))
    }
}
