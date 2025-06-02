use crate::parser::{AddressedCallPayload, FromBytes, ParserError};
use core::mem::MaybeUninit;
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u32},
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct AddressedCall<'b> {
    pub source_address_size: u32,
    pub source_address: &'b [u8],
    pub message_type: u32,
    pub payload: AddressedCallPayload<'b>,
}

impl<'b> FromBytes<'b> for AddressedCall<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("AddressedCall::from_bytes_into\x00");

        let out = out.as_mut_ptr();

        // codec_id (2 bytes)
        let (rem, codec_id) = be_u16(input)?;
        if codec_id != 0 {
            return Err(nom::Err::Error(ParserError::InvalidCodecId));
        }

        // type_id (4 bytes)
        let (rem, type_id) = be_u32(rem)?;
        if type_id != 1 {
            return Err(nom::Err::Error(ParserError::InvalidTypeId));
        }

        // source address size (4 bytes)
        let (rem, source_address_size) = be_u32(rem)?;

        // source address (variable size)
        let (rem, source_address) = take(source_address_size as usize)(rem)?;

        // payload_size (4 bytes)
        let (rem, _) = be_u32(rem)?;

        // payload (remaining bytes) - parse as AddressedCallPayload
        let payload = AddressedCallPayload::from_payload(rem)?;

        unsafe {
            core::ptr::addr_of_mut!((*out).source_address_size).write(source_address_size);
            core::ptr::addr_of_mut!((*out).source_address).write(source_address);
            core::ptr::addr_of_mut!((*out).payload).write(payload);
        }

        Ok(&[]) // All bytes consumed
    }
}
