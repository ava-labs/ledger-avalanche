use crate::parser::{AddressedCall, FromBytes, NetworkId, ParserError};
use core::mem::MaybeUninit;
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u32},
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct WarpMessage<'b> {
    pub codec_id: u16,
    pub network_id: NetworkId,
    pub source_chain_id: &'b [u8; 32],
    pub payload: AddressedCall<'b>,
}

impl<'b> FromBytes<'b> for WarpMessage<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("WarpMessage::from_bytes_into\x00");

        let out = out.as_mut_ptr();

        // codecID (2 bytes)
        let (rem, codec_id) = be_u16(input)?;

        if codec_id != 0 {
            return Err(nom::Err::Error(ParserError::InvalidCodecId));
        }

        // networkID (4 bytes)
        let (rem, network_id) = be_u32(rem)?;
        let network_id =
            NetworkId::try_from(network_id).map_err(|_| ParserError::InvalidNetworkId)?;

        // sourceChainId (32 bytes)
        let (rem, source_chain_id) = take(32usize)(rem)?;
        let source_chain_id = arrayref::array_ref!(source_chain_id, 0, 32);

        // payload_size (4 bytes)
        let (rem, _) = be_u32(rem)?;

        // addressed_call - parse the payload as AddressedCall
        let addressed_call = unsafe { &mut *core::ptr::addr_of_mut!((*out).payload).cast() };
        let _ = AddressedCall::from_bytes_into(rem, addressed_call)?;

        unsafe {
            core::ptr::addr_of_mut!((*out).codec_id).write(codec_id);
            core::ptr::addr_of_mut!((*out).network_id).write(network_id);
            core::ptr::addr_of_mut!((*out).source_chain_id).write(source_chain_id);
        }

        Ok(&[])
    }
}
