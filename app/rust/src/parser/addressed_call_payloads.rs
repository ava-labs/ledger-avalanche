use crate::parser::{
    proof_of_possession::BLS_PUBKEY_LEN, FromBytes, NodeId, ParserError, PchainOwner, SubnetId,
    PAYLOAD_MIN_LEN, PVM_REGISTER_L1_VALIDATOR_TYPE, PVM_SET_L1_VALIDATOR_WEIGHT_TYPE,
    VALIDATION_ID_LEN,
};
use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u32, be_u64},
};

// RegisterL1ValidatorMessage structure
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct RegisterL1ValidatorMessage<'b> {
    pub subnet_id: SubnetId<'b>,
    pub node_id: NodeId<'b>,
    pub bls_pubkey: &'b [u8; BLS_PUBKEY_LEN],
    pub expiry: u64,
    pub remaining_balance_owner: PchainOwner<'b>,
    pub disable_owner: PchainOwner<'b>,
    pub weight: u64,
}

impl<'b> FromBytes<'b> for RegisterL1ValidatorMessage<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("RegisterL1ValidatorMessage::from_bytes_into\x00");

        let out = out.as_mut_ptr();

        // subnet_id
        let subnet_id = unsafe { &mut *core::ptr::addr_of_mut!((*out).subnet_id).cast() };
        let rem = SubnetId::from_bytes_into(input, subnet_id)?;

        // Node id size, not used
        let (rem, _node_size) = be_u32(rem)?;

        // node_id
        let node_id = unsafe { &mut *addr_of_mut!((*out).node_id).cast() };
        let rem = NodeId::from_bytes_into(rem, node_id)?;

        // bls_pubkey
        let (rem, bls_pubkey) = take(BLS_PUBKEY_LEN)(rem)?;
        let bls_pubkey = arrayref::array_ref!(bls_pubkey, 0, BLS_PUBKEY_LEN);

        // expiration
        let (rem, expiry) = be_u64(rem)?;

        // remaining_balance_owner
        let remaining_balance_owner =
            unsafe { &mut *core::ptr::addr_of_mut!((*out).remaining_balance_owner).cast() };
        let rem = PchainOwner::from_bytes_into(rem, remaining_balance_owner)?;

        // disable_owner
        let disable_owner = unsafe { &mut *core::ptr::addr_of_mut!((*out).disable_owner).cast() };
        let rem = PchainOwner::from_bytes_into(rem, disable_owner)?;

        // weight
        let (rem, weight) = be_u64(rem)?;

        unsafe {
            core::ptr::addr_of_mut!((*out).bls_pubkey).write(bls_pubkey);
            core::ptr::addr_of_mut!((*out).expiry).write(expiry);
            core::ptr::addr_of_mut!((*out).weight).write(weight);
        }

        Ok(rem)
    }
}

// SetL1ValidatorWeightMessage structure
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct SetL1ValidatorWeightMessage<'b> {
    pub codec_id: u16,
    pub type_id: u32,
    pub validation_id: &'b [u8; VALIDATION_ID_LEN],
    pub nonce: u64,
    pub weight: u64,
}

impl<'b> FromBytes<'b> for SetL1ValidatorWeightMessage<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("SetL1ValidatorWeightMessage::from_bytes_into\x00");

        let out = out.as_mut_ptr();

        // validation_id
        let (rem, validation_id) = take(VALIDATION_ID_LEN)(input)?;
        let validation_id = arrayref::array_ref!(validation_id, 0, VALIDATION_ID_LEN);

        // nonce
        let (rem, nonce) = be_u64(rem)?;

        // weight
        let (rem, weight) = be_u64(rem)?;

        unsafe {
            core::ptr::addr_of_mut!((*out).validation_id).write(validation_id);
            core::ptr::addr_of_mut!((*out).nonce).write(nonce);
            core::ptr::addr_of_mut!((*out).weight).write(weight);
            // Initialize codec_id and type_id with default values
            // These will be overwritten by the parent function if needed
            core::ptr::addr_of_mut!((*out).codec_id).write(0u16);
            core::ptr::addr_of_mut!((*out).type_id).write(0u32);
        }

        Ok(rem)
    }
}

// Enum to represent different L1 validator message types
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub enum AddressedCallPayload<'b> {
    RegisterL1Validator(RegisterL1ValidatorMessage<'b>),
    SetL1ValidatorWeight(SetL1ValidatorWeightMessage<'b>),
}

impl<'b> AddressedCallPayload<'b> {
    pub fn from_payload(payload: &'b [u8]) -> Result<Self, ParserError> {
        if payload.len() < PAYLOAD_MIN_LEN {
            return Err(ParserError::InvalidLength);
        }

        // Read codec_id
        let (rem, codec_id) = be_u16(payload)?;
        if codec_id != 0 {
            return Err(ParserError::InvalidCodecId);
        }

        // Read type_id
        let (rem, type_id) = be_u32(rem)?;

        match type_id {
            PVM_REGISTER_L1_VALIDATOR_TYPE => {
                let mut msg = core::mem::MaybeUninit::uninit();
                let _ = RegisterL1ValidatorMessage::from_bytes_into(rem, &mut msg)?;
                let msg = unsafe { msg.assume_init() };
                Ok(AddressedCallPayload::RegisterL1Validator(msg))
            }
            PVM_SET_L1_VALIDATOR_WEIGHT_TYPE => {
                let mut msg = core::mem::MaybeUninit::uninit();
                let _ = SetL1ValidatorWeightMessage::from_bytes_into(rem, &mut msg)?;
                let mut msg = unsafe { msg.assume_init() };
                // Override codec_id and type_id with the values read at the parent level
                msg.codec_id = codec_id;
                msg.type_id = type_id;
                Ok(AddressedCallPayload::SetL1ValidatorWeight(msg))
            }
            _ => Err(ParserError::InvalidTypeId),
        }
    }
}
