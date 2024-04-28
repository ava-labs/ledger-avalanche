use crate::parser::ParserError;

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct parser_context_t {
    pub buffer: *const u8,
    pub buffer_len: u16,
    pub offset: u16,
    pub ins: u8,
    pub tx_obj: parse_tx_t,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct parse_tx_t {
    pub state: *mut u8,
    pub len: u16,
}

#[repr(u8)]
pub enum Instruction {
    SignAvaxTx = 0x00,
    SignEthTx,
    SignAvaxMsg,
    SignEthMsg,
    SignAvaxHash,
}

impl TryFrom<u8> for Instruction {
    type Error = ParserError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Instruction::SignAvaxTx),
            0x01 => Ok(Instruction::SignEthTx),
            0x02 => Ok(Instruction::SignAvaxMsg),
            0x03 => Ok(Instruction::SignEthMsg),
            0x04 => Ok(Instruction::SignAvaxHash),
            _ => Err(ParserError::InvalidTransactionType),
        }
    }
}
