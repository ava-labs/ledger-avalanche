use core::ptr::addr_of_mut;

use nom::number::complete::be_u64;
use zemu_sys::ViewError;

use crate::{
    handlers::handle_ui_message,
    parser::{nano_avax_to_fp_str, u64_to_str, DisplayableItem, FromBytes, U64_FORMATTED_SIZE},
};

pub trait StakeTrait {
    fn stake(&self) -> u64;
}

pub trait WeightTrait {
    fn weight(&self) -> u64;
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct Stake(u64);

impl<'b> FromBytes<'b> for Stake {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<crate::parser::ParserError>> {
        let out = out.as_mut_ptr();

        let (rem, weight) = be_u64(input)?;

        unsafe {
            addr_of_mut!((*out).0).write(weight);
        }

        Ok(rem)
    }
}

impl StakeTrait for Stake {
    fn stake(&self) -> u64 {
        self.0
    }
}

impl DisplayableItem for Stake {
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
        use bolos::{pic_str, PIC};

        match item_n {
            0 => {
                let label = pic_str!(b"Total stake(AVAX)");
                title[..label.len()].copy_from_slice(label);

                let mut buffer = [0; U64_FORMATTED_SIZE + 2];
                let num =
                    nano_avax_to_fp_str(self.0, &mut buffer[..]).map_err(|_| ViewError::Unknown)?;

                handle_ui_message(num, message, page)
            }
            _ => Err(ViewError::NoData),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct Weight(u64);

impl WeightTrait for Weight {
    fn weight(&self) -> u64 {
        self.0
    }
}

impl<'b> FromBytes<'b> for Weight {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<crate::parser::ParserError>> {
        let out = out.as_mut_ptr();

        let (rem, weight) = be_u64(input)?;

        unsafe {
            addr_of_mut!((*out).0).write(weight);
        }

        Ok(rem)
    }
}

impl DisplayableItem for Weight {
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
        use bolos::{pic_str, PIC};

        match item_n {
            0 => {
                let label = pic_str!(b"Weight");
                title[..label.len()].copy_from_slice(label);

                let mut buffer = [0; U64_FORMATTED_SIZE];
                let num = u64_to_str(self.0, &mut buffer[..]).map_err(|_| ViewError::Unknown)?;

                handle_ui_message(num, message, page)
            }
            _ => Err(ViewError::NoData),
        }
    }
}
