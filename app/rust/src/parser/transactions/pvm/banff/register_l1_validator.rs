use crate::parser::{nano_avax_to_fp_str, ADDRESS_LEN};
use crate::utils::hex_encode;
use crate::{
    handlers::handle_ui_message,
    parser::{
        pchain_owner::PchainOwner, proof_of_possession::BLS_SIGNATURE_LEN, BaseTxFields,
        DisplayableItem, FromBytes, Header, NodeId, ParserError, PvmOutput, SubnetId,
        PVM_REGISTER_L1_VALIDATOR,
    },
};
use bolos::PIC;
use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::{
    bytes::complete::{tag, take},
    number::complete::{be_u16, be_u32, be_u64},
};
use zemu_sys::ViewError;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct RegisterL1ValidatorTx<'b> {
    pub tx_header: Header<'b>,
    pub base_tx: BaseTxFields<'b, PvmOutput<'b>>,
    pub balance: u64,
    pub signer: &'b [u8; BLS_SIGNATURE_LEN],
    // RegisterL1ValidatorMessage payload
    pub codec_id: u16,
    pub type_id: u32,
    pub subnet_id: SubnetId<'b>,
    pub node_id: NodeId<'b>,
    pub bls_pubkey: &'b [u8; 48],
    pub expiry: u64,
    pub remaining_balance_owner: PchainOwner<'b>,
    pub disable_owner: PchainOwner<'b>,
    pub weight: u64,
}

impl<'b> FromBytes<'b> for RegisterL1ValidatorTx<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("RegisterL1ValidatorTx::from_bytes_into\x00");

        let (rem, _) = tag(PVM_REGISTER_L1_VALIDATOR.to_be_bytes())(input)?;

        let out = out.as_mut_ptr();

        // tx header
        let tx_header = unsafe { &mut *addr_of_mut!((*out).tx_header).cast() };
        let rem = Header::from_bytes_into(rem, tx_header)?;

        // base_tx
        let base_tx = unsafe { &mut *addr_of_mut!((*out).base_tx).cast() };
        let rem = BaseTxFields::<PvmOutput>::from_bytes_into(rem, base_tx)?;

        // balance
        let (rem, balance) = be_u64(rem)?;

        // signer
        let (rem, signer) = take(BLS_SIGNATURE_LEN)(rem)?;
        let signer = arrayref::array_ref!(signer, 0, BLS_SIGNATURE_LEN);

        // codec_id
        let (rem, codec_id) = be_u16(rem)?;

        // type_id
        let (rem, type_id) = be_u32(rem)?;
        if type_id != 1 {
            return Err(nom::Err::Error(ParserError::InvalidTypeId));
        }

        // subnet_id
        let subnet_id = unsafe { &mut *addr_of_mut!((*out).subnet_id).cast() };
        let rem = SubnetId::from_bytes_into(rem, subnet_id)?;

        // Node id size, not used
        let (rem, _unused_value) = take(4usize)(rem)?;

        // node_id
        let node_id = unsafe { &mut *addr_of_mut!((*out).node_id).cast() };
        let rem = NodeId::from_bytes_into(rem, node_id)?;

        // bls_pubkey
        let (rem, bls_pubkey) = take(48usize)(rem)?;
        let bls_pubkey = arrayref::array_ref!(bls_pubkey, 0, 48);

        // expiration
        let (rem, expiry) = be_u64(rem)?;

        // remaining_balance_owner
        let remaining_balance_owner =
            unsafe { &mut *addr_of_mut!((*out).remaining_balance_owner).cast() };
        let rem = PchainOwner::from_bytes_into(rem, remaining_balance_owner)?;

        // disable_owner
        let disable_owner = unsafe { &mut *addr_of_mut!((*out).disable_owner).cast() };
        let rem = PchainOwner::from_bytes_into(rem, disable_owner)?;

        // weight
        let (rem, weight) = be_u64(rem)?;

        unsafe {
            addr_of_mut!((*out).codec_id).write(codec_id);
            addr_of_mut!((*out).weight).write(weight);
            addr_of_mut!((*out).balance).write(balance);
            addr_of_mut!((*out).bls_pubkey).write(bls_pubkey);
            addr_of_mut!((*out).expiry).write(expiry);
            addr_of_mut!((*out).signer).write(signer);
        }

        Ok(rem)
    }
}

impl<'b> RegisterL1ValidatorTx<'b> {
    // Info at https://github.com/ava-labs/avalanchejs/blob/master/src/utils/getBurnedAmountByTx.ts
    fn fee(&'b self) -> Result<u64, ParserError> {
        let sum_inputs = self.base_tx.sum_inputs_amount()?;

        let base_outputs = self.base_tx.sum_outputs_amount()?;

        let mut fee = sum_inputs
            .checked_sub(base_outputs)
            .ok_or(ParserError::OperationOverflows)?;

        fee = fee
            .checked_sub(self.balance)
            .ok_or(ParserError::OperationOverflows)?;

        Ok(fee)
    }
}

impl<'b> DisplayableItem for RegisterL1ValidatorTx<'b> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // tx_info, node_id, weight, balance, fee, remaining_balance_owner, disable_owner
        let n_addresses =
            self.remaining_balance_owner.addresses.len() + self.disable_owner.addresses.len();
        Ok(5u8 + n_addresses as u8)
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::pic_str;
        use lexical_core::{write as itoa, Number};
        let mut buffer = [0; u64::FORMATTED_SIZE + 2];

        let n_remain_addresses = self.remaining_balance_owner.addresses.len();
        let n_disable_addresses = self.disable_owner.addresses.len();
        let prefix = pic_str!(b"0x"!);
        match item_n {
            0 => {
                let label = pic_str!(b"RegisterL1Val");
                title[..label.len()].copy_from_slice(label);
                let content = pic_str!(b"Transaction");
                handle_ui_message(content, message, page)
            }
            1 => self.node_id.render_item(0, title, message, page),
            2 => {
                let label = pic_str!(b"Weight");
                title[..label.len()].copy_from_slice(label);
                let buffer = itoa(self.weight, &mut buffer);
                handle_ui_message(buffer, message, page)
            }
            3 => {
                let label = pic_str!(b"Balance (AVAX)");
                title[..label.len()].copy_from_slice(label);

                let balance_buff = nano_avax_to_fp_str(self.balance, &mut buffer[..])
                    .map_err(|_| ViewError::Unknown)?;

                handle_ui_message(balance_buff, message, page)
            }
            4 => {
                let label = pic_str!(b"Fee(AVAX)");
                title[..label.len()].copy_from_slice(label);

                let fee = self.fee().map_err(|_| ViewError::Unknown)?;
                let fee_buff =
                    nano_avax_to_fp_str(fee, &mut buffer[..]).map_err(|_| ViewError::Unknown)?;

                handle_ui_message(fee_buff, message, page)
            }
            x if x >= 5 && x < (5 + n_remain_addresses as u8) => {
                let label = pic_str!(b"Remaining Owner");
                title[..label.len()].copy_from_slice(label);

                let mut out = [0; ADDRESS_LEN * 2 + 2];
                let mut sz = prefix.len();
                out[..prefix.len()].copy_from_slice(&prefix[..]);

                sz += hex_encode(
                    self.remaining_balance_owner.addresses[x as usize - 5],
                    &mut out[prefix.len()..],
                )
                .map_err(|_| ViewError::Unknown)?;

                handle_ui_message(&out[..sz], message, page)
            }
            x if x >= (5 + n_remain_addresses as u8)
                && x < (5 + n_remain_addresses as u8 + n_disable_addresses as u8) =>
            {
                let label = pic_str!(b"Disable Owner");
                title[..label.len()].copy_from_slice(label);

                let mut out = [0; ADDRESS_LEN * 2 + 2];
                let mut sz = prefix.len();
                out[..prefix.len()].copy_from_slice(&prefix[..]);

                sz += hex_encode(
                    self.disable_owner.addresses[x as usize - 5 - n_remain_addresses as usize],
                    &mut out[prefix.len()..],
                )
                .map_err(|_| ViewError::Unknown)?;

                handle_ui_message(&out[..sz], message, page)
            }
            _ => Err(ViewError::NoData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::prelude::v1::*;

    use crate::parser::snapshots_common::ReducedPage;
    use zuit::Page;

    const DATA: &[u8] = &[];

    include!("testvectors/register_l1_validator.rs");
    #[test]
    fn parse_register_l1_validator() {
        let remaining_balance_owner_address = [
            0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e,
            0x7f, 0x80, 0x81, 0x82, 0x83, 0x84,
        ];

        let disable_owner_address = [
            0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
            0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c,
        ];
        let (_, tx) = RegisterL1ValidatorTx::from_bytes(REGISTER_L1_VALIDATOR_DATA).unwrap();

        assert_eq!(
            tx.remaining_balance_owner.addresses[0],
            remaining_balance_owner_address
        );
        assert_eq!(tx.disable_owner.addresses[0], disable_owner_address);
        assert_eq!(tx.weight, 11357690822530343844);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn ui_register_l1_validator() {
        for (i, data) in [REGISTER_L1_VALIDATOR_DATA].iter().enumerate() {
            println!("-------------------- Register L1 Validator TX #{i} ------------------------");
            let (_, tx) = RegisterL1ValidatorTx::from_bytes(data).unwrap();

            let items = tx.num_items().expect("Overflow?");

            let mut pages = Vec::<Page<18, 1024>>::with_capacity(items as usize);
            for i in 0..items {
                let mut page = Page::default();

                tx.render_item(i as _, &mut page.title, &mut page.message, 0)
                    .unwrap();

                pages.push(page);
            }

            let reduced = pages.iter().map(ReducedPage::from).collect::<Vec<_>>();
            insta::assert_debug_snapshot!(reduced);
        }
    }
}
