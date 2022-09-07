/*******************************************************************************
*   (c) 2021 Zondax GmbH
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
use core::{convert::TryFrom, mem::MaybeUninit, ptr::addr_of_mut};
use nom::{
    bytes::complete::take,
    combinator::peek,
    number::complete::{be_u16, be_u32},
    sequence::tuple,
};

mod base_export;
mod base_import;
mod base_tx_fields;
mod transfer;
mod tx_header;

pub use base_export::BaseExport;
pub use base_import::BaseImport;
pub use base_tx_fields::BaseTxFields;
pub use transfer::Transfer;
pub use tx_header::{Header, BLOCKCHAIN_ID_LEN};

mod avm;
mod pvm;

use crate::parser::{
    DisplayableItem, ExportTx as EvmExport, ImportTx as EvmImport, EVM_IMPORT_TX, PVM_EXPORT_TX,
    PVM_IMPORT_TX,
};
pub use avm::{AvmExportTx, AvmImportTx, CreateAssetTx};
pub use pvm::{
    AddDelegatorTx, AddSubnetValidatorTx, AddValidatorTx, CreateChainTx, CreateSubnetTx,
    PvmExportTx, PvmImportTx,
};

use super::{
    ChainId, FromBytes, NetworkInfo, ParserError, AVM_CREATE_ASSET_TX, AVM_EXPORT_TX,
    AVM_IMPORT_TX, EVM_EXPORT_TX, PVM_ADD_DELEGATOR, PVM_ADD_SUBNET_VALIDATOR, PVM_ADD_VALIDATOR,
    PVM_CREATE_CHAIN, PVM_CREATE_SUBNET, TRANSFER_TX,
};

// Important: do not change the repr attribute,
// as this type is use as the tag field
// for the Transaction enum which has the same representation
#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
#[repr(u8)]
pub enum TransactionType {
    XImport,
    XExport,
    XAsset,
    PImport,
    PExport,
    CImport,
    CExport,
    Validator,
    Delegator,
    CreateChain,
    CreateSubnet,
    SubnetValidator,
    Transfer,
}

impl TryFrom<(u32, NetworkInfo)> for TransactionType {
    type Error = ParserError;

    fn try_from(value: (u32, NetworkInfo)) -> Result<Self, Self::Error> {
        crate::sys::zemu_log_stack("TransactionType::TryFrom\x00");
        let tx_type = match value.0 {
            PVM_EXPORT_TX => TransactionType::PExport,
            PVM_IMPORT_TX => TransactionType::PImport,
            AVM_EXPORT_TX => TransactionType::XExport,
            AVM_IMPORT_TX => TransactionType::XImport,
            // avoid collition with evm_export tx in C-chain
            AVM_CREATE_ASSET_TX if matches!(value.1.chain_id, ChainId::XChain) => {
                TransactionType::XAsset
            }
            PVM_CREATE_CHAIN => TransactionType::CreateChain,
            // avoid collition with createAsset tx in X-chain
            EVM_EXPORT_TX if matches!(value.1.chain_id, ChainId::CChain) => {
                TransactionType::CExport
            }
            // avoid collition with normal_transfer tx in X-chain/P-chain
            EVM_IMPORT_TX if matches!(value.1.chain_id, ChainId::CChain) => {
                TransactionType::CImport
            }
            PVM_ADD_DELEGATOR => TransactionType::Delegator,
            PVM_CREATE_SUBNET => TransactionType::CreateSubnet,
            PVM_ADD_VALIDATOR => TransactionType::Validator,
            PVM_ADD_SUBNET_VALIDATOR => TransactionType::SubnetValidator,
            TRANSFER_TX => TransactionType::Transfer,
            _ => return Err(ParserError::InvalidTransactionType),
        };

        Ok(tx_type)
    }
}

#[repr(C)]
struct XImportVariant<'b>(TransactionType, AvmImportTx<'b>);

#[repr(C)]
struct XExportVariant<'b>(TransactionType, AvmExportTx<'b>);

#[repr(C)]
struct XCreateAssetVariant<'b>(TransactionType, CreateAssetTx<'b>);

#[repr(C)]
struct PImportVariant<'b>(TransactionType, PvmImportTx<'b>);

#[repr(C)]
struct PExportVariant<'b>(TransactionType, PvmExportTx<'b>);

#[repr(C)]
struct CImportVariant<'b>(TransactionType, EvmImport<'b>);

#[repr(C)]
struct CExportVariant<'b>(TransactionType, EvmExport<'b>);

#[repr(C)]
struct ChainVariant<'b>(TransactionType, CreateChainTx<'b>);

#[repr(C)]
struct SubnetVariant<'b>(TransactionType, CreateSubnetTx<'b>);

#[repr(C)]
struct ValidatorVariant<'b>(TransactionType, AddValidatorTx<'b>);

#[repr(C)]
struct SubnetValidatorVariant<'b>(TransactionType, AddSubnetValidatorTx<'b>);

#[repr(C)]
struct DelegatorVariant<'b>(TransactionType, AddDelegatorTx<'b>);

#[repr(C)]
struct TransferVariant<'b>(TransactionType, Transfer<'b>);

#[derive(Clone, Copy, PartialEq)]
// DO not change the representation
// as it would cause unalignment issues
// with the OutputType tag
#[repr(u8)]
#[cfg_attr(test, derive(Debug))]
pub enum Transaction<'b> {
    XImport(AvmImportTx<'b>),
    XExport(AvmExportTx<'b>),
    XAsset(CreateAssetTx<'b>),
    PImport(PvmImportTx<'b>),
    PExport(PvmExportTx<'b>),
    CImport(EvmImport<'b>),
    CExport(EvmExport<'b>),
    Validator(AddValidatorTx<'b>),
    Delegator(AddDelegatorTx<'b>),
    CreateChain(CreateChainTx<'b>),
    CreateSubnet(CreateSubnetTx<'b>),
    SubnetValidator(AddSubnetValidatorTx<'b>),
    Transfer(Transfer<'b>),
}

impl<'b> Transaction<'b> {
    fn peek_transaction_info(input: &'b [u8]) -> Result<(u32, NetworkInfo), nom::Err<ParserError>> {
        // peek transaction type, network_id and blockchain_id
        let (_, (raw_tx_id, network_id, blockchain_id)) =
            peek(tuple((be_u32, be_u32, take(BLOCKCHAIN_ID_LEN))))(input)?;
        let blockchain_id = arrayref::array_ref!(blockchain_id, 0, BLOCKCHAIN_ID_LEN);
        let network_info = NetworkInfo::try_from((network_id, blockchain_id))?;
        Ok((raw_tx_id, network_info))
    }

    #[cfg(test)]
    pub fn new(input: &'b [u8]) -> Result<Self, ParserError> {
        let mut variant = MaybeUninit::uninit();
        Self::new_into(input, &mut variant)?;
        // Safe as parsing initializes it
        Ok(unsafe { variant.assume_init() })
    }

    pub fn new_into(input: &'b [u8], this: &mut MaybeUninit<Self>) -> Result<(), ParserError> {
        let (rem, codec) = be_u16(input)?;

        if codec != 0 {
            return Err(ParserError::InvalidCodec);
        }
        Self::parse(rem, this)?;

        Ok(())
    }

    pub fn disable_output_if(&mut self, address: &[u8]) {
        match self {
            Self::XImport(tx) => tx.disable_output_if(address),
            Self::XExport(tx) => tx.disable_output_if(address),
            Self::PImport(tx) => tx.disable_output_if(address),
            Self::PExport(tx) => tx.disable_output_if(address),
            Self::Transfer(tx) => tx.disable_output_if(address),
            Self::CImport(tx) => tx.disable_output_if(address),
            Self::CExport(tx) => tx.disable_output_if(address),
            Self::Validator(tx) => tx.disable_output_if(address),
            Self::Delegator(tx) => tx.disable_output_if(address),
            _ => {}
        }
    }

    fn parse(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        let info = Self::peek_transaction_info(input)?;
        let transaction_type = TransactionType::try_from(info)?;

        let rem = match transaction_type {
            TransactionType::PImport => {
                let out = out.as_mut_ptr() as *mut PImportVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = PvmImportTx::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(TransactionType::PImport);
                }

                rem
            }
            TransactionType::PExport => {
                let out = out.as_mut_ptr() as *mut PExportVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = PvmExportTx::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(TransactionType::PExport);
                }

                rem
            }
            TransactionType::XImport => {
                let out = out.as_mut_ptr() as *mut XImportVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = AvmImportTx::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(TransactionType::XImport);
                }

                rem
            }
            TransactionType::XExport => {
                let out = out.as_mut_ptr() as *mut XExportVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = AvmExportTx::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(TransactionType::XExport);
                }

                rem
            }
            TransactionType::XAsset => {
                let out = out.as_mut_ptr() as *mut XCreateAssetVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = CreateAssetTx::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(TransactionType::XAsset);
                }

                rem
            }
            TransactionType::CExport => {
                let out = out.as_mut_ptr() as *mut CExportVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = EvmExport::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(TransactionType::CExport);
                }

                rem
            }
            TransactionType::CImport => {
                let out = out.as_mut_ptr() as *mut CImportVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = EvmImport::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(TransactionType::CImport);
                }

                rem
            }
            TransactionType::CreateChain => {
                let out = out.as_mut_ptr() as *mut ChainVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = CreateChainTx::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(TransactionType::CreateChain);
                }

                rem
            }
            TransactionType::CreateSubnet => {
                let out = out.as_mut_ptr() as *mut SubnetVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = CreateSubnetTx::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(TransactionType::CreateSubnet);
                }

                rem
            }
            TransactionType::Validator => {
                let out = out.as_mut_ptr() as *mut ValidatorVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = AddValidatorTx::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(TransactionType::Validator);
                }

                rem
            }
            TransactionType::Delegator => {
                let out = out.as_mut_ptr() as *mut DelegatorVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = AddDelegatorTx::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(TransactionType::Delegator);
                }

                rem
            }
            TransactionType::SubnetValidator => {
                let out = out.as_mut_ptr() as *mut SubnetValidatorVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = AddSubnetValidatorTx::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(TransactionType::SubnetValidator);
                }

                rem
            }
            TransactionType::Transfer => {
                let out = out.as_mut_ptr() as *mut TransferVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = Transfer::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(TransactionType::Transfer);
                }

                rem
            }
        };

        // check rem is empty??
        Ok(rem)
    }

    // Returns True if transaction is one of the supported coreth transactions.
    pub fn is_eth(&self) -> bool {
        matches!(self, Self::CExport(_)) || matches!(self, Self::CImport(_))
    }
}

impl<'b> DisplayableItem for Transaction<'b> {
    fn num_items(&self) -> usize {
        match self {
            Self::XImport(tx) => tx.num_items(),
            Self::XExport(tx) => tx.num_items(),
            Self::XAsset(tx) => tx.num_items(),
            Self::PImport(tx) => tx.num_items(),
            Self::PExport(tx) => tx.num_items(),
            Self::CImport(tx) => tx.num_items(),
            Self::CExport(tx) => tx.num_items(),
            Self::Validator(tx) => tx.num_items(),
            Self::SubnetValidator(tx) => tx.num_items(),
            Self::Delegator(tx) => tx.num_items(),
            Self::CreateChain(tx) => tx.num_items(),
            Self::CreateSubnet(tx) => tx.num_items(),
            Self::Transfer(tx) => tx.num_items(),
        }
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        match self {
            Self::XImport(tx) => tx.render_item(item_n, title, message, page),
            Self::XExport(tx) => tx.render_item(item_n, title, message, page),
            Self::XAsset(tx) => tx.render_item(item_n, title, message, page),
            Self::PImport(tx) => tx.render_item(item_n, title, message, page),
            Self::PExport(tx) => tx.render_item(item_n, title, message, page),
            Self::CImport(tx) => tx.render_item(item_n, title, message, page),
            Self::CExport(tx) => tx.render_item(item_n, title, message, page),
            Self::Validator(tx) => tx.render_item(item_n, title, message, page),
            Self::SubnetValidator(tx) => tx.render_item(item_n, title, message, page),
            Self::Delegator(tx) => tx.render_item(item_n, title, message, page),
            Self::CreateChain(tx) => tx.render_item(item_n, title, message, page),
            Self::CreateSubnet(tx) => tx.render_item(item_n, title, message, page),
            Self::Transfer(tx) => tx.render_item(item_n, title, message, page),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fmt::{Debug, Display},
        prelude::v1::*,
    };

    use zemu_sys::Viewable;
    use zuit::{MockDriver, Page};

    use crate::utils::strlen;

    use super::*;

    /// This is only to be used for testing, hence why
    /// it's present inside the `mod test` block only
    impl Viewable for Transaction<'static> {
        fn num_items(&mut self) -> Result<u8, zemu_sys::ViewError> {
            Ok(DisplayableItem::num_items(&*self) as u8)
        }

        fn render_item(
            &mut self,
            item_idx: u8,
            title: &mut [u8],
            message: &mut [u8],
            page_idx: u8,
        ) -> Result<u8, zemu_sys::ViewError> {
            DisplayableItem::render_item(&*self, item_idx, title, message, page_idx)
        }

        fn accept(&mut self, _: &mut [u8]) -> (usize, u16) {
            (0, 0)
        }

        fn reject(&mut self, _: &mut [u8]) -> (usize, u16) {
            (0, 0)
        }
    }

    const DATA: &[u8] = &[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x30, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0xdb, 0xcf, 0x89, 0x0f, 0x77, 0xf4, 0x9b, 0x96, 0x85, 0x76, 0x48, 0xb7, 0x2b, 0x77,
        0xf9, 0xf8, 0x29, 0x37, 0xf2, 0x8a, 0x68, 0x70, 0x4a, 0xf0, 0x5d, 0xa0, 0xdc, 0x12, 0xba,
        0x53, 0xf2, 0xdb, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0xee, 0x5b, 0xe5, 0xc0,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x01, 0xda, 0x2b, 0xee, 0x01, 0xbe, 0x82, 0xec, 0xc0, 0x0c, 0x34, 0xf3, 0x61, 0xed, 0xa8,
        0xeb, 0x30, 0xfb, 0x5a, 0x71, 0x5c, 0x00, 0x00, 0x00, 0x01, 0xdf, 0xaf, 0xbd, 0xf5, 0xc8,
        0x1f, 0x63, 0x5c, 0x92, 0x57, 0x82, 0x4f, 0xf2, 0x1c, 0x8e, 0x3e, 0x6f, 0x7b, 0x63, 0x2a,
        0xc3, 0x06, 0xe1, 0x14, 0x46, 0xee, 0x54, 0x0d, 0x34, 0x71, 0x1a, 0x15, 0x00, 0x00, 0x00,
        0x01, 0xdb, 0xcf, 0x89, 0x0f, 0x77, 0xf4, 0x9b, 0x96, 0x85, 0x76, 0x48, 0xb7, 0x2b, 0x77,
        0xf9, 0xf8, 0x29, 0x37, 0xf2, 0x8a, 0x68, 0x70, 0x4a, 0xf0, 0x5d, 0xa0, 0xdc, 0x12, 0xba,
        0x53, 0xf2, 0xdb, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x01, 0xd2, 0x97, 0xb5, 0x48, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe9, 0x09, 0x4f,
        0x73, 0x69, 0x80, 0x02, 0xfd, 0x52, 0xc9, 0x08, 0x19, 0xb4, 0x57, 0xb9, 0xfb, 0xc8, 0x66,
        0xab, 0x80, 0x00, 0x00, 0x00, 0x00, 0x5f, 0x21, 0xf3, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x5f,
        0x49, 0x7d, 0xc6, 0x00, 0x00, 0x01, 0xd1, 0xa9, 0x4a, 0x20, 0x00, 0x00, 0x00, 0x00, 0x01,
        0xdb, 0xcf, 0x89, 0x0f, 0x77, 0xf4, 0x9b, 0x96, 0x85, 0x76, 0x48, 0xb7, 0x2b, 0x77, 0xf9,
        0xf8, 0x29, 0x37, 0xf2, 0x8a, 0x68, 0x70, 0x4a, 0xf0, 0x5d, 0xa0, 0xdc, 0x12, 0xba, 0x53,
        0xf2, 0xdb, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x01, 0xd1, 0xa9, 0x4a, 0x20, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        0x3c, 0xb7, 0xd3, 0x84, 0x2e, 0x8c, 0xee, 0x6a, 0x0e, 0xbd, 0x09, 0xf1, 0xfe, 0x88, 0x4f,
        0x68, 0x61, 0xe1, 0xb2, 0x9c, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0xda, 0x2b, 0xee, 0x01, 0xbe,
        0x82, 0xec, 0xc0, 0x0c, 0x34, 0xf3, 0x61, 0xed, 0xa8, 0xeb, 0x30, 0xfb, 0x5a, 0x71, 0x5c,
    ];

    #[test]
    fn parse_transaction() {
        let tx = Transaction::new(DATA).unwrap();
        assert!(matches!(tx, Transaction::Delegator(..)));
    }

    /// Executes the provided closure passing in the provided data
    /// as a &'static [T].
    ///
    /// This is really only useful to construct a type as `'static` for the purpose
    /// of satisfying a bound like the one in `Viewable`
    ///
    /// # Safety
    /// `f` shouldn't store the data or rely on it being _actually_ available for the entire
    /// duration of the program, but rather only have it valid for the call to the closure itself
    unsafe fn with_leaked<'a, T: 'static, U: 'a>(
        data: Vec<T>,
        mut f: impl FnMut(&'static [T]) -> U,
    ) -> U {
        //this way we also drop the excess capacity
        let data = data.into_boxed_slice();

        let ptr = Box::into_raw(data);

        //it's fine to unwrap here, the pointer is aligned
        // and everything...
        let r = f(ptr.as_ref().unwrap_unchecked());

        //reclaim the box an drop it
        // this is the "unsafe" part of the function
        // because if `f` stored the data somewhere now it would be freed
        // and this isn't good, but that's why we have #Safety
        let _ = Box::from_raw(ptr);

        r
    }

    /// This struct is useful to have more concise output a certain page
    ///
    /// By default, to construct this you'd use `from` and the implementation will
    /// try to parse the title and message of the page as UTF8 to display those
    ///
    /// The Debug impl is based on Display and is of the format `"{title}": "{message}"`
    struct ReducedPage<'b> {
        title: &'b str,
        message: &'b str,
    }

    impl<'b, const T: usize, const M: usize> From<&'b Page<T, M>> for ReducedPage<'b> {
        fn from(page: &'b Page<T, M>) -> Self {
            let tlen = strlen(&page.title);
            let title = std::str::from_utf8(&page.title[..tlen]).expect("title was not valid utf8");

            let mlen = strlen(&page.message);
            let message =
                std::str::from_utf8(&page.message[..mlen]).expect("message was not valid utf8");

            ReducedPage { title, message }
        }
    }

    impl<'b> Debug for ReducedPage<'b> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            Display::fmt(self, f)
        }
    }
    impl<'b> Display for ReducedPage<'b> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "{:?}: {:?}", self.title, self.message)
        }
    }

    #[test]
    fn tx_ui() {
        insta::glob!("testvectors/*.json", |path| {
            let file = std::fs::File::open(path)
                .unwrap_or_else(|e| panic!("Unable to open file {:?}: {:?}", path, e));
            let input: Vec<u8> = serde_json::from_reader(file)
                .unwrap_or_else(|e| panic!("Unable to read file {:?} as json: {:?}", path, e));

            let test = |data| {
                let tx = Transaction::new(data).expect("parse tx from data");

                let mut driver = MockDriver::<_, 18, 4096>::new(tx);
                driver.drive();

                let ui = driver.into_out_ui();

                let reduced = ui
                    .iter()
                    .map(|item| item.iter().map(ReducedPage::from).collect::<Vec<_>>())
                    .collect::<Vec<_>>();

                insta::assert_debug_snapshot!(reduced);
            };

            unsafe { with_leaked(input, test) };
        });
    }
}
