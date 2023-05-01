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
use cfg_if::cfg_if;
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
pub use avm::{AvmExportTx, AvmImportTx, OperationTx};
pub use pvm::{PvmExportTx, PvmImportTx};

#[cfg(feature = "create-asset")]
pub use avm::CreateAssetTx;

#[cfg(feature = "create-chain")]
pub use pvm::CreateChainTx;

#[cfg(feature = "add-subnet-validator")]
pub use pvm::AddSubnetValidatorTx;

#[cfg(feature = "create-subnet")]
pub use pvm::CreateSubnetTx;

#[cfg(feature = "add-delegator")]
pub use pvm::AddDelegatorTx;

#[cfg(feature = "add-validator")]
pub use pvm::AddValidatorTx;

cfg_if! {
    if #[cfg(feature = "banff")] {
        pub use pvm::{
            RemoveSubnetValidatorTx,
            AddPermissionlessValidatorTx,
            AddPermissionlessDelegatorTx,
        };
    }
}

use super::{
    ChainId, FromBytes, NetworkInfo, ParserError, AVM_EXPORT_TX, AVM_IMPORT_TX, AVM_OPERATION_TX,
    EVM_EXPORT_TX, TRANSFER_TX,
};

#[cfg(feature = "create-asset")]
use super::AVM_CREATE_ASSET_TX;

#[cfg(feature = "create-chain")]
use super::PVM_CREATE_CHAIN;

#[cfg(feature = "create-subnet")]
use super::PVM_CREATE_SUBNET;

#[cfg(feature = "add-subnet-validator")]
use super::PVM_ADD_SUBNET_VALIDATOR;

#[cfg(feature = "add-validator")]
use super::PVM_ADD_VALIDATOR;

#[cfg(feature = "add-delegator")]
use super::PVM_ADD_DELEGATOR;

cfg_if! {
    if #[cfg(feature = "banff")] {
        use super::{
            PVM_ADD_PERMISSIONLESS_DELEGATOR, PVM_ADD_PERMISSIONLESS_VALIDATOR, PVM_TRANSFORM_SUBNET, PVM_REMOVE_SUBNET_VALIDATOR
        };
    }
}

impl TryFrom<(u32, NetworkInfo)> for Transaction__Type {
    type Error = ParserError;

    fn try_from(value: (u32, NetworkInfo)) -> Result<Self, Self::Error> {
        crate::sys::zemu_log_stack("TransactionType::TryFrom\x00");
        let tx_type = match value.0 {
            PVM_EXPORT_TX => Transaction__Type::PExport,
            PVM_IMPORT_TX => Transaction__Type::PImport,
            AVM_EXPORT_TX => Transaction__Type::XExport,
            AVM_IMPORT_TX => Transaction__Type::XImport,
            AVM_OPERATION_TX => Transaction__Type::XOperation,
            // avoid collision with evm_export tx in C-chain
            // avoid collision with createAsset tx in X-chain
            EVM_EXPORT_TX if matches!(value.1.chain_id, ChainId::CChain) => {
                Transaction__Type::CExport
            }
            // avoid collision with normal_transfer tx in X-chain/P-chain
            EVM_IMPORT_TX if matches!(value.1.chain_id, ChainId::CChain) => {
                Transaction__Type::CImport
            }
            TRANSFER_TX => Transaction__Type::Transfer,
            #[cfg(feature = "create-asset")]
            AVM_CREATE_ASSET_TX if matches!(value.1.chain_id, ChainId::XChain) => {
                Transaction__Type::XAsset
            }
            #[cfg(feature = "create-chain")]
            PVM_CREATE_CHAIN => Transaction__Type::CreateChain,
            #[cfg(feature = "add-delegator")]
            PVM_ADD_DELEGATOR => Transaction__Type::Delegator,
            #[cfg(feature = "create-subnet")]
            PVM_CREATE_SUBNET => Transaction__Type::CreateSubnet,
            #[cfg(feature = "add-validator")]
            PVM_ADD_VALIDATOR => Transaction__Type::Validator,
            #[cfg(feature = "add-subnet-validator")]
            PVM_ADD_SUBNET_VALIDATOR => Transaction__Type::SubnetValidator,
            #[cfg(feature = "banff")]
            PVM_REMOVE_SUBNET_VALIDATOR => Transaction__Type::RemoveSubnetValidator,
            #[cfg(feature = "banff")]
            PVM_ADD_PERMISSIONLESS_VALIDATOR => Transaction__Type::PermissionlessValidator,
            #[cfg(feature = "banff")]
            PVM_ADD_PERMISSIONLESS_DELEGATOR => Transaction__Type::PermissionlessDelegator,
            _ => return Err(ParserError::InvalidTransactionType),
        };

        Ok(tx_type)
    }
}

#[avalanche_app_derive::enum_init]
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum Transaction<'b> {
    XImport(AvmImportTx<'b>),
    XExport(AvmExportTx<'b>),
    XOperation(OperationTx<'b>),
    PImport(PvmImportTx<'b>),
    PExport(PvmExportTx<'b>),
    CImport(EvmImport<'b>),
    CExport(EvmExport<'b>),
    Transfer(Transfer<'b>),
    #[cfg(feature = "create-asset")]
    XAsset(CreateAssetTx<'b>),
    #[cfg(feature = "add-validator")]
    Validator(AddValidatorTx<'b>),
    #[cfg(feature = "add-delegator")]
    Delegator(AddDelegatorTx<'b>),
    #[cfg(feature = "create-chain")]
    CreateChain(CreateChainTx<'b>),
    #[cfg(feature = "create-subnet")]
    CreateSubnet(CreateSubnetTx<'b>),
    #[cfg(feature = "add-subnet-validator")]
    SubnetValidator(AddSubnetValidatorTx<'b>),
    #[cfg(feature = "banff")]
    RemoveSubnetValidator(RemoveSubnetValidatorTx<'b>),
    #[cfg(feature = "banff")]
    PermissionlessValidator(AddPermissionlessValidatorTx<'b>),
    #[cfg(feature = "banff")]
    PermissionlessDelegator(AddPermissionlessDelegatorTx<'b>),
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
            Self::XOperation(tx) => tx.disable_output_if(address),
            Self::PImport(tx) => tx.disable_output_if(address),
            Self::PExport(tx) => tx.disable_output_if(address),
            Self::Transfer(tx) => tx.disable_output_if(address),
            Self::CImport(tx) => tx.disable_output_if(address),
            Self::CExport(tx) => tx.disable_output_if(address),
            #[cfg(feature = "add-validator")]
            Self::Validator(tx) => tx.disable_output_if(address),
            #[cfg(feature = "add-delegator")]
            Self::Delegator(tx) => tx.disable_output_if(address),
            #[cfg(feature = "banff")]
            Self::PermissionlessValidator(tx) => tx.disable_output_if(address),
            #[cfg(feature = "banff")]
            Self::PermissionlessDelegator(tx) => tx.disable_output_if(address),
            _ => {}
        }
    }

    fn parse(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        let info = Self::peek_transaction_info(input)?;
        let transaction_type = Transaction__Type::try_from(info)?;

        match transaction_type {
            Transaction__Type::PImport => {
                Self::init_as_p_import(|out| PvmImportTx::from_bytes_into(input, out), out)
            }
            Transaction__Type::PExport => {
                Self::init_as_p_export(|out| PvmExportTx::from_bytes_into(input, out), out)
            }
            Transaction__Type::XImport => {
                Self::init_as_x_import(|out| AvmImportTx::from_bytes_into(input, out), out)
            }
            Transaction__Type::XExport => {
                Self::init_as_x_export(|out| AvmExportTx::from_bytes_into(input, out), out)
            }
            Transaction__Type::XOperation => {
                Self::init_as_x_operation(|out| OperationTx::from_bytes_into(input, out), out)
            }
            Transaction__Type::CExport => {
                Self::init_as_c_export(|out| EvmExport::from_bytes_into(input, out), out)
            }
            Transaction__Type::CImport => {
                Self::init_as_c_import(|out| EvmImport::from_bytes_into(input, out), out)
            }
            Transaction__Type::Transfer => {
                Self::init_as_transfer(|out| Transfer::from_bytes_into(input, out), out)
            }
            #[cfg(feature = "create-asset")]
            Transaction__Type::XAsset => {
                Self::init_as_x_asset(|out| CreateAssetTx::from_bytes_into(input, out), out)
            }
            #[cfg(feature = "create-chain")]
            Transaction__Type::CreateChain => {
                Self::init_as_create_chain(|out| CreateChainTx::from_bytes_into(input, out), out)
            }
            #[cfg(feature = "create-subnet")]
            Transaction__Type::CreateSubnet => {
                Self::init_as_create_subnet(|out| CreateSubnetTx::from_bytes_into(input, out), out)
            }
            #[cfg(feature = "add-validator")]
            Transaction__Type::Validator => {
                Self::init_as_validator(|out| AddValidatorTx::from_bytes_into(input, out), out)
            }
            #[cfg(feature = "add-delegator")]
            Transaction__Type::Delegator => {
                Self::init_as_delegator(|out| AddDelegatorTx::from_bytes_into(input, out), out)
            }
            #[cfg(feature = "add-subnet-validator")]
            Transaction__Type::SubnetValidator => Self::init_as_subnet_validator(
                |out| AddSubnetValidatorTx::from_bytes_into(input, out),
                out,
            ),
            #[cfg(feature = "banff")]
            Transaction__Type::RemoveSubnetValidator => Self::init_as_remove_subnet_validator(
                |out| RemoveSubnetValidatorTx::from_bytes_into(input, out),
                out,
            ),
            #[cfg(feature = "banff")]
            Transaction__Type::PermissionlessValidator => Self::init_as_permissionless_validator(
                |out| AddPermissionlessValidatorTx::from_bytes_into(input, out),
                out,
            ),
            #[cfg(feature = "banff")]
            Transaction__Type::PermissionlessDelegator => Self::init_as_permissionless_delegator(
                |out| AddPermissionlessDelegatorTx::from_bytes_into(input, out),
                out,
            ),
        }
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
            Self::XOperation(tx) => tx.num_items(),
            Self::PImport(tx) => tx.num_items(),
            Self::PExport(tx) => tx.num_items(),
            Self::CImport(tx) => tx.num_items(),
            Self::CExport(tx) => tx.num_items(),
            Self::Transfer(tx) => tx.num_items(),
            #[cfg(feature = "create-asset")]
            Self::XAsset(tx) => tx.num_items(),
            #[cfg(feature = "add-validator")]
            Self::Validator(tx) => tx.num_items(),
            #[cfg(feature = "add-subnet-validator")]
            Self::SubnetValidator(tx) => tx.num_items(),
            #[cfg(feature = "add-delegator")]
            Self::Delegator(tx) => tx.num_items(),
            #[cfg(feature = "create-chain")]
            Self::CreateChain(tx) => tx.num_items(),
            #[cfg(feature = "create-subnet")]
            Self::CreateSubnet(tx) => tx.num_items(),
            #[cfg(feature = "banff")]
            Self::RemoveSubnetValidator(tx) => tx.num_items(),
            #[cfg(feature = "banff")]
            Self::PermissionlessValidator(tx) => tx.num_items(),
            #[cfg(feature = "banff")]
            Self::PermissionlessDelegator(tx) => tx.num_items(),
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
            Self::XOperation(tx) => tx.render_item(item_n, title, message, page),
            Self::PImport(tx) => tx.render_item(item_n, title, message, page),
            Self::PExport(tx) => tx.render_item(item_n, title, message, page),
            Self::CImport(tx) => tx.render_item(item_n, title, message, page),
            Self::CExport(tx) => tx.render_item(item_n, title, message, page),
            Self::Transfer(tx) => tx.render_item(item_n, title, message, page),
            #[cfg(feature = "create-asset")]
            Self::XAsset(tx) => tx.render_item(item_n, title, message, page),
            #[cfg(feature = "add-validator")]
            Self::Validator(tx) => tx.render_item(item_n, title, message, page),
            #[cfg(feature = "add-subnet-validator")]
            Self::SubnetValidator(tx) => tx.render_item(item_n, title, message, page),
            #[cfg(feature = "add-delegator")]
            Self::Delegator(tx) => tx.render_item(item_n, title, message, page),
            #[cfg(feature = "create-chain")]
            Self::CreateChain(tx) => tx.render_item(item_n, title, message, page),
            #[cfg(feature = "create-subnet")]
            Self::CreateSubnet(tx) => tx.render_item(item_n, title, message, page),
            #[cfg(feature = "banff")]
            Self::RemoveSubnetValidator(tx) => tx.render_item(item_n, title, message, page),
            #[cfg(feature = "banff")]
            Self::PermissionlessValidator(tx) => tx.render_item(item_n, title, message, page),
            #[cfg(feature = "banff")]
            Self::PermissionlessDelegator(tx) => tx.render_item(item_n, title, message, page),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::prelude::v1::*;

    use zemu_sys::Viewable;

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

    // Transfer transaction
    const DATA:&str = "00000000000000000005ab68eb1ee142a05cfe768c36e11f0b596db5a3c6c77aabe665dad9e638ca94f7000000023d9bdac0ed1d761330cf680efdeb1a42159eb387d6d2950c96f7d28f61bbe2aa00000007000000003b9aca0000000000000000000000000100000001636fb961b8bce4d0038796f5db330fecc8e36f723d9bdac0ed1d761330cf680efdeb1a42159eb387d6d2950c96f7d28f61bbe2aa0000000700000000f44284800000000000000000000000010000000107fe53d8ed2b004df3ac75175a4e727a6dd461d8000000023be4ead93aa5e6396d1f2c6e9587c7642b30d52d605f917d8a402e6823f965f2000000003d9bdac0ed1d761330cf680efdeb1a42159eb387d6d2950c96f7d28f61bbe2aa000000050000000005e69ec0000000010000000095aff4ba72647c2a6a41802c047a9f3a3919b35aefcf7da843d4cc34980c7102000000003d9bdac0ed1d761330cf680efdeb1a42159eb387d6d2950c96f7d28f61bbe2aa00000005000000012a05f200000000010000000000000000";

    // provided change_address
    const CHANGE_ADDRESS: &str = "07fe53d8ed2b004df3ac75175a4e727a6dd461d8";

    #[test]
    fn parse_transaction() {
        let data = hex::decode(DATA).unwrap();
        let change_address = hex::decode(CHANGE_ADDRESS).unwrap();

        let mut tx = Transaction::new(&data).unwrap();
        // get number of items with all active outputs
        let num_items = tx.num_items();

        // disable one output.
        tx.disable_output_if(&change_address);

        //get again the number of outputs
        let num_items_hide = tx.num_items();

        // ensure the number of items has changed
        // as there is now one output that is disable
        assert!(num_items > num_items_hide);

        assert!(matches!(tx, Transaction::Transfer(..)));
    }

    #[test]
    #[cfg(feature = "full")]
    //isolation is enabled by defalt in miri
    // and this prevents opening files, amonst other things
    // we could either disable isolation or have miri
    // return errors on open & co.
    //
    // considering we aren't doing anything special in this test
    // we can just avoid having it run in miri directly
    #[cfg_attr(miri, ignore)]
    fn tx_ui() {
        use crate::parser::snapshots_common::{with_leaked, ReducedPage};

        insta::glob!("testvectors/*.json", |path| {
            let file = std::fs::File::open(path)
                .unwrap_or_else(|e| panic!("Unable to open file {:?}: {:?}", path, e));
            let input: Vec<u8> = serde_json::from_reader(file)
                .unwrap_or_else(|e| panic!("Unable to read file {:?} as json: {:?}", path, e));

            let test = |data| {
                let tx = Transaction::new(data).expect("parse tx from data");

                let mut driver = zuit::MockDriver::<_, 18, 1024>::new(tx);
                driver.drive();

                let ui = driver.out_ui();

                let reduced = ui
                    .iter()
                    .flat_map(|item| item.iter().map(ReducedPage::from))
                    .collect::<Vec<_>>();

                insta::assert_debug_snapshot!(reduced);
            };

            unsafe { with_leaked(input, test) };
        });
    }
}
