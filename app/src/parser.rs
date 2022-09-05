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
use core::mem::MaybeUninit;

use zemu_sys::ViewError;

mod address;
mod asset_id;
mod avm_output;
mod constants;
mod coreth;
mod error;
mod initial_state;
mod inputs;
mod message;
mod network_info;
mod object_list;
mod operations;
mod outputs;
mod pvm_output;
mod subnet_auth;
mod subnet_id;
mod transactions;
mod utils;
mod validator;

pub use address::*;
pub use asset_id::AssetId;
pub use avm_output::AvmOutput;
pub use constants::*;
pub use coreth::{export_tx::ExportTx, import_tx::ImportTx};
pub use error::ParserError;
pub use initial_state::{FxId, InitialState};
pub use inputs::{Input, SECPTransferInput, TransferableInput};
pub use message::AvaxMessage;
pub use network_info::*;
pub use object_list::ObjectList;
pub use outputs::{
    NFTMintOutput, NFTTransferOutput, Output, OutputType, SECPMintOutput, SECPOutputOwners,
    SECPTransferOutput, TransferableOutput,
};
pub use pvm_output::PvmOutput;
pub use subnet_auth::SubnetAuth;
pub use subnet_id::*;
pub use transactions::*;
pub use utils::*;
pub use validator::*;

///This trait defines the interface useful in the UI context
/// so that all the different OperationTypes or other items can handle their own UI
pub trait DisplayableItem {
    /// Returns the number of items to display
    fn num_items(&self) -> usize;

    /// This is invoked when a given page is to be displayed
    ///
    /// `item_n` is the item of the operation to display;
    /// guarantee: 0 <= item_n < self.num_items()
    /// `title` is the title of the item
    /// `message` is the contents of the item
    /// `page` is what page we are supposed to display, this is used to split big messages
    ///
    /// returns the total number of pages on success
    ///
    /// It's a good idea to always put `#[inline(never)]` on top of this
    /// function's implementation
    //#[inline(never)]
    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError>;
}

///This trait defines an useful interface to parse
///objects from bytes.
///this gives different objects in a transaction
///a way to define their own deserilization implementation, allowing higher level objects to generalize the
///parsing of their inner types
pub trait FromBytes<'b>: Sized {
    /// this method is avaliable for testing only, as the preferable
    /// option is to save stack by passing the memory where the object should
    /// store itself
    #[cfg(test)]
    fn from_bytes(input: &'b [u8]) -> Result<(&'b [u8], Self), nom::Err<ParserError>> {
        let mut out = MaybeUninit::uninit();
        let rem = Self::from_bytes_into(input, &mut out)?;
        unsafe { Ok((rem, out.assume_init())) }
    }

    ///Main deserialization method
    ///`input` the input data that contains the serialized form in bytes of this object.
    ///`out` the memory where this object would be stored
    ///
    /// returns the remaining bytes on success
    ///
    /// `Safety` Dealing with uninitialize memory is undefine behavior
    /// even in rust, so implementors should follow the rust documentation
    /// for MaybeUninit and unsafe guidelines.
    ///
    /// It's a good idea to always put `#[inline(never)]` on top of this
    /// function's implementation
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>>;
}
