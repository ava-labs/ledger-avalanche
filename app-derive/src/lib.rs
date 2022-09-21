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

//! This crate exports 2 macros with a specific use case for the ledger-avalanche app
//!
//! See [macro@unroll] for more documentation

use proc_macro::TokenStream;

mod version;
#[proc_macro]
/// Reads the file located at the provided input path extracts the version variables from it.
///
/// The expected contents of the file is a list of definitions of the format
/// `NAME=VALUE`
///
/// Each value is parsed and saved as an `u8`, and each definition will
/// be made available in the macro call site with the provided name.
///
/// # Note
///
/// The provided path will be made relative to the `CARGO_MANIFEST_DIR` of the invoking crate.
///
/// In other words, the provided input path will have the current crate's root directory prepended
pub fn version(input: TokenStream) -> TokenStream {
    version::version(input)
}

mod unroll;
#[proc_macro]
/// Reads the file located at the provided input path and "unrolls" it.
///
/// The expected contents of the file is a JSON array of [unroll::KnownChain],
/// these will be read and the IDs will be compacted slightly before
/// being all put in a function that will convert a given chainID to an alias
///
/// # Note
///
/// The provided path will be made relative to the `CARGO_MANIFEST_DIR` of the invoking crate.
///
/// In other words, the provided input path will have the current crate's root directory prepended
pub fn unroll(input: TokenStream) -> TokenStream {
    unroll::unroll(input)
}

mod enum_init;
#[proc_macro_attribute]
/// The aim of this macro is to ease the writing of boilerplate for enums
/// where we want to initialize said enum using [`MaybeUninit`].
///
/// The macro will generate an enum with N unit variants and N structs
/// based on the number of variants of the original enum.
///
/// # Example
/// ```rust,ignore
/// #[enum_init]
/// pub enum Foo {
///     Bar(BarStruct),
///     Baz(BazStruct)
/// }
///
/// //will generate
/// #[repr(u8)]
/// enum FooType {
///     Bar,
///     Baz
/// }
///
/// #[repr(C)]
/// struct BarVariant(FooType, Bar);
///
/// #[repr(C)]
/// struct BazVariant(FooType, Baz);
/// ```
pub fn enum_init(metadata: TokenStream, input: TokenStream) -> TokenStream {
    enum_init::enum_init(metadata, input)
}
