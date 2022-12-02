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
use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{parse_macro_input, Error, Expr, ExprArray, ExprLit, LitByte, LitStr};

use std::{
    convert::{TryFrom, TryInto},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

/// This structs represents the expected schematic of the chain ids data
#[derive(Clone, Serialize, Deserialize)]
struct KnownChain {
    alias: String,
    #[serde(alias = "chainID")]
    id: String,
}

///This struct is the chain ID data decoded (for the address)
/// and ready to be used for code generation
#[derive(PartialEq, Eq)]
struct ReducedID {
    id: [u8; 32],
    alias: String,
}

impl Ord for ReducedID {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl PartialOrd for ReducedID {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl TryFrom<KnownChain> for ReducedID {
    type Error = bs58::decode::Error;
    fn try_from(from: KnownChain) -> Result<Self, Self::Error> {
        let vid = bs58::decode(from.id.as_bytes()).as_cb58(None).into_vec()?;

        let mut id = [0; 32];
        id.copy_from_slice(&vid);

        Ok(Self {
            alias: from.alias,
            id,
        })
    }
}

pub fn unroll(input: TokenStream) -> TokenStream {
    let data_filepath = parse_macro_input!(input as LitStr);

    let data = match retrieve_data(data_filepath.value(), data_filepath.span()) {
        Err(e) => return e.into_compile_error().into(),
        Ok(data) => data,
    };

    let elems = data.into_iter().map(|ReducedID { alias, id }| {
        let alias = alias.as_str();
        let id = ExprArray {
            attrs: vec![],
            bracket_token: Default::default(),
            elems: id
                .iter()
                .map(|&num| LitByte::new(num, Span::call_site()))
                .map(|lit| {
                    Expr::Lit(ExprLit {
                        attrs: vec![],
                        lit: lit.into(),
                    })
                })
                .collect(),
        };
        quote! {
            (&#id, #alias)
        }
    });

    let out = quote! {

        #[cfg_attr(test, derive(Debug))]
        pub struct ChainNotFound;

        type KnownChainIDsTable<'data> = [(&'data [u8], &'data str)];

        pub const KNOWN_CHAINS: &KnownChainIDsTable<'_> = &[
            #(#elems, )*
        ];

        #[inline(never)]
        pub fn chain_alias_lookup(id: &[u8; 32]) -> Result<&'static str, ChainNotFound> {
            zemu_log_stack("chain_alias_lookup\x00");

            let known_ids: &KnownChainIDsTable<'_> = {
                let data = KNOWN_CHAINS;
                let data_len = data.len();

                let to_pic = data.as_ptr() as usize;
                let picced = unsafe { PIC::manual(to_pic) } as *const ();

                //cast to same type as `to_pic`
                let ptr = picced.cast();
                unsafe {
                    ::core::slice::from_raw_parts(ptr, data_len)
                }
            };

            let out_idx = known_ids
                .binary_search_by(|&(probe_id, _)| {
                    let probe_id = PIC::new(probe_id).into_inner();

                    probe_id.cmp(id)
                })
                .map_err(|_| ChainNotFound)?;

            match known_ids.get(out_idx) {
                Some((_, alias)) => Ok(PIC::new(*alias).into_inner()),
                None => unsafe { core::hint::unreachable_unchecked() }
            }
        }

    };

    out.into()
}

fn retrieve_data(path: impl AsRef<Path>, path_span: Span) -> Result<Vec<ReducedID>, Error> {
    let base_path: PathBuf = ::std::env::var_os("CARGO_MANIFEST_DIR")
        .expect("Missing `CARGO_MANIFEST_DIR` env var")
        .into();

    let mut data_path = base_path;
    data_path.push(path.as_ref());

    let data_path = match data_path.canonicalize() {
        Ok(path) => path,
        Err(err) => {
            return Err(Error::new(
                path_span,
                format!(
                    "Invalid path provided. Input path: {}; err={:?}",
                    data_path.display(),
                    err
                ),
            ));
        }
    };

    let data = std::fs::read_to_string(data_path.as_path()).map_err(|err| {
        Error::new(
            path_span,
            format!("Could not read file. Path: {:?}; err={:?}", data_path, err),
        )
    })?;

    let chains: Vec<KnownChain> = serde_json::from_str(&data)
        .map_err(|err| Error::new(path_span, format!("File was not valid JSON. err={:?}", err)))?;

    let data: Result<Vec<_>, _> = chains
        .into_iter()
        .enumerate()
        .map(|(i, item)| item.try_into().map_err(|e| (i, e)))
        .collect();

    data.map_err(|(i, e)| {
        Error::new(
            path_span,
            format!("Entry #{}'s chainID was not valid base58; err={:?}", i, e),
        )
    })
    .map(|mut v| {
        v.dedup();
        v.sort();
        v
    })
}
