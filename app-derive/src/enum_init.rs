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
use syn::{parse_macro_input, parse_quote_spanned, Field, Ident, ItemEnum, ItemStruct, Variant};

pub fn enum_init(_metadata: TokenStream, input: TokenStream) -> TokenStream {
    let ItemEnum {
        attrs,
        vis,
        ident,
        generics,
        variants,
        ..
    } = parse_macro_input!(input as ItemEnum);

    let type_enum = create_type_enum(&ident, variants.iter().map(|variant| &variant.ident));

    let structs = variants
        .iter()
        .map(|variant| match &variant.fields {
            syn::Fields::Named(_) => Err(syn::Error::new(
                variant.ident.span(),
                "named variants are not supported",
            )),
            syn::Fields::Unit => Ok(create_variant_struct_for_unit(
                &type_enum.ident,
                &variant.ident,
            )),
            syn::Fields::Unnamed(unnamed) => {
                let unnamed = &unnamed.unnamed;
                if unnamed.len() != 1 {
                    Err(syn::Error::new(
                        variant.ident.span(),
                        "only 1 item in field supported",
                    ))
                } else {
                    create_variant_struct_for_unnamed(
                        &type_enum.ident,
                        &variant.ident,
                        unnamed.first().unwrap(),
                    )
                }
            }
        })
        .collect::<Result<Vec<_>, _>>();

    let structs = match structs {
        Ok(s) => s,
        Err(e) => return e.to_compile_error().into(),
    };

    quote! {
        #type_enum

        #(#structs)*

        #(#attrs)*
        #vis enum #ident #generics {
            #variants
        }
    }
    .into()
}

fn create_type_enum<'a>(name: &Ident, variants: impl Iterator<Item = &'a Ident>) -> ItemEnum {
    let name = Ident::new(&format!("{}__Type", name), name.span());

    //simple way to retrieve some items,
    // in this case the attributes and some extra bits
    let ItemEnum {
        attrs,
        enum_token,
        generics,
        brace_token,
        ..
    }: ItemEnum = parse_quote_spanned! { name.span() =>
        #[derive(Clone, Copy, PartialEq)]
        #[cfg_attr(test, derive(Debug))]
        #[allow(non_camel_case_types)]
        #[repr(u8)]
        enum Foo {}
    };

    let variants = variants.cloned().map(|ident| Variant {
        attrs: vec![],
        ident,
        fields: syn::Fields::Unit,
        discriminant: None,
    });

    ItemEnum {
        attrs,
        vis: syn::Visibility::Inherited,
        enum_token,
        ident: name,
        generics,
        brace_token,
        variants: variants.collect(),
    }
}

fn retrieve_generics_from_path(
    span: Span,
    path: &syn::Path,
) -> Result<Vec<syn::GenericArgument>, syn::Error> {
    //traverse all path segements and collect the generics aruments within
    //only angle brackets supported

    let mut generics = vec![];
    for segment in &path.segments {
        match &segment.arguments {
            syn::PathArguments::None => continue,
            syn::PathArguments::Parenthesized(_) => {
                return Err(syn::Error::new(
                    span,
                    "paranthesized generics arguments not supported".to_string(),
                ))
            }
            syn::PathArguments::AngleBracketed(syn::AngleBracketedGenericArguments {
                args,
                ..
            }) => generics.extend(args.iter().cloned()),
        }
    }

    Ok(generics)
}

fn create_variant_struct_for_unnamed(
    type_enum: &Ident,
    name: &Ident,
    inner: &Field,
) -> Result<ItemStruct, syn::Error> {
    let Field {
        attrs: inner_attrs,
        ty: inner_ty,
        ..
    } = inner;

    let generics = match &inner_ty {
        syn::Type::Path(path) => retrieve_generics_from_path(name.span(), &path.path)?,
        _ => todo!("only structs supported"),
    };

    let name = Ident::new(&format!("{}__Variant", name), name.span());

    Ok(parse_quote_spanned! { name.span() =>
        #[allow(non_camel_case_types)]
        #[repr(C)]
        struct #name<#(#generics)*>(#type_enum, #(#inner_attrs)* #inner_ty);
    })
}

fn create_variant_struct_for_unit(type_enum: &Ident, name: &Ident) -> ItemStruct {
    let name = Ident::new(&format!("{}__Variant", name), name.span());

    parse_quote_spanned! { name.span() =>
        #[allow(non_camel_case_types)]
        #[repr(C)]
        struct #name(#type_enum);
    }
}
