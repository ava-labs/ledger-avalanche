/*******************************************************************************
*   (c) 2022 Zondax AG
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
use proc_macro_error::{abort, abort_if_dirty};
use quote::{quote, ToTokens};
use syn::{
    parse_macro_input, parse_quote, parse_quote_spanned, punctuated::Punctuated, token::Comma,
    Attribute, Field, GenericArgument, Generics, Ident, ItemEnum, ItemImpl, ItemStruct, Token,
    Type, Variant, Visibility,
};

use crate::utils::*;
use convert_case::Casing;

pub fn enum_init(_metadata: TokenStream, input: TokenStream) -> TokenStream {
    let ItemEnum {
        attrs,
        vis,
        ident,
        generics,
        variants,
        ..
    } = parse_macro_input!(input as ItemEnum);

    let type_enum = create_type_enum(
        &ident,
        variants.iter().map(|variant| {
            (
                &variant.ident,
                cfg_variant_attributes(variant.attrs.clone()),
            )
        }),
    );

    let items = variants.iter().map(|variant| match &variant.fields {
        syn::Fields::Named(named) => {
            let cfg_attrs = cfg_variant_attributes(variant.attrs.clone());

            // create the struct definition containing the fields
            // so later we can treat it as an "unnamed" field
            let def = create_data_struct_for_named(
                &variant.ident,
                &remove_doc_comment_attributes(attrs.clone()),
                &cfg_attrs,
                named.named.clone(),
                &GenericParamsCollector::traverse_generics(&generics).idents,
            );

            //make the Type of the "unnamed" variant
            // which is simply the struct we just created
            // + the necessary generics
            let def_generics = &def.generics.params;
            let def_name = &variant.ident;
            let inner: Type = parse_quote_spanned! { variant.ident.span() =>
                    #def_name<#def_generics>
            };
            let variant_struct = create_variant_struct_for_unnamed(
                &type_enum.ident,
                &variant.ident,
                &cfg_attrs,
                &Field {
                    attrs: variant.attrs.clone(),
                    vis: Visibility::Inherited,
                    ident: None,
                    colon_token: None,
                    ty: inner.clone(),
                },
            );

            //create the initializer helper
            let block = impl_initializer(
                &ident,
                &generics,
                &type_enum.ident,
                &variant.ident,
                IdentsCollector::traverse_type(&inner)
                    .idents
                    .first()
                    .unwrap(),
                GenericArgumentsCollector::traverse_type(&inner, None).generics,
                &variant_struct.ident,
                &cfg_attrs,
            );

            quote! { #def #variant_struct #block }
        }
        syn::Fields::Unit => {
            let cfg_attrs = cfg_variant_attributes(variant.attrs.clone());
            create_variant_struct_for_unit(&type_enum.ident, &variant.ident, &cfg_attrs)
                .to_token_stream()
        }
        syn::Fields::Unnamed(unnamed) => {
            let cfg_attrs = cfg_variant_attributes(variant.attrs.clone());

            let unnamed = &unnamed.unnamed;
            if unnamed.len() != 1 {
                abort!(variant.ident.span(), "only 1 item in field supported")
            } else {
                let field = unnamed.first().unwrap();
                let variant_struct = create_variant_struct_for_unnamed(
                    &type_enum.ident,
                    &variant.ident,
                    &cfg_attrs,
                    field,
                );

                //create the initializer helper
                let block = impl_initializer(
                    &ident,
                    &generics,
                    &type_enum.ident,
                    &variant.ident,
                    IdentsCollector::traverse_type(&field.ty)
                        .idents
                        .first()
                        .unwrap(),
                    GenericArgumentsCollector::traverse_type(&field.ty, None).generics,
                    &variant_struct.ident,
                    &cfg_attrs,
                );

                quote! { #variant_struct #block }
            }
        }
    });

    //if we emitted errors let's abort before we emit weird data
    abort_if_dirty();

    quote! {
        #type_enum

        #(#items)*

        #(#attrs)*
        #[repr(u8)]
        #vis enum #ident #generics {
            #variants
        }
    }
    .into()
}

/// Creates an enum that only contains unit variants with the given names and attributes for the variants
fn create_type_enum<'a>(
    name: &Ident,
    variants: impl Iterator<Item = (&'a Ident, Vec<Attribute>)>,
) -> ItemEnum {
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

    let variants = variants.map(|(ident, attrs)| Variant {
        attrs,
        ident: ident.clone(),
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

///Create a struct for the specific enum variant with unnamed field
fn create_variant_struct_for_unnamed(
    type_enum: &Ident,
    name: &Ident,
    extra_attrs: &[Attribute],
    inner: &Field,
) -> ItemStruct {
    let Field {
        attrs: inner_attrs,
        ty: inner_ty,
        ..
    } = inner;

    let generics = GenericArgumentsCollector::traverse_type(inner_ty, None)
        .generics
        .into_iter()
        .fold_punctuate::<Token![,]>();

    let name = Ident::new(&format!("{}__Variant", name), name.span());

    parse_quote_spanned! { name.span() =>
        #[allow(non_camel_case_types)]
        #[repr(C)]
        #(#extra_attrs)*
        pub struct #name<#generics>(#type_enum, #(#inner_attrs)* #inner_ty);
    }
}

///Create a struct for the specific enum variant with no fields
fn create_variant_struct_for_unit(
    type_enum: &Ident,
    name: &Ident,
    extra_attrs: &[Attribute],
) -> ItemStruct {
    let name = Ident::new(&format!("{}__Variant", name), name.span());

    parse_quote_spanned! { name.span() =>
        #[allow(non_camel_case_types)]
        #[repr(C)]
        #(#extra_attrs)*
        struct #name(#type_enum);
    }
}

///Create a struct for the specific enum variant with named fields
fn create_data_struct_for_named(
    name: &Ident,
    variant_attrs: &[Attribute],
    //attributes that we want on top of the struct definition
    // NOT the variant attributes
    extra_attrs: &[Attribute],
    fields: Punctuated<Field, Comma>,
    //the list of generics that are valid
    filter_generics: &[&Ident],
) -> ItemStruct {
    let mut generics = fields
        .iter()
        .flat_map(|Field { ty: inner_ty, .. }| {
            GenericArgumentsCollector::traverse_type(inner_ty, filter_generics.to_vec()).generics
        })
        .collect::<Vec<_>>();

    //remove duplicated, like multiple instances of the same lifetime
    // since we collected them from _all_ fields
    generics.dedup();

    //punctuate
    let generics = generics.into_iter().fold_punctuate::<Token![,]>();

    parse_quote_spanned! { name.span() =>
        #(#extra_attrs)*
        #(#variant_attrs)*
        #[repr(C)]
        pub struct #name <#generics> {
            #fields
        }
    }
}

/// Create an initializer impl block for `name` (with the given `generics`)
///
/// The impl block will contain a function of the form `init_as` to initialize
/// the enum with a specific `variant`, casting with the given `variant_struct`
/// and using the given `type_enum` to construct the discriminator
///
/// Doesn't make sense to be used for unit variants, so we have the generation there instead
#[allow(clippy::too_many_arguments)]
pub fn impl_initializer(
    name: &Ident,
    generics: &Generics,
    type_enum: &Ident,
    variant: &Ident,
    inner_name: &Ident,
    variant_generics: Vec<&GenericArgument>,
    variant_struct: &Ident,
    block_attrs: &[Attribute],
) -> ItemImpl {
    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();

    let variant_method_name = Ident::new(
        &format!(
            "init_as_{}",
            variant.to_string().to_case(convert_case::Case::Snake)
        ),
        variant.span(),
    );

    let extra_generics = {
        let variant_generics =
            IdentsCollector::traverse_generic_arguments(&variant_generics).idents;
        //this represents all the generic arguments used in the enum type definition
        let mut generic_params = GenericParamsCollector::traverse_generics(generics).idents;
        generic_params.dedup();

        //filter the list out so we don't have duplicates
        // in the function definition
        // since the generics would have appeared in the impl block
        variant_generics
            .into_iter()
            .filter(|arg| !generic_params.contains(arg))
            .fold_punctuate::<Token![,]>()
    };

    let variant_generics = variant_generics.iter().fold_punctuate::<Token![,]>();

    parse_quote! {
        #(#block_attrs)*
        impl #impl_generics #name #type_generics #where_clause {
            #[doc = "Initialize #name::#variant with the given closure"]
            #[doc = ""]
            #[doc = "The closure accepts a mutable reference to `MaybeUninit<#variant_struct>`"]
            #[doc = "which is supposed to be written to"]
            pub fn #variant_method_name <__T, __F, #extra_generics> (mut init: __F, out: &mut ::core::mem::MaybeUninit<Self>) -> __T
            where
                __F: FnMut(&mut ::core::mem::MaybeUninit<#inner_name<#variant_generics>>) -> __T
            {
                let out = out.as_mut_ptr() as *mut #variant_struct;
                unsafe {
                    ::core::ptr::addr_of_mut!((*out).0).write(#type_enum::#variant);
                }

                let item = unsafe { &mut * ::core::ptr::addr_of_mut!((*out).1).cast() };

                init(item)
            }
        }
    }
}
