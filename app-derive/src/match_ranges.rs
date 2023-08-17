/*******************************************************************************
*   (c) 2023 Zondax AG
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

use std::iter::FromIterator;

use proc_macro::TokenStream;
use proc_macro_error::abort;
use quote::quote;

use syn::{
    parse::{Parse, Parser},
    parse_macro_input, parse_quote,
    spanned::Spanned,
    Expr, Ident, Lit, Token,
};

mod kw {
    syn::custom_keyword!(alias);
    pub use alias as ident_name_token;

    syn::custom_keyword!(until);
}

fn ident_to_path(ident: Ident) -> syn::Path {
    let segment = syn::PathSegment::from(ident);
    let segments = syn::punctuated::Punctuated::from_iter([segment]);

    syn::Path {
        leading_colon: None,
        segments,
    }
}

fn expr_to_paren_expr(expr: Box<Expr>) -> Box<Expr> {
    parse_quote! { ( #expr ) }
}

#[derive(Debug)]
enum RangePat {
    Lit(Lit),
    Ident(Ident),
    Wild(Token![_]),
}

impl RangePat {
    fn is_wild(&self) -> bool {
        matches!(self, Self::Wild(_))
    }

    fn as_expr(&self) -> Option<Expr> {
        match self {
            Self::Lit(lit) => Some(Expr::Lit(syn::ExprLit {
                attrs: vec![],
                lit: Lit::Int(syn::LitInt::new("1", lit.span())),
            })),
            Self::Ident(ident) => Some(Expr::Path(syn::ExprPath {
                attrs: vec![],
                qself: None,
                path: ident_to_path(ident.clone()),
            })),
            Self::Wild(_) => None,
        }
    }

    fn span(&self) -> proc_macro2::Span {
        match self {
            RangePat::Lit(lit) => lit.span(),
            RangePat::Ident(ident) => ident.span(),
            RangePat::Wild(wild) => wild.span(),
        }
    }
}

impl Parse for RangePat {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        if let Ok(wild) = input.parse::<Token![_]>() {
            Ok(Self::Wild(wild))
        } else if let Ok(ident) = input.parse::<Ident>() {
            Ok(Self::Ident(ident))
        } else if let Ok(lit) = input.parse::<Lit>() {
            Ok(Self::Lit(lit))
        } else {
            Err(input.error("Expected identifier, literal or _"))
        }
    }
}

#[derive(Debug)]
struct RangeArm {
    pat: RangePat,
    extra_guard: Option<(Token![if], Box<Expr>)>,
    fat_arrow_token: Token![=>],
    body: Box<Expr>,
    comma: Option<Token![,]>,
}

impl Parse for RangeArm {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let pat = input.parse()?;
        let extra_guard = if let Ok(if_token) = input.parse::<Token![if]>() {
            Some((if_token, Box::new(input.parse()?)))
        } else {
            None
        };
        let fat_arrow_token = input.parse()?;
        let body = input.parse()?;
        let comma = match input.parse() {
            Ok(comma) => Some(comma),
            Err(_) => None,
        };

        Ok(RangeArm {
            pat,
            extra_guard,
            fat_arrow_token,
            body,
            comma,
        })
    }
}

struct MatchRanges {
    match_token: Token![match],
    expr: Box<Expr>,
    ident_name_token: kw::ident_name_token,
    ident_name: Ident,
    arms: Vec<RangeArm>,
}

impl MatchRanges {
    fn base_for_arm(&self, idx: usize) -> Option<Box<Expr>> {
        let arms = self.arms.get(..idx).expect("arm idx in range");
        match arms {
            [] => None,
            [first] => first.pat.as_expr().map(Box::new),
            [first, rest @ ..] => {
                let first = first.pat.as_expr().map(Box::new).unwrap_or_else(|| {
                    let span = first.pat.span();
                    abort!(span, "wilcard is only allowed in the last arm")
                });
                Some(rest.iter().fold(first, |acc, x| {
                    let acc = expr_to_paren_expr(acc);
                    if let Some(expr) = x.pat.as_expr().map(Box::new) {
                        parse_quote! { #acc + #expr }
                    } else {
                        acc
                    }
                }))
            }
        }
    }

    fn guard_for_arm(&self, idx: usize) -> Option<Box<Expr>> {
        let ident = &self.ident_name;
        let next = self.arms.get(idx).expect("arm idx in range");

        let base = self.base_for_arm(idx);

        let is_wild = next.pat.is_wild();
        let guard = match (base, next.pat.as_expr()) {
            _ if is_wild => None,
            (None, None) => None,
            (Some(base), None) => Some(parse_quote! { #ident < #base }),
            (Some(base), Some(expr)) => {
                Some(parse_quote! { (#ident >= #base) && (#ident < #base + #expr) })
            }
            (None, Some(expr)) => Some(parse_quote! { #ident < #expr }),
        };

        match (guard, &next.extra_guard) {
            (None, None) => None,
            (None, Some((_, expr))) => Some(expr.clone()),
            (Some(expr), None) => Some(expr),
            (Some(expr), Some((_, extra_guard))) => Some(parse_quote! { (#expr) && #extra_guard }),
        }
    }

    fn pat_for_arm(&self, idx: usize) -> Option<syn::Pat> {
        let ident = &self.ident_name;
        let arm = self.arms.get(idx).expect("arm idx in range");
        let tokens: TokenStream = match &arm.pat {
            RangePat::Lit(lit) => quote! { #ident @ #lit },
            RangePat::Ident(..) | RangePat::Wild(_) => quote! { #ident },
        }
        .into();

        let parser = syn::Pat::parse_single;
        Some(parser.parse(tokens).unwrap())
    }

    pub fn arms(&'_ self) -> impl Iterator<Item = syn::Arm> + '_ {
        let ident = &self.ident_name;

        self.arms
            .iter()
            .enumerate()
            .map(move |(i, RangeArm { body, pat, .. })| {
                let is_wild = pat.is_wild();

                let pat = self.pat_for_arm(i);
                let base = self.base_for_arm(i);
                let guard = match self.guard_for_arm(i) {
                    None => quote! {},
                    Some(guard) => quote! { if #guard },
                };

                let body = match base {
                    Some(base) if !is_wild => quote! {
                        {
                            let #ident = #ident - (#base);
                            #body
                        }
                    },
                    _ => quote! { #body },
                };

                parse_quote! {
                    #pat #guard => #body
                }
            })
    }
}

impl Parse for MatchRanges {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let match_token: Token![match] = input.parse()?;
        let expr: Box<Expr> = input.parse()?;
        let ident_name_token = input.parse()?;
        let ident_name: Ident = input.parse()?;

        // Parse arms inside curly braces
        let content;
        let _ = syn::braced!(content in input);
        let mut arms = Vec::new();
        while !content.is_empty() {
            arms.push(content.call(RangeArm::parse)?);
        }

        Ok(MatchRanges {
            match_token,
            expr,
            ident_name_token,
            ident_name,
            arms: arms.into_iter().collect(),
        })
    }
}

pub fn match_ranges(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as MatchRanges);

    let expr = input.expr.clone();
    let arms = input.arms();

    quote! {
        #[allow(unused_variables)]
        match #expr {
            #(#arms),*
        }
    }
    .into()
}
