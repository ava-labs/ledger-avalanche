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
use proc_macro_error::emit_error;
use syn::{
    punctuated::Punctuated, spanned::Spanned, visit::Visit, Attribute, Error, GenericArgument,
    GenericParam, Generics, Ident, Type, TypePath,
};

/// Helper extension iterator to `syn` things
pub trait SynIteratorExtend: Iterator {
    fn fold_punctuate<P: Default>(self) -> Punctuated<Self::Item, P>
    where
        Self: Sized,
    {
        self.fold(Punctuated::new(), |mut acc, x| {
            acc.push(x);
            acc
        })
    }

    fn syn_try_fold<C, T>(self) -> Result<C, Error>
    where
        Self: Sized,
        Self: Iterator<Item = Result<T, Error>>,
        C: Extend<T> + Default,
    {
        self.fold(Ok(Default::default()), |acc, x| match (acc, x) {
            (Err(e), Ok(_)) | (Ok(_), Err(e)) => Err(e),
            (Err(mut e), Err(e2)) => {
                e.combine(e2);
                Err(e)
            }
            (Ok(mut v), Ok(x)) => {
                v.extend(std::iter::once(x));
                Ok(v)
            }
        })
    }
}

impl<I: Iterator> SynIteratorExtend for I {}

/// Collect all generic arguments in a given item
#[derive(Default, Clone)]
pub struct GenericArgumentsCollector<'ast> {
    pub generics: Vec<&'ast GenericArgument>,
    pub idents: Vec<&'ast Ident>,
    filter: Option<Vec<&'ast Ident>>,
}

impl<'ast> GenericArgumentsCollector<'ast> {
    pub fn traverse_type(ty: &'ast Type, filter: impl Into<Option<Vec<&'ast Ident>>>) -> Self {
        let mut this = Self::default().with_filter(filter.into());

        match ty {
            Type::Array(i) => this.visit_type_array(i),
            Type::Path(i) => this.visit_type_path(i),
            Type::Tuple(i) => this.visit_type_tuple(i),
            _ => emit_error!(ty.span(), "unsupported type"),
        }

        this
    }

    pub fn traverse_generics(
        g: &'ast Generics,
        filter: impl Into<Option<Vec<&'ast Ident>>>,
    ) -> Self {
        let mut this = Self::default().with_filter(filter.into());

        this.visit_generics(g);

        this
    }

    pub fn with_filter(mut self, filter: Option<Vec<&'ast Ident>>) -> Self {
        self.filter = filter;
        self
    }
}

impl<'ast> Visit<'ast> for GenericArgumentsCollector<'ast> {
    fn visit_parenthesized_generic_arguments(
        &mut self,
        i: &'ast syn::ParenthesizedGenericArguments,
    ) {
        emit_error!(i.span(), "paranthesized generics arguments not supported")
    }

    fn visit_generic_argument(&mut self, i: &'ast GenericArgument) {
        match i {
            GenericArgument::Lifetime(syn::Lifetime { ident, .. }) => {
                if let Some(filter) = &self.filter {
                    if filter.contains(&ident) {
                        self.generics.push(i);
                    }
                } else {
                    self.generics.push(i);
                }

                self.idents.push(ident);
                syn::visit::visit_generic_argument(self, i)
            }
            //everything else that makes sense to collect
            // includes const items (if identities)
            GenericArgument::Type(Type::Path(TypePath { path, .. })) => {
                let ident = path.get_ident();

                if let (Some(filter), Some(ident)) = (&self.filter, &ident) {
                    if filter.contains(ident) {
                        self.generics.push(i)
                    }
                } else {
                    self.generics.push(i);
                }

                if let Some(ident) = ident {
                    self.idents.push(ident)
                }
                syn::visit::visit_generic_argument(self, i)
            }
            _ => {}
        }
    }
}

/// Collect generics params of a given generics
#[derive(Default, Clone)]
pub struct GenericParamsCollector<'ast> {
    pub params: Vec<&'ast GenericParam>,
    pub idents: Vec<&'ast Ident>,
}

impl<'ast> GenericParamsCollector<'ast> {
    pub fn traverse_generics(generics: &'ast Generics) -> Self {
        let mut this = Self::default();

        this.visit_generics(generics);

        this
    }

    pub fn traverse_type(ty: &'ast Type) -> Self {
        let mut this = Self::default();

        this.visit_type(ty);

        this
    }
}

impl<'ast> Visit<'ast> for GenericParamsCollector<'ast> {
    fn visit_generic_param(&mut self, i: &'ast GenericParam) {
        self.params.push(i);

        match i {
            GenericParam::Type(t) => self.idents.push(&t.ident),
            GenericParam::Lifetime(l) => self.idents.push(&l.lifetime.ident),
            GenericParam::Const(c) => self.idents.push(&c.ident),
        }
    }
}

///Filter out attributes that are doc comments
pub fn remove_doc_comment_attributes(attrs: Vec<Attribute>) -> Vec<Attribute> {
    attrs
        .into_iter()
        .filter(|a| !a.path().is_ident("doc"))
        .collect()
}

/// Keep all attributes that the macro supports being above variants
///
/// These attributes will be propagated on top of all generated items
pub fn cfg_variant_attributes(attrs: Vec<Attribute>) -> Vec<Attribute> {
    attrs
        .into_iter()
        .filter(|a| a.path().is_ident("cfg"))
        .collect()
}

/// Collect idents
#[derive(Default, Clone)]
pub struct IdentsCollector<'ast> {
    pub idents: Vec<&'ast Ident>,
}

impl<'ast> IdentsCollector<'ast> {
    pub fn traverse_generics(generics: &'ast Generics) -> Self {
        let mut this = Self::default();

        this.visit_generics(generics);

        this
    }

    pub fn traverse_type(ty: &'ast Type) -> Self {
        let mut this = Self::default();

        this.visit_type(ty);

        this
    }

    pub fn traverse_generic_arguments(arguments: &[&'ast GenericArgument]) -> Self {
        let mut this = Self::default();

        for arg in arguments {
            this.visit_generic_argument(arg);
        }

        this
    }
}

impl<'ast> Visit<'ast> for IdentsCollector<'ast> {
    fn visit_ident(&mut self, i: &'ast Ident) {
        self.idents.push(i);
    }
}
