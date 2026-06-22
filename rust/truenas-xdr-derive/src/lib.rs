//! Derive macros for [`truenas-xdr`](https://docs.rs/truenas-xdr): `XdrEnum` and
//! `XdrUnion`. They read a type's explicit `#[repr(iN)]` discriminants and generate
//! `serde::Serialize`/`Deserialize` impls that encode/decode the **declared** `i32`
//! discriminant value — required for byte-exact RFC-4506 enums/unions with discriminant
//! gaps (e.g. the FreeBSD `sctrl` union where `grab = 4`, not the arm index `3`).
//!
//! - `#[derive(XdrEnum)]` — a field-less enum, encoded as a single `i32`.
//! - `#[derive(XdrUnion)]` — a discriminated union (data-bearing enum), encoded as an
//!   `i32` discriminant followed by the active arm's fields (a void arm emits only the tag).
//!
//! Limitations (documented): discriminants must be integer literals (an explicit `= N`,
//! or implicit sequential `prev + 1`); a non-literal const-expr discriminant or a generic
//! type is a compile error — use the manual `XdrEnum<E>` wrapper there.

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, Data, DataEnum, DeriveInput, Expr, ExprLit, ExprUnary, Fields, Lit, UnOp};

/// Derive `Serialize`/`Deserialize` for a field-less enum, encoding it as its declared
/// `i32` discriminant.
#[proc_macro_derive(XdrEnum)]
pub fn derive_xdr_enum(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_enum(input).unwrap_or_else(|e| e.to_compile_error().into())
}

/// Derive `Serialize`/`Deserialize` for a discriminated union (data-bearing enum),
/// encoding it as an `i32` discriminant + the active arm.
#[proc_macro_derive(XdrUnion)]
pub fn derive_xdr_union(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_union(input).unwrap_or_else(|e| e.to_compile_error().into())
}

/// Parse a discriminant `Expr` (`= N` or `= -N`) as an `i32`.
fn parse_disc(expr: &Expr) -> syn::Result<i32> {
    match expr {
        Expr::Lit(ExprLit { lit: Lit::Int(li), .. }) => li.base10_parse::<i32>(),
        Expr::Unary(ExprUnary { op: UnOp::Neg(_), expr, .. }) => {
            if let Expr::Lit(ExprLit { lit: Lit::Int(li), .. }) = &**expr {
                Ok(-(li.base10_parse::<i32>()?))
            } else {
                Err(syn::Error::new_spanned(expr, "expected an integer literal discriminant"))
            }
        }
        _ => Err(syn::Error::new_spanned(
            expr,
            "XdrEnum/XdrUnion needs an explicit integer-literal discriminant (e.g. `= 4`)",
        )),
    }
}

/// The `i32` discriminant of every variant (explicit literal, else sequential `prev + 1`).
fn discriminants(data: &DataEnum) -> syn::Result<Vec<i32>> {
    let mut next: i32 = 0;
    let mut out = Vec::with_capacity(data.variants.len());
    for v in &data.variants {
        let value = match &v.discriminant {
            Some((_, expr)) => parse_disc(expr)?,
            None => next,
        };
        out.push(value);
        next = value
            .checked_add(1)
            .ok_or_else(|| syn::Error::new_spanned(v, "discriminant overflows i32"))?;
    }
    Ok(out)
}

/// Reject generics (the codec's wire layout is for concrete types; documented limitation).
fn reject_generics(input: &DeriveInput) -> syn::Result<()> {
    if input.generics.params.is_empty() {
        Ok(())
    } else {
        Err(syn::Error::new_spanned(
            &input.generics,
            "XdrEnum/XdrUnion does not support generic types",
        ))
    }
}

fn expand_enum(input: DeriveInput) -> syn::Result<TokenStream> {
    reject_generics(&input)?;
    let name = &input.ident;
    let data = match &input.data {
        Data::Enum(d) => d,
        _ => return Err(syn::Error::new_spanned(&input, "XdrEnum can only be derived for enums")),
    };
    for v in &data.variants {
        if !matches!(v.fields, Fields::Unit) {
            return Err(syn::Error::new_spanned(
                v,
                "XdrEnum requires field-less variants; use XdrUnion for data-bearing variants",
            ));
        }
    }
    let discs = discriminants(data)?;
    let idents: Vec<_> = data.variants.iter().map(|v| &v.ident).collect();

    let expanded = quote! {
        impl ::serde::Serialize for #name {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> ::core::result::Result<S::Ok, S::Error> {
                let disc: i32 = match self { #( #name::#idents => #discs, )* };
                serializer.serialize_i32(disc)
            }
        }
        impl<'de> ::serde::Deserialize<'de> for #name {
            fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> ::core::result::Result<Self, D::Error> {
                let disc = <i32 as ::serde::Deserialize>::deserialize(deserializer)?;
                match disc {
                    #( #discs => ::core::result::Result::Ok(#name::#idents), )*
                    other => ::core::result::Result::Err(
                        <D::Error as ::serde::de::Error>::custom(
                            ::std::format!("unknown {} discriminant {}", ::core::stringify!(#name), other),
                        ),
                    ),
                }
            }
        }
    };
    Ok(expanded.into())
}

fn expand_union(input: DeriveInput) -> syn::Result<TokenStream> {
    reject_generics(&input)?;
    let name = &input.ident;
    let data = match &input.data {
        Data::Enum(d) => d,
        _ => return Err(syn::Error::new_spanned(&input, "XdrUnion can only be derived for enums")),
    };
    let discs = discriminants(data)?;

    let mut ser_arms = Vec::new();
    let mut de_arms = Vec::new();
    let mut max_elems = 1usize; // tag + widest arm

    for (v, &disc) in data.variants.iter().zip(&discs) {
        let ident = &v.ident;
        match &v.fields {
            Fields::Unit => {
                ser_arms.push(quote! {
                    #name::#ident => {
                        let mut tup = serializer.serialize_tuple(1)?;
                        ::serde::ser::SerializeTuple::serialize_element(&mut tup, &(#disc as i32))?;
                        ::serde::ser::SerializeTuple::end(tup)
                    }
                });
                de_arms.push(quote! { #disc => ::core::result::Result::Ok(#name::#ident), });
            }
            Fields::Unnamed(fields) => {
                let n = fields.unnamed.len();
                max_elems = max_elems.max(1 + n);
                let binds: Vec<_> = (0..n).map(|i| format_ident!("__f{}", i)).collect();
                ser_arms.push(quote! {
                    #name::#ident( #(#binds),* ) => {
                        let mut tup = serializer.serialize_tuple(1 + #n)?;
                        ::serde::ser::SerializeTuple::serialize_element(&mut tup, &(#disc as i32))?;
                        #( ::serde::ser::SerializeTuple::serialize_element(&mut tup, #binds)?; )*
                        ::serde::ser::SerializeTuple::end(tup)
                    }
                });
                de_arms.push(quote! {
                    #disc => {
                        #( let #binds = ::serde::de::SeqAccess::next_element(&mut seq)?
                            .ok_or_else(|| <A::Error as ::serde::de::Error>::custom("missing XDR union field"))?; )*
                        ::core::result::Result::Ok(#name::#ident( #(#binds),* ))
                    }
                });
            }
            Fields::Named(fields) => {
                let n = fields.named.len();
                max_elems = max_elems.max(1 + n);
                let fnames: Vec<_> = fields.named.iter().map(|f| f.ident.as_ref().unwrap()).collect();
                let binds: Vec<_> = (0..n).map(|i| format_ident!("__f{}", i)).collect();
                ser_arms.push(quote! {
                    #name::#ident { #( #fnames: #binds ),* } => {
                        let mut tup = serializer.serialize_tuple(1 + #n)?;
                        ::serde::ser::SerializeTuple::serialize_element(&mut tup, &(#disc as i32))?;
                        #( ::serde::ser::SerializeTuple::serialize_element(&mut tup, #binds)?; )*
                        ::serde::ser::SerializeTuple::end(tup)
                    }
                });
                de_arms.push(quote! {
                    #disc => {
                        #( let #binds = ::serde::de::SeqAccess::next_element(&mut seq)?
                            .ok_or_else(|| <A::Error as ::serde::de::Error>::custom("missing XDR union field"))?; )*
                        ::core::result::Result::Ok(#name::#ident { #( #fnames: #binds ),* })
                    }
                });
            }
        }
    }

    let expanded = quote! {
        impl ::serde::Serialize for #name {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> ::core::result::Result<S::Ok, S::Error> {
                match self { #( #ser_arms )* }
            }
        }
        impl<'de> ::serde::Deserialize<'de> for #name {
            fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> ::core::result::Result<Self, D::Error> {
                struct __Visitor;
                impl<'de> ::serde::de::Visitor<'de> for __Visitor {
                    type Value = #name;
                    fn expecting(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                        f.write_str(::core::concat!("XDR union ", ::core::stringify!(#name)))
                    }
                    fn visit_seq<A: ::serde::de::SeqAccess<'de>>(self, mut seq: A) -> ::core::result::Result<#name, A::Error> {
                        let tag: i32 = ::serde::de::SeqAccess::next_element(&mut seq)?
                            .ok_or_else(|| <A::Error as ::serde::de::Error>::custom("missing XDR union discriminant"))?;
                        match tag {
                            #( #de_arms )*
                            other => ::core::result::Result::Err(
                                <A::Error as ::serde::de::Error>::custom(
                                    ::std::format!("unknown {} discriminant {}", ::core::stringify!(#name), other),
                                ),
                            ),
                        }
                    }
                }
                ::serde::Deserializer::deserialize_tuple(deserializer, #max_elems, __Visitor)
            }
        }
    };
    Ok(expanded.into())
}
