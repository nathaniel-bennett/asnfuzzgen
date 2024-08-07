//! `APER` Code generation for ASN.1 INTEGER Type

use quote::quote;

use crate::{attrs::TyCodecParams, utils};

pub(super) fn generate_aper_codec_for_asn_integer(
    ast: &syn::DeriveInput,
    params: &TyCodecParams,
    aligned: bool,
) -> proc_macro::TokenStream {
    let name = &ast.ident;

    let (codec_path, codec_encode_fn, codec_decode_fn, ty_encode_path, ty_decode_path) = if aligned
    {
        (
            quote!(asnfuzzgen_codecs::aper::AperCodec),
            quote!(aper_encode),
            quote!(aper_decode),
            quote!(asnfuzzgen_codecs::aper::encode::encode_integer),
            quote!(asnfuzzgen_codecs::aper::decode::decode_integer),
        )
    } else {
        (
            quote!(asnfuzzgen_codecs::uper::UperCodec),
            quote!(uper_encode),
            quote!(uper_decode),
            quote!(asnfuzzgen_codecs::uper::encode::encode_integer),
            quote!(asnfuzzgen_codecs::uper::decode::decode_integer),
        )
    };
    let ty = if let syn::Data::Struct(ref d) = &ast.data {
        match d.fields {
            syn::Fields::Unnamed(ref f) => {
                if f.unnamed.len() == 1 {
                    let first = f.unnamed.first().unwrap();
                    Some(first.ty.clone())
                } else {
                    None
                }
            }
            _ => None,
        }
    } else {
        None
    };

    if ty.is_none() {
        return syn::Error::new_spanned(ast, format!("{} Should be a Unit Struct.", name))
            .to_compile_error()
            .into();
    }

    let (lb, ub, ext) = utils::get_bounds_extensible_from_params(params);

    let tokens = quote! {

        impl #codec_path for #name {
            type Output = Self;

            fn #codec_decode_fn(data: &mut asnfuzzgen_codecs::PerCodecData) -> Result<Self::Output, asnfuzzgen_codecs::PerCodecError> {

                let decoded = #ty_decode_path(data, #lb, #ub, #ext)?;
                Ok(Self(decoded.0 as #ty))
            }
            fn #codec_encode_fn(&self, data: &mut asnfuzzgen_codecs::PerCodecData) -> Result<(), asnfuzzgen_codecs::PerCodecError> {

                #ty_encode_path(data, #lb, #ub, #ext, self.0 as i128, false)
            }
        }
    };

    tokens.into()
}
