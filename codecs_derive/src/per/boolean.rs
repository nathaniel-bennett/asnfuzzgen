//! `APER` Code generation for ASN.1 Boolean Type

use proc_macro::TokenStream;
use quote::quote;

use crate::attrs::TyCodecParams;

pub(super) fn generate_aper_codec_for_asn_boolean(
    ast: &syn::DeriveInput,
    _params: &TyCodecParams,
    aligned: bool,
) -> proc_macro::TokenStream {
    let name = &ast.ident;

    let (codec_path, codec_encode_fn, codec_decode_fn, ty_encode_path, ty_decode_path) = if aligned
    {
        (
            quote!(asnfuzzgen_codecs::aper::AperCodec),
            quote!(aper_encode),
            quote!(aper_decode),
            quote!(asnfuzzgen_codecs::aper::encode::encode_bool),
            quote!(asnfuzzgen_codecs::aper::decode::decode_bool),
        )
    } else {
        (
            quote!(asnfuzzgen_codecs::uper::UperCodec),
            quote!(uper_encode),
            quote!(uper_decode),
            quote!(asnfuzzgen_codecs::uper::encode::encode_bool),
            quote!(asnfuzzgen_codecs::uper::decode::decode_bool),
        )
    };
    let tokens = quote! {

        impl #codec_path for #name {
            type Output = Self;

            fn #codec_decode_fn(data: &mut asnfuzzgen_codecs::PerCodecData) -> Result<Self::Output, asnfuzzgen_codecs::PerCodecError> {

                let value = #ty_decode_path(data)?;
                Ok(Self(value))
            }

            fn #codec_encode_fn(&self, data: &mut asnfuzzgen_codecs::PerCodecData) -> Result<(), asnfuzzgen_codecs::PerCodecError> {

                #ty_encode_path(data, self.0)
            }
        }
    };

    TokenStream::from(tokens)
}
