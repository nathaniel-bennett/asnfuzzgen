//! Handling of ASN.1 NULL Type

use quote::quote;

use crate::attrs::TyCodecParams;

pub(super) fn generate_aper_codec_for_asn_object_identifier(
    ast: &syn::DeriveInput,
    _params: &TyCodecParams,
    aligned: bool,
) -> proc_macro::TokenStream {
    let name = &ast.ident;

    let (codec_path, codec_encode_fn, codec_decode_fn) = if aligned {
        (
            quote!(asnfuzzgen_codecs::aper::AperCodec),
            quote!(aper_encode),
            quote!(aper_decode),
        )
    } else {
        (
            quote!(asnfuzzgen_codecs::uper::UperCodec),
            quote!(uper_encode),
            quote!(uper_decode),
        )
    };
    let tokens = quote! {

        impl #codec_path for #name {

            type Output = Self;

            fn #codec_decode_fn(_data: &mut asnfuzzgen_codecs::PerCodecData) -> Result<Self::Output, asnfuzzgen_codecs::PerCodecError> {
                Err(asnfuzzgen_codecs::PerCodecError::new("Object Identifier Decode Not Supported!"))
            }
            fn #codec_encode_fn(&self, _data: &mut asnfuzzgen_codecs::PerCodecData) -> Result<(), asnfuzzgen_codecs::PerCodecError> {
                Err(asnfuzzgen_codecs::PerCodecError::new("Object Identifier Encode Not Supported!"))
            }
        }
    };

    tokens.into()
}
