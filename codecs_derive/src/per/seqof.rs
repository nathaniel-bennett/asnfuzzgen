//! `APER` Code generation for ASN.1 OCTET STRING Type

use quote::quote;

use crate::{attrs::TyCodecParams, utils};

pub(super) fn generate_aper_codec_for_asn_sequence_of(
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
            quote!(asnfuzzgen_codecs::aper::encode::encode_length_determinent),
            quote!(asnfuzzgen_codecs::aper::decode::decode_length_determinent),
        )
    } else {
        (
            quote!(asnfuzzgen_codecs::uper::UperCodec),
            quote!(uper_encode),
            quote!(uper_decode),
            quote!(asnfuzzgen_codecs::uper::encode::encode_length_determinent),
            quote!(asnfuzzgen_codecs::uper::decode::decode_length_determinent),
        )
    };
    let ty = if let syn::Data::Struct(ref d) = &ast.data {
        match d.fields {
            syn::Fields::Unnamed(ref f) => {
                if f.unnamed.len() == 1 {
                    let first = f.unnamed.first().unwrap();
                    let inner_ty = get_inner_ty_for_vec(first);
                    Some(inner_ty)
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

    let (sz_lb, sz_ub, sz_ext) = utils::get_sz_bounds_extensible_from_params(params);

    let tokens = quote! {

        impl #codec_path for #name {
            type Output = Self;

            fn #codec_decode_fn(data: &mut asnfuzzgen_codecs::PerCodecData) -> Result<Self::Output, asnfuzzgen_codecs::PerCodecError> {
                let length = #ty_decode_path(data, #sz_lb, #sz_ub, #sz_ext)?;

                let mut items = vec![];
                let mut count = 0;
                loop {
                    items.push(#ty::#codec_decode_fn(data)?);
                    count += 1;
                    if count == length {
                        break;
                    }
                }

                Ok(Self(items))
            }

            fn #codec_encode_fn(&self, data:&mut asnfuzzgen_codecs::PerCodecData) -> Result<(), asnfuzzgen_codecs::PerCodecError> {
                let _ = #ty_encode_path(data, #sz_lb, #sz_ub, #sz_ext, self.0.len());

                for elem in &self.0 {
                    let _ = elem.#codec_encode_fn(data)?;
                }
                Ok(())
            }
        }
    };

    tokens.into()
}

fn get_inner_ty_for_vec(field: &syn::Field) -> Option<syn::Ident> {
    if let syn::Type::Path(ref tp) = field.ty {
        let type_params = &tp.path.segments.iter().next().unwrap().arguments;
        match type_params {
            syn::PathArguments::AngleBracketed(params) => {
                let generic_args = params.args.iter().next().unwrap();
                if let syn::GenericArgument::Type(syn::Type::Path(tpinner)) = generic_args {
                    Some(tpinner.path.segments.iter().next().unwrap().ident.clone())
                } else {
                    None
                }
            }
            _ => None,
        }
    } else {
        None
    }
}
