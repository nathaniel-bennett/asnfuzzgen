//! A simple utility to tokenize ASN files.

use std::io::{self, Write};

use clap::Parser;

use asnfuzzgen::{
    generator::{Codec, Derive, Visibility},
    Asn1Compiler,
};

use std::fs::File;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(last = true)]
    files: Vec<String>,

    /// Name of the Rust Module to write generated code to.
    #[arg(short, long)]
    module: String,

    /// The name of the root ASN.1 structure to derive structured fuzzing routines for.
    #[arg(short, long, required = true)]
    root: String,

    #[arg(short, action=clap::ArgAction::Count)]
    debug: u8,

    /// Visibility of Generated Structures and members:
    #[arg(long, value_enum, default_value_t=Visibility::Public)]
    visibility: Visibility,

    /// ASN.1 Codecs to be Supported during code generation.
    #[arg(long, required = true)]
    codec: Codec,

    /// Generate code for these derive macros during code generation.
    #[arg(long)]
    derive: Vec<Derive>,
}

fn main() -> io::Result<()> {
    let mut cli = Cli::parse();

    if cli.files.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "No Input files Specified",
        ));
    }

    let derives = if cli.derive.contains(&Derive::All) {
        cli.derive
            .into_iter()
            .filter(|t| t == &Derive::All)
            .collect::<Vec<Derive>>()
    } else {
        if !cli.derive.contains(&Derive::Debug) {
            cli.derive.push(Derive::Debug);
        }
        cli.derive
    };

    let level = if cli.debug > 0 {
        if cli.debug == 1 {
            "debug"
        } else {
            "trace"
        }
    } else {
        "info"
    };

    let env = env_logger::Env::default().filter_or("MY_LOG_LEVEL", level);
    env_logger::init_from_env(env);

    let mut compiler = Asn1Compiler::new(&cli.module, &cli.visibility, cli.codec, derives.clone());
    compiler.compile_files(&cli.files)?;
    compile_lib_files(cli.module.as_str(), cli.root.as_str(), cli.codec);

    Ok(())
}

fn compile_lib_files(module: &str, root: &str, codec: Codec) {
    let module_lower = module.to_lowercase();
    let module_upper = module.to_uppercase();

    let codec_lower = match codec {
        Codec::Aper => "aper",
        Codec::Uper => "uper",
    };

    let codec_camel = match codec {
        Codec::Aper => "Aper",
        Codec::Uper => "Uper",
    };

    let codec_upper = match codec {
        Codec::Aper => "APER",
        Codec::Uper => "UPER",
    };

    let dir = format!("asnfuzz-{}-{}", module_lower, codec_lower);

    std::fs::create_dir(&dir).unwrap();
    std::fs::create_dir(format!("{}/src", &dir)).unwrap();

    std::fs::rename(&module_lower, format!("{}/src/{}.rs", dir, &module_lower)).unwrap();

    let mut output_file_h = File::create(format!(
        "{}/asnfuzz_{}_{}.h",
        dir, module_lower, codec_lower
    ))
    .unwrap();
    output_file_h
        .write_all(
            format!(
                "
#ifndef ASNFUZZ_{}_{}_H
#define ASNFUZZ_{}_{}_H

#ifdef __cplusplus
extern \"C\" {{
#endif // __cplusplus

/// An invalid argument was supplied to the function.
const long ASNFUZZGEN_ERR_ARGS = -1;

/// Structuring failed due to insufficent bytes.
const long ASNFUZZGEN_ERR_ENTROPIC = -2;

/// Failed to convert bytes to or from ASN.1 wire format.
const long ASNFUZZGEN_ERR_ENCODING = -3;

/// The resulting bytes could not fit within the provided buffer.
const long ASNFUZZGEN_ERR_TRUNCATED = -4;

/// Converts unstructured bytes into a structured ASN.1 message.
/// Returns a the length of the structured bytes written to `buf_out`, or
/// a negative error code on failure.
long {}_{}_structure(char *buf_in, long in_len, char *buf_out, long out_max);

/// Converts a structured ASN.1 message into unstructured bytes.
/// Returns a the length of the unstructured bytes written to `buf_out`, or
/// a negative error code on failure.
long {}_{}_destructure(char *buf_in, long in_len, char *buf_out, long out_max);

#ifdef __cplusplus
}}
#endif // __cplusplus

#endif // ASNFUZZ_{}_{}_H
",
                module_upper,
                codec_upper,
                module_upper,
                codec_upper,
                codec_lower,
                module_lower,
                codec_lower,
                module_lower,
                module_upper,
                codec_upper
            )
            .as_bytes(),
        )
        .unwrap();

    let mut output_file_lib = File::create(format!("{}/src/lib.rs", dir)).unwrap();
    output_file_lib.write_all(format!("
#![allow(non_camel_case_types)]

mod {}; // generated module

use std::slice;
use std::os::raw::c_char;
use asnfuzzgen_codecs::{}::{}Codec;
use entropic::prelude::*;

/// An invalid argument was supplied to the function.
const ASNFUZZGEN_ERR_ARGS: isize = -1;

/// Structuring failed due to insufficent bytes.
const ASNFUZZGEN_ERR_ENTROPIC: isize = -2;

/// Failed to convert bytes to or from ASN.1 wire format.
const ASNFUZZGEN_ERR_ENCODING: isize = -3;

/// The resulting bytes could not fit within the provided buffer.
const ASNFUZZGEN_ERR_TRUNCATED: isize = -4;

#[no_mangle]
pub unsafe extern \"C\" fn {}_{}_structure(buf_in: *mut c_char, in_len: isize, buf_out: *mut c_char, out_max: isize) -> isize {{
    let in_len: usize = match in_len.try_into() {{
        Ok(l) => l,
        Err(_) => return ASNFUZZGEN_ERR_ARGS,
    }};

    let out_max: usize = match out_max.try_into() {{
        Ok(l) => l,
        Err(_) => return ASNFUZZGEN_ERR_ARGS,
    }};

    let in_slice = slice::from_raw_parts(buf_in as *const u8, in_len);
    let out_slice = slice::from_raw_parts_mut(buf_out as *mut u8, out_max);

    let in_iter = in_slice.iter().chain(std::iter::repeat(&0u8).take(200_000 - in_slice.len())); // Cap total entropy to 200,000 bytes for performance

    let Ok(message) = {}::{}::from_entropy::<_, entropic::scheme::DefaultEntropyScheme>(in_iter) else {{
        return ASNFUZZGEN_ERR_ENTROPIC
    }};

    let mut encoded = asnfuzzgen_codecs::PerCodecData::new_{}();
    match message.{}_encode(&mut encoded) {{
        Ok(()) => (),
        _ => return ASNFUZZGEN_ERR_ENCODING // If the encoding isn't successful, short-circuit this test
    }}

    let output_bytes = encoded.into_bytes();
    let output_slice = output_bytes.as_slice();
    if output_slice.len() > out_max {{
        return ASNFUZZGEN_ERR_TRUNCATED
    }}

    out_slice[..output_slice.len()].copy_from_slice(output_slice);

    match output_slice.len().try_into() {{
        Ok(l) => l,
        Err(_) => ASNFUZZGEN_ERR_TRUNCATED
    }}
}}

#[no_mangle]
pub unsafe extern \"C\" fn {}_{}_destructure(buf_in: *mut c_char, in_len: isize, buf_out: *mut c_char, out_max: isize) -> isize {{
    let in_len: usize = match in_len.try_into() {{
        Ok(l) => l,
        Err(_) => return ASNFUZZGEN_ERR_ARGS,
    }};

    let out_max: usize = match out_max.try_into() {{
        Ok(l) => l,
        Err(_) => return ASNFUZZGEN_ERR_ARGS,
    }};

    let in_slice = slice::from_raw_parts(buf_in as *const u8, in_len);
    let out_slice = slice::from_raw_parts_mut(buf_out as *mut u8, out_max);

    let mut packet = asnfuzzgen_codecs::PerCodecData::from_slice_{}(in_slice);
    let Ok(pdu) = {}::{}::{}_decode(&mut packet) else {{
        return ASNFUZZGEN_ERR_ENCODING
    }};

    let mut output = [0u8; 2_000_000];

    let Ok(output_len) = pdu.to_entropy::<_, DefaultEntropyScheme>(&mut output) else {{
        return ASNFUZZGEN_ERR_ENTROPIC
    }};
    
    let output_slice = &output[..output_len];
    if output_slice.len() > out_max {{
        return ASNFUZZGEN_ERR_TRUNCATED
    }}

    out_slice[..output_slice.len()].copy_from_slice(output_slice);

    match output_slice.len().try_into() {{
        Ok(l) => l,
        Err(_) => ASNFUZZGEN_ERR_TRUNCATED
    }}
}}
", module_lower, codec_lower, codec_camel, codec_lower, module_lower, module_lower, root, codec_lower, codec_lower, codec_lower, module_lower, codec_lower, module_lower, root, codec_lower).as_bytes()).unwrap();

    let mut output_file_cargo = File::create(format!("{}/Cargo.toml", dir)).unwrap();
    output_file_cargo.write_all(format!("
[package]
name = \"asnfuzz_{}_{}\"
version = \"0.1.0\"
edition = \"2021\"

[lib]
name = \"asnfuzz_{}_{}\"
crate-type = [\"rlib\", \"staticlib\"]

[dependencies]
asnfuzzgen-codecs = {{ version = \"0.1\", path = \"../asnfuzzgen/codecs\" }}
asnfuzzgen-codecs-derive = {{ version = \"0.1\", path = \"../asnfuzzgen/codecs_derive\" }}
bitvec = {{ version = \"1.0\" }}
entropic = {{ version = \"0.1\", path = \"../entropic/entropic\", features = [\"derive\", \"bitvec\"] }}
log = {{ version = \"0.4\" }}
", module_lower, codec_lower, module_lower, codec_lower).as_bytes()).unwrap();

    if module_lower == "ngap" {
        std::process::Command::new("python3")
            .args([
                "extract_ngap_proto_ies.py",
                "examples/specs/ngap/NGAP-PDU-Contents.asn",
                "./asnfuzz-ngap-aper/src/ngap.rs",
            ])
            .output()
            .unwrap();
    } else if module_lower == "s1ap" {
        std::process::Command::new("python3")
            .args([
                "extract_s1ap_proto_ies.py",
                "examples/specs/s1ap/S1AP-PDU-Contents.asn",
                "../asnfuzz-s1ap-aper/src/s1ap.rs",
            ])
            .output()
            .unwrap();
    }
}
