#![allow(dead_code)]

use asnfuzzgen_codecs_derive::{AperCodec, UperCodec};

#[derive(Debug, AperCodec, UperCodec)]
#[asn(type = "ENUMERATED", extensible = true, lb = "0", ub = "0")]
pub struct AdditionalQosFlowInformation(u8);
impl AdditionalQosFlowInformation {
    const MORE_LIKELY: u8 = 0u8;
}

fn main() {
    eprintln!("Enumerated");
}
