//! Handling of Integer Type

#[derive(Debug, Clone)]
pub(crate) enum NamedValue {
    Number(String),
    ValueRef(#[allow(unused)] String),
}

/// A Structure representing ASN.1 Integer
#[derive(Debug, Clone)]
pub(crate) struct Asn1TypeInteger {
    #[allow(unused)]
    pub(crate) named_values: Option<Vec<(String, NamedValue)>>,
}

#[derive(Debug, Clone)]
pub(crate) struct EnumValue {
    pub(crate) name: String,
    pub(crate) value: Option<NamedValue>,
}

#[derive(Debug, Clone)]
pub(crate) struct Asn1TypeEnumerated {
    pub(crate) root_values: Vec<EnumValue>,
    pub(crate) ext_marker_index: Option<usize>,
    pub(crate) ext_values: Vec<EnumValue>,
}

#[derive(Debug, Clone)]
pub(crate) struct Asn1TypeBitString {
    pub(crate) named_bits: Option<Vec<(String, NamedValue)>>,
}
