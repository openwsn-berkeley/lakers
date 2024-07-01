use super::*;

#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "python-bindings", pyclass)]
#[repr(C)]
pub struct CredentialRPK {
    pub value: EdhocMessageBuffer,
    pub public_key: BytesP256ElemLen, // could be a reference, but safe Rust doesn't allow self-referencing structs
    pub kid: u8,
}

impl CredentialRPK {
    pub fn new(value: EdhocMessageBuffer) -> Result<Self, EDHOCError> {
        let (public_key, kid) = Self::parse(value.as_slice())?;
        Ok(Self {
            value,
            public_key,
            kid,
        })
    }

    pub fn reference_only(&self) -> bool {
        self.value.len == 0
    }

    pub fn get_id_cred(&self) -> BytesIdCred {
        [0xa1, 0x04, 0x41, self.kid] // cbor map = {4: kid}
    }

    fn parse(cred: &[u8]) -> Result<(BytesP256ElemLen, u8), EDHOCError> {
        // NOTE: this routine is only guaranteed to work with credentials from RFC9529
        const CCS_PREFIX_LEN: usize = 3;
        const CNF_AND_COSE_KEY_PREFIX_LEN: usize = 8;
        const COSE_KEY_FIRST_ITEMS_LEN: usize = 6;

        if cred.len()
            < 3 + CCS_PREFIX_LEN
                + 1
                + CNF_AND_COSE_KEY_PREFIX_LEN
                + COSE_KEY_FIRST_ITEMS_LEN
                + P256_ELEM_LEN
        {
            Err(EDHOCError::ParsingError)
        } else {
            let subject_len = CBORDecoder::info_of(cred[2]) as usize;

            let id_cred_offset: usize = CCS_PREFIX_LEN
                .checked_add(subject_len)
                .and_then(|x| x.checked_add(CNF_AND_COSE_KEY_PREFIX_LEN))
                .ok_or(EDHOCError::ParsingError)?;

            let g_a_x_offset: usize = id_cred_offset
                .checked_add(COSE_KEY_FIRST_ITEMS_LEN)
                .ok_or(EDHOCError::ParsingError)?;

            if g_a_x_offset
                .checked_add(P256_ELEM_LEN)
                .map_or(false, |end| end <= cred.len())
            {
                Ok((
                    cred[g_a_x_offset..g_a_x_offset + P256_ELEM_LEN]
                        .try_into()
                        .expect("Wrong key length"),
                    cred[id_cred_offset],
                ))
            } else {
                Err(EDHOCError::ParsingError)
            }
        }
    }
}

#[derive(Debug, Copy, Clone)]
enum ByValueStyle {
    /// The value of the credential is a CCS. It is encoded directly in CBOR.
    KCCS,
    // TBD: Add X509 and others, possibly also as ByteEncoded(key)
}

// From https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
const COSE_HEADER_PARAMETER_KCCS: u8 = 14;

impl ByValueStyle {
    fn encode(&self, value: &[u8]) {
        todo!("and add a an encode buffer")
    }

    // and decode
}

/// A credential along with its corresponding public key
///
/// It may contain information about the key ID, which enables its use by reference, and of its
/// value type, which enables its use by value.
///
/// Future extensions may also add other optional identifiers (eg. an identifying URI) that might
/// enable additional kinds of referncing the credential; some of those may also not be stored but
/// merely generated (eg. thumbprints, although in that case the type of credential needs to be
/// stored, so that it can be decided whether the thumbprint is an x5t or a c5t).
#[derive(Clone, Copy, Debug)]
pub struct Credential {
    /// Bytes of the credential. Lakers and EDHOC make no requirement on their format.
    value: EdhocMessageBuffer,
    /// Public authentication key (G_I or G_R) expressed in the credential
    // For CCSs, this could be a reference into value, but Rust does not allow self-referential structs anyway.
    public_key: BytesP256ElemLen,
    /// Key ID.
    ///
    /// If set, it enables turning the credential into an IdCred that is a key ID (the most compact
    /// form of ID_CRED_x).
    ///
    /// Future versions may widen this to allow longer KIDs.
    kid: Option<u8>,
    /// COSE Header Parameter Label indicating the type of credential this is.
    ///
    /// If set, it enables using the credential by value. Setting this adds the requirement that
    /// the value is well-formed according to the type. In particular, when set to KCCS or any
    /// other Map-valued types, a value that is not CBOR can result in hard to debug parsing errors
    /// on the other end, even before it reaches the credential validation at the peer.
    value_type: Option<ByValueStyle>,
}

impl Credential {
    /// Build a Credential from the value and the public_key
    ///
    /// Requirements on what credentials can be used with EDHOC differ by application; Appendix D
    /// of RFC9528 has some guidance.
    ///
    /// If any of the optional fields are to be set, they can be added using the builder pattern
    /// methods [`.with_kid()`] and [`.with_value_type()`].
    pub fn new(value: EdhocMessageBuffer, public_key: BytesP256ElemLen) -> Self {
        Self {
            value,
            public_key,
            kid: None,
            value_type: None,
        }
    }

    /// Builder to set the KID
    ///
    /// Setting this enables the use of a credential by key ID:
    ///
    /// ```rust
    /// let cred_i = Credential::new(b'my very custom credential format', [42; _])
    ///     .with_kid(b'\x04');
    /// let id_cred_i = cred_i.by_kid().expect("We just set a short KID so it works");
    /// ```
    pub fn with_kid(self, kid: &[u8]) -> Self {
        // We could also make this fallible, but these are generated locally, not network
        // processed. If we make it fallible, we should have a dedicated error type for "programmer
        // messed up" where unwrapping totally makes sense.
        assert!(
            kid.len() == 1 && todo!("Check whether it's in the CBOR range -24..23"),
            "Chosen KID is not expressible in Lakers right now"
        );
        let kid = kid[0];
        Self {
            value: self.value,
            public_key: self.public_key,
            kid: Some(kid.into()),
            value_type: self.value_type,
        }
    }

    /// Parse a CCS style credential
    ///
    /// If the given value matches the shape Lakers expects of a CCS, its public key and key ID are
    /// extracted into a full credential.
    pub fn parse_ccs(value: &[u8]) -> Result<Self, EDHOCError> {
        // Implementing in terms of the old structure, to be moved in here in later versions of
        // this change set
        let (public_key, kid) = CredentialRPK::parse(value)?;
        Ok(Self {
            value: EdhocMessageBuffer::new_from_slice(value)
                .map_err(|_| EDHOCError::ParsingError)?,
            public_key,
            kid: Some(kid),
            value_type: Some(ByValueStyle::KCCS),
        })
    }

    pub fn by_value(&self) -> Option<IdCredential> {
        let value_type = self.value_type?;
        todo!("Build an IdCredential from the CBOR serialization of {{value_type: self.value}}")
    }

    pub fn by_kid(&self) -> Option<IdCredential> {
        let kid = self.kid?;
        let mut buf = EdhocMessageBuffer::default();
        // { /kid/ 4: 'k' }
        buf.extend_from_slice(&[0xa1, 0x04, 0x41, 0x41, kid])
            .expect("Slice is sort enough to always fit in the buffer");
        Some(IdCredential { value: buf })
    }
}

/// A value of ID_CRED_x: a credential identifier
///
/// Possible values include key IDs, credentials by value and others.
pub struct IdCredential {
    /// The value is always stored in the ID_CRED_x form as a serialized one-element dictionary;
    /// while this technically wastes a byte, it has the convenient property of having the full
    /// value available as a slice.
    value: EdhocMessageBuffer,
}

impl IdCredential {
    /// View the full value of the ID_CRED_x: the CBOR encoding of a 1-element CBOR map
    pub fn as_full_value(&self) -> &[u8] {
        self.value.as_slice()
    }

    /// View the value as encoded in the ID_CRED_x position of plaintext_2 and plaintext_3,
    /// applying the Compact Encoding of ID_CRED Fields described in RFC9528 Section 3.5.3.2
    pub fn as_compact_encoding(&self) -> &[u8] {
        match self.value.as_slice() {
            [0xa1, 0x04, 0x41, x] if (x >> 5) < 2 && (x & 0x1f) < 24 => &self.value.as_slice()[3..],
            [0xa1, 0x04, ..] => &self.value.as_slice()[2..],
            _ => self.value.as_slice(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hexlit::hex;

    const CRED_TV: &[u8] = &hex!("a2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
    const G_A_TV: &[u8] = &hex!("BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F0");
    const ID_CRED_TV: &[u8] = &hex!("a1044132");

    #[test]
    fn test_new_cred() {
        let cred_tv: EdhocMessageBuffer = CRED_TV.try_into().unwrap();

        let res = CredentialRPK::new(CRED_TV.try_into().unwrap());
        assert!(res.is_ok());
        let cred = res.unwrap();
        assert_eq!(cred.value, cred_tv);
        assert_eq!(cred.public_key, G_A_TV);
        assert_eq!(cred.kid, ID_CRED_TV[3]);
        assert_eq!(cred.get_id_cred(), ID_CRED_TV);
    }
}
