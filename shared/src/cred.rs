use super::*;

pub type BufferCred = EdhocBuffer<192>; // arbitrary size
pub type BufferKid = EdhocBuffer<16>; // variable size, up to 16 bytes
pub type BufferIdCred = EdhocBuffer<192>; // variable size, can contain either the contents of a BufferCred or a BufferKid
pub type BytesKeyAES128 = [u8; 16];
pub type BytesKeyEC2 = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C)]
pub enum CredentialKey {
    Symmetric(BytesKeyAES128),
    EC2Compact(BytesKeyEC2),
    // Add other key types as needed
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C)]
pub enum CredentialType {
    CCS,
    #[allow(non_camel_case_types)]
    CCS_PSK,
    // Add other credential types as needed
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum IdCredType {
    KID = 4,
    KCCS = 14,
}

impl From<u8> for IdCredType {
    fn from(value: u8) -> Self {
        match value {
            4 => IdCredType::KID,
            14 => IdCredType::KCCS,
            _ => panic!("Invalid IdCredType"),
        }
    }
}

/// A value of ID_CRED_x: a credential identifier
///
/// Possible values include key IDs, credentials by value and others.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[repr(C)]
pub struct IdCred {
    /// The value is always stored in the ID_CRED_x form as a serialized one-element dictionary;
    /// while this technically wastes two bytes, it has the convenient property of having the full
    /// value available as a slice.
    pub bytes: BufferIdCred, // variable size, can contain either the contents of a BufferCred or a BufferKid
}

impl IdCred {
    pub fn new() -> Self {
        Self {
            bytes: BufferIdCred::new(),
        }
    }

    pub fn from_full_value(value: &[u8]) -> Result<Self, EDHOCError> {
        Ok(Self {
            bytes: BufferIdCred::new_from_slice(value)
                .map_err(|_| EDHOCError::CredentialTooLongError)?,
        })
    }

    /// Instantiate an IdCred from an encoded value.
    pub fn from_encoded_value(value: &[u8]) -> Result<Self, EDHOCError> {
        let bytes = match value {
            // kid that has been encoded as CBOR integer
            &[x] if Self::bstr_representable_as_int(x) => {
                BufferIdCred::new_from_slice(&[0xa1, KID_LABEL, 0x41, x])
                    .map_err(|_| EDHOCError::CredentialTooLongError)? // TODO: how to avoid map_err overuse?
            }
            // kid that has been encoded as CBOR byte string
            &[0x41, x, ..] if !Self::bstr_representable_as_int(x) => {
                let mut bytes = BufferIdCred::new_from_slice(&[0xa1, KID_LABEL])
                    .map_err(|_| EDHOCError::CredentialTooLongError)?;
                bytes
                    .extend_from_slice(value)
                    .map_err(|_| EDHOCError::CredentialTooLongError)?;
                bytes
            }
            // CCS by value
            &[0xa1, KCSS_LABEL, ..] => BufferIdCred::new_from_slice(value)
                .map_err(|_| EDHOCError::CredentialTooLongError)?,
            _ => return Err(EDHOCError::ParsingError),
        };

        Ok(Self { bytes })
    }

    /// View the full value of the ID_CRED_x: the CBOR encoding of a 1-element CBOR map
    ///
    /// This is the value that is used when ID_CRED_x has no impact on message size, see RFC 9528 Section 3.5.3.2.
    pub fn as_full_value(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// View the value as encoded in the ID_CRED_x position of plaintext_2 and plaintext_3.
    ///
    /// Note that this is NOT doing CBOR encoding, it is rather performing (when applicable)
    /// the compact encoding of ID_CRED fields.
    /// This style of encoding is used when ID_CRED_x has an impact on message size.
    pub fn as_encoded_value(&self) -> &[u8] {
        match self.bytes.as_slice() {
            [0xa1, KID_LABEL, 0x41, x] if (x >> 5) < 2 && (x & 0x1f) < 24 => {
                &self.bytes.as_slice()[3..]
            }
            [0xa1, KID_LABEL, ..] => &self.bytes.as_slice()[2..],
            _ => self.bytes.as_slice(),
        }
    }

    pub fn reference_only(&self) -> bool {
        [IdCredType::KID].contains(&self.item_type())
    }

    pub fn item_type(&self) -> IdCredType {
        self.bytes.as_slice()[1].into()
    }

    pub fn get_ccs(&self) -> Option<Credential> {
        if self.item_type() == IdCredType::KCCS {
            Credential::parse_ccs(&self.bytes.as_slice()[2..]).ok()
        } else {
            None
        }
    }

    fn bstr_representable_as_int(value: u8) -> bool {
        (0x0..=0x17).contains(&value) || (0x20..=0x37).contains(&value)
    }
}

/// A credential for use in EDHOC
///
/// For now supports CCS credentials only.
/// Experimental support for CCS_PSK credentials is also available.
// TODO: add back support for C and Python bindings
#[cfg_attr(feature = "python-bindings", pyclass)]
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C)]
pub struct Credential {
    /// Original bytes of the credential, CBOR-encoded
    ///
    /// If the credential is a CCS, it contains an encoded CBOR map containnig
    /// a COSE_Key in a cnf claim, see RFC 9528 Section 3.5.2.
    pub bytes: BufferCred,
    pub key: CredentialKey,
    pub kid: Option<BufferKid>, // other types of identifiers can be added, such as `pub x5t: Option<BytesX5T>`
    pub cred_type: CredentialType,
}

impl Credential {
    /// Creates a new CCS credential with the given bytes and public key
    pub fn new_ccs(bytes: BufferCred, public_key: BytesKeyEC2) -> Self {
        Self {
            bytes,
            key: CredentialKey::EC2Compact(public_key),
            kid: None,
            cred_type: CredentialType::CCS,
        }
    }

    /// Creates a new CCS credential with the given bytes and a pre-shared key
    ///
    /// NOTE: For now this is only useful for the experimental PSK method.
    pub fn new_ccs_symmetric(bytes: BufferCred, symmetric_key: BytesKeyAES128) -> Self {
        Self {
            bytes,
            key: CredentialKey::Symmetric(symmetric_key),
            kid: None,
            cred_type: CredentialType::CCS_PSK,
        }
    }

    pub fn with_kid(self, kid: BufferKid) -> Self {
        Self {
            kid: Some(kid),
            ..self
        }
    }

    pub fn public_key(&self) -> Option<BytesKeyEC2> {
        match self.key {
            CredentialKey::EC2Compact(key) => Some(key),
            _ => None,
        }
    }

    /// Parse a CCS style credential.
    ///
    /// If the given value matches the shape lakers expects of a CCS, i.e. credentials from RFC9529,
    /// its public key and key ID are extracted into a full credential.
    pub fn parse_ccs(value: &[u8]) -> Result<Self, EDHOCError> {
        const CCS_PREFIX_LEN: usize = 3;
        const CNF_AND_COSE_KEY_PREFIX_LEN: usize = 8;
        const COSE_KEY_FIRST_ITEMS_LEN: usize = 6;

        if value.len()
            < 3 + CCS_PREFIX_LEN
                + 1
                + CNF_AND_COSE_KEY_PREFIX_LEN
                + COSE_KEY_FIRST_ITEMS_LEN
                + P256_ELEM_LEN
        {
            Err(EDHOCError::ParsingError)
        } else {
            let subject_len = CBORDecoder::info_of(value[2]) as usize;

            let id_cred_offset: usize = CCS_PREFIX_LEN
                .checked_add(subject_len)
                .and_then(|x| x.checked_add(CNF_AND_COSE_KEY_PREFIX_LEN))
                .ok_or(EDHOCError::ParsingError)?;

            let g_a_x_offset: usize = id_cred_offset
                .checked_add(COSE_KEY_FIRST_ITEMS_LEN)
                .ok_or(EDHOCError::ParsingError)?;

            if g_a_x_offset
                .checked_add(P256_ELEM_LEN)
                .map_or(false, |end| end <= value.len())
            {
                let public_key: BytesKeyEC2 = value[g_a_x_offset..g_a_x_offset + P256_ELEM_LEN]
                    .try_into()
                    .expect("Wrong key length");
                let kid = value[id_cred_offset];

                Ok(Self {
                    bytes: BufferCred::new_from_slice(value)
                        .map_err(|_| EDHOCError::ParsingError)?,
                    key: CredentialKey::EC2Compact(public_key),
                    kid: Some(BufferKid::new_from_slice(&[kid]).unwrap()),
                    cred_type: CredentialType::CCS,
                })
            } else {
                Err(EDHOCError::ParsingError)
            }
        }
    }

    /// Parse a CCS style credential, but the key is a symmetric key.
    ///
    /// NOTE: For now this is only useful for the experimental PSK method.
    pub fn parse_ccs_symmetric(value: &[u8]) -> Result<Self, EDHOCError> {
        const CCS_PREFIX_LEN: usize = 3;
        const CNF_AND_COSE_KEY_PREFIX_LEN: usize = 8;
        const COSE_KEY_FIRST_ITEMS_LEN: usize = 3; //COSE for symmetric key
        const SYMMETRIC_KEY_LEN: usize = 16; // Assuming a 128-bit symmetric key

        if value.len()
            < CCS_PREFIX_LEN
                + 1
                + CNF_AND_COSE_KEY_PREFIX_LEN
                + COSE_KEY_FIRST_ITEMS_LEN
                + SYMMETRIC_KEY_LEN
        {
            Err(EDHOCError::ParsingError)
        } else {
            let subject_len = CBORDecoder::info_of(value[2]) as usize;

            let id_cred_offset: usize = CCS_PREFIX_LEN
                .checked_add(subject_len)
                .and_then(|x| x.checked_add(CNF_AND_COSE_KEY_PREFIX_LEN))
                .ok_or(EDHOCError::ParsingError)?;

            let symmetric_key_offset: usize = id_cred_offset
                .checked_add(COSE_KEY_FIRST_ITEMS_LEN)
                .ok_or(EDHOCError::ParsingError)?;

            if symmetric_key_offset
                .checked_add(SYMMETRIC_KEY_LEN)
                .map_or(false, |end| end <= value.len())
            {
                let symmetric_key: [u8; SYMMETRIC_KEY_LEN] = value
                    [symmetric_key_offset..symmetric_key_offset + SYMMETRIC_KEY_LEN]
                    .try_into()
                    .map_err(|_| EDHOCError::ParsingError)?;

                let kid = value[id_cred_offset];

                Ok(Self {
                    bytes: BufferCred::new_from_slice(value)
                        .map_err(|_| EDHOCError::ParsingError)?,
                    key: CredentialKey::Symmetric(symmetric_key),
                    kid: Some(BufferKid::new_from_slice(&[kid]).unwrap()),
                    cred_type: CredentialType::CCS_PSK,
                })
            } else {
                Err(EDHOCError::ParsingError)
            }
        }
    }

    /// Returns a COSE_Header map with a single entry representing a credential by value.
    ///
    /// For example, if the credential is a CCS:
    ///   { /kccs/ 14: bytes }
    pub fn by_value(&self) -> Result<IdCred, EDHOCError> {
        match self.cred_type {
            CredentialType::CCS => {
                let mut id_cred = IdCred::new();
                id_cred
                    .bytes
                    .extend_from_slice(&[CBOR_MAJOR_MAP + 1, KCSS_LABEL])
                    .map_err(|_| EDHOCError::CredentialTooLongError)?;
                id_cred
                    .bytes
                    .extend_from_slice(self.bytes.as_slice())
                    .unwrap();
                Ok(id_cred)
            }
            // if we could encode a message along the error below,
            // it would be this: "Symmetric keys cannot be sent by value"
            CredentialType::CCS_PSK => Err(EDHOCError::UnexpectedCredential),
        }
    }

    /// Returns a COSE_Header map with a single entry representing a credential by reference.
    ///
    /// For example, if the reference is a kid:
    ///   { /kid/ 4: kid }
    ///
    /// TODO: accept a parameter to specify the type of reference, e.g. kid, x5t, etc.
    pub fn by_kid(&self) -> Result<IdCred, EDHOCError> {
        let Some(kid) = self.kid.as_ref() else {
            return Err(EDHOCError::MissingIdentity);
        };
        let mut id_cred = IdCred::new();
        id_cred
            .bytes
            .extend_from_slice(&[
                CBOR_MAJOR_MAP + 1,
                KID_LABEL,
                CBOR_MAJOR_BYTE_STRING | kid.len() as u8,
            ])
            .map_err(|_| EDHOCError::CredentialTooLongError)?;
        id_cred.bytes.extend_from_slice(kid.as_slice()).unwrap();
        Ok(id_cred)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hexlit::hex;
    use rstest::rstest;

    const CRED_TV: &[u8] = &hex!("a2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
    const G_A_TV: &[u8] = &hex!("BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F0");
    const ID_CRED_BY_REF_TV: &[u8] = &hex!("a1044132");
    const ID_CRED_BY_VALUE_TV: &[u8] = &hex!("A10EA2026B6578616D706C652E65647508A101A501020241322001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");
    const KID_VALUE_TV: &[u8] = &hex!("32");

    const CRED_PSK: &[u8] =
        &hex!("A202686D79646F74626F7408A101A30104024132205050930FF462A77A3540CF546325DEA214");
    const K: &[u8] = &hex!("50930FF462A77A3540CF546325DEA214");
    const KID_VALUE_PSK: &[u8] = &hex!("32");

    #[test]
    fn test_new_cred_ccs() {
        let cred = Credential::new_ccs(CRED_TV.try_into().unwrap(), G_A_TV.try_into().unwrap());
        assert_eq!(cred.bytes.as_slice(), CRED_TV);
    }

    #[test]
    fn test_cred_ccs_by_value_or_reference() {
        let cred = Credential::new_ccs(CRED_TV.try_into().unwrap(), G_A_TV.try_into().unwrap())
            .with_kid(KID_VALUE_TV.try_into().unwrap());
        let id_cred = cred.by_value().unwrap();
        assert_eq!(id_cred.bytes.as_slice(), ID_CRED_BY_VALUE_TV);
        assert_eq!(id_cred.item_type(), IdCredType::KCCS);
        let id_cred = cred.by_kid().unwrap();
        assert_eq!(id_cred.bytes.as_slice(), ID_CRED_BY_REF_TV);
        assert_eq!(id_cred.item_type(), IdCredType::KID);
    }

    #[test]
    fn test_parse_ccs() {
        let cred = Credential::parse_ccs(CRED_TV).unwrap();
        assert_eq!(cred.bytes.as_slice(), CRED_TV);
        assert_eq!(
            cred.key,
            CredentialKey::EC2Compact(G_A_TV.try_into().unwrap())
        );
        assert_eq!(cred.kid.unwrap().as_slice(), KID_VALUE_TV);
        assert_eq!(cred.cred_type, CredentialType::CCS);
    }

    #[rstest]
    #[case(&[0x0D], &[0xa1, 0x04, 0x41, 0x0D])] // two optimizations: omit kid label and encode as CBOR integer
    #[case(&[0x41, 0x18], &[0xa1, 0x04, 0x41, 0x18])] // one optimization: omit kid label
    #[case(ID_CRED_BY_VALUE_TV, ID_CRED_BY_VALUE_TV)] // regular credential by value
    fn test_id_cred_from_encoded_plaintext(#[case] input: &[u8], #[case] expected: &[u8]) {
        assert_eq!(
            IdCred::from_encoded_value(input).unwrap().as_full_value(),
            expected
        );
    }
}

#[cfg(test)]
mod test_experimental {
    use super::*;
    use hexlit::hex;

    const CRED_PSK: &[u8] =
        &hex!("A202686D79646F74626F7408A101A30104024132205050930FF462A77A3540CF546325DEA214");
    const K: &[u8] = &hex!("50930FF462A77A3540CF546325DEA214");
    const KID_VALUE_PSK: &[u8] = &hex!("32");

    #[test]
    fn test_cred_ccs_symmetric_by_value_or_reference() {
        // TODO
    }

    #[test]
    fn test_new_cred_ccs_symmetric() {
        let cred =
            Credential::new_ccs_symmetric(CRED_PSK.try_into().unwrap(), K.try_into().unwrap());
        assert_eq!(cred.bytes.as_slice(), CRED_PSK);
    }

    #[test]
    fn test_parse_ccs_symmetric() {
        let cred = Credential::parse_ccs_symmetric(CRED_PSK).unwrap();
        assert_eq!(cred.bytes.as_slice(), CRED_PSK);
        assert_eq!(cred.key, CredentialKey::Symmetric(K.try_into().unwrap()));
        assert_eq!(cred.kid.unwrap().as_slice(), KID_VALUE_PSK);
        assert_eq!(cred.cred_type, CredentialType::CCS_PSK);
    }
}
