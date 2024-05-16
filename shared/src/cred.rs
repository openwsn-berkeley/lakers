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
