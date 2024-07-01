use super::*;

pub type BufferCred = EdhocBuffer<128>; // arbitrary size
pub type BufferKid = EdhocBuffer<16>; // variable size, up to 16 bytes
pub type BufferIdCred = EdhocBuffer<128>; // variable size, can contain either the contents of a BufferCred or a BufferKid
pub type BytesKey128 = [u8; 16];
pub type BytesKeyEC2 = [u8; 32];
pub type BytesKeyOKP = [u8; 32];
pub type BytesX5T = [u8; 8];
pub type BytesC5T = [u8; 8];

pub enum CredentialKey {
    Symmetric(BytesKey128),
    EC2 {
        x: BytesKeyEC2,
        y: Option<BytesKeyEC2>,
    },
    // Add other key types as needed
}

pub trait EdhocCredentialContent {
    /// Returns the key of the credential, e.g., a public EC2 key or a PSK
    fn get_credential_key(&self) -> CredentialKey;
    /// Returns the CBOR-encoded ID_CRED containing the credential by value
    fn as_id_cred_value(&self, cred_bytes: &[u8]) -> BufferIdCred;
    /// Returns the CBOR-encoded ID_CRED containing the credential by reference
    fn as_id_cred_ref(&self) -> BufferIdCred;
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CredentialType {
    CCS,
    CCS_PSK,
    // C509,
}

pub struct Credential<EdhocCred: EdhocCredentialContent> {
    /// Original bytes of the credential, CBOR-encoded
    pub bytes: BufferCred,
    pub cred_type: CredentialType,
    pub content: EdhocCred,
}

impl<EdhocCred: EdhocCredentialContent> Credential<EdhocCred> {
    // FIXME: should handle errors instead of panicking
    pub fn by_value(&self) -> BufferIdCred {
        if self.cred_type == CredentialType::CCS_PSK {
            panic!("The PSK must never be sent by value")
        } else {
            self.content.as_id_cred_value(self.bytes.as_slice())
        }
    }
    pub fn by_reference(&self) -> BufferIdCred {
        self.content.as_id_cred_ref()
    }
}

// example of how some fields of a X509 certificate could be stored
// #[derive(Clone, Copy, Debug)]
// pub struct X509 {
//     pub x5t: Option<BytesX5T>,
//     pub c5t: Option<BytesC5T>,
//     pub public_key: BytesKeyEC2,
// }

/// A COSE_Key structure, as defined in RFC 9052
///
/// NOTE: ideally, this should be implemented by a CredentialCCS struct,
/// but we use CoseKey directly for now as we don't need the extra complexity
#[derive(Clone, Copy, Debug)]
pub struct CoseKey {
    pub kty: CoseKTY,
    pub kid: BufferKid,
    pub x: Option<BytesKeyEC2>,
    pub y: Option<BytesKeyEC2>,
    pub k: Option<BytesKey128>,
}

#[derive(Clone, Copy, Debug)]
pub enum CoseKTY {
    EC2 = 2,
    Symmetric = 4,
}

impl CoseKey {
    pub fn new(kty: CoseKTY, kid: BufferKid) -> Self {
        Self {
            kty,
            kid,
            x: None,
            y: None,
            k: None,
        }
    }

    pub fn with_x(self, x: BytesKeyEC2) -> Self {
        Self { x: Some(x), ..self }
    }

    pub fn with_y(self, y: BytesKeyEC2) -> Self {
        Self { y: Some(y), ..self }
    }

    pub fn with_k(self, k: BytesKey128) -> Self {
        Self { k: Some(k), ..self }
    }
}

impl EdhocCredentialContent for CoseKey {
    fn get_credential_key(&self) -> CredentialKey {
        match self.kty {
            CoseKTY::Symmetric => {
                let mut k: BytesKey128 = Default::default();
                k.copy_from_slice(self.k.as_ref().unwrap());
                CredentialKey::Symmetric(k)
            }
            CoseKTY::EC2 => {
                let mut x: BytesKeyEC2 = Default::default();
                x.copy_from_slice(self.x.as_ref().unwrap());
                CredentialKey::EC2 { x, y: self.y }
            }
            _ => panic!("No key found"),
        }
    }

    /// Returns a COSE_Header map with a single entry:
    ///   { /kccs/ 14: cred }
    fn as_id_cred_value(&self, cred_bytes: &[u8]) -> BufferIdCred {
        let mut cred = BufferIdCred::new();
        cred.extend_from_slice(&[CBOR_MAJOR_MAP + 1, KCSS_LABEL])
            .map_err(|_| EDHOCError::CredentialTooLongError)
            .unwrap();
        cred.extend_from_slice(cred_bytes).unwrap();
        cred
    }

    /// Returns a COSE_Header map with a single entry:
    ///   { /kid/ 4: kid }
    fn as_id_cred_ref(&self) -> BufferIdCred {
        let mut id_cred = BufferIdCred::new();
        id_cred
            .extend_from_slice(&[CBOR_MAJOR_MAP + 1, KID_LABEL])
            .unwrap();
        id_cred
            .push(CBOR_MAJOR_BYTE_STRING | self.kid.len() as u8)
            .unwrap();
        // if self.kid.len() == 1 {
        //     let kid = self.kid[0];
        //     // CBOR encoding
        // } else {
        //     todo!("Larger kid not supported yet");
        // }
        id_cred
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hexlit::hex;

    const CRED_TV: &[u8] = &hex!("a2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
    const G_A_TV: &[u8] = &hex!("BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F0");
    const ID_CRED_TV: &[u8] = &hex!("a1044132");
    const KID_VALUE_TV: &[u8] = &hex!("32");

    const CRED_PSK: &[u8] =
        &hex!("A202686D79646F74626F7408A101A30104024132205050930FF462A77A3540CF546325DEA214");
    const K: &[u8] = &hex!("50930FF462A77A3540CF546325DEA214");

    #[test]
    fn test_new_cose_key() {
        let g_a_tv = BytesKeyEC2::default();

        let key = CoseKey::new(
            CoseKTY::EC2,
            BufferKid::new_from_slice(KID_VALUE_TV).unwrap(),
        )
        .with_x(G_A_TV.try_into().unwrap());
    }

    #[test]
    fn test_new_cose_key_psk() {
        let key = CoseKey::new(
            CoseKTY::Symmetric,
            BufferKid::new_from_slice(KID_VALUE_TV).unwrap(),
        )
        .with_k(K.try_into().unwrap());
    }
}
