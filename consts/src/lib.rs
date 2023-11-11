#![no_std]

pub use cbor::*;
pub use common_edhoc_parsing::*;
pub use helpers::*;

// ---- constants and types

// TODO: find a way to configure the buffer size
// need 128 to handle EAD fields, and 192 for the EAD_1 voucher
pub const MAX_MESSAGE_SIZE_LEN: usize = 128 + 64;

pub const ID_CRED_LEN: usize = 4;
pub const SUITES_LEN: usize = 9;
pub const SUPPORTED_SUITES_LEN: usize = 1;
pub const EDHOC_METHOD: u8 = 3u8; // stat-stat is the only supported method
pub const P256_ELEM_LEN: usize = 32;
pub const SHA256_DIGEST_LEN: usize = 32;
pub const AES_CCM_KEY_LEN: usize = 16;
pub const AES_CCM_IV_LEN: usize = 13;
pub const AES_CCM_TAG_LEN: usize = 8;
pub const MAC_LENGTH: usize = 8; // used for EAD Zeroconf
pub const MAC_LENGTH_2: usize = MAC_LENGTH;
pub const MAC_LENGTH_3: usize = MAC_LENGTH_2;
pub const ENCODED_VOUCHER_LEN: usize = 1 + MAC_LENGTH; // 1 byte for the length of the bstr-encoded voucher

// maximum supported length of connection identifier for R
pub const MAX_KDF_CONTEXT_LEN: usize = 150;
pub const MAX_KDF_LABEL_LEN: usize = 15; // for "KEYSTREAM_2"
pub const MAX_BUFFER_LEN: usize = 256;
pub const CBOR_BYTE_STRING: u8 = 0x58u8;
pub const CBOR_TEXT_STRING: u8 = 0x78u8;
pub const CBOR_UINT_1BYTE: u8 = 0x18u8;
pub const CBOR_NEG_INT_1BYTE_START: u8 = 0x20u8;
pub const CBOR_NEG_INT_1BYTE_END: u8 = 0x37u8;
pub const CBOR_UINT_1BYTE_START: u8 = 0x0u8;
pub const CBOR_UINT_1BYTE_END: u8 = 0x17u8;
pub const CBOR_MAJOR_TEXT_STRING: u8 = 0x60u8;
pub const CBOR_MAJOR_BYTE_STRING: u8 = 0x40u8;
pub const CBOR_MAJOR_BYTE_STRING_MAX: u8 = 0x57u8;
pub const CBOR_MAJOR_ARRAY: u8 = 0x80u8;
pub const CBOR_MAJOR_ARRAY_MAX: u8 = 0x97u8;
pub const MAX_INFO_LEN: usize = 2 + SHA256_DIGEST_LEN + // 32-byte digest as bstr
				            1 + MAX_KDF_LABEL_LEN +     // label <24 bytes as tstr
						    1 + MAX_KDF_CONTEXT_LEN +   // context <24 bytes as bstr
						    1; // length as u8

pub const ENC_STRUCTURE_LEN: usize = 8 + 5 + SHA256_DIGEST_LEN; // 8 for ENCRYPT0

pub const MAX_EAD_SIZE_LEN: usize = 64;
pub const EAD_ZEROCONF_LABEL: u8 = 0x1; // NOTE: in lake-authz-draft-02 it is still TBD1
pub const EAD_ZEROCONF_INFO_K_1_LABEL: u8 = 0x0;
pub const EAD_ZEROCONF_INFO_IV_1_LABEL: u8 = 0x1;
pub const EAD_ZEROCONF_ENC_STRUCTURE_LEN: usize = 2 + 8 + 3;

pub type BytesEad2 = [u8; 0];
pub type BytesIdCred = [u8; ID_CRED_LEN];

pub type BytesSuites = [u8; SUITES_LEN];
pub type BytesSupportedSuites = [u8; SUPPORTED_SUITES_LEN];
pub const EDHOC_SUITES: BytesSuites = [0, 1, 2, 3, 4, 5, 6, 24, 25]; // all but private cipher suites
pub const EDHOC_SUPPORTED_SUITES: BytesSupportedSuites = [0x2u8];

pub type Bytes8 = [u8; 8];
pub type BytesCcmKeyLen = [u8; AES_CCM_KEY_LEN];
pub type BytesCcmIvLen = [u8; AES_CCM_IV_LEN];
pub type BufferPlaintext2 = EdhocMessageBuffer;
pub type BufferPlaintext3 = EdhocMessageBuffer;
pub type BytesMac2 = [u8; MAC_LENGTH_2];
pub type BytesMac3 = [u8; MAC_LENGTH_3];
pub type BufferMessage1 = EdhocMessageBuffer;
pub type BufferMessage3 = EdhocMessageBuffer;
pub type BufferCiphertext2 = EdhocMessageBuffer;
pub type BufferCiphertext3 = EdhocMessageBuffer;
pub type BytesHashLen = [u8; SHA256_DIGEST_LEN];
pub type BytesP256ElemLen = [u8; P256_ELEM_LEN];
pub type BufferMessage2 = EdhocMessageBuffer;
pub type BytesMaxBuffer = [u8; MAX_BUFFER_LEN];
pub type BytesMaxContextBuffer = [u8; MAX_KDF_CONTEXT_LEN];
pub type BytesMaxInfoBuffer = [u8; MAX_INFO_LEN];
pub type BytesMaxLabelBuffeer = [u8; MAX_KDF_LABEL_LEN];
pub type BytesEncStructureLen = [u8; ENC_STRUCTURE_LEN];

pub type BytesMac = [u8; MAC_LENGTH];
pub type BytesEncodedVoucher = [u8; ENCODED_VOUCHER_LEN];
pub type EADMessageBuffer = EdhocMessageBuffer; // TODO: make it of size MAX_EAD_SIZE_LEN

#[repr(C)]
#[derive(Default, PartialEq, Copy, Clone, Debug)]
pub enum EDHOCState {
    #[default]
    Start = 0, // initiator and responder
    WaitMessage2 = 1,      // initiator
    ProcessedMessage2 = 2, // initiator
    ProcessedMessage1 = 3, // responder
    WaitMessage3 = 4,      // responder
    Completed = 5,         // initiator and responder
}

#[repr(C)]
#[derive(PartialEq, Debug)]
pub enum EDHOCError {
    Success = 0,
    UnknownPeer = 1,
    MacVerificationFailed = 2,
    UnsupportedMethod = 3,
    UnsupportedCipherSuite = 4,
    ParsingError = 5,
    WrongState = 6,
    EADError = 7,
    UnknownError = 8,
}

#[repr(C)]
#[derive(Default, Copy, Clone, Debug)]
pub struct State(
    pub EDHOCState,
    pub BytesP256ElemLen, // x or y, ephemeral private key of myself
    pub u8,               // c_i, connection identifier chosen by the initiator
    pub BytesP256ElemLen, // g_y or g_x, ephemeral public key of the peer
    pub BytesHashLen,     // prk_3e2m
    pub BytesHashLen,     // prk_4e3m
    pub BytesHashLen,     // prk_out
    pub BytesHashLen,     // prk_exporter
    pub BytesHashLen,     // h_message_1
    pub BytesHashLen,     // th_3
);

#[repr(C)]
#[derive(PartialEq, Debug, Copy, Clone)]
pub struct EdhocMessageBuffer {
    pub content: [u8; MAX_MESSAGE_SIZE_LEN],
    pub len: usize,
}

impl Default for EdhocMessageBuffer {
    fn default() -> Self {
        EdhocMessageBuffer {
            content: [0; MAX_MESSAGE_SIZE_LEN],
            len: 0,
        }
    }
}

pub trait MessageBufferTrait {
    fn new() -> Self;
    fn from_hex(hex: &str) -> Self;
}

impl MessageBufferTrait for EdhocMessageBuffer {
    fn new() -> Self {
        EdhocMessageBuffer {
            content: [0u8; MAX_MESSAGE_SIZE_LEN],
            len: 0,
        }
    }
    fn from_hex(hex: &str) -> Self {
        let mut buffer = EdhocMessageBuffer::new();
        buffer.len = hex.len() / 2;
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let chunk_str = core::str::from_utf8(chunk).unwrap();
            buffer.content[i] = u8::from_str_radix(chunk_str, 16).unwrap();
        }
        buffer
    }
}

impl TryInto<EdhocMessageBuffer> for &[u8] {
    type Error = ();

    fn try_into(self) -> Result<EdhocMessageBuffer, Self::Error> {
        if self.len() <= MAX_MESSAGE_SIZE_LEN {
            let mut buffer = [0u8; MAX_MESSAGE_SIZE_LEN];
            for i in 0..self.len() {
                buffer[i] = self[i];
            }

            Ok(EdhocMessageBuffer {
                content: buffer,
                len: self.len(),
            })
        } else {
            Err(())
        }
    }
}

#[derive(Debug)]
pub struct EADItem {
    pub label: u8,
    pub is_critical: bool,
    // TODO[ead]: have adjustable (smaller) length for this buffer
    pub value: Option<EdhocMessageBuffer>,
}

pub trait EADTrait {
    fn new() -> Self;
}

impl EADTrait for EADItem {
    fn new() -> Self {
        EADItem {
            label: 0,
            is_critical: false,
            value: None,
        }
    }
}

#[derive(Debug)]
pub enum IdCred<'a> {
    CompactKid(u8),
    FullCredential(&'a [u8]),
}

// ---- common functions

mod cbor {
    use super::*;

    /// Check for: an unsigned integer encoded as a single byte
    #[inline(always)]
    pub fn is_cbor_uint_1byte(byte: u8) -> bool {
        return byte >= CBOR_UINT_1BYTE_START && byte <= CBOR_UINT_1BYTE_END;
    }

    /// Check for: an unsigned integer encoded as two bytes
    #[inline(always)]
    pub fn is_cbor_uint_2bytes(byte: u8) -> bool {
        return byte == CBOR_UINT_1BYTE;
    }

    /// Check for: a negative integer encoded as a single byte
    #[inline(always)]
    pub fn is_cbor_neg_int_1byte(byte: u8) -> bool {
        return byte >= CBOR_NEG_INT_1BYTE_START && byte <= CBOR_NEG_INT_1BYTE_END;
    }

    /// Check for: a bstr denoted by a single byte which encodes both type and content length
    #[inline(always)]
    pub fn is_cbor_bstr_1byte_prefix(byte: u8) -> bool {
        return byte >= CBOR_MAJOR_BYTE_STRING && byte <= CBOR_MAJOR_BYTE_STRING_MAX;
    }

    /// Check for: a bstr denoted by two bytes, one for type the other for content length
    #[inline(always)]
    pub fn is_cbor_bstr_2bytes_prefix(byte: u8) -> bool {
        return byte == CBOR_BYTE_STRING;
    }

    /// Check for: a tstr denoted by two bytes, one for type the other for content length
    #[inline(always)]
    pub fn is_cbor_tstr_2bytes_prefix(byte: u8) -> bool {
        return byte == CBOR_TEXT_STRING;
    }

    /// Check for: an array denoted by a single byte which encodes both type and content length
    #[inline(always)]
    pub fn is_cbor_array_1byte_prefix(byte: u8) -> bool {
        return byte >= CBOR_MAJOR_ARRAY && byte <= CBOR_MAJOR_ARRAY_MAX;
    }
}

mod helpers {
    use super::*;

    pub fn encode_info(
        label: u8,
        context: &BytesMaxContextBuffer,
        context_len: usize,
        length: usize,
    ) -> (BytesMaxInfoBuffer, usize) {
        let mut info: BytesMaxInfoBuffer = [0x00; MAX_INFO_LEN];

        // construct info with inline cbor encoding
        info[0] = label;
        let mut info_len = if context_len < 24 {
            info[1] = context_len as u8 | CBOR_MAJOR_BYTE_STRING;
            info[2..2 + context_len].copy_from_slice(&context[..context_len]);
            2 + context_len
        } else {
            info[1] = CBOR_BYTE_STRING;
            info[2] = context_len as u8;
            info[3..3 + context_len].copy_from_slice(&context[..context_len]);
            3 + context_len
        };

        info_len = if length < 24 {
            info[info_len] = length as u8;
            info_len + 1
        } else {
            info[info_len] = CBOR_UINT_1BYTE;
            info[info_len + 1] = length as u8;
            info_len + 2
        };

        (info, info_len)
    }

    pub fn parse_cred<'a>(cred: &'a [u8]) -> Result<(BytesP256ElemLen, u8), EDHOCError> {
        // NOTE: this routine is only guaranteed to work with credentials from lake-traces
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
            return Err(EDHOCError::ParsingError);
        }

        let subject_len = (cred[2] - CBOR_MAJOR_TEXT_STRING) as usize;
        let id_cred_offset: usize = CCS_PREFIX_LEN + subject_len + CNF_AND_COSE_KEY_PREFIX_LEN;
        let g_a_x_offset: usize = id_cred_offset + COSE_KEY_FIRST_ITEMS_LEN;

        Ok((
            cred[g_a_x_offset..g_a_x_offset + P256_ELEM_LEN]
                .try_into()
                .expect("Wrong key length"),
            cred[id_cred_offset],
        ))
    }

    pub fn get_id_cred<'a>(cred: &'a [u8]) -> BytesIdCred {
        let (_g, kid) = parse_cred(cred).unwrap();
        [0xa1, 0x04, 0x41, kid]
    }
}

mod common_edhoc_parsing {
    use super::cbor::*;
    use super::*;

    pub fn parse_suites_i(
        rcvd_message_1: &BufferMessage1,
    ) -> Result<(BytesSuites, usize, usize), EDHOCError> {
        let mut error: EDHOCError = EDHOCError::UnknownError;
        let mut raw_suites_len = 0;
        let mut suites_i = [0u8; SUITES_LEN];
        let mut suites_i_len: usize = 0;

        // match based on first byte of SUITES_I, which can be either an int or an array
        if is_cbor_uint_1byte(rcvd_message_1.content[1]) {
            // CBOR unsigned integer (0..=23)
            suites_i[0] = rcvd_message_1.content[1];
            suites_i_len = 1;
            raw_suites_len = 1;
            error = EDHOCError::Success;
        } else if is_cbor_uint_2bytes(rcvd_message_1.content[1]) {
            // CBOR unsigned integer (one-byte uint8_t follows)
            suites_i[0] = rcvd_message_1.content[2];
            suites_i_len = 1;
            raw_suites_len = 2;
            error = EDHOCError::Success;
        } else if is_cbor_array_1byte_prefix(rcvd_message_1.content[1]) {
            // CBOR array (0..=23 data items follow)
            // the CBOR array length is encoded in the first byte, so we extract it
            let suites_len: usize = (rcvd_message_1.content[1] - CBOR_MAJOR_ARRAY).into();
            raw_suites_len = 1; // account for the CBOR_MAJOR_ARRAY byte
            if suites_len > 1 && suites_len <= EDHOC_SUITES.len() {
                // cipher suite array must be at least 2 elements long, but not longer than the defined cipher suites
                let mut error_occurred = false;
                for j in 0..suites_len {
                    raw_suites_len += 1;
                    if !error_occurred {
                        // parse based on cipher suite identifier
                        if is_cbor_uint_1byte(rcvd_message_1.content[raw_suites_len]) {
                            // CBOR unsigned integer (0..23)
                            suites_i[j] = rcvd_message_1.content[raw_suites_len];
                            suites_i_len += 1;
                        } else if is_cbor_uint_2bytes(rcvd_message_1.content[raw_suites_len]) {
                            // CBOR unsigned integer (one-byte uint8_t follows)
                            raw_suites_len += 1; // account for the 0x18 tag byte
                            suites_i[j] = rcvd_message_1.content[raw_suites_len];
                            suites_i_len += 1;
                        } else {
                            error = EDHOCError::ParsingError;
                            error_occurred = true;
                        }
                    }
                }
                if !error_occurred {
                    error = EDHOCError::Success;
                }
            } else {
                error = EDHOCError::ParsingError;
            }
        } else {
            error = EDHOCError::ParsingError;
        }

        match error {
            EDHOCError::Success => Ok((suites_i, suites_i_len, raw_suites_len)),
            _ => Err(error),
        }
    }

    pub fn parse_ead(
        message: &EdhocMessageBuffer,
        offset: usize,
    ) -> Result<Option<EADItem>, EDHOCError> {
        let mut error: EDHOCError = EDHOCError::UnknownError;
        let mut ead_item = None::<EADItem>;
        let mut ead_value = None::<EdhocMessageBuffer>;

        // assuming label is a single byte integer (negative or positive)
        let label = message.content[offset];
        let res_label = if is_cbor_uint_1byte(label) {
            // CBOR unsigned integer (0..=23)
            Ok((label as u8, false))
        } else if is_cbor_neg_int_1byte(label) {
            // CBOR negative integer (-1..=-24)
            Ok((label - (CBOR_NEG_INT_1BYTE_START - 1), true))
        } else {
            Err(EDHOCError::ParsingError)
        };

        if res_label.is_ok() {
            let (label, is_critical) = res_label.unwrap();
            if message.len > (offset + 1) {
                // EAD value is present
                let mut buffer = EdhocMessageBuffer::new();
                buffer.content[..message.len - (offset + 1)]
                    .copy_from_slice(&message.content[offset + 1..message.len]);
                buffer.len = message.len - (offset + 1);
                ead_value = Some(buffer);
            }
            ead_item = Some(EADItem {
                label,
                is_critical,
                value: ead_value,
            });
            error = EDHOCError::Success;
        } else {
            error = res_label.unwrap_err();
        }

        match error {
            EDHOCError::Success => Ok(ead_item),
            _ => Err(error),
        }
    }

    pub fn parse_message_1(
        rcvd_message_1: &BufferMessage1,
    ) -> Result<
        (
            u8,
            BytesSuites,
            usize,
            BytesP256ElemLen,
            u8,
            Option<EADItem>,
        ),
        EDHOCError,
    > {
        let mut error: EDHOCError = EDHOCError::UnknownError;
        let mut method: u8 = 0xff;
        let mut g_x: BytesP256ElemLen = [0x00; P256_ELEM_LEN];
        let mut suites_i: BytesSuites = [0u8; SUITES_LEN];
        let mut suites_i_len: usize = 0;
        let mut raw_suites_len: usize = 0;
        let mut c_i = 0;
        let mut ead_1 = None::<EADItem>;

        // first element of CBOR sequence must be an integer
        if is_cbor_uint_1byte(rcvd_message_1.content[0]) {
            method = rcvd_message_1.content[0];
            let res_suites = parse_suites_i(rcvd_message_1);

            if res_suites.is_ok() {
                (suites_i, suites_i_len, raw_suites_len) = res_suites.unwrap();

                if is_cbor_bstr_2bytes_prefix(rcvd_message_1.content[1 + raw_suites_len]) {
                    g_x.copy_from_slice(
                        &rcvd_message_1.content
                            [3 + raw_suites_len..3 + raw_suites_len + P256_ELEM_LEN],
                    );

                    c_i = rcvd_message_1.content[3 + raw_suites_len + P256_ELEM_LEN];
                    // check that c_i is encoded as single-byte int (we still do not support bstr encoding)
                    if is_cbor_neg_int_1byte(c_i) || is_cbor_uint_1byte(c_i) {
                        // if there is still more to parse, the rest will be the EAD_1
                        if rcvd_message_1.len > (4 + raw_suites_len + P256_ELEM_LEN) {
                            // NOTE: since the current implementation only supports one EAD handler,
                            // we assume only one EAD item
                            let ead_res =
                                parse_ead(rcvd_message_1, 4 + raw_suites_len + P256_ELEM_LEN);
                            if ead_res.is_ok() {
                                ead_1 = ead_res.unwrap();
                                error = EDHOCError::Success;
                            } else {
                                error = ead_res.unwrap_err();
                            }
                        } else if rcvd_message_1.len == (4 + raw_suites_len + P256_ELEM_LEN) {
                            error = EDHOCError::Success;
                        } else {
                            error = EDHOCError::ParsingError;
                        }
                    } else {
                        error = EDHOCError::ParsingError;
                    }
                } else {
                    error = EDHOCError::ParsingError;
                }
            } else {
                error = res_suites.unwrap_err();
            }
        } else {
            error = EDHOCError::ParsingError;
        }

        match error {
            EDHOCError::Success => Ok((method, suites_i, suites_i_len, g_x, c_i, ead_1)),
            _ => Err(error),
        }
    }
}

#[cfg(test)]
mod test {
    use super::helpers::*;
    use hexlit::hex;

    const CRED_TV: &[u8] = &hex!("a2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
    const G_A_TV: &[u8] = &hex!("BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F0");
    const ID_CRED_TV: &[u8] = &hex!("a1044132");

    #[test]
    fn test_parse_cred() {
        let res = parse_cred(CRED_TV);
        assert!(res.is_ok());
        let (g_a, kid) = res.unwrap();
        assert_eq!(g_a, G_A_TV);
        assert_eq!(kid, ID_CRED_TV[3]);
        assert_eq!(get_id_cred(CRED_TV), ID_CRED_TV);
    }
}
