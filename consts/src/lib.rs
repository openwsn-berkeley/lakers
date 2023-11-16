#![no_std]

use core::marker::PhantomData;

pub use cbor::*;
pub use common_edhoc_parsing::*;
pub use helpers::*;

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

pub type BytesSuites = [u8; SUITES_LEN];
pub type BytesSupportedSuites = [u8; SUPPORTED_SUITES_LEN];
pub const EDHOC_SUITES: BytesSuites = [0, 1, 2, 3, 4, 5, 6, 24, 25]; // all but private cipher suites
pub const EDHOC_SUPPORTED_SUITES: BytesSupportedSuites = [0x2u8];

pub type BytesEad2 = [u8; 0];
pub type BytesIdCred = [u8; ID_CRED_LEN];
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

// This is sealed
pub trait EDHOCState: core::fmt::Debug {}
// For both initiator and responder
#[derive(Debug)]
pub struct Start;
impl EDHOCState for Start {}
// For the initiator
#[derive(Debug)]
pub struct WaitMessage2;
impl EDHOCState for WaitMessage2 {}
#[derive(Debug)]
pub struct ProcessedMessage2;
impl EDHOCState for ProcessedMessage2 {}
// For the responder
#[derive(Debug)]
pub struct ProcessedMessage1;
impl EDHOCState for ProcessedMessage1 {}
#[derive(Debug)]
pub struct WaitMessage3;
impl EDHOCState for WaitMessage3 {}
// For both again
#[derive(Debug)]
pub struct Completed;
impl EDHOCState for Completed {}

#[repr(C)]
#[derive(PartialEq, Debug)]
pub enum EDHOCError {
    UnknownPeer = 1,
    MacVerificationFailed = 2,
    UnsupportedMethod = 3,
    UnsupportedCipherSuite = 4,
    ParsingError = 5,
    EADError = 7,
    UnknownError = 8,
}

#[repr(C)]
#[derive(Debug)]
pub struct State<Phase: EDHOCState>(
    pub PhantomData<Phase>,
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

impl Default for State<Start> {
    fn default() -> Self {
        // This is also what `#[derive(Default)]` would do, but we can't limit that to Start.
        State(
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
        )
    }
}

pub enum AccessError {
    OutOfBounds,
}

impl From<AccessError> for EDHOCError {
    fn from(error: AccessError) -> Self {
        // TODO: can we make this conversion more robust, i.e. what if the access fails but the reason is not ParsingError?
        match error {
            AccessError::OutOfBounds => EDHOCError::ParsingError,
        }
    }
}

#[repr(C)]
#[derive(PartialEq, Debug, Copy, Clone)]
pub struct EdhocMessageBuffer {
    pub content: [u8; MAX_MESSAGE_SIZE_LEN],
    pub len: usize,
}

impl EdhocMessageBuffer {}

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
    fn get(self, index: usize) -> Result<u8, AccessError>;
    fn get_slice<'a>(&'a self, start: usize, len: usize) -> Result<&'a [u8], AccessError>;
    fn from_hex(hex: &str) -> Self;
}

impl MessageBufferTrait for EdhocMessageBuffer {
    fn new() -> Self {
        EdhocMessageBuffer {
            content: [0u8; MAX_MESSAGE_SIZE_LEN],
            len: 0,
        }
    }

    fn get(self, index: usize) -> Result<u8, AccessError> {
        if index >= self.len {
            Err(AccessError::OutOfBounds)
        } else {
            Ok(self.content[index])
        }
    }

    fn get_slice<'a>(&'a self, start: usize, len: usize) -> Result<&'a [u8], AccessError> {
        if start > self.len || start > len || len > self.len {
            Err(AccessError::OutOfBounds)
        } else {
            Ok(&self.content[start..len])
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

    /// returning raw integer, since it is used like this over the library
    pub fn cbor_consume_raw_int(buffer: &[u8], offset: usize) -> Option<(u8, usize)> {
        let byte = *buffer.get(0)?;

        if is_cbor_uint_1byte(byte) || is_cbor_neg_int_1byte(byte) {
            Some((byte, offset + 1))
        } else {
            None
        }
    }

    pub fn cbor_consume_uint(buffer: &[u8], offset: usize) -> Option<(u8, usize)> {
        let byte = *buffer.get(0)?;

        if is_cbor_uint_1byte(byte) {
            Some((byte, offset + 1))
        } else if is_cbor_uint_2bytes(byte) {
            let value = *buffer.get(1)?;
            Some((value, offset + 2))
        } else {
            None
        }
    }

    pub fn cbor_consume_bstr(buffer: &[u8], offset: usize) -> Option<(&[u8], usize)> {
        let first_byte = *buffer.get(0)?;

        if is_cbor_bstr_1byte_prefix(first_byte) {
            let len = (first_byte - CBOR_MAJOR_BYTE_STRING) as usize;
            let data = buffer.get(0..len)?;
            Some((data, offset + 1 + len))
        } else if is_cbor_bstr_2bytes_prefix(first_byte) {
            let len = *buffer.get(1)?;
            let len: usize = len.try_into().expect("Conversion to usize failed");
            let data = buffer.get(2..len + 2)?;
            Some((data, offset + 2 + len))
        } else {
            None
        }
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
    use crate::cbor_decoder::*;

    use super::cbor::*;
    use super::*;

    pub fn parse_suites_i(
        rcvd_message_1: &BufferMessage1,
    ) -> Result<(BytesSuites, usize, usize), EDHOCError> {
        let mut error: EDHOCError = EDHOCError::UnknownError;
        let mut raw_suites_len;
        let mut suites_i = [0u8; SUITES_LEN];
        let mut suites_i_len: usize = 0;
        let suites_i_start = rcvd_message_1.get(1)?;

        // match based on first byte of SUITES_I, which can be either an int or an array
        if is_cbor_uint_1byte(suites_i_start) {
            // CBOR unsigned integer (0..=23)
            suites_i[0] = suites_i_start;
            suites_i_len = 1;
            raw_suites_len = 1;
            Ok((suites_i, suites_i_len, raw_suites_len))
        } else if is_cbor_uint_2bytes(suites_i_start) {
            // CBOR unsigned integer (one-byte uint8_t follows)
            suites_i[0] = rcvd_message_1.get(2)?;
            suites_i_len = 1;
            raw_suites_len = 2;
            Ok((suites_i, suites_i_len, raw_suites_len))
        } else if is_cbor_array_1byte_prefix(suites_i_start) {
            // CBOR array (0..=23 data items follow)
            // the CBOR array length is encoded in the first byte, so we extract it
            let suites_len: usize = (suites_i_start - CBOR_MAJOR_ARRAY).into();
            raw_suites_len = 1; // account for the CBOR_MAJOR_ARRAY byte
            if suites_len > 1 && suites_len <= EDHOC_SUITES.len() {
                // cipher suite array must be at least 2 elements long, but not longer than the defined cipher suites
                let mut error_occurred = false;
                for j in 0..suites_len {
                    raw_suites_len += 1;
                    if !error_occurred {
                        // parse based on cipher suite identifier
                        if is_cbor_uint_1byte(rcvd_message_1.get(raw_suites_len)?) {
                            // CBOR unsigned integer (0..23)
                            suites_i[j] = rcvd_message_1.get(raw_suites_len)?;
                            suites_i_len += 1;
                        } else if is_cbor_uint_2bytes(rcvd_message_1.get(raw_suites_len)?) {
                            // CBOR unsigned integer (one-byte uint8_t follows)
                            raw_suites_len += 1; // account for the 0x18 tag byte
                            suites_i[j] = rcvd_message_1.get(raw_suites_len)?;
                            suites_i_len += 1;
                        } else {
                            error = EDHOCError::ParsingError;
                            error_occurred = true;
                        }
                    }
                }
                if !error_occurred {
                    Ok((suites_i, suites_i_len, raw_suites_len))
                } else {
                    Err(error)
                }
            } else {
                Err(EDHOCError::ParsingError)
            }
        } else {
            Err(EDHOCError::ParsingError)
        }
    }

    pub fn parse_ead(
        message: &EdhocMessageBuffer,
        offset: usize,
    ) -> Result<Option<EADItem>, EDHOCError> {
        let ead_item;
        let mut ead_value = None::<EdhocMessageBuffer>;

        // assuming label is a single byte integer (negative or positive)
        let label = message.get(offset)?;
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
                    .copy_from_slice(&message.get_slice(offset + 1, message.len)?);
                buffer.len = message.len - (offset + 1);
                ead_value = Some(buffer);
            }
            ead_item = Some(EADItem {
                label,
                is_critical,
                value: ead_value,
            });
            Ok(ead_item)
        } else {
            Err(res_label.unwrap_err())
        }
    }

    pub fn parse_message_1(
        rcvd_message_1: &BufferMessage1,
    ) -> Option<(
        u8,
        BytesSuites,
        usize,
        BytesP256ElemLen,
        u8,
        Option<EADItem>,
    )> {
        let suites_i: BytesSuites;
        let suites_i_len: usize;
        let raw_suites_len: usize;

        let mut decoder = CBORDecoder::new(&rcvd_message_1.content);

        let (method, mut offset) = cbor_consume_uint(&rcvd_message_1.content[..], 0)?;

        let res_suites = parse_suites_i(rcvd_message_1);

        if res_suites.is_ok() {
            (suites_i, suites_i_len, raw_suites_len) = res_suites.unwrap();
            offset += raw_suites_len;

            let (g_x_slice, offset) = cbor_consume_bstr(&rcvd_message_1.content[offset..], offset)?;
            let mut g_x: BytesP256ElemLen = [0x00; P256_ELEM_LEN];
            g_x.copy_from_slice(g_x_slice);

            // consume c_i encoded as single-byte int (we still do not support bstr encoding)
            let (c_i, _offset) = cbor_consume_raw_int(&rcvd_message_1.content[offset..], offset)?;

            // if there is still more to parse, the rest will be the EAD_1
            if rcvd_message_1.len > (4 + raw_suites_len + P256_ELEM_LEN) {
                // NOTE: since the current implementation only supports one EAD handler,
                // we assume only one EAD item
                let ead_res = parse_ead(rcvd_message_1, 4 + raw_suites_len + P256_ELEM_LEN);
                if ead_res.is_ok() {
                    let ead_1 = ead_res.unwrap();
                    Some((method, suites_i, suites_i_len, g_x, c_i, ead_1))
                } else {
                    None
                }
            } else if rcvd_message_1.len == (4 + raw_suites_len + P256_ELEM_LEN) {
                Some((method, suites_i, suites_i_len, g_x, c_i, None))
            } else {
                None
            }
        } else {
            None
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

mod edhoc_parser {
    use super::cbor_decoder::*;
    use super::*;

    pub fn parse_message_1_new(
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
        let mut suites_i: BytesSuites = Default::default();
        let suites_i_len: usize;
        let mut g_x: BytesP256ElemLen = [0x00; P256_ELEM_LEN];

        let mut decoder = CBORDecoder::new(&rcvd_message_1.content);

        let method = decoder.u8()?;

        if let Ok(curr) = decoder.current() {
            if CBOR_UINT_1BYTE == CBORDecoder::type_of(curr) {
                suites_i[0] = decoder.u8()?;
                suites_i_len = 1;
            } else if CBOR_MAJOR_ARRAY == CBORDecoder::type_of(curr) {
                // TODO: check array len > 1
                let suites = decoder.array_u8()?;
                suites_i.copy_from_slice(&suites);
                suites_i_len = suites_i.len();
            } else {
                return Err(EDHOCError::ParsingError);
            }
        } else {
            return Err(EDHOCError::ParsingError);
        }

        g_x.copy_from_slice(decoder.array_u8()?);

        //     // consume c_i encoded as single-byte int (we still do not support bstr encoding)
        let c_i = decoder.int_raw()?;

        // // if there is still more to parse, the rest will be the EAD_1
        // if rcvd_message_1.len > decoder.position() {
        //     // NOTE: since the current implementation only supports one EAD handler,
        //     // we assume only one EAD item
        //     let ead_res = parse_ead(rcvd_message_1, 4 + raw_suites_len + P256_ELEM_LEN);
        //     if ead_res.is_ok() {
        //         let ead_1 = ead_res.unwrap();
        //         Some((method, suites_i, suites_i_len, g_x, c_i, ead_1))
        //     } else {
        //         None
        //     }
        // } else if rcvd_message_1.len == (4 + raw_suites_len + P256_ELEM_LEN) {
        //     Some((method, suites_i, suites_i_len, g_x, c_i, None))
        // } else {
        //     None
        // }

        Err(EDHOCError::ParsingError)
    }
}

mod cbor_decoder {
    /// Decoder inspired by the [minicbor](https://crates.io/crates/minicbor) crate.
    use super::*;

    #[derive(Debug)]
    pub enum CBORError {
        DecodingError,
    }

    impl From<CBORError> for EDHOCError {
        fn from(error: CBORError) -> Self {
            match error {
                CBORError::DecodingError => EDHOCError::ParsingError,
            }
        }
    }

    /// CBOR data types.
    #[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
    pub enum Type {
        Bool,
        Null,
        Undefined,
        U8,
        I8,
        Int,
        Bytes,
        String,
        Array,
        Map,
        Break,
        Unknown(u8),
    }

    #[derive(Debug)]
    pub struct CBORDecoder<'a> {
        buf: &'a [u8],
        pos: usize,
    }

    impl<'a> CBORDecoder<'a> {
        pub fn new(bytes: &'a [u8]) -> Self {
            CBORDecoder { buf: bytes, pos: 0 }
        }

        pub fn position(&self) -> usize {
            self.pos
        }

        fn read(&mut self) -> Result<u8, CBORError> {
            if let Some(b) = self.buf.get(self.pos) {
                self.pos += 1;
                return Ok(*b);
            }
            Err(CBORError::DecodingError)
        }

        /// Consume and return *n* bytes starting at the current position.
        fn read_slice(&mut self, n: usize) -> Result<&'a [u8], CBORError> {
            if let Some(b) = self
                .pos
                .checked_add(n)
                .and_then(|end| self.buf.get(self.pos..end))
            {
                self.pos += n;
                return Ok(b);
            }
            Err(CBORError::DecodingError)
        }

        /// Decode a `u8` value.
        pub fn u8(&mut self) -> Result<u8, CBORError> {
            match self.read()? {
                n @ 0..=0x17 => Ok(n),
                0x18 => self.read(),
                _ => Err(CBORError::DecodingError),
            }
        }

        /// Decode an `i8` value.
        pub fn i8(&mut self) -> Result<i8, CBORError> {
            let p = self.pos;
            match self.read()? {
                n @ 0x00..=0x17 => Ok(n as i8),
                n @ 0x20..=0x37 => Ok(-1 - (n - 0x20) as i8),
                _b => Err(CBORError::DecodingError),
            }
        }

        /// Get the raw `i8` or `u8` value.
        pub fn int_raw(&mut self) -> Result<u8, CBORError> {
            let p = self.pos;
            match self.read()? {
                n @ 0x00..=0x17 => Ok(n),
                n @ 0x20..=0x37 => Ok(n),
                _b => Err(CBORError::DecodingError),
            }
        }

        /// Decode a string slice.
        ///
        /// This only decodes string slices of definite lengths.
        pub fn str(&mut self) -> Result<&'a [u8], CBORError> {
            let p = self.pos;
            let b = self.read()?;
            if CBOR_MAJOR_TEXT_STRING != Self::type_of(b) || Self::info_of(b) == 31 {
                return Err(CBORError::DecodingError);
            }
            let n = Self::u64_to_usize(self.unsigned(Self::info_of(b), p)?, p)?;
            self.read_slice(n)
        }

        /// Decode a byte slice.
        ///
        /// This only decodes byte slices of definite lengths.
        pub fn bytes(&mut self) -> Result<&'a [u8], CBORError> {
            let p = self.pos;
            let b = self.read()?;
            if CBOR_MAJOR_BYTE_STRING != Self::type_of(b) || Self::info_of(b) == 31 {
                return Err(CBORError::DecodingError);
            }
            let n = Self::u64_to_usize(self.unsigned(Self::info_of(b), p)?, p)?;
            self.read_slice(n)
        }

        /// Decodes an array of u8 items.
        pub fn array_u8(&mut self) -> Result<&'a [u8], CBORError> {
            let p = self.pos;
            let b = self.read()?;
            if CBOR_MAJOR_ARRAY != Self::type_of(b) {
                return Err(CBORError::DecodingError);
            }
            let n = Self::u64_to_usize(self.unsigned(Self::info_of(b), p)?, p)?;
            self.read_slice(n)
        }

        /// Decode a `u64` value beginning with `b`.
        pub(crate) fn unsigned(&mut self, b: u8, p: usize) -> Result<u64, CBORError> {
            match b {
                n @ 0..=0x17 => Ok(u64::from(n)),
                0x18 => self.read().map(u64::from),
                _ => Err(CBORError::DecodingError),
            }
        }

        /// Get the byte at the current position.
        pub(crate) fn current(&self) -> Result<u8, CBORError> {
            if let Some(b) = self.buf.get(self.pos) {
                return Ok(*b);
            }
            Err(CBORError::DecodingError)
        }

        fn u64_to_usize(n: u64, pos: usize) -> Result<usize, CBORError> {
            n.try_into().map_err(|_| CBORError::DecodingError)
        }

        /// Get the major type info of the given byte (highest 3 bits).
        pub(crate) fn type_of(b: u8) -> u8 {
            b & 0b111_00000
        }

        /// Get the additionl type info of the given byte (lowest 5 bits).
        fn info_of(b: u8) -> u8 {
            b & 0b000_11111
        }
    }
}

#[cfg(test)]
mod test_cbor_decoder {
    use super::cbor_decoder::*;

    #[test]
    fn test_cbor_decoder() {
        // CBOR sequence: 1, -1, "hi", h'fefe'
        let input = [0x01, 0x20, 0x62, 0x68, 0x69, 0x42, 0xFE, 0xFE];
        let mut decoder = CBORDecoder::new(&input);

        assert_eq!(1, decoder.u8().unwrap());
        assert_eq!(-1, decoder.i8().unwrap());
        assert_eq!([0x68, 0x69], decoder.str().unwrap()); // "hi"
        assert_eq!([0xFE, 0xFE], decoder.bytes().unwrap());
    }
}
