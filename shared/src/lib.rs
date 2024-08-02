//! Common data structures used by [lakers] and its dependent crates
//!
//! This crate is separate from lakers to avoid circular dependencies that would otherwise arise
//! from the pattern in which [lakers-ead] combined the main crate with variations of the
//! protocol's EAD handling. As its types will then likely move over into the main lakers crate, it
//! is recommended to use them through the public re-export there wherever possible.
//!
//! [lakers]: https://docs.rs/lakers/
//! [lakers-ead]: https://docs.rs/lakers-ead/latest/lakers_ead/
// NOTE: if there is no python-bindings feature, which will be the case for embedded builds,
//       then the crate will be no_std
#![cfg_attr(not(feature = "python-bindings"), no_std)]

pub use cbor_decoder::*;
pub use edhoc_parser::*;
pub use helpers::*;

use core::num::NonZeroI16;
use defmt_or_log::trace;

mod crypto;
pub use crypto::*;

mod cred;
pub use cred::*;

mod buffer;
pub use buffer::*;

#[cfg(feature = "python-bindings")]
use pyo3::prelude::*;
#[cfg(feature = "python-bindings")]
mod python_bindings;

/// Configured upscaling applied to fixed-size buffers
///
/// Do not rely on this: It is only pub because cbindgen needs it.
#[cfg(not(feature = "quadruple_sizes"))]
#[doc(hidden)]
pub const SCALE_FACTOR: usize = 1;
#[cfg(feature = "quadruple_sizes")]
#[doc(hidden)]
pub const SCALE_FACTOR: usize = 4;

// TODO: find a way to configure the buffer size
// need 128 to handle EAD fields, and 192 for the EAD_1 voucher
pub const MAX_MESSAGE_SIZE_LEN: usize = SCALE_FACTOR * (128 + 64);

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
pub const MAX_KDF_CONTEXT_LEN: usize = SCALE_FACTOR * 256;
pub const MAX_KDF_LABEL_LEN: usize = 15; // for "KEYSTREAM_2"
pub const MAX_BUFFER_LEN: usize = SCALE_FACTOR * 256 + 64;
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
pub const CBOR_MAJOR_MAP: u8 = 0xA0;
pub const MAX_INFO_LEN: usize = 2 + SHA256_DIGEST_LEN + // 32-byte digest as bstr
				            1 + MAX_KDF_LABEL_LEN +     // label <24 bytes as tstr
						    1 + MAX_KDF_CONTEXT_LEN +   // context <24 bytes as bstr
						    1; // length as u8

pub const KCSS_LABEL: u8 = 14;
pub const KID_LABEL: u8 = 4;

pub const ENC_STRUCTURE_LEN: usize = 8 + 5 + SHA256_DIGEST_LEN; // 8 for ENCRYPT0

pub const MAX_EAD_SIZE_LEN: usize = SCALE_FACTOR * 64;

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

/// Value of C_R or C_I, as chosen by ourself or the peer.
///
/// Semantically, this is a byte string of some length.
///
/// This currently only supports numeric values (see
/// https://github.com/openwsn-berkeley/lakers/issues/258), but may support larger values in the
/// future.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
// TODO: This should not be needed, there is nothing special about the value 0.
#[derive(Default)]
pub struct ConnId(u8);

impl ConnId {
    /// Construct a ConnId from the result of [`cbor_decoder::int_raw`], which is a
    /// byte that represents a single positive or negative CBOR integer encoded in the 5 bits minor
    /// type.
    ///
    /// Evolving from u8-only values, this could later interact with the decoder directly.
    pub const fn from_int_raw(raw: u8) -> Self {
        debug_assert!(raw >> 5 <= 1, "Major type is not an integer");
        debug_assert!(raw & 0x1f < 24, "Value is not immediate");
        Self(raw)
    }

    /// The bytes that form the identifier (an arbitrary byte string)
    pub fn as_slice(&self) -> &[u8] {
        core::slice::from_ref(&self.0)
    }

    /// The CBOR encoding of the identifier.
    ///
    /// For the 48 compact connection identifiers -24..=23, this is identical to the slice
    /// representation:
    ///
    /// ```
    /// # use lakers_shared::ConnId;
    /// let c_i = ConnId::from_slice(&[0x04]).unwrap();
    /// assert_eq!(c_i.as_cbor(), &[0x04]);
    /// ```
    ///
    /// For other IDs, this contains an extra byte header (but those are currently unsupported):
    ///
    /// ```should_panic
    /// # use lakers_shared::ConnId;
    /// let c_i = ConnId::from_slice(&[0xff]).unwrap();
    /// assert_eq!(c_i.as_cbor(), &[0x41, 0xff]);
    /// ```
    pub fn as_cbor(&self) -> &[u8] {
        core::slice::from_ref(&self.0)
    }

    /// Try to construct a ConnId from a slice.
    ///
    /// This is the inverse of [Self::as_slice], and returns None if the identifier is too long
    /// (or, if only the compact 48 values are supported, outside of that range).
    ///
    /// ```
    /// # use lakers_shared::ConnId;
    /// let c_i = &[0x04];
    /// let c_i = ConnId::from_slice(c_i).unwrap();
    /// assert!(c_i.as_slice() == &[0x04]);
    ///
    /// // So far, longer slices are unsupported
    /// assert!(ConnId::from_slice(&[0x12, 0x34]).is_none());
    /// ```
    pub fn from_slice(input: &[u8]) -> Option<Self> {
        if input.len() != 1 {
            return None;
        }
        if input[0] >> 5 > 1 {
            return None;
        }
        if input[0] & 0x1f >= 24 {
            return None;
        }
        Some(Self(input[0]))
    }
}

#[derive(PartialEq, Debug)]
pub enum EDHOCMethod {
    StatStat = 3,
    // add others, such as:
    // PSK1 = ?,
    // PSK2 = ?,
}

impl From<EDHOCMethod> for u8 {
    fn from(method: EDHOCMethod) -> u8 {
        method as u8
    }
}

#[derive(PartialEq, Debug)]
pub enum EDHOCSuite {
    CipherSuite2 = 2,
    // add others, such as:
    // CiherSuite3 = 3,
}

impl From<EDHOCSuite> for u8 {
    fn from(suite: EDHOCSuite) -> u8 {
        suite as u8
    }
}

#[derive(PartialEq, Debug)]
#[non_exhaustive]
pub enum EDHOCError {
    /// In an exchange, a credential was set as "expected", but the credential configured by the
    /// peer did not match what was presented. This is more an application internal than an EDHOC
    /// error: When the application sets the expected credential, that process should be informed
    /// by the known details.
    UnexpectedCredential,
    MissingIdentity,
    IdentityAlreadySet,
    MacVerificationFailed,
    UnsupportedMethod,
    UnsupportedCipherSuite,
    ParsingError,
    EncodingError,
    CredentialTooLongError,
    EadLabelTooLongError,
    EadTooLongError,
    /// An EAD was received that was either not known (and critical), or not understood, or
    /// otherwise erroneous.
    EADUnprocessable,
    /// The credential or EADs could be processed (possibly by a third party), but the decision
    /// based on that was to not to continue the EDHOC session.
    ///
    /// See also
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-lake-authz#name-edhoc-error-access-denied>
    AccessDenied,
}

impl EDHOCError {
    /// The ERR_CODE corresponding to the error
    ///
    /// Errors that refer to internal limitations (such as EadTooLongError) are treated the same
    /// way as parsing errors, and return an unspecified error: Those are equivalent to limitations
    /// of the parser, and a constrained system can not be expected to differentiate between "the
    /// standard allows this but my number space is too small" and "this violates the standard".
    ///
    /// If an EDHOCError is returned through EDHOC, it will use this in its EDHOC error message.
    ///
    /// Note that this on its own is insufficient to create an error message: Additional ERR_INFO
    /// is needed, which may or may not be available with the EDHOCError alone.
    ///
    /// TODO: Evolve the EDHOCError type such that all information needed is available.
    pub fn err_code(&self) -> ErrCode {
        use EDHOCError::*;
        match self {
            UnexpectedCredential => ErrCode::UNSPECIFIED,
            MissingIdentity => ErrCode::UNSPECIFIED,
            IdentityAlreadySet => ErrCode::UNSPECIFIED,
            MacVerificationFailed => ErrCode::UNSPECIFIED,
            UnsupportedMethod => ErrCode::UNSPECIFIED,
            UnsupportedCipherSuite => ErrCode::WRONG_SELECTED_CIPHER_SUITE,
            ParsingError => ErrCode::UNSPECIFIED,
            EncodingError => ErrCode::UNSPECIFIED,
            CredentialTooLongError => ErrCode::UNSPECIFIED,
            EadLabelTooLongError => ErrCode::UNSPECIFIED,
            EadTooLongError => ErrCode::UNSPECIFIED,
            EADUnprocessable => ErrCode::UNSPECIFIED,
            AccessDenied => ErrCode::ACCESS_DENIED,
        }
    }
}

/// Representation of an EDHOC ERR_CODE
#[repr(C)]
pub struct ErrCode(pub NonZeroI16);

impl ErrCode {
    // The way these are initialized will be simplified once const_option is stable

    pub const UNSPECIFIED: Self = ErrCode(match NonZeroI16::new(1) {
        Some(v) => v,
        _ => unreachable!(),
    });
    pub const WRONG_SELECTED_CIPHER_SUITE: Self = ErrCode(match NonZeroI16::new(2) {
        Some(v) => v,
        _ => unreachable!(),
    });
    pub const UNKNOWN_CREDENTIAL: Self = ErrCode(match NonZeroI16::new(3) {
        Some(v) => v,
        _ => unreachable!(),
    });
    // Code requested in https://datatracker.ietf.org/doc/html/draft-ietf-lake-authz
    pub const ACCESS_DENIED: Self = ErrCode(match NonZeroI16::new(3333) {
        Some(v) => v,
        _ => unreachable!(),
    });
}

#[derive(Debug)]
#[repr(C)]
pub struct InitiatorStart {
    pub suites_i: EdhocBuffer<MAX_SUITES_LEN>,
    pub method: u8,
    pub x: BytesP256ElemLen,   // ephemeral private key of myself
    pub g_x: BytesP256ElemLen, // ephemeral public key of myself
}

#[derive(Debug)]
pub struct ResponderStart {
    pub method: u8,
    pub y: BytesP256ElemLen,   // ephemeral private key of myself
    pub g_y: BytesP256ElemLen, // ephemeral public key of myself
}

#[derive(Default, Debug)]
pub struct ProcessingM1 {
    pub y: BytesP256ElemLen,
    pub g_y: BytesP256ElemLen,
    pub c_i: ConnId,
    pub g_x: BytesP256ElemLen, // ephemeral public key of the initiator
    pub h_message_1: BytesHashLen,
}

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct WaitM2 {
    pub x: BytesP256ElemLen, // ephemeral private key of the initiator
    pub h_message_1: BytesHashLen,
}

#[derive(Default, Debug)]
pub struct WaitM3 {
    pub y: BytesP256ElemLen, // ephemeral private key of the responder
    pub prk_3e2m: BytesHashLen,
    pub th_3: BytesHashLen,
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct ProcessingM2 {
    pub mac_2: BytesMac2,
    pub prk_2e: BytesHashLen,
    pub th_2: BytesHashLen,
    pub x: BytesP256ElemLen,
    pub g_y: BytesP256ElemLen,
    pub plaintext_2: EdhocMessageBuffer,
    pub c_r: ConnId,
    pub id_cred_r: IdCred,
    pub ead_2: Option<EADItem>,
}

#[derive(Default, Debug)]
#[repr(C)]
pub struct ProcessedM2 {
    pub prk_3e2m: BytesHashLen,
    pub prk_4e3m: BytesHashLen,
    pub th_3: BytesHashLen,
}

#[derive(Default, Debug)]
pub struct ProcessingM3 {
    pub mac_3: BytesMac3,
    pub y: BytesP256ElemLen, // ephemeral private key of the responder
    pub prk_3e2m: BytesHashLen,
    pub th_3: BytesHashLen,
    pub id_cred_i: IdCred,
    pub plaintext_3: EdhocMessageBuffer,
    pub ead_3: Option<EADItem>,
}

#[derive(Debug)]
pub struct PreparingM3 {
    pub prk_3e2m: BytesHashLen,
    pub prk_4e3m: BytesHashLen,
    pub th_3: BytesHashLen,
    pub mac_3: BytesMac3,
}

#[derive(Default, Debug)]
#[repr(C)]
pub struct Completed {
    pub prk_out: BytesHashLen,
    pub prk_exporter: BytesHashLen,
}

#[cfg_attr(feature = "python-bindings", pyclass(eq, eq_int))]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(C)]
pub enum CredentialTransfer {
    ByReference,
    ByValue,
}

#[derive(PartialEq, Debug)]
#[repr(C)]
pub enum MessageBufferError {
    BufferAlreadyFull,
    SliceTooLong,
}

/// An owned u8 vector of a limited length
///
/// It is used to represent the various messages in encrypted and in decrypted form, as well as
/// other data items. Its maximum length is [MAX_MESSAGE_SIZE_LEN].
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

impl EdhocMessageBuffer {
    pub fn new() -> Self {
        EdhocMessageBuffer {
            content: [0u8; MAX_MESSAGE_SIZE_LEN],
            len: 0,
        }
    }

    pub fn new_from_slice(slice: &[u8]) -> Result<Self, MessageBufferError> {
        let mut buffer = Self::new();
        if buffer.fill_with_slice(slice).is_ok() {
            Ok(buffer)
        } else {
            Err(MessageBufferError::SliceTooLong)
        }
    }

    pub fn get(self, index: usize) -> Option<u8> {
        self.content.get(index).copied()
    }

    pub fn push(&mut self, item: u8) -> Result<(), MessageBufferError> {
        if self.len < self.content.len() {
            self.content[self.len] = item;
            self.len += 1;
            Ok(())
        } else {
            Err(MessageBufferError::BufferAlreadyFull)
        }
    }

    pub fn get_slice(&self, start: usize, len: usize) -> Option<&[u8]> {
        self.content.get(start..start + len)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.content[0..self.len]
    }

    pub fn fill_with_slice(&mut self, slice: &[u8]) -> Result<(), MessageBufferError> {
        if slice.len() <= self.content.len() {
            self.len = slice.len();
            self.content[..self.len].copy_from_slice(slice);
            Ok(())
        } else {
            Err(MessageBufferError::SliceTooLong)
        }
    }

    pub fn extend_from_slice(&mut self, slice: &[u8]) -> Result<(), MessageBufferError> {
        if self.len + slice.len() <= self.content.len() {
            self.content[self.len..self.len + slice.len()].copy_from_slice(slice);
            self.len += slice.len();
            Ok(())
        } else {
            Err(MessageBufferError::SliceTooLong)
        }
    }

    pub fn from_hex(hex: &str) -> Self {
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
        let mut buffer = [0u8; MAX_MESSAGE_SIZE_LEN];
        if self.len() <= buffer.len() {
            buffer[..self.len()].copy_from_slice(self);

            Ok(EdhocMessageBuffer {
                content: buffer,
                len: self.len(),
            })
        } else {
            Err(())
        }
    }
}

#[cfg_attr(feature = "python-bindings", pyclass)]
#[derive(Clone, Debug)]
pub struct EADItem {
    pub label: u8,
    pub is_critical: bool,
    // TODO[ead]: have adjustable (smaller) length for this buffer
    pub value: Option<EdhocMessageBuffer>,
}

impl EADItem {
    pub fn new() -> Self {
        EADItem {
            label: 0,
            is_critical: false,
            value: None,
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
}

// TODO: move to own file (or even to the main crate, once EAD is extracted as an external dependency)
mod edhoc_parser {
    use super::*;

    pub fn parse_ead(buffer: &[u8]) -> Result<Option<EADItem>, EDHOCError> {
        trace!("Enter parse_ead");
        // assuming label is a single byte integer (negative or positive)
        if let Some((&label, tail)) = buffer.split_first() {
            let label_res = if CBORDecoder::is_u8(label) {
                // CBOR unsigned integer (0..=23)
                Ok((label, false))
            } else if CBORDecoder::is_i8(label) {
                // CBOR negative integer (-1..=-24)
                Ok((label - (CBOR_NEG_INT_1BYTE_START - 1), true))
            } else {
                Err(EDHOCError::ParsingError)
            };

            if let Ok((label, is_critical)) = label_res {
                let ead_value = if tail.len() > 0 {
                    // EAD value is present
                    let mut buffer = EdhocMessageBuffer::new();
                    buffer.fill_with_slice(tail).unwrap(); // TODO(hax): this *should* not panic due to the buffer sizes passed from upstream functions. can we prove it with hax?
                    buffer.len = tail.len();
                    Some(buffer)
                } else {
                    None
                };
                let ead_item = Some(EADItem {
                    label,
                    is_critical,
                    value: ead_value,
                });
                Ok(ead_item)
            } else {
                Err(EDHOCError::ParsingError)
            }
        } else {
            Err(EDHOCError::ParsingError)
        }
    }

    pub fn parse_suites_i(
        mut decoder: CBORDecoder,
    ) -> Result<(EdhocBuffer<MAX_SUITES_LEN>, CBORDecoder), EDHOCError> {
        trace!("Enter parse_suites_i");
        let mut suites_i: EdhocBuffer<MAX_SUITES_LEN> = Default::default();
        if let Ok(curr) = decoder.current() {
            if CBOR_UINT_1BYTE_START == CBORDecoder::type_of(curr) {
                let Ok(_) = suites_i.push(decoder.u8()?) else {
                    return Err(EDHOCError::ParsingError);
                };
                Ok((suites_i, decoder))
            } else if CBOR_MAJOR_ARRAY == CBORDecoder::type_of(curr)
                && CBORDecoder::info_of(curr) >= 2
            {
                // NOTE: arrays must be at least 2 items long, otherwise the compact encoding (int) must be used
                let received_suites_i_len = decoder.array()?;
                if received_suites_i_len <= suites_i.capacity() {
                    for i in 0..received_suites_i_len {
                        // NOTE: could use suites_i.push, but hax complains about mutable references in loops
                        suites_i.content[i] = decoder.u8()?;
                    }
                    suites_i.len = received_suites_i_len;
                    Ok((suites_i, decoder))
                } else {
                    Err(EDHOCError::ParsingError)
                }
            } else {
                Err(EDHOCError::ParsingError)
            }
        } else {
            Err(EDHOCError::ParsingError)
        }
    }

    pub fn parse_message_1(
        rcvd_message_1: &BufferMessage1,
    ) -> Result<
        (
            u8,
            EdhocBuffer<MAX_SUITES_LEN>,
            BytesP256ElemLen,
            ConnId,
            Option<EADItem>,
        ),
        EDHOCError,
    > {
        trace!("Enter parse_message_1");
        let mut decoder = CBORDecoder::new(rcvd_message_1.as_slice());
        let method = decoder.u8()?;

        if let Ok((suites_i, mut decoder)) = parse_suites_i(decoder) {
            let mut g_x: BytesP256ElemLen = [0x00; P256_ELEM_LEN];
            g_x.copy_from_slice(decoder.bytes_sized(P256_ELEM_LEN)?);

            // consume c_i encoded as single-byte int (we still do not support bstr encoding)
            let c_i = ConnId::from_int_raw(decoder.int_raw()?);

            // if there is still more to parse, the rest will be the EAD_1
            if rcvd_message_1.len > decoder.position() {
                // NOTE: since the current implementation only supports one EAD handler,
                // we assume only one EAD item
                let ead_res = parse_ead(decoder.remaining_buffer()?);
                if let Ok(ead_1) = ead_res {
                    Ok((method, suites_i, g_x, c_i, ead_1))
                } else {
                    Err(ead_res.unwrap_err())
                }
            } else if decoder.finished() {
                Ok((method, suites_i, g_x, c_i, None))
            } else {
                Err(EDHOCError::ParsingError)
            }
        } else {
            Err(EDHOCError::ParsingError)
        }
    }

    pub fn parse_message_2(
        rcvd_message_2: &BufferMessage2,
    ) -> Result<(BytesP256ElemLen, BufferCiphertext2), EDHOCError> {
        trace!("Enter parse_message_2");
        // FIXME decode negative integers as well
        let mut ciphertext_2: BufferCiphertext2 = BufferCiphertext2::new();

        let mut decoder = CBORDecoder::new(rcvd_message_2.as_slice());

        // message_2 consists of 1 bstr element; this element in turn contains the concatenation of g_y and ciphertext_2
        let decoded = decoder.bytes()?;
        if decoder.finished() {
            if let Some(key) = decoded.get(0..P256_ELEM_LEN) {
                let mut g_y: BytesP256ElemLen = [0x00; P256_ELEM_LEN];
                g_y.copy_from_slice(key);
                if let Some(c2) = decoded.get(P256_ELEM_LEN..) {
                    if ciphertext_2.fill_with_slice(c2).is_ok() {
                        Ok((g_y, ciphertext_2))
                    } else {
                        Err(EDHOCError::ParsingError)
                    }
                } else {
                    Err(EDHOCError::ParsingError)
                }
            } else {
                Err(EDHOCError::ParsingError)
            }
        } else {
            Err(EDHOCError::ParsingError)
        }
    }

    pub fn decode_plaintext_2(
        plaintext_2: &BufferCiphertext2,
    ) -> Result<(ConnId, IdCred, BytesMac2, Option<EADItem>), EDHOCError> {
        trace!("Enter decode_plaintext_2");
        let mut mac_2: BytesMac2 = [0x00; MAC_LENGTH_2];

        let mut decoder = CBORDecoder::new(plaintext_2.as_slice());

        let c_r = ConnId::from_int_raw(decoder.int_raw()?);

        // the id_cred may have been encoded as a single int, a byte string, or a map
        let id_cred_r = IdCred::from_encoded_value(decoder.any_as_encoded()?)?;

        mac_2[..].copy_from_slice(decoder.bytes_sized(MAC_LENGTH_2)?);

        // if there is still more to parse, the rest will be the EAD_2
        if plaintext_2.len > decoder.position() {
            // assume only one EAD item
            let ead_res = parse_ead(decoder.remaining_buffer()?);
            if let Ok(ead_2) = ead_res {
                Ok((c_r, id_cred_r, mac_2, ead_2))
            } else {
                Err(ead_res.unwrap_err())
            }
        } else if decoder.finished() {
            Ok((c_r, id_cred_r, mac_2, None))
        } else {
            Err(EDHOCError::ParsingError)
        }
    }

    pub fn decode_plaintext_3(
        plaintext_3: &BufferPlaintext3,
    ) -> Result<(IdCred, BytesMac3, Option<EADItem>), EDHOCError> {
        trace!("Enter decode_plaintext_3");
        let mut mac_3: BytesMac3 = [0x00; MAC_LENGTH_3];

        let mut decoder = CBORDecoder::new(plaintext_3.as_slice());

        // the id_cred may have been encoded as a single int, a byte string, or a map
        let id_cred_i = IdCred::from_encoded_value(decoder.any_as_encoded()?)?;

        mac_3[..].copy_from_slice(decoder.bytes_sized(MAC_LENGTH_3)?);

        // if there is still more to parse, the rest will be the EAD_3
        if plaintext_3.len > decoder.position() {
            // assume only one EAD item
            let ead_res = parse_ead(decoder.remaining_buffer()?);
            if let Ok(ead_3) = ead_res {
                Ok((id_cred_i, mac_3, ead_3))
            } else {
                Err(ead_res.unwrap_err())
            }
        } else if decoder.finished() {
            Ok((id_cred_i, mac_3, None))
        } else {
            Err(EDHOCError::ParsingError)
        }
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

    #[derive(Debug)]
    pub struct CBORDecoder<'a> {
        buf: &'a [u8],
        pos: usize,
    }

    impl<'a> CBORDecoder<'a> {
        pub fn new(bytes: &'a [u8]) -> Self {
            CBORDecoder { buf: bytes, pos: 0 }
        }

        fn read(&mut self) -> Result<u8, CBORError> {
            if let Some(b) = self.buf.get(self.pos) {
                self.pos += 1;
                Ok(*b)
            } else {
                Err(CBORError::DecodingError)
            }
        }

        /// Consume and return *n* bytes starting at the current position.
        fn read_slice(&mut self, n: usize) -> Result<&'a [u8], CBORError> {
            if let Some(b) = self
                .pos
                .checked_add(n)
                .and_then(|end| self.buf.get(self.pos..end))
            {
                self.pos += n;
                Ok(b)
            } else {
                Err(CBORError::DecodingError)
            }
        }

        pub fn position(&self) -> usize {
            self.pos
        }

        pub fn finished(&self) -> bool {
            self.pos == self.buf.len()
        }

        pub fn ensure_finished(&self) -> Result<(), CBORError> {
            if self.finished() {
                Ok(())
            } else {
                Err(CBORError::DecodingError)
            }
        }

        pub fn remaining_buffer(&self) -> Result<&[u8], CBORError> {
            if let Some(buffer) = self.buf.get(self.pos..) {
                Ok(buffer)
            } else {
                Err(CBORError::DecodingError)
            }
        }

        /// Get the byte at the current position.
        pub fn current(&self) -> Result<u8, CBORError> {
            if let Some(b) = self.buf.get(self.pos) {
                Ok(*b)
            } else {
                Err(CBORError::DecodingError)
            }
        }

        /// Decode a `u8` value.
        pub fn u8(&mut self) -> Result<u8, CBORError> {
            let n = self.read()?;
            // NOTE: thid could be a `match` with `n @ 0x00..=0x17` clauses but hax doesn't support it
            if (0..=0x17).contains(&n) {
                Ok(n)
            } else if 0x18 == n {
                self.read()
            } else {
                Err(CBORError::DecodingError)
            }
        }

        /// Decode an `i8` value.
        pub fn i8(&mut self) -> Result<i8, CBORError> {
            let n = self.read()?;
            if (0..=0x17).contains(&n) {
                Ok(n as i8)
            } else if (0x20..=0x37).contains(&n) {
                Ok(-1 - (n - 0x20) as i8)
            } else if 0x18 == n {
                Ok(self.read()? as i8)
            } else if 0x38 == n {
                Ok(-1 - (self.read()? - 0x20) as i8)
            } else {
                Err(CBORError::DecodingError)
            }
        }

        /// Get the raw `i8` or `u8` value.
        pub fn int_raw(&mut self) -> Result<u8, CBORError> {
            let n = self.read()?;
            if (0..=0x17).contains(&n) || (0x20..=0x37).contains(&n) {
                Ok(n)
            } else {
                Err(CBORError::DecodingError)
            }
        }

        /// Decode a string slice.
        pub fn str(&mut self) -> Result<&'a [u8], CBORError> {
            let b = self.read()?;
            if CBOR_MAJOR_TEXT_STRING != Self::type_of(b) || Self::info_of(b) == 31 {
                Err(CBORError::DecodingError)
            } else {
                let n = self.as_usize(Self::info_of(b))?;
                self.read_slice(n)
            }
        }

        /// Decode a byte slice.
        pub fn bytes(&mut self) -> Result<&'a [u8], CBORError> {
            let b = self.read()?;
            if CBOR_MAJOR_BYTE_STRING != Self::type_of(b) || Self::info_of(b) == 31 {
                Err(CBORError::DecodingError)
            } else {
                let n = self.as_usize(Self::info_of(b))?;
                self.read_slice(n)
            }
        }

        /// Decode a byte slice of an expected size.
        pub fn bytes_sized(&mut self, expected_size: usize) -> Result<&'a [u8], CBORError> {
            let res = self.bytes()?;
            if res.len() == expected_size {
                Ok(res)
            } else {
                Err(CBORError::DecodingError)
            }
        }

        /// Begin decoding an array.
        pub fn array(&mut self) -> Result<usize, CBORError> {
            let b = self.read()?;
            if CBOR_MAJOR_ARRAY != Self::type_of(b) {
                Err(CBORError::DecodingError)
            } else {
                match Self::info_of(b) {
                    31 => Err(CBORError::DecodingError), // no support for unknown size arrays
                    n => Ok(self.as_usize(n)?),
                }
            }
        }

        /// Begin decoding a map.
        pub fn map(&mut self) -> Result<usize, CBORError> {
            let b = self.read()?;
            if CBOR_MAJOR_MAP != Self::type_of(b) {
                Err(CBORError::DecodingError)
            } else {
                match Self::info_of(b) {
                    n if n < 24 => Ok(self.as_usize(n)?),
                    _ => Err(CBORError::DecodingError), // no support for long or indeterminate size
                }
            }
        }

        /// Decode a `u8` value into usize.
        pub fn as_usize(&mut self, b: u8) -> Result<usize, CBORError> {
            if (0..=0x17).contains(&b) {
                Ok(usize::from(b))
            } else if 0x18 == b {
                self.read().map(usize::from)
            } else {
                Err(CBORError::DecodingError)
            }
        }

        /// Get the major type info of the given byte (highest 3 bits).
        pub fn type_of(b: u8) -> u8 {
            b & 0b111_00000
        }

        /// Get the additionl type info of the given byte (lowest 5 bits).
        pub fn info_of(b: u8) -> u8 {
            b & 0b000_11111
        }

        /// Check for: an unsigned integer encoded as a single byte
        pub fn is_u8(byte: u8) -> bool {
            byte >= CBOR_UINT_1BYTE_START && byte <= CBOR_UINT_1BYTE_END
        }

        /// Check for: a negative integer encoded as a single byte
        pub fn is_i8(byte: u8) -> bool {
            byte >= CBOR_NEG_INT_1BYTE_START && byte <= CBOR_NEG_INT_1BYTE_END
        }

        /// Decode any (supported) CBOR item, but ignore its internal structure and just return the
        /// encoded data.
        ///
        /// To have bound memory requirements, this depends on the encoded data to be in
        /// deterministic encoding, thus not having any indeterminate length items.
        pub fn any_as_encoded(&mut self) -> Result<&'a [u8], CBORError> {
            let mut remaining_items = 1;
            let start = self.position();

            // Instead of `while remaining_items > 0`, this loop helps hax to see that the loop
            // terminates. As every loop iteration advances the cursor by at least 1, the iteration
            // bound introduced by the for loop will never be reached, and the loop only terminates
            // through the remaining_items condition or a failure to read.
            //
            // I trust (but did not verify) that the Rust compiler can make something sensible out
            // of this (especially not keep looping needlessly) and doesn't do anything worse than
            // keep a limited loop counter.
            for _ in self.buf.iter() {
                if remaining_items > 0 {
                    remaining_items -= 1;
                    let head = self.read()?;
                    let major = head >> 5;
                    let minor = head & 0x1f;
                    let argument = match minor {
                        0..=23 => minor,
                        24 => self.read()?,
                        // We do not support values outside the range -256..256.
                        // FIXME: Sooner or later we should. There is probably an upper bound on
                        // lengths we need to support (we don't need to support 32bit integer decoding
                        // for map keys when our maximum buffers are 256 long); will split things up
                        // here into major-0/1/6/7 where we can just skip 1/2/4/8 bytes vs. the other
                        // majors where this is an out-of-bounds error anyway, or just have up to 64bit
                        // decoding available consistently for all?
                        25 | 26 | 27 => return Err(CBORError::DecodingError),
                        // Reserved, not well-formed
                        28 | 29 | 30 => return Err(CBORError::DecodingError),
                        // Indefinite length markers are forbidden in deterministic CBOR (or it's one
                        // of the major types where this is just not well-formed)
                        31 => return Err(CBORError::DecodingError),
                        _ => unreachable!("Value was masked to 5 bits"),
                    };
                    match major {
                        0..=1 => (), // Argument consumed, remaining items were already decremented
                        7 => (), // Same, but in separate line due to Hax FStar backend limitations
                        6 => {
                            remaining_items += 1;
                        }
                        2..=3 => {
                            self.read_slice(argument.into())?;
                        }
                        4 => {
                            remaining_items += argument;
                        }
                        5 => {
                            remaining_items += argument * 2;
                        }
                        _ => unreachable!("Value is result of a right shift trimming it to 3 bits"),
                    }
                }
            }

            Ok(&self.buf[start..self.position()])
        }
    }
}

#[cfg(test)]
mod test_cbor_decoder {
    use super::cbor_decoder::*;
    use hexlit::hex;

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

    #[test]
    fn test_cbor_decoder_any_as_decoded() {
        // {"bytes": 'val', "n": 123, "tagged": 255(["a", -1]), "deep": [[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]], {1: {2: {3: {4: [simple(0), true, null, simple(128)]}}}}]}
        // Note we can't have floats b/c we don't skip long arguments yet (and all floats have
        // minor 25 or longer).
        let input = hex!("A46562797465734376616C616E187B66746167676564D8FF82616120646465657082818181818181818181818181818181818181818180A101A102A103A10484E0F5F6F880");
        let mut decoder = CBORDecoder::new(&input);

        assert_eq!(input, decoder.any_as_encoded().unwrap());
        assert!(decoder.finished())
    }
}
