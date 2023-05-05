#![no_std]

pub use common::*;

#[cfg(feature = "hacspec")]
pub use hacspec::*;

#[cfg(feature = "rust")]
pub use rust::*;

mod common {

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

    #[derive(PartialEq, Debug)]
    pub enum EDHOCError {
        Success = 0,
        UnknownPeer = 1,
        MacVerificationFailed = 2,
        UnsupportedMethod = 3,
        UnsupportedCipherSuite = 4,
        ParsingError = 5,
        WrongState = 6,
        UnknownError = 7,
    }

    #[derive(PartialEq, Debug)]
    pub struct EdhocMessageBuffer {
        pub content: [u8; MAX_MESSAGE_SIZE_LEN],
        pub len: usize,
    }

    impl Default for EdhocMessageBuffer {
        fn default() -> Self {
            EdhocMessageBuffer {
                content: [0u8; MAX_MESSAGE_SIZE_LEN],
                len: 0,
            }
        }
    }

    pub const ID_CRED_LEN: usize = 4;
    pub const SUITES_LEN: usize = 9;
    pub const SUPPORTED_SUITES_LEN: usize = 1;
    pub const MAX_MESSAGE_SIZE_LEN: usize = 120;
    pub const EDHOC_METHOD: u8 = 3u8; // stat-stat is the only supported method
    pub const P256_ELEM_LEN: usize = 32;
    pub const SHA256_DIGEST_LEN: usize = 32;
    pub const AES_CCM_KEY_LEN: usize = 16;
    pub const AES_CCM_IV_LEN: usize = 13;
    pub const AES_CCM_TAG_LEN: usize = 8;
    pub const MAC_LENGTH_2: usize = 8;
    pub const MAC_LENGTH_3: usize = MAC_LENGTH_2;

    // maximum supported length of connection identifier for R
    pub const MAX_KDF_CONTEXT_LEN: usize = 150;
    pub const MAX_KDF_LABEL_LEN: usize = 15; // for "KEYSTREAM_2"
    pub const MAX_BUFFER_LEN: usize = 220;
    pub const CBOR_BYTE_STRING: u8 = 0x58u8;
    pub const CBOR_UINT_1BYTE: u8 = 0x18u8;
    pub const CBOR_MAJOR_TEXT_STRING: u8 = 0x60u8;
    pub const CBOR_MAJOR_BYTE_STRING: u8 = 0x40u8;
    pub const CBOR_MAJOR_ARRAY: u8 = 0x80u8;
    pub const MAX_INFO_LEN: usize = 2 + SHA256_DIGEST_LEN + // 32-byte digest as bstr
				            1 + MAX_KDF_LABEL_LEN +     // label <24 bytes as tstr
						    1 + MAX_KDF_CONTEXT_LEN +   // context <24 bytes as bstr
						    1; // length as u8

    pub const ENC_STRUCTURE_LEN: usize = 8 + 5 + SHA256_DIGEST_LEN; // 8 for ENCRYPT0
}

#[cfg(feature = "rust")]
mod rust {
    use super::common::*;

    pub type U8 = u8;
    pub type BytesEad2 = [u8; 0];
    pub type BytesIdCred = [u8; ID_CRED_LEN];
    pub type BytesSuites = [u8; SUITES_LEN];
    pub type BytesSupportedSuites = [u8; SUPPORTED_SUITES_LEN];
    pub type Bytes8 = [u8; 8];
    pub type BytesCcmKeyLen = [u8; AES_CCM_KEY_LEN];
    pub type BytesCcmIvLen = [u8; AES_CCM_IV_LEN];
    pub type BytesPlaintext2 = EdhocMessageBuffer;
    pub type BytesPlaintext3 = EdhocMessageBuffer;
    pub type BytesMac2 = [u8; MAC_LENGTH_2];
    pub type BytesMac3 = [u8; MAC_LENGTH_3];
    pub type BytesMessage1 = EdhocMessageBuffer;
    pub type BytesMessage3 = EdhocMessageBuffer;
    pub type BytesCiphertext2 = EdhocMessageBuffer;
    pub type BytesCiphertext3 = EdhocMessageBuffer;
    pub type BytesHashLen = [u8; SHA256_DIGEST_LEN];
    pub type BytesP256ElemLen = [u8; P256_ELEM_LEN];
    pub type BytesMessage2 = EdhocMessageBuffer;
    pub type BytesMaxBuffer = [u8; MAX_BUFFER_LEN];
    pub type BytesMaxContextBuffer = [u8; MAX_KDF_CONTEXT_LEN];
    pub type BytesMaxInfoBuffer = [u8; MAX_INFO_LEN];
    pub type BytesMaxLabelBuffeer = [u8; MAX_KDF_LABEL_LEN];
    pub type BytesEncStructureLen = [u8; ENC_STRUCTURE_LEN];

    pub const C_I: u8 = 0x37u8;
    pub const C_R: u8 = 0x00u8;
    pub const EDHOC_SUITES: BytesSuites = [0, 1, 2, 3, 4, 5, 6, 24, 25]; // all but private cipher suites
    pub const EDHOC_SUPPORTED_SUITES: BytesSupportedSuites = [0x2u8];

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
}

#[cfg(feature = "hacspec")]
mod hacspec {
    use super::common::*;
    use hacspec_lib::*;

    pub const MESSAGE_3_LEN: usize = CIPHERTEXT_3_LEN + 1; // 1 to wrap ciphertext into a cbor byte string
                                                           // ciphertext is message_len -1 for c_r, -2 for cbor magic numbers
    pub const PLAINTEXT_3_LEN: usize = MAC_LENGTH_3 + 2; // support for kid auth only
    pub const CIPHERTEXT_3_LEN: usize = PLAINTEXT_3_LEN + AES_CCM_TAG_LEN;

    array!(BytesMessageBuffer, MAX_MESSAGE_SIZE_LEN, U8);

    #[derive(Debug)]
    pub struct EdhocMessageBufferHacspec {
        pub content: BytesMessageBuffer,
        pub len: usize,
    }

    impl Default for EdhocMessageBufferHacspec {
        fn default() -> Self {
            EdhocMessageBufferHacspec {
                content: BytesMessageBuffer::new(),
                len: 0,
            }
        }
    }

    impl EdhocMessageBufferHacspec {
        pub fn from_hex(hex: &str) -> Self {
            let mut buffer = EdhocMessageBufferHacspec::default();
            buffer.len = hex.len() / 2;
            for i in (0..hex.len()).step_by(2) {
                buffer.content[i / 2] = U8(u8::from_str_radix(&hex[i..i + 2], 16).unwrap());
            }
            buffer
        }
        pub fn from_public_slice(buffer: &EdhocMessageBuffer) -> Self {
            let mut hacspec_buffer = EdhocMessageBufferHacspec::default();
            hacspec_buffer.len = buffer.len;
            hacspec_buffer.content = BytesMessageBuffer::from_public_slice(&buffer.content[..]);
            hacspec_buffer
        }
        pub fn from_slice_bytes_max(buffer: &BytesMaxBuffer, start: usize, len: usize) -> Self {
            // FIXME: refactor to have EdhocMessageBuffer instead of BytesMaxBuffer, then remove or adjust this function
            let mut hacspec_buffer = EdhocMessageBufferHacspec::default();
            hacspec_buffer.len = len;
            hacspec_buffer.content = BytesMessageBuffer::from_slice(buffer, start, len);
            hacspec_buffer
        }
        pub fn from_slice(buffer: &BytesMessageBuffer, start: usize, len: usize) -> Self {
            let mut hacspec_buffer = EdhocMessageBufferHacspec::default();
            hacspec_buffer.len = len;
            hacspec_buffer.content = BytesMessageBuffer::from_slice(buffer, start, len);
            hacspec_buffer
        }
        pub fn from_seq(buffer: &Seq<U8>) -> Self {
            EdhocMessageBufferHacspec {
                content: BytesMessageBuffer::from_slice(buffer, 0, buffer.len()),
                len: buffer.len(),
            }
        }
        pub fn to_public_array(&self) -> EdhocMessageBuffer {
            let mut buffer = EdhocMessageBuffer::default();
            buffer.content = self.content.to_public_array();
            buffer.len = self.len;
            buffer
        }
    }

    array!(BytesEad2, 0, U8);
    array!(BytesIdCred, ID_CRED_LEN, U8);
    array!(BytesSupportedSuites, SUPPORTED_SUITES_LEN, U8);
    array!(Bytes8, 8, U8);
    array!(BytesCcmKeyLen, AES_CCM_KEY_LEN, U8);
    array!(BytesCcmIvLen, AES_CCM_IV_LEN, U8);
    pub type BytesPlaintext2 = EdhocMessageBufferHacspec;
    pub type BytesPlaintext3 = EdhocMessageBufferHacspec;
    array!(BytesMac2, MAC_LENGTH_2, U8);
    array!(BytesMac3, MAC_LENGTH_3, U8);
    pub type BytesMessage1 = EdhocMessageBufferHacspec;
    pub type BytesMessage3 = EdhocMessageBufferHacspec;
    pub type BytesCiphertext2 = EdhocMessageBufferHacspec;
    pub type BytesCiphertext3 = EdhocMessageBufferHacspec;
    array!(BytesHashLen, SHA256_DIGEST_LEN, U8);
    array!(BytesP256ElemLen, P256_ELEM_LEN, U8);
    pub type BytesMessage2 = EdhocMessageBufferHacspec;
    array!(BytesMaxBuffer, MAX_BUFFER_LEN, U8);
    array!(BytesMaxContextBuffer, MAX_KDF_CONTEXT_LEN, U8);
    array!(BytesMaxInfoBuffer, MAX_INFO_LEN, U8);
    array!(BytesMaxLabelBuffer, MAX_KDF_LABEL_LEN, U8);
    array!(BytesEncStructureLen, ENC_STRUCTURE_LEN, U8);

    pub const C_I: U8 = U8(0x37u8);
    pub const C_R: U8 = U8(0x00u8);

    // Currently only suite number 2 is supported,
    // which corresponds to the array 10, -16, 8, 1, -7, 10, -16,
    // which in turn corresponds to the following:
    // - AES-CCM-16-64-128 | EDHOC AEAD algorithm
    // - SHA-256 | EDHOC hash algorithm
    // - 8 | MAC length in bytes
    // - P-256 | key exchange algorithm
    // - ES256 | signature algorithm
    // - AES-CCM-16-64-128 | Application AEAD algorithm
    // - SHA-256 | Application hash algorithm
    pub const EDHOC_SUPPORTED_SUITES: BytesSupportedSuites =
        BytesSupportedSuites(secret_bytes!([0x2u8]));

    #[derive(Default, Copy, Clone, Debug)]
    pub struct State(
        pub EDHOCState,
        pub BytesP256ElemLen, // x or y, ephemeral private key of myself
        pub U8,               // c_i, connection identifier chosen by the initiator
        pub BytesP256ElemLen, // g_y or g_x, ephemeral public key of the peer
        pub BytesHashLen,     // prk_3e2m
        pub BytesHashLen,     // prk_4e3m
        pub BytesHashLen,     // prk_out
        pub BytesHashLen,     // prk_exporter
        pub BytesHashLen,     // h_message_1
        pub BytesHashLen,     // th_3
    );
}
