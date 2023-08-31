#![no_std]

pub use common::*;

#[cfg(feature = "hacspec")]
pub use hacspec::*;

#[cfg(feature = "rust")]
pub use rust::*;

mod common {

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
    #[derive(PartialEq, Debug)]
    pub struct EdhocMessageBuffer {
        pub content: [u8; MAX_MESSAGE_SIZE_LEN],
        pub len: usize,
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

    pub const MAX_MESSAGE_SIZE_LEN: usize = 64;
    pub const MAX_EAD_SIZE_LEN: usize = 64;
    pub type EADMessageBuffer = EdhocMessageBuffer; // TODO: make it of size MAX_EAD_SIZE_LEN
    pub const EAD_ZEROCONF_LABEL: u8 = 0x1; // NOTE: in lake-authz-draft-02 it is still TBD1

    pub const ID_CRED_LEN: usize = 4;
    pub const SUITES_LEN: usize = 9;
    pub const SUPPORTED_SUITES_LEN: usize = 1;
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
    pub const CBOR_NEG_INT_1BYTE_START: u8 = 0x20u8;
    pub const CBOR_NEG_INT_1BYTE_END: u8 = 0x37u8;
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

    pub const EDHOC_SUITES: BytesSuites = [0, 1, 2, 3, 4, 5, 6, 24, 25]; // all but private cipher suites
    pub const EDHOC_SUPPORTED_SUITES: BytesSupportedSuites = [0x2u8];

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
}

#[cfg(feature = "hacspec")]
mod hacspec {
    use super::common::*;
    use hacspec_lib::*;

    array!(BytesMessageBuffer, MAX_MESSAGE_SIZE_LEN, U8);

    #[derive(Debug)]
    pub struct EdhocMessageBufferHacspec {
        pub content: BytesMessageBuffer,
        pub len: usize,
    }

    pub trait MessageBufferHacspecTrait {
        fn new() -> Self;
        fn from_hex(hex: &str) -> Self;
        fn from_public_buffer(buffer: &EdhocMessageBuffer) -> Self;
        fn from_slice<A>(slice: &A, start: usize, len: usize) -> Self
        where
            A: SeqTrait<U8>;
        fn from_seq(buffer: &Seq<U8>) -> Self;
        fn to_public_buffer(&self) -> EdhocMessageBuffer;
    }

    impl MessageBufferHacspecTrait for EdhocMessageBufferHacspec {
        fn new() -> Self {
            EdhocMessageBufferHacspec {
                content: BytesMessageBuffer::new(),
                len: 0,
            }
        }
        fn from_hex(hex: &str) -> Self {
            let mut buffer = EdhocMessageBufferHacspec::new();
            buffer.len = hex.len() / 2;
            for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
                let chunk_str = core::str::from_utf8(chunk).unwrap();
                buffer.content[i] = U8(u8::from_str_radix(chunk_str, 16).unwrap());
            }
            buffer
        }
        fn from_public_buffer(buffer: &EdhocMessageBuffer) -> Self {
            let mut hacspec_buffer = EdhocMessageBufferHacspec::new();
            hacspec_buffer.len = buffer.len;
            hacspec_buffer.content = BytesMessageBuffer::from_public_slice(&buffer.content[..]);
            hacspec_buffer
        }
        fn from_slice<A>(slice: &A, start: usize, len: usize) -> Self
        where
            A: SeqTrait<U8>,
        {
            let mut hacspec_buffer = EdhocMessageBufferHacspec::new();
            hacspec_buffer.len = len;
            hacspec_buffer.content = BytesMessageBuffer::from_slice(slice, start, len);
            hacspec_buffer
        }
        fn from_seq(buffer: &Seq<U8>) -> Self {
            EdhocMessageBufferHacspec {
                content: BytesMessageBuffer::from_slice(buffer, 0, buffer.len()),
                len: buffer.len(),
            }
        }
        fn to_public_buffer(&self) -> EdhocMessageBuffer {
            let mut buffer = EdhocMessageBuffer::new();
            buffer.content = self.content.to_public_array();
            buffer.len = self.len;
            buffer
        }
    }

    #[derive(Debug)]
    pub struct EADItemHacspec {
        pub label: U8,
        pub is_critical: bool,
        // TODO[ead]: have adjustable (smaller) length for this buffer
        pub value: Option<EdhocMessageBufferHacspec>,
    }

    pub trait EADItemHacspecTrait {
        fn new() -> Self;
        fn from_public_item(item: &EADItem) -> Self;
        fn to_public_item(&self) -> EADItem;
    }

    impl EADItemHacspecTrait for EADItemHacspec {
        fn new() -> Self {
            EADItemHacspec {
                label: U8(0),
                is_critical: false,
                value: None,
            }
        }
        fn from_public_item(item: &EADItem) -> Self {
            EADItemHacspec {
                label: U8(item.label),
                is_critical: item.is_critical,
                value: match &item.value {
                    Some(value) => Some(EdhocMessageBufferHacspec::from_public_buffer(value)),
                    None => None,
                },
            }
        }
        fn to_public_item(&self) -> EADItem {
            EADItem {
                label: self.label.declassify(),
                is_critical: self.is_critical,
                value: match &self.value {
                    Some(value) => Some(value.to_public_buffer()),
                    None => None,
                },
            }
        }
    }

    array!(BytesIdCred, ID_CRED_LEN, U8);
    array!(BytesSuites, SUITES_LEN, U8);
    array!(BytesSupportedSuites, SUPPORTED_SUITES_LEN, U8);
    array!(Bytes8, 8, U8);
    array!(BytesCcmKeyLen, AES_CCM_KEY_LEN, U8);
    array!(BytesCcmIvLen, AES_CCM_IV_LEN, U8);
    pub type BufferPlaintext2 = EdhocMessageBufferHacspec;
    pub type BufferPlaintext3 = EdhocMessageBufferHacspec;
    array!(BytesMac2, MAC_LENGTH_2, U8);
    array!(BytesMac3, MAC_LENGTH_3, U8);
    pub type BufferMessage1 = EdhocMessageBufferHacspec;
    pub type BufferMessage3 = EdhocMessageBufferHacspec;
    pub type BufferCiphertext2 = EdhocMessageBufferHacspec;
    pub type BufferCiphertext3 = EdhocMessageBufferHacspec;
    array!(BytesHashLen, SHA256_DIGEST_LEN, U8);
    array!(BytesP256ElemLen, P256_ELEM_LEN, U8);
    pub type BufferMessage2 = EdhocMessageBufferHacspec;
    array!(BytesMaxBuffer, MAX_BUFFER_LEN, U8);
    array!(BytesMaxContextBuffer, MAX_KDF_CONTEXT_LEN, U8);
    array!(BytesMaxInfoBuffer, MAX_INFO_LEN, U8);
    array!(BytesMaxLabelBuffer, MAX_KDF_LABEL_LEN, U8);
    array!(BytesEncStructureLen, ENC_STRUCTURE_LEN, U8);

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
    pub const EDHOC_SUITES: BytesSuites = BytesSuites(secret_bytes!([0, 1, 2, 3, 4, 5, 6, 24, 25])); // all but private cipher suites

    #[repr(C)]
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
