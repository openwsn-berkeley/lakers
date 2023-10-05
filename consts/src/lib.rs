#![no_std]

pub use consts::*;
pub use structs::*;

mod consts {
    use super::structs::*;

    pub const MAX_MESSAGE_SIZE_LEN: usize = 128; // need 128 to handle EAD fields
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

    pub const EDHOC_SUITES: BytesSuites = [0, 1, 2, 3, 4, 5, 6, 24, 25]; // all but private cipher suites
    pub const EDHOC_SUPPORTED_SUITES: BytesSupportedSuites = [0x2u8];
}

mod structs {
    use super::consts::*;

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
}
