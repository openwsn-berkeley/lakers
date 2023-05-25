#![no_std]

pub use common::*;

#[cfg(feature = "hacspec")]
pub use hacspec::*;

#[cfg(feature = "rust")]
pub use rust::*;

#[cfg(feature = "ead-zeroconf")]
pub use structs_ead_zeroconf::*;

#[cfg(feature = "ead-none")]
pub use ead_none::*;

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
        EADHandlingFailed = 7,
        UnknownError = 8,
    }

    #[derive(PartialEq, Debug)]
    pub struct EdhocMessageBuffer {
        pub content: [u8; MAX_MESSAGE_SIZE_LEN],
        pub len: usize,
    }

    impl EdhocMessageBuffer {
        pub fn new() -> Self {
            EdhocMessageBuffer {
                content: [0u8; MAX_MESSAGE_SIZE_LEN],
                len: 0,
            }
        }
        pub fn from_hex(hex: &str) -> Self {
            let mut buffer = EdhocMessageBuffer::new();
            buffer.len = hex.len() / 2;
            for i in (0..hex.len()).step_by(2) {
                buffer.content[i / 2] = u8::from_str_radix(&hex[i..i + 2], 16).unwrap();
            }
            buffer
        }
    }

    impl TryInto<EdhocMessageBuffer> for &[u8] {
        type Error = ();

        fn try_into(self) -> Result<EdhocMessageBuffer, Self::Error> {
            if self.len() <= MAX_MESSAGE_SIZE_LEN {
                let mut buffer = [0u8; MAX_MESSAGE_SIZE_LEN];
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

    pub const MAX_MESSAGE_SIZE_LEN: usize = 64;
    pub const MAX_EAD_ITEM_LEN: usize = 64;

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
    pub const CBOR_NEG_INT_RANGE_START: u8 = 0x20u8;
    pub const CBOR_NEG_INT_RANGE_END: u8 = 0x37u8;
    pub const CBOR_MAJOR_TEXT_STRING: u8 = 0x60u8;
    pub const CBOR_MAJOR_BYTE_STRING: u8 = 0x40u8;
    pub const CBOR_MAJOR_ARRAY: u8 = 0x80u8;
    pub const MAX_INFO_LEN: usize = 2 + SHA256_DIGEST_LEN + // 32-byte digest as bstr
				            1 + MAX_KDF_LABEL_LEN +     // label <24 bytes as tstr
						    1 + MAX_KDF_CONTEXT_LEN +   // context <24 bytes as bstr
						    1; // length as u8

    pub const ENC_STRUCTURE_LEN: usize = 8 + 5 + SHA256_DIGEST_LEN; // 8 for ENCRYPT0

    pub const EAD_ZEROCONF_LABEL: u8 = 0x1; // NOTE: in lake-authz-draft-02 it is still TBD1
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

    #[cfg(feature = "ead-zeroconf")]
    use super::structs_ead_zeroconf::*;

    #[cfg(feature = "ead-none")]
    use super::ead_none::*;

    array!(BytesMessageBuffer, MAX_MESSAGE_SIZE_LEN, U8);

    #[derive(Debug)]
    pub struct EdhocMessageBufferHacspec {
        pub content: BytesMessageBuffer,
        pub len: usize,
    }

    impl EdhocMessageBufferHacspec {
        pub fn new() -> Self {
            EdhocMessageBufferHacspec {
                content: BytesMessageBuffer::new(),
                len: 0,
            }
        }
        pub fn from_hex(hex: &str) -> Self {
            let mut buffer = EdhocMessageBufferHacspec::new();
            buffer.len = hex.len() / 2;
            for i in (0..hex.len()).step_by(2) {
                buffer.content[i / 2] = U8(u8::from_str_radix(&hex[i..i + 2], 16).unwrap());
            }
            buffer
        }
        pub fn from_public_buffer(buffer: &EdhocMessageBuffer) -> Self {
            let mut hacspec_buffer = EdhocMessageBufferHacspec::new();
            hacspec_buffer.len = buffer.len;
            hacspec_buffer.content = BytesMessageBuffer::from_public_slice(&buffer.content[..]);
            hacspec_buffer
        }
        pub fn from_slice<A>(slice: &A, start: usize, len: usize) -> Self
        where
            A: SeqTrait<U8>,
        {
            let mut hacspec_buffer = EdhocMessageBufferHacspec::new();
            hacspec_buffer.len = len;
            hacspec_buffer.content = BytesMessageBuffer::from_slice(slice, start, len);
            hacspec_buffer
        }
        pub fn from_seq(buffer: &Seq<U8>) -> Self {
            EdhocMessageBufferHacspec {
                content: BytesMessageBuffer::from_slice(buffer, 0, buffer.len()),
                len: buffer.len(),
            }
        }
        pub fn to_public_buffer(&self) -> EdhocMessageBuffer {
            let mut buffer = EdhocMessageBuffer::new();
            buffer.content = self.content.to_public_array();
            buffer.len = self.len;
            buffer
        }
    }

    array!(BytesEad2, 0, U8);
    pub type BytesEad2New = EdhocMessageBufferHacspec;
    pub type BytesEad1 = EdhocMessageBufferHacspec;
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
    pub const EDHOC_SUITES: BytesSuites = BytesSuites(secret_bytes!([0, 1, 2, 3, 4, 5, 6, 24, 25])); // all but private cipher suites

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
        #[cfg(feature = "ead-zeroconf")] pub Option<EADInitiatorZeroConfHandler>,
        #[cfg(feature = "ead-none")] pub Option<EADInitiatorNoneHandler>,
        #[cfg(feature = "ead-zeroconf")] pub Option<EADResponderZeroConfHandler>,
        #[cfg(feature = "ead-none")] pub Option<EADResponderNoneHandler>,
    );
}

#[cfg(feature = "ead-zeroconf")]
mod structs_ead_zeroconf {
    use super::common::*;

    #[derive(Default, PartialEq, Copy, Clone, Debug)]
    pub enum EADInitiatorProtocolState {
        #[default]
        Start,
        WaitEAD2,
        Completed, // TODO: check if it is really ok to consider Completed after processing EAD_2
    }

    #[derive(Copy, Clone, Debug)]
    pub struct EADInitiatorZeroConfState {
        pub label: u8,
        pub ead_state: EADInitiatorProtocolState,
    }

    #[derive(Copy, Clone, Debug)]
    pub struct EADInitiatorZeroConfHandler {
        pub state: EADInitiatorZeroConfState,
        // TODO: use a smaller buffer for EAD items (and check if hacspec-v2 supports `const generics`)
        pub prepare_ead_1_cb:
            fn(EADInitiatorZeroConfState) -> (EdhocMessageBuffer, EADInitiatorZeroConfState),
        pub process_ead_2_cb:
            fn(EdhocMessageBuffer, EADInitiatorZeroConfState) -> EADInitiatorZeroConfState,
        pub prepare_ead_3_cb:
            fn(EADInitiatorZeroConfState) -> (EdhocMessageBuffer, EADInitiatorZeroConfState),
    }

    impl Default for EADInitiatorZeroConfHandler {
        fn default() -> Self {
            EADInitiatorZeroConfHandler {
                state: EADInitiatorZeroConfState {
                    label: EAD_ZEROCONF_LABEL,
                    ead_state: EADInitiatorProtocolState::Start,
                },
                prepare_ead_1_cb: |state| (EdhocMessageBuffer::new(), state),
                process_ead_2_cb: |_msg2, state| state,
                prepare_ead_3_cb: |state| (EdhocMessageBuffer::new(), state),
            }
        }
    }

    #[derive(Default, PartialEq, Copy, Clone, Debug)]
    pub enum EADResponderProtocolState {
        #[default]
        Start,
        ProcessedEAD1,
        WaitMessage3,
        Completed,
    }

    #[derive(Copy, Clone, Debug)]
    pub struct EADResponderZeroConfState {
        pub label: u8,
        pub ead_state: EADResponderProtocolState,
    }

    #[derive(Copy, Clone, Debug)]
    pub struct EADResponderZeroConfHandler {
        pub state: EADResponderZeroConfState,
        pub process_ead_1_cb: fn(
            EdhocMessageBuffer,
            EADResponderZeroConfState,
        ) -> (Result<(), ()>, EADResponderZeroConfState),
        pub prepare_ead_2_cb:
            fn(EADResponderZeroConfState) -> (EdhocMessageBuffer, EADResponderZeroConfState),
        pub process_ead_3_cb:
            fn(EdhocMessageBuffer, EADResponderZeroConfState) -> EADResponderZeroConfState,
    }

    impl Default for EADResponderZeroConfHandler {
        fn default() -> Self {
            EADResponderZeroConfHandler {
                state: EADResponderZeroConfState {
                    label: EAD_ZEROCONF_LABEL,
                    ead_state: EADResponderProtocolState::Start,
                },
                process_ead_1_cb: |_ead_1, state| (Ok(()), state),
                prepare_ead_2_cb: |state| (EdhocMessageBuffer::new(), state),
                process_ead_3_cb: |_ead_3, state| state,
            }
        }
    }
}

#[cfg(feature = "ead-none")]
mod ead_none {
    // the functions in this module will never be actually called, they are
    // here just so that Rust will compile without complaining, in the case
    // when using the zeroconf EAD feature is not a goal

    use super::common::*;

    #[derive(Copy, Clone, Debug)]
    pub struct EADNoneState;

    #[derive(Copy, Clone, Debug)]
    pub struct EADInitiatorNoneHandler {
        pub state: EADNoneState,
        pub prepare_ead_1_cb: fn(EADNoneState) -> (EdhocMessageBuffer, EADNoneState),
        pub process_ead_2_cb: fn(EdhocMessageBuffer, EADNoneState) -> EADNoneState,
        pub prepare_ead_3_cb: fn(EADNoneState) -> (EdhocMessageBuffer, EADNoneState),
    }

    impl Default for EADInitiatorNoneHandler {
        fn default() -> Self {
            EADInitiatorNoneHandler {
                state: EADNoneState,
                prepare_ead_1_cb: |state| (EdhocMessageBuffer::new(), state),
                process_ead_2_cb: |_ead_2, state| state,
                prepare_ead_3_cb: |state| (EdhocMessageBuffer::new(), state),
            }
        }
    }

    #[derive(Copy, Clone, Debug)]
    pub struct EADResponderNoneHandler {
        pub state: EADNoneState,
        pub process_ead_1_cb:
            fn(EdhocMessageBuffer, EADNoneState) -> (Result<(), ()>, EADNoneState),
        pub prepare_ead_2_cb: fn(EADNoneState) -> (EdhocMessageBuffer, EADNoneState),
        pub process_ead_3_cb: fn(EdhocMessageBuffer, EADNoneState) -> EADNoneState,
    }

    impl Default for EADResponderNoneHandler {
        fn default() -> Self {
            EADResponderNoneHandler {
                state: EADNoneState,
                process_ead_1_cb: |_ead_1, state| (Ok(()), state),
                prepare_ead_2_cb: |state| (EdhocMessageBuffer::new(), state),
                process_ead_3_cb: |_ead_3, state| state,
            }
        }
    }
}
