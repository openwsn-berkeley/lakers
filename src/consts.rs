use hacspec_lib::*;

array!(Bytes1, 1, U8);
array!(BytesCid, 1, U8);
array!(BytesEad2, 0, U8);
array!(BytesIdCred, 4, U8);
array!(BytesSupportedSuites, 1, U8);
array!(Bytes3, 3, U8);
array!(Bytes4, 4, U8);
array!(Bytes8, 8, U8);
array!(BytesCcmKeyLen, AES_CCM_KEY_LEN, U8);
array!(BytesCcmIvLen, AES_CCM_IV_LEN, U8);
array!(BytesPlaintext2, PLAINTEXT_2_LEN, U8);
array!(BytesPlaintext3, PLAINTEXT_3_LEN, U8);
array!(BytesMac2, MAC_LENGTH_2, U8);
array!(BytesMac3, MAC_LENGTH_3, U8);
array!(BytesMessage3, MESSAGE_3_LEN, U8);
array!(BytesCiphertext2, CIPHERTEXT_2_LEN, U8);
array!(BytesCiphertext3, CIPHERTEXT_3_LEN, U8);
array!(Bytes32, 32, U8);
array!(BytesHashLen, 32, U8);
array!(BytesP256ElemLen, 32, U8);
array!(BytesMessage2, MESSAGE_2_LEN, U8);
array!(Bytes83, 83, U8);
array!(Bytes84, 84, U8);
array!(BytesMaxBuffer, MAX_BUFFER_LEN, U8);
array!(BytesMaxContextBuffer, MAX_KDF_CONTEXT_LEN, U8);
array!(BytesMaxInfoBuffer, MAX_INFO_LEN, U8);
array!(BytesMaxLabelBuffer, MAX_KDF_LABEL_LEN, U8);
array!(BytesEncStructureLen, ENC_STRUCTURE_LEN, U8);

pub const I: BytesP256ElemLen = BytesP256ElemLen(secret_bytes!([
    0xfbu8, 0x13u8, 0xadu8, 0xebu8, 0x65u8, 0x18u8, 0xceu8, 0xe5u8, 0xf8u8, 0x84u8, 0x17u8, 0x66u8,
    0x08u8, 0x41u8, 0x14u8, 0x2eu8, 0x83u8, 0x0au8, 0x81u8, 0xfeu8, 0x33u8, 0x43u8, 0x80u8, 0xa9u8,
    0x53u8, 0x40u8, 0x6au8, 0x13u8, 0x05u8, 0xe8u8, 0x70u8, 0x6bu8
]));

pub const G_R: BytesP256ElemLen = BytesP256ElemLen(secret_bytes!([
    0xbbu8, 0xc3u8, 0x49u8, 0x60u8, 0x52u8, 0x6eu8, 0xa4u8, 0xd3u8, 0x2eu8, 0x94u8, 0x0cu8, 0xadu8,
    0x2au8, 0x23u8, 0x41u8, 0x48u8, 0xddu8, 0xc2u8, 0x17u8, 0x91u8, 0xa1u8, 0x2au8, 0xfbu8, 0xcbu8,
    0xacu8, 0x93u8, 0x62u8, 0x20u8, 0x46u8, 0xddu8, 0x44u8, 0xf0u8
]));

pub const C_I: BytesCid = BytesCid(secret_bytes!([0x0eu8]));
pub const G_X: BytesP256ElemLen = BytesP256ElemLen(secret_bytes!([
    0x8au8, 0xf6u8, 0xf4u8, 0x30u8, 0xebu8, 0xe1u8, 0x8du8, 0x34u8, 0x18u8, 0x40u8, 0x17u8, 0xa9u8,
    0xa1u8, 0x1bu8, 0xf5u8, 0x11u8, 0xc8u8, 0xdfu8, 0xf8u8, 0xf8u8, 0x34u8, 0x73u8, 0x0bu8, 0x96u8,
    0xc1u8, 0xb7u8, 0xc8u8, 0xdbu8, 0xcau8, 0x2fu8, 0xc3u8, 0xb6u8
]));
pub const X: BytesP256ElemLen = BytesP256ElemLen(secret_bytes!([
    0x36u8, 0x8eu8, 0xc1u8, 0xf6u8, 0x9au8, 0xebu8, 0x65u8, 0x9bu8, 0xa3u8, 0x7du8, 0x5au8, 0x8du8,
    0x45u8, 0xb2u8, 0x1bu8, 0xdcu8, 0x02u8, 0x99u8, 0xdcu8, 0xeau8, 0xa8u8, 0xefu8, 0x23u8, 0x5fu8,
    0x3cu8, 0xa4u8, 0x2cu8, 0xe3u8, 0x53u8, 0x0fu8, 0x95u8, 0x25u8
]));
pub const MESSAGE_2_LEN: usize = 45;
pub const MESSAGE_3_LEN: usize = CIPHERTEXT_3_LEN + 1; // 1 to wrap ciphertext into a cbor byte string
pub const EDHOC_METHOD: u8 = 3u8; // stat-stat is the only supported method
pub const EDHOC_SUPPORTED_SUITES: BytesSupportedSuites =
    BytesSupportedSuites(secret_bytes!([0x2u8]));
pub const P256_ELEM_LEN: usize = 32;
pub const SHA256_DIGEST_LEN: usize = 32;
pub const AES_CCM_KEY_LEN: usize = 16;
pub const AES_CCM_IV_LEN: usize = 13;
pub const AES_CCM_TAG_LEN: usize = 8;
pub const MAC_LENGTH_2: usize = 8;
pub const MAC_LENGTH_3: usize = MAC_LENGTH_2;
// ciphertext is message_len -1 for c_r, -2 for cbor magic numbers
pub const CIPHERTEXT_2_LEN: usize = MESSAGE_2_LEN - P256_ELEM_LEN - 1 - 2;
pub const PLAINTEXT_2_LEN: usize = CIPHERTEXT_2_LEN;
pub const PLAINTEXT_3_LEN: usize = MAC_LENGTH_3 + 2; // support for kid auth only
pub const CIPHERTEXT_3_LEN: usize = PLAINTEXT_3_LEN + AES_CCM_TAG_LEN;

// maximum supported length of connection identifier for R
pub const MAX_KDF_CONTEXT_LEN: usize = 150;
pub const MAX_KDF_LABEL_LEN: usize = 15; // for "KEYSTREAM_2"
pub const MAX_BUFFER_LEN: usize = 150;
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
