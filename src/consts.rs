use hexlit::hex;

pub const I: [u8; P256_ELEM_LEN] =
    hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
pub const ID_CRED_R: [u8; 3] = hex!("A10405");
pub const CRED_R : [u8; 83] = hex!("A2026008A101A50102020520012158206F9702A66602D78F5E81BAC1E0AF01F8B52810C502E87EBB7C926C07426FD02F225820C8D33274C71C9B3EE57D842BBF2238B8283CB410ECA216FB72A78EA7A870F800");
pub const G_R: [u8; P256_ELEM_LEN] =
    hex!("6f9702a66602d78f5e81bac1e0af01f8b52810c502e87ebb7c926c07426fd02f");
pub const C_I: i8 = -24;
pub const G_X: [u8; 32] =
    hex!("8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6");
pub const X: [u8; 32] =
    hex!("368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525");
pub const MESSAGE_2_LEN: usize = 45;
pub const MESSAGE_3_LEN: usize = CIPHERTEXT_3_LEN + 1; // 1 to wrap ciphertext into a cbor byte string
pub const EDHOC_METHOD: u8 = 3; // stat-stat is the only supported method
pub const EDHOC_SUPPORTED_SUITES: [u8; 1] = [2];
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
pub const MAX_KDF_CONTEXT_LEN: usize = 120;
pub const MAX_KDF_LABEL_LEN: usize = 15; // for "KEYSTREAM_2"
pub const MAX_BUFFER_LEN: usize = 150;
pub const CBOR_BYTE_STRING: u8 = 0x58;
pub const CBOR_MAJOR_TEXT_STRING: u8 = 0x60;
pub const CBOR_MAJOR_BYTE_STRING: u8 = 0x40;
pub const CBOR_MAJOR_ARRAY: u8 = 0x80;
