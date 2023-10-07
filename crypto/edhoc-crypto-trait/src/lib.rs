//! Cryptography trait back-end for the edhoc-crypto crate
#![no_std]

use edhoc_consts::*;

pub trait Crypto {
    fn sha256_digest(message: &BytesMaxBuffer, message_len: usize) -> BytesHashLen;
    fn hkdf_expand(
        prk: &BytesHashLen,
        info: &BytesMaxInfoBuffer,
        info_len: usize,
        length: usize,
    ) -> BytesMaxBuffer;
    fn hkdf_extract(salt: &BytesHashLen, ikm: &BytesP256ElemLen) -> BytesHashLen;
    fn aes_ccm_encrypt_tag_8(
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &BytesEncStructureLen,
        plaintext: &BufferPlaintext3,
    ) -> BufferCiphertext3;
    fn aes_ccm_decrypt_tag_8(
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &BytesEncStructureLen,
        ciphertext: &BufferCiphertext3,
    ) -> Result<BufferPlaintext3, EDHOCError>;
    fn p256_ecdh(private_key: &BytesP256ElemLen, public_key: &BytesP256ElemLen)
        -> BytesP256ElemLen;
    fn get_random_byte() -> u8;
    fn p256_generate_key_pair() -> (BytesP256ElemLen, BytesP256ElemLen);
}
