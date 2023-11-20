//! Cryptography trait back-end for the edhoc-crypto crate

use super::*;

pub trait Crypto: core::fmt::Debug {
    fn sha256_digest(&mut self, message: &BytesMaxBuffer, message_len: usize) -> BytesHashLen;
    fn hkdf_expand(
        &mut self,
        prk: &BytesHashLen,
        info: &BytesMaxInfoBuffer,
        info_len: usize,
        length: usize,
    ) -> BytesMaxBuffer;
    fn hkdf_extract(&mut self, salt: &BytesHashLen, ikm: &BytesP256ElemLen) -> BytesHashLen;
    fn aes_ccm_encrypt_tag_8(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        plaintext: &BufferPlaintext3,
    ) -> BufferCiphertext3;
    fn aes_ccm_decrypt_tag_8(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        ciphertext: &BufferCiphertext3,
    ) -> Result<BufferPlaintext3, EDHOCError>;
    fn p256_ecdh(
        &mut self,
        private_key: &BytesP256ElemLen,
        public_key: &BytesP256ElemLen,
    ) -> BytesP256ElemLen;
    fn get_random_byte(&mut self) -> u8;
    fn p256_generate_key_pair(&mut self) -> (BytesP256ElemLen, BytesP256ElemLen);
}
