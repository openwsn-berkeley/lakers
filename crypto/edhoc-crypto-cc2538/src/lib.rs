#![no_std]

use lakers_shared::*;

use cc2538_hal::crypto::aes_engine::ccm::AesCcmInfo;
use cc2538_hal::crypto::aes_engine::keys::{AesKey, AesKeySize, AesKeys};
use cc2538_hal::crypto::ecc::EcPoint;
use cc2538_hal::crypto::ecc::EccCurveInfo;
use cc2538_hal::crypto::Crypto;

pub fn sha256_digest(message: &BytesMaxBuffer, message_len: usize) -> BytesHashLen {
    BytesHashLen::new()
}

pub fn hkdf_expand(
    prk: &BytesHashLen,
    info: &BytesMaxInfoBuffer,
    info_len: usize,
    length: usize,
) -> BytesMaxBuffer {
    BytesMaxBuffer::new()
}

pub fn hkdf_extract(salt: &BytesHashLen, ikm: &BytesP256ElemLen) -> BytesHashLen {
    BytesHashLen::new()
}

pub fn aes_ccm_encrypt_tag_8(
    key: &BytesCcmKeyLen,
    iv: &BytesCcmIvLen,
    ad: &BytesEncStructureLen,
    plaintext: &BufferPlaintext3,
) -> BufferCiphertext3 {
    BufferCiphertext3::new()
}

pub fn aes_ccm_decrypt_tag_8(
    key: &BytesCcmKeyLen,
    iv: &BytesCcmIvLen,
    ad: &BytesEncStructureLen,
    ciphertext: &BufferCiphertext3,
) -> Result<BufferPlaintext3, EDHOCError> {
    Ok(BufferPlaintext3::new())
}
pub fn p256_ecdh(
    private_key: &BytesP256ElemLen,
    public_key: &BytesP256ElemLen,
) -> BytesP256ElemLen {
    BytesP256ElemLen::new()
}

pub fn p256_generate_key_pair() -> (BytesP256ElemLen, BytesP256ElemLen) {
    (BytesP256ElemLen::new(), BytesP256ElemLen::new())
}
