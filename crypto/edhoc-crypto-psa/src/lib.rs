#![no_std]

use edhoc_consts::*;
use hacspec_lib::*;

pub fn sha256_digest(message: &BytesMaxBuffer, message_len: usize) -> BytesHashLen {
    // use psa_crypto::operations::hash::hash_compute;
    // use psa_crypto::types::algorithm::Hash;
    // let hash_alg = Hash::Sha256;
    // let mut hash: [u8; 16] = [0; 16];
    // //no idea how to convert the types :/ (@kaspar030)
    // let size = hash_compute(
    //     hash_alg,
    //     message,
    //     &mut hash,
    // )
    // .unwrap();
    // let output = BytesHashLen::from_seq(&hash);
    let output = BytesHashLen::new();
    // TODO
    output
}

pub fn hkdf_expand(
    prk: &BytesHashLen,
    info: &BytesMaxInfoBuffer,
    info_len: usize,
    length: usize,
) -> BytesMaxBuffer {
    let mut output = BytesMaxBuffer::new();
    // TODO
    output
}

pub fn hkdf_extract(salt: &BytesHashLen, ikm: &BytesP256ElemLen) -> BytesHashLen {
    let output = BytesHashLen::new();

    // TODO

    output
}

pub fn aes_ccm_encrypt_tag_8(
    key: &BytesCcmKeyLen,
    iv: &BytesCcmIvLen,
    ad: &BytesEncStructureLen,
    plaintext: &BytesPlaintext3,
) -> BytesCiphertext3 {
    let output = BytesCiphertext3::new();
    // TODO
    output
}

pub fn aes_ccm_decrypt_tag_8(
    key: &BytesCcmKeyLen,
    iv: &BytesCcmIvLen,
    ad: &BytesEncStructureLen,
    ciphertext: &BytesCiphertext3,
) -> (EDHOCError, BytesPlaintext3) {
    let (err, p3) = (EDHOCError::UnknownError, BytesPlaintext3::new());
    // TODO

    (err, p3)
}
pub fn p256_ecdh(
    private_key: &BytesP256ElemLen,
    public_key: &BytesP256ElemLen,
) -> BytesP256ElemLen {
    let secret = BytesP256ElemLen::new();
    // TODO
    secret
}
