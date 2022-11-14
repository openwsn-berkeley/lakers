#![no_std]

use edhoc_consts::*;
use hacspec_lib::*;

pub fn sha256_digest(message: &BytesMaxBuffer, message_len: usize) -> BytesHashLen {
    use psa_crypto::operations::hash::hash_compute;
    use psa_crypto::types::algorithm::Hash;

    let hash_alg = Hash::Sha256;
    let mut hash: [u8; SHA256_DIGEST_LEN] = [0; SHA256_DIGEST_LEN];
    let message = message.to_public_array();
    psa_crypto::init().unwrap();
    let size = hash_compute(hash_alg, &message[..message_len], &mut hash).unwrap();
    let output = BytesHashLen::from_public_slice(&hash);

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
    use psa_crypto::operations::{aead, key_management};
    use psa_crypto::types::algorithm::{Aead, AeadWithDefaultLengthTag};
    use psa_crypto::types::algorithm::Aead::{AeadWithShortenedTag};
    use psa_crypto::types::key::{Attributes, Lifetime, Policy, Type, UsageFlags};

    psa_crypto::init().unwrap();

    let alg = Aead::AeadWithShortenedTag {aead_alg: AeadWithDefaultLengthTag::Ccm, tag_length: 8};
    let mut usage_flags: UsageFlags = Default::default();
    usage_flags.set_encrypt();

    let attributes = Attributes {
        key_type: Type::Aes,
        bits: 128,
        lifetime: Lifetime::Volatile,
        policy: Policy {
            usage_flags,
            permitted_algorithms: alg.into(),
        },
    };
    let my_key = key_management::import(attributes, None, &key.to_public_array()).unwrap();
    let mut output_buffer : [u8; CIPHERTEXT_3_LEN] = [0; CIPHERTEXT_3_LEN];

    let length = aead::encrypt(
        my_key,
        alg,
        &iv.to_public_array(),
        &ad.to_public_array(),
        &plaintext.to_public_array(),
        &mut output_buffer,
    )
    .unwrap();

    let output = BytesCiphertext3::from_public_slice(&output_buffer[..]);
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
