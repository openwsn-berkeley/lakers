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
    use psa_crypto::operations::{key_derivation, key_management};
    use psa_crypto::types::algorithm::{Hash, KeyDerivation};
    use psa_crypto::types::key::{Attributes, Lifetime, Policy, Type, UsageFlags};
    use psa_crypto::types::key_derivation::{Input, InputSecret, Inputs, Operation};

    let mut usage_flags: UsageFlags = Default::default();
    usage_flags.set_derive();
    let mut attributes = Attributes {
        key_type: Type::Derive,
        bits: 256,
        lifetime: Lifetime::Volatile,
        policy: Policy {
            usage_flags,
            permitted_algorithms: KeyDerivation::Hkdf {
                hash_alg: Hash::Sha256,
            }
            .into(),
        },
    };

    let mut usage_flags: UsageFlags = Default::default();
    usage_flags.set_derive();
    let mut derived_key_attributes = Attributes {
        key_type: Type::RawData,
        bits: 256, // 32 bytes fixed length in extract
        lifetime: Lifetime::Volatile,
        policy: Policy {
            usage_flags,
            permitted_algorithms: KeyDerivation::Hkdf {
                hash_alg: Hash::Sha256,
            }
            .into(),
        },
    };

    psa_crypto::init().unwrap();
    let my_key = key_management::import(attributes, None, &ikm.to_public_array()).unwrap();
    let salt_array = salt.to_public_array();
    let mut operation = Operation {
        inputs: Inputs::Hkdf {
            hash_alg: Hash::Sha256,
            salt: Some(Input::Bytes(&salt_array)),
            secret: InputSecret::Input(Input::Key(my_key)),
            info: Input::Bytes(&[]),
        },
        capacity: None,
    };
    let _new_key = key_derivation::output_key(operation, derived_key_attributes, None).unwrap();

    let mut output_buf: [u8; SHA256_DIGEST_LEN] = [0; SHA256_DIGEST_LEN];
    let output_size = key_management::export(_new_key, &mut output_buf).unwrap();
    let output = BytesHashLen::from_public_slice(&output_buf[..]);

    output
}

pub fn aes_ccm_encrypt_tag_8(
    key: &BytesCcmKeyLen,
    iv: &BytesCcmIvLen,
    ad: &BytesEncStructureLen,
    plaintext: &BytesPlaintext3,
) -> BytesCiphertext3 {
    use psa_crypto::operations::{aead, key_management};
    use psa_crypto::types::algorithm::Aead::AeadWithShortenedTag;
    use psa_crypto::types::algorithm::{Aead, AeadWithDefaultLengthTag};
    use psa_crypto::types::key::{Attributes, Lifetime, Policy, Type, UsageFlags};

    psa_crypto::init().unwrap();

    let alg = Aead::AeadWithShortenedTag {
        aead_alg: AeadWithDefaultLengthTag::Ccm,
        tag_length: 8,
    };
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
    let mut output_buffer: [u8; CIPHERTEXT_3_LEN] = [0; CIPHERTEXT_3_LEN];

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
    use psa_crypto::operations::{aead, key_management};
    use psa_crypto::types::algorithm::Aead::AeadWithShortenedTag;
    use psa_crypto::types::algorithm::{Aead, AeadWithDefaultLengthTag};
    use psa_crypto::types::key::{Attributes, Lifetime, Policy, Type, UsageFlags};
    use psa_crypto::types::status::Result;

    psa_crypto::init().unwrap();

    let alg = Aead::AeadWithShortenedTag {
        aead_alg: AeadWithDefaultLengthTag::Ccm,
        tag_length: 8,
    };
    let mut usage_flags: UsageFlags = Default::default();
    usage_flags.set_decrypt();

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
    let mut output_buffer: [u8; PLAINTEXT_3_LEN] = [0; PLAINTEXT_3_LEN];

    let (plaintext, err) = match aead::decrypt(
        my_key,
        alg,
        &iv.to_public_array(),
        &ad.to_public_array(),
        &ciphertext.to_public_array(),
        &mut output_buffer,
    ) {
        Result::Ok(_) => (
            BytesPlaintext3::from_public_slice(&output_buffer[..]),
            EDHOCError::Success,
        ),
        Result::Err(_) => (BytesPlaintext3::new(), EDHOCError::MacVerificationFailed),
    };

    (err, plaintext)
}
pub fn p256_ecdh(
    private_key: &BytesP256ElemLen,
    public_key: &BytesP256ElemLen,
) -> BytesP256ElemLen {
    use psa_crypto::operations::{key_agreement, key_management};
    use psa_crypto::types::algorithm::{KeyAgreement, RawKeyAgreement};
    use psa_crypto::types::key::{Attributes, EccFamily, Lifetime, Policy, Type, UsageFlags};

    let mut peer_public_key: [u8; 33] = [0; 33];
    peer_public_key[0] = 0x02; // sign does not matter for ECDH operation
    peer_public_key[1..33].copy_from_slice(&public_key.to_public_array());

    let alg = RawKeyAgreement::Ecdh;
    let mut usage_flags: UsageFlags = Default::default();
    usage_flags.set_derive();
    let attributes = Attributes {
        key_type: Type::EccKeyPair {
            curve_family: EccFamily::SecpR1,
        },
        bits: 256,
        lifetime: Lifetime::Volatile,
        policy: Policy {
            usage_flags,
            permitted_algorithms: KeyAgreement::Raw(alg).into(),
        },
    };

    psa_crypto::init().unwrap();
    let my_key = key_management::import(attributes, None, &private_key.to_public_array()).unwrap();
    let mut output_buffer: [u8; P256_ELEM_LEN] = [0; P256_ELEM_LEN];

    let size = key_agreement::raw_key_agreement(alg, my_key, &peer_public_key, &mut output_buffer)
        .unwrap();

    let output = BytesP256ElemLen::from_public_slice(&output_buffer[..]);

    output
}

pub fn hmac_sha256(message: &[u8], key: [u8; SHA256_DIGEST_LEN]) -> BytesHashLen {
    // implementation of HMAC as per RFC2104

    const IPAD: [u8; 64] = [0x36; 64];
    const OPAD: [u8; 64] = [0x5C; 64];

    //    (1) append zeros to the end of K to create a B byte string
    //        (e.g., if K is of length 20 bytes and B=64, then K will be
    //         appended with 44 zero bytes 0x00)
    let mut B: [u8; MAX_BUFFER_LEN] = [0; MAX_BUFFER_LEN];
    B[0..SHA256_DIGEST_LEN].copy_from_slice(&key);

    //    (2) XOR (bitwise exclusive-OR) the B byte string computed in step
    //        (1) with ipad
    let mut s2: [u8; MAX_BUFFER_LEN] = [0; MAX_BUFFER_LEN];
    for i in 0..64 {
        s2[i] = B[i] ^ IPAD[i];
    }

    //    (3) append the stream of data 'text' to the B byte string resulting
    //        from step (2)
    s2[64..64 + message.len()].copy_from_slice(message);

    //    (4) apply H to the stream generated in step (3)
    let ih = sha256_digest(&BytesMaxBuffer::from_public_slice(&s2), 64 + message.len());

    //    (5) XOR (bitwise exclusive-OR) the B byte string computed in
    //        step (1) with opad
    let mut s5: [u8; MAX_BUFFER_LEN] = [0; MAX_BUFFER_LEN];
    for i in 0..64 {
        s5[i] = B[i] ^ OPAD[i];
    }
    //    (6) append the H result from step (4) to the B byte string
    //        resulting from step (5)
    s5[64..64 + SHA256_DIGEST_LEN].copy_from_slice(&ih.to_public_array());

    //    (7) apply H to the stream generated in step (6) and output
    //        the result
    let oh = sha256_digest(
        &BytesMaxBuffer::from_public_slice(&s5),
        3 * SHA256_DIGEST_LEN,
    );

    oh
}
