#![no_std]

use edhoc_consts::*;
use psa_crypto::operations::hash::hash_compute;
use psa_crypto::operations::{aead, key_agreement, key_management, other::generate_random};
use psa_crypto::types::algorithm::Hash;
use psa_crypto::types::algorithm::{Aead, AeadWithDefaultLengthTag, KeyAgreement, RawKeyAgreement};
use psa_crypto::types::key::{Attributes, EccFamily, Lifetime, Policy, Type, UsageFlags};

#[no_mangle]
pub extern "C" fn mbedtls_hardware_poll(
    data: *mut ::core::ffi::c_void,
    output: *mut ::core::ffi::c_uchar,
    len: usize,
    olen: *mut usize,
) -> ::core::ffi::c_int {
    unsafe {
        *olen = len;
    }
    0i32
}

pub fn sha256_digest(message: &BytesMaxBuffer, message_len: usize) -> BytesHashLen {
    let hash_alg = Hash::Sha256;
    let mut hash: [u8; SHA256_DIGEST_LEN] = [0; SHA256_DIGEST_LEN];
    psa_crypto::init().unwrap();
    hash_compute(hash_alg, &message[..message_len], &mut hash).unwrap();

    hash
}

pub fn hkdf_expand(
    prk: &BytesHashLen,
    info: &BytesMaxInfoBuffer,
    info_len: usize,
    length: usize,
) -> BytesMaxBuffer {
    // Implementation of HKDF-Expand as per RFC5869

    let mut output: [u8; MAX_BUFFER_LEN] = [0; MAX_BUFFER_LEN];

    let mut n = 0;

    // N = ceil(L/HashLen)
    if length % SHA256_DIGEST_LEN == 0 {
        n = length / SHA256_DIGEST_LEN;
    } else {
        n = length / SHA256_DIGEST_LEN + 1;
    }

    let mut message: [u8; MAX_INFO_LEN + SHA256_DIGEST_LEN + 1] =
        [0; MAX_INFO_LEN + SHA256_DIGEST_LEN + 1];
    message[..info_len].copy_from_slice(&info[..info_len]);
    message[info_len] = 0x01;
    let mut t_i = hmac_sha256(&message[..info_len + 1], prk);
    output[..SHA256_DIGEST_LEN].copy_from_slice(&t_i);

    for i in 2..n {
        message[..SHA256_DIGEST_LEN].copy_from_slice(&t_i);
        message[SHA256_DIGEST_LEN..SHA256_DIGEST_LEN + info_len].copy_from_slice(&info[..info_len]);
        message[SHA256_DIGEST_LEN + info_len] = i as u8;
        t_i = hmac_sha256(&message[..SHA256_DIGEST_LEN + info_len + 1], prk);
        output[i * SHA256_DIGEST_LEN..(i + 1) * SHA256_DIGEST_LEN].copy_from_slice(&t_i);
    }

    output[length..].fill(0x00);

    output
}

pub fn hkdf_extract(salt: &BytesHashLen, ikm: &BytesP256ElemLen) -> BytesHashLen {
    // Implementation of HKDF-Extract as per RFC 5869

    // TODO generalize if salt is not provided
    let output = hmac_sha256(ikm, salt);

    output
}

pub fn aes_ccm_encrypt_tag_8(
    key: &BytesCcmKeyLen,
    iv: &BytesCcmIvLen,
    ad: &BytesEncStructureLen,
    plaintext: &BufferPlaintext3,
) -> BufferCiphertext3 {
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
    let my_key = key_management::import(attributes, None, &key[..]).unwrap();
    let mut output_buffer: BufferCiphertext3 = BufferCiphertext3::new();

    aead::encrypt(
        my_key,
        alg,
        iv,
        ad,
        &plaintext.content[..plaintext.len],
        &mut output_buffer.content,
    )
    .unwrap();

    output_buffer.len = plaintext.len + AES_CCM_TAG_LEN;
    output_buffer
}

pub fn aes_ccm_decrypt_tag_8(
    key: &BytesCcmKeyLen,
    iv: &BytesCcmIvLen,
    ad: &BytesEncStructureLen,
    ciphertext: &BufferCiphertext3,
) -> Result<BufferPlaintext3, EDHOCError> {
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
    let my_key = key_management::import(attributes, None, &key[..]).unwrap();
    let mut output_buffer: BufferPlaintext3 = BufferPlaintext3::new();

    match aead::decrypt(
        my_key,
        alg,
        iv,
        ad,
        &ciphertext.content[..ciphertext.len],
        &mut output_buffer.content,
    ) {
        Ok(_) => {
            output_buffer.len = ciphertext.len - AES_CCM_TAG_LEN;
            Ok(output_buffer)
        }
        Err(_) => Err(EDHOCError::MacVerificationFailed),
    }
}

pub fn p256_ecdh(
    private_key: &BytesP256ElemLen,
    public_key: &BytesP256ElemLen,
) -> BytesP256ElemLen {
    let mut peer_public_key: [u8; 33] = [0; 33];
    peer_public_key[0] = 0x02; // sign does not matter for ECDH operation
    peer_public_key[1..33].copy_from_slice(&public_key[..]);

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
    let my_key = key_management::import(attributes, None, private_key).unwrap();
    let mut output_buffer: [u8; P256_ELEM_LEN] = [0; P256_ELEM_LEN];

    key_agreement::raw_key_agreement(alg, my_key, &peer_public_key, &mut output_buffer).unwrap();

    output_buffer
}

pub fn hmac_sha256(message: &[u8], key: &[u8; SHA256_DIGEST_LEN]) -> BytesHashLen {
    // implementation of HMAC as per RFC2104

    const IPAD: [u8; 64] = [0x36; 64];
    const OPAD: [u8; 64] = [0x5C; 64];

    //    (1) append zeros to the end of K to create a B byte string
    //        (e.g., if K is of length 20 bytes and B=64, then K will be
    //         appended with 44 zero bytes 0x00)
    let mut b: [u8; MAX_BUFFER_LEN] = [0; MAX_BUFFER_LEN];
    b[0..SHA256_DIGEST_LEN].copy_from_slice(&key[..]);

    //    (2) XOR (bitwise exclusive-OR) the B byte string computed in step
    //        (1) with ipad
    let mut s2: [u8; MAX_BUFFER_LEN] = [0; MAX_BUFFER_LEN];
    for i in 0..64 {
        s2[i] = b[i] ^ IPAD[i];
    }

    //    (3) append the stream of data 'text' to the B byte string resulting
    //        from step (2)
    s2[64..64 + message.len()].copy_from_slice(message);

    //    (4) apply H to the stream generated in step (3)
    let ih = sha256_digest(&s2, 64 + message.len());

    //    (5) XOR (bitwise exclusive-OR) the B byte string computed in
    //        step (1) with opad
    let mut s5: [u8; MAX_BUFFER_LEN] = [0; MAX_BUFFER_LEN];
    for i in 0..64 {
        s5[i] = b[i] ^ OPAD[i];
    }
    //    (6) append the H result from step (4) to the B byte string
    //        resulting from step (5)
    s5[64..64 + SHA256_DIGEST_LEN].copy_from_slice(&ih);

    //    (7) apply H to the stream generated in step (6) and output
    //        the result
    let oh = sha256_digest(&s5, 3 * SHA256_DIGEST_LEN);

    oh
}

pub fn get_random_byte() -> u8 {
    psa_crypto::init().unwrap();
    let mut buffer = [0u8; 1];
    generate_random(&mut buffer); // TODO: check return value
    buffer[0]
}

pub fn p256_generate_key_pair() -> (BytesP256ElemLen, BytesP256ElemLen) {
    let alg = RawKeyAgreement::Ecdh;
    let mut usage_flags: UsageFlags = UsageFlags::default();
    usage_flags.set_export();
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

    let key_id = key_management::generate(attributes, None).unwrap();
    let mut private_key: [u8; P256_ELEM_LEN] = [0; P256_ELEM_LEN];
    key_management::export(key_id, &mut private_key).unwrap();

    let mut public_key: [u8; P256_ELEM_LEN * 2 + 1] = [0; P256_ELEM_LEN * 2 + 1]; // allocate buffer for: sign, x, and y coordinates
    key_management::export_public(key_id, &mut public_key).unwrap();
    let public_key: [u8; P256_ELEM_LEN] = public_key[1..33].try_into().unwrap(); // return only the x coordinate

    (private_key, public_key)
}

pub fn p256_validate_compact_public_key(public_key: &BytesP256ElemLen) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256() {
        const KEY: [u8; 32] = [0x0b; 32];
        const MESSAGE_1: [u8; 0] = [];
        const RESULT_1_TV: [u8; 32] = [
            0x51, 0x77, 0xe6, 0x37, 0xaa, 0xac, 0x0b, 0x50, 0xe5, 0xdc, 0xa8, 0xbb, 0x05, 0xb0,
            0xb5, 0x71, 0x44, 0x4b, 0xd5, 0x9b, 0x9b, 0x0d, 0x83, 0x4d, 0x50, 0x68, 0x1a, 0xf2,
            0x1f, 0xc1, 0x4b, 0x1e,
        ];
        const MESSAGE_2: [u8; 1] = [0x0a];
        const RESULT_2_TV: [u8; 32] = [
            0x30, 0x50, 0x86, 0x79, 0x39, 0x85, 0x02, 0xd9, 0xdd, 0x70, 0x7e, 0xff, 0x6c, 0x84,
            0x08, 0x9d, 0x83, 0x12, 0xcc, 0xea, 0x25, 0x36, 0x4d, 0x9c, 0xb8, 0xb0, 0xbd, 0x94,
            0xd0, 0xe6, 0x55, 0xa3,
        ];

        let result_1 = hmac_sha256(&MESSAGE_1, &KEY);
        assert_eq!(result_1, RESULT_1_TV);

        let result_2 = hmac_sha256(&MESSAGE_2, &KEY);
        assert_eq!(result_2, RESULT_2_TV);
    }
}
