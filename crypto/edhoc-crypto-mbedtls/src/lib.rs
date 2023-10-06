#![no_std]

use edhoc_consts::*;
use mbedtls::bignum::Mpi;
use mbedtls::cipher::raw::Cipher;
use mbedtls::cipher::raw::CipherId;
use mbedtls::cipher::raw::CipherMode;
use mbedtls::cipher::raw::Operation::*;
use mbedtls::ecp::EcGroup;
use mbedtls::ecp::EcPoint;
use mbedtls::hash::Hmac;
use mbedtls::hash::Md;
use mbedtls::hash::Type::Sha256;
use mbedtls::pk::EcGroupId;
use mbedtls::pk::Pk;
use mbedtls::rng;
use mbedtls::rng::CtrDrbg;
use mbedtls::rng::OsEntropy;
use mbedtls::rng::Random;

pub fn sha256_digest(message: &BytesMaxBuffer, message_len: usize) -> BytesHashLen {
    let mut out: [u8; SHA256_DIGEST_LEN] = [0; SHA256_DIGEST_LEN];
    Md::hash(Sha256, &message[..message_len], &mut out).unwrap();
    out
}

pub fn hkdf_expand(
    prk: &BytesHashLen,
    info: &BytesMaxInfoBuffer,
    info_len: usize,
    length: usize,
) -> BytesMaxBuffer {
    let mut output: [u8; MAX_BUFFER_LEN] = [0; MAX_BUFFER_LEN];
    // Implementation of HKDF-Expand as per RFC5869

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
    let mut output_buffer: BufferCiphertext3 = BufferCiphertext3::new();

    let mut cipher = Cipher::setup(CipherId::Aes, CipherMode::CCM, 128).unwrap();
    cipher.set_key(Encrypt, key).unwrap();
    cipher.set_iv(iv).unwrap();
    let res = cipher
        .encrypt_auth(
            ad,
            &plaintext.content[..plaintext.len],
            &mut output_buffer.content,
            8,
        )
        .unwrap();
    output_buffer.len = res;

    output_buffer
}

pub fn aes_ccm_decrypt_tag_8(
    key: &BytesCcmKeyLen,
    iv: &BytesCcmIvLen,
    ad: &BytesEncStructureLen,
    ciphertext: &BufferCiphertext3,
) -> Result<BufferPlaintext3, EDHOCError> {
    let mut error = EDHOCError::UnknownError;
    let mut output_buffer: BufferPlaintext3 = BufferPlaintext3::new();

    let mut cipher = Cipher::setup(CipherId::Aes, CipherMode::CCM, 128).unwrap();
    cipher.set_key(Decrypt, key).unwrap();
    cipher.set_iv(iv).unwrap();

    let res = cipher.decrypt_auth(
        ad,
        &ciphertext.content[..ciphertext.len],
        &mut output_buffer.content,
        8,
    );

    if res.is_ok() {
        error = EDHOCError::Success;
        output_buffer.len = res.unwrap();
    } else {
        error = EDHOCError::MacVerificationFailed;
    }

    match error {
        EDHOCError::Success => Ok(output_buffer),
        _ => Err(error),
    }
}

pub fn p256_ecdh(
    private_key: &BytesP256ElemLen,
    public_key: &BytesP256ElemLen,
) -> BytesP256ElemLen {
    let mut output_buffer = [0u8; P256_ELEM_LEN];
    let mut peer_public_key = [0u8; P256_ELEM_LEN + 1];
    peer_public_key[0] = 0x02; // sign does not matter for ECDH operation
    peer_public_key[1..P256_ELEM_LEN + 1].copy_from_slice(&public_key[..]);
    let mut group = EcGroup::new(EcGroupId::SecP256R1).unwrap();
    let pubk = EcPoint::from_binary(&group, &peer_public_key).unwrap();
    let privk = Mpi::from_binary(private_key).unwrap();
    let secret = pubk.mul(&mut group, &privk).unwrap();
    let secret_x = secret.x().unwrap().to_binary().unwrap();
    output_buffer.copy_from_slice(&secret_x[..]);

    output_buffer
}

// FIXME this works on std using OS Entropy, fix for no_std
pub fn get_random_byte() -> u8 {
    let mut output = [0x00u8; 1];

    // use OS entropy for the moment
    let entropy = OsEntropy::new();

    // init mbedTLS RNG
    let mut ctr = CtrDrbg::new(entropy.into(), Some(&[0xcau8, 0xfeu8])).unwrap();

    // get one random byte
    ctr.random(&mut output).unwrap();
    output[0]
}

// FIXME this works on std using OS Entropy, fix for no_std
pub fn p256_generate_key_pair() -> (BytesP256ElemLen, BytesP256ElemLen) {
    let mut private_key: [u8; P256_ELEM_LEN] = [0; P256_ELEM_LEN];
    let mut public_key: [u8; P256_ELEM_LEN] = [0; P256_ELEM_LEN];

    let secp256r1 = EcGroup::new(EcGroupId::SecP256R1).unwrap();
    let entropy = OsEntropy::new();
    let mut ctr = CtrDrbg::new(entropy.into(), Some(&[0xcau8, 0xfeu8])).unwrap();

    // generate a key pair
    let pk = Pk::generate_ec(&mut ctr, secp256r1).unwrap();

    // export the keys to appropriate format
    private_key.copy_from_slice(&pk.ec_private().unwrap().to_binary().unwrap()[..]);
    public_key.copy_from_slice(&pk.ec_public().unwrap().x().unwrap().to_binary().unwrap()[..]);

    (private_key, public_key)
}

pub fn hmac_sha256(message: &[u8], key: &[u8; SHA256_DIGEST_LEN]) -> BytesHashLen {
    let mut out: [u8; SHA256_DIGEST_LEN] = [0; SHA256_DIGEST_LEN];
    let res = Hmac::hmac(Sha256, key, message, &mut out).unwrap();

    out
}
