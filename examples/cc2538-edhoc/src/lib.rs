#![no_std]

use edhoc::consts::*;
use edhoc::Accelerator;

use cc2538_hal::crypto::Crypto;
use cc2538_hal::crypto::ecc::EccCurveInfo;
use cc2538_hal::crypto::ecc::EcPoint;
use cc2538_hal::crypto::aes_engine::ccm::AesCcmInfo;
use cc2538_hal::crypto::aes_engine::keys::{AesKey, AesKeySize, AesKeys};

use rtt_target::{rprintln, rtt_init_print};

pub struct Cc2538Accelerator<'c> {
    crypto: Crypto<'c>,
}

impl<'c> Cc2538Accelerator<'c> {
    pub fn new(crypto: Crypto<'c>) -> Self {
        Self { crypto }
    }
}

fn as_u32_be(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 24)
        + ((array[1] as u32) << 16)
        + ((array[2] as u32) << 8)
        + ((array[3] as u32) << 0)
}

impl<'c> Accelerator for Cc2538Accelerator<'c> {
    fn p256_ecdh(
        &mut self,
        private_key: &[u8],
        public_key: &[u8],
        secret: &mut [u8; P256_ELEM_LEN],
    ) {
        let curve = EccCurveInfo::nist_p_256();

        // (p+1)/4 calculated offline
        let exp: [u32; P256_ELEM_LEN/4] = [
            0x00000000, 0x00000000, 0x40000000, 0x00000000, 0x00000000, 0x40000000, 0xc0000000, 0x3fffffff];

        let mut private_key_u32_le : [u32; P256_ELEM_LEN / 4] = [0x00; P256_ELEM_LEN / 4];
        for i in 0..private_key_u32_le.len() {
            private_key_u32_le[i] = as_u32_be(&[
                                            private_key[private_key.len() - 4*i - 4],
                                            private_key[private_key.len() - 4*i - 3],
                                            private_key[private_key.len() - 4*i - 2],
                                            private_key[private_key.len() - 4*i - 1]]);
        }

        let mut public_key_u32_le : [u32; P256_ELEM_LEN / 4] = [0x00; P256_ELEM_LEN / 4];
        for i in 0..public_key_u32_le.len() {
            public_key_u32_le[i] = as_u32_be(&[
                                            public_key[public_key.len() - 4*i - 4],
                                            public_key[public_key.len() - 4*i - 3],
                                            public_key[public_key.len() - 4*i - 2],
                                            public_key[public_key.len() - 4*i - 1]]);
        }

        // w = (x^3 + a*x + b)^((p+1)/4) (mod p). [RFC6090, Appendix C]
        //
        let mut x_3 = [0u32; 8];
        self.crypto.exp(&[0x3], &curve.prime, &public_key_u32_le, &mut x_3);

        let mut three_x = [0u32; 32];
        self.crypto.mul(&[3], &public_key_u32_le, &mut three_x);

        let mut temp1 = [0u32; 32];
        self.crypto.add(&x_3, &curve.b_coef, &mut temp1); // x^3 + b

        // let z = (x^3 - 3x) + b;
        let mut z = [0u32; 32];
        self.crypto.sub(&temp1, &three_x, &mut z); // temp1 - three_x

        // w is z to power of exp
        let mut w = [0u32; 32];
        self.crypto.exp(&exp, &curve.prime, &z, &mut w);

        let point = EcPoint {
            x: &public_key_u32_le,
            y: &w,
        };

        let mut result = [0u32; 32];

        self.crypto.ecc_mul(&curve, &private_key_u32_le, &point, &mut result).unwrap();

        // take only the x coordinate
        for i in 0..P256_ELEM_LEN/4 {
            let temp = result[i].to_be_bytes();
            for j in 0..temp.len() {
                secret[P256_ELEM_LEN - 4*i - 4 + j] = temp[j];
            }
        }
    }

    fn sha256_digest(&mut self, message: &[u8], output: &mut [u8; SHA256_DIGEST_LEN]) {
        self.crypto.sha256(message, output);
    }

    fn hkdf_extract(
        &mut self,
        salt: &[u8],
        ikm: [u8; P256_ELEM_LEN],
        okm: &mut [u8; P256_ELEM_LEN],
    ) {
        todo!()
    }

    fn hkdf_expand(
        &mut self,
        prk: [u8; P256_ELEM_LEN],
        info: &[u8],
        length: usize,
        output: &mut [u8],
    ) {
        todo!()
    }

    fn aes_ccm_encrypt(
        &mut self,
        key: [u8; AES_CCM_KEY_LEN],
        iv: [u8; AES_CCM_IV_LEN],
        tag_len: usize,
        ad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) {
        let aes_key = AesKey::Key128(key);
        let aes_keys = AesKeys::create(&[aes_key], AesKeySize::Key128, 0);
        self.crypto.load_key(&aes_keys);

        let ccm_info = AesCcmInfo::new(0, 2, AES_CCM_TAG_LEN as u8).with_added_auth_data(ad);

        let mut tag : [u8; 16] = [0x00; 16];

        self.crypto.ccm_encrypt(
            &ccm_info,
            &iv,
            plaintext,
            ciphertext,
            &mut tag[..],
        );

        // truncate the tag
        for i in 0..AES_CCM_TAG_LEN {
            ciphertext[plaintext.len() + i] = tag[i];
        }
    }
}
