#![no_std]

use edhoc::consts::*;
use edhoc::Accelerator;

use cc2538_hal::crypto::Crypto;
use cc2538_hal::crypto::ecc::EccCurveInfo;

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
        let b: [u32; P256_ELEM_LEN/4] = [
            0x5ac635d8, 0xaa3a93e7, 0xb3ebbd55, 0x769886bc, 0x651d06b0, 0xcc53b0f6, 0x3bce3c3e, 0x27d2604b,];

        // (p+1)/4 calculated offline
        let exp: [u32; P256_ELEM_LEN/4] = [
            0x3fffffff, 0xc0000000, 0x40000000, 0x00000000, 0x00000000, 0x40000000, 0x00000000, 0x00000000,];

        let p: [u32; P256_ELEM_LEN/4] = [0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF, ];

        let mut private_key_u32: [u32; P256_ELEM_LEN / 4] = [0x00; P256_ELEM_LEN / 4];
        for i in 0..private_key_u32.len() {
            private_key_u32[i] = as_u32_be(&[
                private_key[i * 4],
                private_key[i * 4 + 1],
                private_key[i * 4 + 2],
                private_key[i * 4 + 3],
            ]);
        }

        // w = (x^3 + a*x + b)^((p+1)/4) (mod p). [RFC6090, Appendix C]
        //
        let mut x_3 = [0u32; 16];

        self.crypto.exp(&[3], &p, &private_key_u32, &mut x_3);

        let mut three_x = [0u32; 16];
        self.crypto.mul(&[3], &private_key_u32, &mut three_x);

        let mut temp1 = [0u32; 16];
        self.crypto.sub(&x_3, &three_x, &mut temp1); // x^3 - 3x

        // let z = x * x * x - 3u128 * x + b;
        let mut z = [0u32, 16];
        self.crypto.add(&b, &[1], &mut z);

        let mut z_mod_p = [0u32; P256_ELEM_LEN/4];
        self.crypto.modulo(&z, &p, &mut z_mod_p);

        // w is z to power of exp
        let mut w = [0u32; P256_ELEM_LEN/4];
        self.crypto.exp(&exp, &p, &z, &mut w);

        // TODO continue the implementation of ECDH
        todo!();

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
        todo!()
    }
}
