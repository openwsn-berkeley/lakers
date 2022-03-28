#![no_std]

use edhoc::consts::*;
use edhoc::Accelerator;

use cc2538_hal::crypto::Crypto;

pub struct Cc2538Accelerator<'c> {
    crypto: Crypto<'c>,
}

impl<'c> Cc2538Accelerator<'c> {
    pub fn new(crypto: Crypto<'c>) -> Self {
        Self { crypto }
    }
}

impl<'c> Accelerator for Cc2538Accelerator<'c> {
    fn p256_ecdh(
        &mut self,
        private_key: &[u8],
        public_key: &[u8],
        secret: &mut [u8; P256_ELEM_LEN],
    ) {
        todo!()
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
