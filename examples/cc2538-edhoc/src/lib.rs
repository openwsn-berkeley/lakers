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

        // Point multiplication of CC2538 internally uses the Montgommery ladder algorithm
        // which depends on the x coordinate only. Therefore, we can set y to a dummy
        // value and disregard the y coordinate of the point multiplication operation
        let y: [u32; P256_ELEM_LEN/4] = [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];

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

        let point = EcPoint {
            x: &public_key_u32_le,
            y: &y,
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
        // adata needs to be in RAM, which is not the case when executing test vectors
        // code below is a hack
        assert!(ad.len() < 100);
        let mut adata : [u8; 100] = [0; 100];
        let _ = &adata[..ad.len()].copy_from_slice(&ad[..]);
        let ad = &adata[..ad.len()];

        let aes_key = AesKey::Key128(key);
        let aes_keys_128 = AesKeys::create(
            &[aes_key],
            AesKeySize::Key128,
            0,
        );
        self.crypto.load_key(&aes_keys_128);

        let ccm_info = AesCcmInfo::new(0, 2, 8).with_added_auth_data(&ad);

        let (mut ct, mut tag_truncated) = ciphertext.split_at_mut(plaintext.len());

        let mut tag : [u8; 16] = [0x00; 16];

        self.crypto.ccm_encrypt(
            &ccm_info,
            &iv,
            &plaintext,
            &mut ct,
            &mut tag,
            );

        tag_truncated.copy_from_slice(&tag[0..tag_truncated.len()]);
    }
}
