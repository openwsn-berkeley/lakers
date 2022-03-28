use crate::consts::*;

pub trait Accelerator {
    fn p256_ecdh(
        &mut self,
        private_key: &[u8],
        public_key: &[u8],
        secret: &mut [u8; P256_ELEM_LEN],
    );

    fn sha256_digest(&mut self, message: &[u8], output: &mut [u8; SHA256_DIGEST_LEN]);

    fn hkdf_extract(
        &mut self,
        salt: &[u8],
        ikm: [u8; P256_ELEM_LEN],
        okm: &mut [u8; P256_ELEM_LEN],
    );

    fn hkdf_expand(
        &mut self,
        prk: [u8; P256_ELEM_LEN],
        info: &[u8],
        length: usize,
        output: &mut [u8],
    );

    fn aes_ccm_encrypt(
        &mut self,
        key: [u8; AES_CCM_KEY_LEN],
        iv: [u8; AES_CCM_IV_LEN],
        tag_len: usize,
        ad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    );
}

#[cfg(feature = "native")]
pub struct NativeAccelerator {}

#[cfg(feature = "native")]
impl NativeAccelerator {
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(feature = "native")]
impl Accelerator for NativeAccelerator {
    fn p256_ecdh(
        &mut self,
        private_key: &[u8],
        public_key: &[u8],
        secret: &mut [u8; P256_ELEM_LEN],
    ) {
        use hacspec_p256::*;

        let scalar = P256Scalar::from_be_bytes(private_key);
        let point = (
            P256FieldElement::from_be_bytes(public_key),
            p256_calculate_w(P256FieldElement::from_be_bytes(public_key)),
        );

        assert!(p256_validate_public_key(point));

        // we only care about the x coordinate
        let secret_felem = match p256_point_mul(scalar, point) {
            Ok(p) => p.0,
            Err(_) => panic!("Error hacspec p256_point_mul"),
        };

        let secret_bytes = secret_felem.to_be_bytes();
        secret[..P256_ELEM_LEN].copy_from_slice(&secret_bytes[..P256_ELEM_LEN]);
    }

    fn sha256_digest(&mut self, message: &[u8], output: &mut [u8; SHA256_DIGEST_LEN]) {
        use hacspec_lib::prelude::*;
        use hacspec_sha256::hash;

        let message_secret: Seq<U8> = Seq::<U8>::from_public_slice(message);
        let digest = hash(&message_secret);

        for i in 00..SHA256_DIGEST_LEN {
            output[i] = digest[i].declassify();
        }
    }

    fn hkdf_extract(
        &mut self,
        salt: &[u8],
        ikm: [u8; P256_ELEM_LEN],
        okm: &mut [u8; P256_ELEM_LEN],
    ) {
        use hacspec_hkdf::*;
        use hacspec_lib::prelude::*;

        let ikm_byteseq: Seq<U8> = Seq::<U8>::from_public_slice(&ikm);
        let salt_byteseq: Seq<U8> = Seq::<U8>::from_public_slice(salt);

        let okm_byteseq = extract(&salt_byteseq, &ikm_byteseq);

        for i in 0..okm_byteseq.len() {
            okm[i] = okm_byteseq[i].declassify();
        }
    }

    fn hkdf_expand(
        &mut self,
        prk: [u8; P256_ELEM_LEN],
        info: &[u8],
        length: usize,
        output: &mut [u8],
    ) {
        use hacspec_hkdf::*;
        use hacspec_lib::prelude::*;

        // call kdf-expand from hacspec
        let prk_byteseq: Seq<U8> = Seq::<U8>::from_public_slice(&prk);
        let info_byteseq: Seq<U8> = Seq::<U8>::from_public_slice(info);

        let okm_byteseq = match expand(&prk_byteseq, &info_byteseq, length) {
            Ok(okm) => okm,
            Err(_) => panic!("edhoc_kdf: error expand"),
        };

        for i in 0..length {
            output[i] = okm_byteseq[i].declassify();
        }
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
        use hacspec_aes::*;
        use hacspec_aes_ccm::*;
        use hacspec_lib::prelude::*;

        let key_secret = Key128::from_public_slice(&key);
        let iv_byteseq: Seq<U8> = Seq::<U8>::from_public_slice(&iv);
        let ad_byteseq: Seq<U8> = Seq::<U8>::from_public_slice(ad);
        let plaintext_byteseq: Seq<U8> = Seq::<U8>::from_public_slice(plaintext);

        let ciphertext_byteseq = encrypt_ccm(
            ad_byteseq,
            iv_byteseq,
            plaintext_byteseq,
            key_secret,
            tag_len,
        );

        for i in 0..ciphertext_byteseq.len() {
            ciphertext[i] = ciphertext_byteseq[i].declassify();
        }
    }
}
