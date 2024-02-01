#![no_std]

use lakers_shared::{
    BufferCiphertext3, BufferPlaintext3, BytesCcmIvLen, BytesCcmKeyLen, BytesHashLen,
    BytesMaxBuffer, BytesMaxInfoBuffer, BytesP256ElemLen, Crypto as CryptoTrait, EDHOCError,
    AES_CCM_TAG_LEN, MAX_BUFFER_LEN,
};

use ccm::AeadInPlace;
use ccm::KeyInit;
use p256::elliptic_curve::point::AffineCoordinates;
use p256::elliptic_curve::point::DecompressPoint;
use sha2::Digest;

type AesCcm16_64_128 = ccm::Ccm<aes::Aes128, ccm::consts::U8, ccm::consts::U13>;

/// A type representing cryptographic operations through various RustCrypto crates (eg. [aes],
/// [ccm], [p256]).
///
/// Its size depends on the implementation of Rng passed in at creation.
pub struct Crypto<Rng: rand_core::RngCore + rand_core::CryptoRng> {
    rng: Rng,
}

impl<Rng: rand_core::RngCore + rand_core::CryptoRng> Crypto<Rng> {
    pub const fn new(rng: Rng) -> Self {
        Self { rng }
    }
}

impl<Rng: rand_core::RngCore + rand_core::CryptoRng> core::fmt::Debug for Crypto<Rng> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("lakers_crypto_rustcrypto::Crypto")
            .field("rng", &core::any::type_name::<Rng>())
            .finish()
    }
}

impl<Rng: rand_core::RngCore + rand_core::CryptoRng> CryptoTrait for Crypto<Rng> {
    fn sha256_digest(&mut self, message: &BytesMaxBuffer, message_len: usize) -> BytesHashLen {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&message[..message_len]);
        hasher.finalize().into()
    }

    fn hkdf_expand(
        &mut self,
        prk: &BytesHashLen,
        info: &BytesMaxInfoBuffer,
        info_len: usize,
        length: usize,
    ) -> BytesMaxBuffer {
        let hkdf =
            hkdf::Hkdf::<sha2::Sha256>::from_prk(prk).expect("Static size was checked at extract");
        let mut output: BytesMaxBuffer = [0; MAX_BUFFER_LEN];
        hkdf.expand(&info[..info_len], &mut output[..length])
            .expect("Static lengths match the algorithm");
        output
    }

    fn hkdf_extract(&mut self, salt: &BytesHashLen, ikm: &BytesP256ElemLen) -> BytesHashLen {
        // While it'd be nice to just pass around an Hkdf, the extract output is not a type generic
        // of this trait (yet?).
        let mut extracted = hkdf::HkdfExtract::<sha2::Sha256>::new(Some(salt));
        extracted.input_ikm(ikm);
        extracted.finalize().0.into()
    }

    fn aes_ccm_encrypt_tag_8(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        plaintext: &BufferPlaintext3,
    ) -> BufferCiphertext3 {
        let key = AesCcm16_64_128::new(key.into());
        let mut outbuffer = BufferCiphertext3::new();
        outbuffer.content[..plaintext.len].copy_from_slice(plaintext.as_slice());
        if let Ok(tag) =
            key.encrypt_in_place_detached(iv.into(), ad, &mut outbuffer.content[..plaintext.len])
        {
            outbuffer.content[plaintext.len..][..AES_CCM_TAG_LEN].copy_from_slice(&tag);
        } else {
            panic!("Preconfigured sizes should not allow encryption to fail")
        }
        outbuffer.len = plaintext.len + AES_CCM_TAG_LEN;
        outbuffer
    }

    fn aes_ccm_decrypt_tag_8(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        ciphertext: &BufferCiphertext3,
    ) -> Result<BufferPlaintext3, EDHOCError> {
        let key = AesCcm16_64_128::new(key.into());
        let mut buffer = BufferPlaintext3::new();
        buffer.len = ciphertext.len - AES_CCM_TAG_LEN;
        buffer.content[..buffer.len].copy_from_slice(&ciphertext.content[..buffer.len]);
        let tag = &ciphertext.content[buffer.len..][..AES_CCM_TAG_LEN];
        key.decrypt_in_place_detached(iv.into(), ad, &mut buffer.content[..buffer.len], tag.into())
            .map_err(|_| EDHOCError::MacVerificationFailed)?;
        Ok(buffer)
    }

    fn p256_ecdh(
        &mut self,
        private_key: &BytesP256ElemLen,
        public_key: &BytesP256ElemLen,
    ) -> BytesP256ElemLen {
        let secret = p256::SecretKey::from_bytes(private_key.as_slice().into())
            .expect("Invalid secret key generated");
        let public = p256::AffinePoint::decompress(
            public_key.into(),
            1.into(), /* Y coordinate choice does not matter for ECDH operation */
        )
        // While this can actually panic so far, the proper fix is in
        // https://github.com/openwsn-berkeley/lakers/issues/93 which will justify this to be a
        // panic (because after that, public key validity will be an invariant of the public key
        // type)
        .expect("Public key is not a good point");

        (*p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public).raw_secret_bytes()).into()
    }

    fn get_random_byte(&mut self) -> u8 {
        self.rng.next_u32() as _
    }

    fn p256_generate_key_pair(&mut self) -> (BytesP256ElemLen, BytesP256ElemLen) {
        let secret = p256::SecretKey::random(&mut self.rng);

        let public_key = secret.public_key().as_affine().x();
        let private_key = secret.to_bytes();

        (private_key.into(), public_key.into())
    }
}
