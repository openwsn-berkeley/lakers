#[cfg(feature = "native")]
pub use native::*;

#[cfg(feature = "native")]
mod native {
    use edhoc_consts::*;
    use hacspec_aes::*;
    use hacspec_aes_ccm::*;
    use hacspec_hkdf::*;
    use hacspec_lib::*;
    use hacspec_p256::*;
    use hacspec_sha256::*;

    pub fn sha256_digest(message: &BytesMaxBuffer, message_len: usize) -> BytesHashLen {
        let output = BytesHashLen::from_seq(&hash(&ByteSeq::from_slice(message, 0, message_len)));
        output
    }

    pub fn hkdf_expand(
        prk: &BytesHashLen,
        info: &BytesMaxInfoBuffer,
        info_len: usize,
        length: usize,
    ) -> BytesMaxBuffer {
        let mut output = BytesMaxBuffer::new();
        output = output.update(
            0,
            &expand(
                &ByteSeq::from_slice(prk, 0, prk.len()),
                &ByteSeq::from_slice(info, 0, info_len),
                length,
            )
            .unwrap(),
        );
        output
    }

    pub fn hkdf_extract(salt: &BytesHashLen, ikm: &BytesP256ElemLen) -> BytesHashLen {
        let output = BytesHashLen::from_seq(&extract(
            &ByteSeq::from_slice(salt, 0, salt.len()),
            &ByteSeq::from_slice(ikm, 0, ikm.len()),
        ));
        output
    }

    pub fn aes_ccm_encrypt_tag_8(
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &BytesEncStructureLen,
        plaintext: &BytesPlaintext3,
    ) -> BytesCiphertext3 {
        let output = BytesCiphertext3::from_seq(&encrypt_ccm(
            ByteSeq::from_slice(ad, 0, ad.len()),
            ByteSeq::from_slice(iv, 0, iv.len()),
            ByteSeq::from_slice(plaintext, 0, plaintext.len()),
            Key128::from_slice(key, 0, key.len()),
            AES_CCM_TAG_LEN,
        ));

        output
    }

    pub fn aes_ccm_decrypt_tag_8(
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &BytesEncStructureLen,
        ciphertext: &BytesCiphertext3,
    ) -> (EDHOCError, BytesPlaintext3) {
        let (err, p3) = match decrypt_ccm(
            ByteSeq::from_slice(ad, 0, ad.len()),
            ByteSeq::from_slice(iv, 0, iv.len()),
            Key128::from_slice(key, 0, key.len()),
            ByteSeq::from_slice(ciphertext, 0, ciphertext.len()),
            ciphertext.len(),
            AES_CCM_TAG_LEN,
        ) {
            AesCcmResult::Ok(p) => (EDHOCError::Success, BytesPlaintext3::from_seq(&p)),
            AesCcmResult::Err(_) => (EDHOCError::MacVerificationFailed, BytesPlaintext3::new()),
        };

        (err, p3)
    }
    pub fn p256_ecdh(
        private_key: &BytesP256ElemLen,
        public_key: &BytesP256ElemLen,
    ) -> BytesP256ElemLen {
        let scalar = P256Scalar::from_byte_seq_be(private_key);
        let point = (
            P256FieldElement::from_byte_seq_be(public_key),
            p256_calculate_w(P256FieldElement::from_byte_seq_be(public_key)),
        );

        // we only care about the x coordinate
        let (x, _y) = p256_point_mul(scalar, point).unwrap();

        let secret = BytesP256ElemLen::from_seq(&x.to_byte_seq_be());
        secret
    }
}
