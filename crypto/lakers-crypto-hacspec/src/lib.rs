#![no_std]

use hacspec_aes::*;
use hacspec_aes_ccm::*;
use hacspec_hkdf::*;
use hacspec_lib::*;
use hacspec_p256::*;
use hacspec_sha256::*;
use lakers_shared::{Crypto as CryptoTrait, *};
use rand::Rng;

// Types and functions to aid in translation between the hacspec and non-hacspec world

// TODO: the `array!` construct is not needed anymore.
// Ideally this should be: `type BytesCcmKeyLen = [u8; AES_CCM_KEY_LEN];`
// However, it is not clear how to implement the equivalents to `from_public_slice` and friends
//  when using the normal array construct.
array!(BytesCcmKeyLenHacspec, AES_CCM_KEY_LEN, U8);
array!(BytesCcmIvLenHacspec, AES_CCM_IV_LEN, U8);
array!(BytesHashLenHacspec, SHA256_DIGEST_LEN, U8);
array!(BytesP256ElemLenHacspec, P256_ELEM_LEN, U8);
array!(BytesMaxBufferHacspec, MAX_BUFFER_LEN, U8);
array!(BytesMaxInfoBufferHacspec, MAX_INFO_LEN, U8);
array!(BytesEncStructureLenHacspec, ENC_STRUCTURE_LEN, U8);

array!(BytesMessageBuffer, MAX_MESSAGE_SIZE_LEN, U8);

#[derive(Debug)]
pub struct EdhocMessageBufferHacspec {
    pub content: BytesMessageBuffer,
    pub len: usize,
}

pub trait MessageBufferHacspecTrait {
    fn new() -> Self;
    fn from_public_buffer(buffer: &EdhocMessageBuffer) -> Self;
    fn from_seq(buffer: &Seq<U8>) -> Self;
    fn to_public_buffer(&self) -> EdhocMessageBuffer;
}

impl MessageBufferHacspecTrait for EdhocMessageBufferHacspec {
    fn new() -> Self {
        EdhocMessageBufferHacspec {
            content: BytesMessageBuffer::new(),
            len: 0,
        }
    }
    fn from_public_buffer(buffer: &EdhocMessageBuffer) -> Self {
        let mut hacspec_buffer = EdhocMessageBufferHacspec::new();
        hacspec_buffer.len = buffer.len;
        hacspec_buffer.content = BytesMessageBuffer::from_public_slice(&buffer.content[..]);
        hacspec_buffer
    }
    fn from_seq(buffer: &Seq<U8>) -> Self {
        EdhocMessageBufferHacspec {
            content: BytesMessageBuffer::from_slice(buffer, 0, buffer.len()),
            len: buffer.len(),
        }
    }
    fn to_public_buffer(&self) -> EdhocMessageBuffer {
        let mut buffer = EdhocMessageBuffer::new();
        buffer.content = self.content.to_public_array();
        buffer.len = self.len;
        buffer
    }
}

type BufferCiphertext3Hacspec = EdhocMessageBufferHacspec;
type BufferPlaintext3Hacspec = EdhocMessageBufferHacspec;

// Public functions

#[derive(Debug)]
pub struct Crypto;

impl CryptoTrait for Crypto {
    fn sha256_digest(&mut self, message: &BytesMaxBuffer, message_len: usize) -> BytesHashLen {
        let message: BytesMaxBufferHacspec = BytesMaxBufferHacspec::from_public_slice(message);

        let output =
            BytesHashLenHacspec::from_seq(&hash(&ByteSeq::from_slice(&message, 0, message_len)));

        output.to_public_array()
    }

    fn hkdf_expand(
        &mut self,
        prk: &BytesHashLen,
        info: &BytesMaxInfoBuffer,
        info_len: usize,
        length: usize,
    ) -> BytesMaxBuffer {
        let mut output = BytesMaxBufferHacspec::new();
        output = output.update(
            0,
            &expand(
                &ByteSeq::from_slice(&BytesHashLenHacspec::from_public_slice(prk), 0, prk.len()),
                &ByteSeq::from_slice(
                    &BytesMaxInfoBufferHacspec::from_public_slice(info),
                    0,
                    info_len,
                ),
                length,
            )
            .unwrap(),
        );
        output.to_public_array()
    }

    fn hkdf_extract(&mut self, salt: &BytesHashLen, ikm: &BytesP256ElemLen) -> BytesHashLen {
        let output = BytesHashLenHacspec::from_seq(&extract(
            &ByteSeq::from_slice(&BytesHashLenHacspec::from_public_slice(salt), 0, salt.len()),
            &ByteSeq::from_slice(
                &BytesP256ElemLenHacspec::from_public_slice(ikm),
                0,
                ikm.len(),
            ),
        ));
        output.to_public_array()
    }

    fn aes_ccm_encrypt_tag_8(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        plaintext: &BufferPlaintext3,
    ) -> BufferCiphertext3 {
        let plaintext = BufferPlaintext3Hacspec::from_public_buffer(plaintext);

        let output = BufferCiphertext3Hacspec::from_seq(&encrypt_ccm(
            ByteSeq::from_public_slice(ad),
            ByteSeq::from_slice(&BytesCcmIvLenHacspec::from_public_slice(iv), 0, iv.len()),
            ByteSeq::from_slice(&plaintext.content, 0, plaintext.len),
            Key128::from_slice(&BytesCcmKeyLenHacspec::from_public_slice(key), 0, key.len()),
            AES_CCM_TAG_LEN,
        ));

        output.to_public_buffer()
    }

    fn aes_ccm_decrypt_tag_8(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        ciphertext: &BufferCiphertext3,
    ) -> Result<BufferPlaintext3, EDHOCError> {
        let ciphertext = BufferCiphertext3Hacspec::from_public_buffer(ciphertext);

        match decrypt_ccm(
            ByteSeq::from_public_slice(ad),
            ByteSeq::from_slice(&BytesCcmIvLenHacspec::from_public_slice(iv), 0, iv.len()),
            Key128::from_slice(&BytesCcmKeyLenHacspec::from_public_slice(key), 0, key.len()),
            ByteSeq::from_slice(&ciphertext.content, 0, ciphertext.len),
            ciphertext.len,
            AES_CCM_TAG_LEN,
        ) {
            Ok(p) => Ok(BufferPlaintext3Hacspec::from_seq(&p).to_public_buffer()),
            Err(_) => Err(EDHOCError::MacVerificationFailed),
        }
    }

    fn p256_ecdh(
        &mut self,
        private_key: &BytesP256ElemLen,
        public_key: &BytesP256ElemLen,
    ) -> BytesP256ElemLen {
        let private_key = BytesP256ElemLenHacspec::from_public_slice(private_key);
        let public_key = BytesP256ElemLenHacspec::from_public_slice(public_key);

        let scalar = P256Scalar::from_byte_seq_be(&private_key);
        let point = (
            P256FieldElement::from_byte_seq_be(&public_key),
            p256_calculate_w(P256FieldElement::from_byte_seq_be(&public_key)),
        );

        // we only care about the x coordinate
        let (x, _y) = p256_point_mul(scalar, point).unwrap();

        let secret = BytesP256ElemLenHacspec::from_seq(&x.to_byte_seq_be());

        secret.to_public_array()
    }

    #[cfg(not(feature = "hacspec-pure"))]
    fn get_random_byte(&mut self) -> u8 {
        rand::thread_rng().gen::<u8>()
    }

    #[cfg(not(feature = "hacspec-pure"))]
    fn p256_generate_key_pair(&mut self) -> (BytesP256ElemLen, BytesP256ElemLen) {
        // generate a private key
        let mut private_key = BytesP256ElemLenHacspec::new();
        loop {
            for i in 0..private_key.len() {
                private_key[i] = U8(rand::thread_rng().gen::<u8>());
            }
            if p256_validate_private_key(&ByteSeq::from_slice(&private_key, 0, private_key.len())) {
                break;
            }
        }

        // obtain the corresponding public key
        let scalar = P256Scalar::from_byte_seq_be(&private_key);
        let public_key_point = p256_point_mul_base(scalar).unwrap();
        let public_key = BytesP256ElemLenHacspec::from_seq(&public_key_point.0.to_byte_seq_be());

        (private_key.to_public_array(), public_key.to_public_array())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p256_keys() {
        let (x, g_x) = Crypto.p256_generate_key_pair();
        assert_eq!(x.len(), 32);
        assert_eq!(g_x.len(), 32);

        let (y, g_y) = Crypto.p256_generate_key_pair();

        let g_xy = Crypto.p256_ecdh(&x, &g_y);
        let g_yx = Crypto.p256_ecdh(&y, &g_x);

        assert_eq!(g_xy, g_yx);
    }
}
