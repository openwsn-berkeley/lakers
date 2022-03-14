//#![no_std]

const MESSAGE_1_LEN: usize = 37;
const MESSAGE_2_LEN: usize = 45;
const MAX_MESSAGE_LEN: usize = MESSAGE_2_LEN;

const EDHOC_METHOD: u8 = 3; // stat-stat is the only supported method
const EDHOC_SUPPORTED_SUITES: u8 = 2;
const EDHOC_CID: u8 = 12;

const P256_ELEM_LEN: usize = 32;
const SHA256_DIGEST_LEN: usize = 32;

// ciphertext is message_len -1 for c_r, -2 for cbor magic numbers
const CIPHERTEXT_2_LEN: usize = MESSAGE_2_LEN - P256_ELEM_LEN - 1 - 2;
const PLAINTEXT_2_LEN: usize = CIPHERTEXT_2_LEN;

// maximum supported length of connection identifier for R
const MAX_C_R_LEN: usize = 0;
const MAX_CONTEXT_LEN: usize = 1;
const MAX_LABEL_LEN: usize = 11; // for "KEYSTREAM_2"

const CBOR_BYTE_STRING: u8 = 0x58;
const CBOR_SHORT_TEXT_STRING: u8 = 0x60;
const CBOR_SHORT_BYTE_STRING: u8 = 0x40;

pub fn encode_message_1(
    method: u8,
    suites: u8,
    g_x: [u8; P256_ELEM_LEN],
    c_i: u8,
    buf: &mut [u8; MESSAGE_1_LEN],
) {
    //								h_message_1: &mut [u8; SHA256_DIGEST_LEN]) {
    assert!(MESSAGE_1_LEN > 1 + 1 + P256_ELEM_LEN + 1); // length check
    assert!(method < 24 && suites < 24 && c_i < 24); // CBOR encoding checks

    buf[0] = method; // CBOR unsigned int less than 24 is encoded verbatim
    buf[1] = suites; // CBOR unsigned int less than 24 is encoded verbatim
    buf[2] = CBOR_BYTE_STRING; // CBOR byte string magic number
    buf[3] = P256_ELEM_LEN as u8; // length of the byte string
    for i in 0..P256_ELEM_LEN {
        // copy byte string
        buf[4 + i] = g_x[i];
    }
    buf[4 + P256_ELEM_LEN] = c_i; // CBOR uint less than 24 is encoded verbatim
}

pub fn parse_message_2(
    rcvd_message_2: &[u8; MESSAGE_2_LEN],
    g_y_buf: &mut [u8; P256_ELEM_LEN],
    ciphertext_2_buf: &mut [u8; CIPHERTEXT_2_LEN],
    c_r: &mut u8,
) {
    assert!(rcvd_message_2.len() == MESSAGE_2_LEN);

    *c_r = rcvd_message_2[MESSAGE_2_LEN - 1];

    for i in 0..P256_ELEM_LEN {
        g_y_buf[i] = rcvd_message_2[i + 2];
    }

    for i in 0..CIPHERTEXT_2_LEN {
        ciphertext_2_buf[i] = rcvd_message_2[i + 2 + P256_ELEM_LEN];
    }
}

pub fn decrypt_ciphertext_2(
    x: [u8; P256_ELEM_LEN],
    g_x: [u8; P256_ELEM_LEN],
    g_y: [u8; P256_ELEM_LEN],
    g_r: [u8; P256_ELEM_LEN],
    c_r: [u8; MAX_C_R_LEN],
    plaintext_2: &mut [u8; PLAINTEXT_2_LEN],
) {
    let mut g_xy = [0x00 as u8; P256_ELEM_LEN];
    let mut th_2 = [0x00 as u8; SHA256_DIGEST_LEN];

    p256_ecdh(x, g_y, &mut g_xy);
    // TODO compute TH_2
    //	compute_th();

    // TODO compute MAC_2

    panic!("not implemented yet!");
}

pub fn sha256_digest(message: &[u8], output: &mut [u8; SHA256_DIGEST_LEN]) {
    use hacspec_lib::prelude::*;
    use hacspec_sha256::hash;

    let message_secret: Seq<U8> = Seq::<U8>::from_public_slice(message);
    let digest = hash(&message_secret);

    for i in 00..SHA256_DIGEST_LEN {
        output[i] = digest[i].declassify();
    }
}

pub fn p256_ecdh(
    private_key: [u8; P256_ELEM_LEN],
    public_key: [u8; P256_ELEM_LEN],
    secret: &mut [u8; P256_ELEM_LEN],
) {
    use hacspec_p256::*;

    let scalar = P256Scalar::from_be_bytes(&private_key);
    let point = (
        P256FieldElement::from_be_bytes(&public_key),
        p256_calculate_w(P256FieldElement::from_be_bytes(&public_key)),
    );

    assert!(p256_validate_public_key(point));

    // we only care about the x coordinate
    let secret_felem = match p256_point_mul(scalar, point) {
        Ok(p) => p.0,
        Err(_) => panic!("Error hacspec p256_point_mul"),
    };

    let secret_bytes = secret_felem.to_be_bytes();
    for i in 0..P256_ELEM_LEN {
        secret[i] = secret_bytes[i];
    }
}

pub fn edhoc_kdf(
    prk: [u8; P256_ELEM_LEN],
    transcript_hash: [u8; SHA256_DIGEST_LEN],
    label: [u8; MAX_LABEL_LEN],
    label_len: usize,
    context: [u8; MAX_CONTEXT_LEN],
    context_len: usize,
    length: usize,
    output: &mut [u8],
) {
    use hacspec_hkdf::*;
    use hacspec_lib::prelude::*;

    const MAX_INFO_LEN: usize = 2 + SHA256_DIGEST_LEN + // 32-byte digest as bstr
						 1 + MAX_LABEL_LEN +     // label <24 bytes as tstr
						 1 + MAX_CONTEXT_LEN +   // context <24 bytes as bstr
						 1; // length as u8

    let mut info = [0x00 as u8; MAX_INFO_LEN];

    // construct info with inline cbor encoding
    info[0] = CBOR_BYTE_STRING;
    info[1] = SHA256_DIGEST_LEN as u8;
    for i in 2..SHA256_DIGEST_LEN + 2 {
        info[i] = transcript_hash[i - 2];
    }
    info[SHA256_DIGEST_LEN + 2] = label_len as u8 | CBOR_SHORT_TEXT_STRING;
    for i in SHA256_DIGEST_LEN + 3..SHA256_DIGEST_LEN + 3 + label_len {
        info[i] = label[i - SHA256_DIGEST_LEN - 3];
    }
    info[SHA256_DIGEST_LEN + 3 + label_len] = context_len as u8 | CBOR_SHORT_BYTE_STRING;
    for i in SHA256_DIGEST_LEN + 4 + label_len..SHA256_DIGEST_LEN + 4 + label_len + context_len {
        info[i] = context[i - SHA256_DIGEST_LEN - 4 - label_len];
    }
    info[SHA256_DIGEST_LEN + 4 + label_len + context_len] = length as u8;

    let info_len = SHA256_DIGEST_LEN + 5 + label_len + context_len;

    // call kdf-expand
    // TODO convert prk to byte seq
    // TODO convert info to byte seq
    let prk_byteseq: Seq<U8> = Seq::<U8>::from_public_slice(&prk);
    let info_byteseq: Seq<U8> = Seq::<U8>::from_public_slice(&info);
    let info_byteseq = Seq::from_slice_range(&info_byteseq, 0..info_len);

    let okm_byteseq = match expand(&prk_byteseq, &info_byteseq, length) {
        Ok(okm) => okm,
        Err(_) => panic!("edhoc_kdf: error expand"),
    };

    for i in 0..length {
        output[i] = okm_byteseq[i].declassify();
    }

    //	println!("info = {:0x?}", info);
    //	println!("info_len = {}", SHA256_DIGEST_LEN + 5 + label_len + context_len);
}

fn main() {
    let x: [u8; P256_ELEM_LEN] = [0x00; P256_ELEM_LEN];
    let g_x: [u8; P256_ELEM_LEN] = [0x00; P256_ELEM_LEN];
    let mut message_1: [u8; MESSAGE_1_LEN] = [0x00; MESSAGE_1_LEN];
    let mut digest_message_1: [u8; SHA256_DIGEST_LEN] = [0x00; SHA256_DIGEST_LEN];
    // TODO load hardcoded static DH key
    // TODO generate private and public key
    encode_message_1(
        EDHOC_METHOD,
        EDHOC_SUPPORTED_SUITES,
        g_x,
        EDHOC_CID,
        &mut message_1,
    );
    sha256_digest(&message_1, &mut digest_message_1);
    // TODO send message_1 over the wire
}

#[cfg(test)]
mod tests {
    use super::*;

    // test vectors (TV)
    const METHOD_TV: u8 = 3;
    const SUITES_TV: u8 = 0;
    const C_I_TV: u8 = 12;
    const C_R_TV: [u8; 0] = [];
    const MESSAGE_1_TV: [u8; MESSAGE_1_LEN] = [
        0x03, 0x00, 0x58, 0x20, 0x3a, 0xa9, 0xeb, 0x32, 0x01, 0xb3, 0x36, 0x7b, 0x8c, 0x8b, 0xe3,
        0x8d, 0x91, 0xe5, 0x7a, 0x2b, 0x43, 0x3e, 0x67, 0x88, 0x8c, 0x86, 0xd2, 0xac, 0x00, 0x6a,
        0x52, 0x08, 0x42, 0xed, 0x50, 0x37, 0x0c,
    ];

    const MESSAGE_2_TV: [u8; MESSAGE_2_LEN] = [
        0x58, 0x2a, 0x25, 0x54, 0x91, 0xb0, 0x5a, 0x39, 0x89, 0xff, 0x2d, 0x3f, 0xfe, 0xa6, 0x20,
        0x98, 0xaa, 0xb5, 0x7c, 0x16, 0x0f, 0x29, 0x4e, 0xd9, 0x48, 0x01, 0x8b, 0x41, 0x90, 0xf7,
        0xd1, 0x61, 0x82, 0x4e, 0x0f, 0xf0, 0x4c, 0x29, 0x4f, 0x4a, 0xc6, 0x02, 0xcf, 0x78, 0x40,
    ];

    const H_MESSAGE_1_TV: [u8; SHA256_DIGEST_LEN] = [
        0x9b, 0xdd, 0xb0, 0xcd, 0x55, 0x48, 0x7f, 0x82, 0xa8, 0x6f, 0xb7, 0x2a, 0x8b, 0xb3, 0x58,
        0x52, 0x68, 0x91, 0xa0, 0xa6, 0xc9, 0x08, 0x61, 0x24, 0x12, 0xf5, 0xaf, 0x29, 0x9d, 0xaf,
        0x01, 0x96,
    ];

    const PLAINTEXT_2_TV: [u8; PLAINTEXT_2_LEN] =
        [0x05, 0x48, 0x8e, 0x27, 0xcb, 0xd4, 0x94, 0xf7, 0x52, 0x83];

    const CIPHERTEXT_2_TV: [u8; CIPHERTEXT_2_LEN] =
        [0x0f, 0xf0, 0x4c, 0x29, 0x4f, 0x4a, 0xc6, 0x02, 0xcf, 0x78];

    const X_TV: [u8; P256_ELEM_LEN] = [
        0xb3, 0x11, 0x19, 0x98, 0xcb, 0x3f, 0x66, 0x86, 0x63, 0xed, 0x42, 0x51, 0xc7, 0x8b, 0xe6,
        0xe9, 0x5a, 0x4d, 0xa1, 0x27, 0xe4, 0xf6, 0xfe, 0xe2, 0x75, 0xe8, 0x55, 0xd8, 0xd9, 0xdf,
        0xd8, 0xed,
    ];

    const G_X_TV: [u8; P256_ELEM_LEN] = [
        0x3a, 0xa9, 0xeb, 0x32, 0x01, 0xb3, 0x36, 0x7b, 0x8c, 0x8b, 0xe3, 0x8d, 0x91, 0xe5, 0x7a,
        0x2b, 0x43, 0x3e, 0x67, 0x88, 0x8c, 0x86, 0xd2, 0xac, 0x00, 0x6a, 0x52, 0x08, 0x42, 0xed,
        0x50, 0x37,
    ];

    const G_Y_TV: [u8; P256_ELEM_LEN] = [
        0x25, 0x54, 0x91, 0xb0, 0x5a, 0x39, 0x89, 0xff, 0x2d, 0x3f, 0xfe, 0xa6, 0x20, 0x98, 0xaa,
        0xb5, 0x7c, 0x16, 0x0f, 0x29, 0x4e, 0xd9, 0x48, 0x01, 0x8b, 0x41, 0x90, 0xf7, 0xd1, 0x61,
        0x82, 0x4e,
    ];

    const G_R_TV: [u8; P256_ELEM_LEN] = [
        0xe6, 0x6f, 0x35, 0x59, 0x90, 0x22, 0x3c, 0x3f, 0x6c, 0xaf, 0xf8, 0x62, 0xe4, 0x07, 0xed,
        0xd1, 0x17, 0x4d, 0x07, 0x01, 0xa0, 0x9e, 0xcd, 0x6a, 0x15, 0xce, 0xe2, 0xc6, 0xce, 0x21,
        0xaa, 0x50,
    ];

    const X_1_TV: [u8; P256_ELEM_LEN] = [
        0x0a, 0x0d, 0x62, 0x2a, 0x47, 0xe4, 0x8f, 0x6b, 0xc1, 0x03, 0x8a, 0xce, 0x43, 0x8c, 0x6f,
        0x52, 0x8a, 0xa0, 0x0a, 0xd2, 0xbd, 0x1d, 0xa5, 0xf1, 0x3e, 0xe4, 0x6b, 0xf5, 0xf6, 0x33,
        0xd7, 0x1a,
    ];

    const G_Y_1_TV: [u8; P256_ELEM_LEN] = [
        0x29, 0x3a, 0xa3, 0x49, 0xb9, 0x34, 0xab, 0x2c, 0x83, 0x9c, 0xf5, 0x4b, 0x8a, 0x73, 0x7d,
        0xf2, 0x30, 0x4e, 0xf9, 0xb2, 0x0f, 0xa4, 0x94, 0xe3, 0x1a, 0xd6, 0x2b, 0x31, 0x5d, 0xd6,
        0xa5, 0x3c,
    ];

    const G_XY_1_TV: [u8; P256_ELEM_LEN] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x09, 0x9f, 0x55,
        0xd5, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ];

    const X_2_TV: [u8; P256_ELEM_LEN] = [
        0x06, 0x12, 0x46, 0x5c, 0x89, 0xa0, 0x23, 0xab, 0x17, 0x85, 0x5b, 0x0a, 0x6b, 0xce, 0xbf,
        0xd3, 0xfe, 0xbb, 0x53, 0xae, 0xf8, 0x41, 0x38, 0x64, 0x7b, 0x53, 0x52, 0xe0, 0x2c, 0x10,
        0xc3, 0x46,
    ];

    const G_Y_2_TV: [u8; P256_ELEM_LEN] = [
        0x62, 0xd5, 0xbd, 0x33, 0x72, 0xaf, 0x75, 0xfe, 0x85, 0xa0, 0x40, 0x71, 0x5d, 0x0f, 0x50,
        0x24, 0x28, 0xe0, 0x70, 0x46, 0x86, 0x8b, 0x0b, 0xfd, 0xfa, 0x61, 0xd7, 0x31, 0xaf, 0xe4,
        0x4f, 0x26,
    ];

    const G_XY_2_TV: [u8; P256_ELEM_LEN] = [
        0x53, 0x02, 0x0d, 0x90, 0x8b, 0x02, 0x19, 0x32, 0x8b, 0x65, 0x8b, 0x52, 0x5f, 0x26, 0x78,
        0x0e, 0x3a, 0xe1, 0x2b, 0xcd, 0x95, 0x2b, 0xb2, 0x5a, 0x93, 0xbc, 0x08, 0x95, 0xe1, 0x71,
        0x42, 0x85,
    ];

    #[test]
    fn test_encode_message_1() {
        let mut message_1_buf = [0xff as u8; MESSAGE_1_LEN];
        encode_message_1(METHOD_TV, SUITES_TV, G_X_TV, C_I_TV, &mut message_1_buf);
        assert!(MESSAGE_1_TV == message_1_buf);
    }

    #[test]
    fn test_parse_message_2() {
        let mut g_y_buf = [0x00 as u8; P256_ELEM_LEN];
        let mut ciphertext_2_buf = [0x00 as u8; CIPHERTEXT_2_LEN];
        let mut c_r = 0xff as u8;
        parse_message_2(&MESSAGE_2_TV, &mut g_y_buf, &mut ciphertext_2_buf, &mut c_r);

        assert!(G_Y_TV == g_y_buf);
        assert!(CIPHERTEXT_2_TV == ciphertext_2_buf);
    }

    #[test]
    fn test_decrypt_ciphertext_2() {
        let mut plaintext_2_buf = [0x00 as u8; PLAINTEXT_2_LEN];
        decrypt_ciphertext_2(X_TV, G_X_TV, G_Y_TV, G_R_TV, C_R_TV, &mut plaintext_2_buf);

        assert!(PLAINTEXT_2_TV == plaintext_2_buf);
    }

    #[test]
    fn test_sha256_digest() {
        let mut digest = [0x00 as u8; SHA256_DIGEST_LEN];

        sha256_digest(&MESSAGE_1_TV, &mut digest);
        assert_eq!(digest, H_MESSAGE_1_TV);
    }

    #[test]
    fn test_p256_ecdh() {
        let mut secret = [0x00 as u8; P256_ELEM_LEN];
        p256_ecdh(X_1_TV, G_Y_1_TV, &mut secret);
        assert!(G_XY_1_TV == secret);

        p256_ecdh(X_2_TV, G_Y_2_TV, &mut secret);
        assert!(G_XY_2_TV == secret);
    }

    #[test]
    fn test_edhoc_kdf() {
        const PRK_2E_TV: [u8; P256_ELEM_LEN] = [
            0xd1, 0xd0, 0x11, 0xa5, 0x9a, 0x6d, 0x10, 0x57, 0x5e, 0xb2, 0x20, 0xc7, 0x65, 0x2e,
            0x6f, 0x98, 0xc4, 0x17, 0xa5, 0x65, 0xe4, 0xe4, 0x5c, 0xf5, 0xb5, 0x01, 0x06, 0x95,
            0x04, 0x3b, 0x0e, 0xb7,
        ];

        const TH_2_TV: [u8; SHA256_DIGEST_LEN] = [
            0x71, 0xA6, 0xC7, 0xC5, 0xBA, 0x9A, 0xD4, 0x7F, 0xE7, 0x2D, 0xA4, 0xDC, 0x35, 0x9B,
            0xF6, 0xB2, 0x76, 0xD3, 0x51, 0x59, 0x68, 0x71, 0x1B, 0x9A, 0x91, 0x1C, 0x71, 0xFC,
            0x09, 0x6A, 0xEE, 0x0E,
        ];
        const LABEL_TV: [u8; MAX_LABEL_LEN] = [
            'K' as u8, 'E' as u8, 'Y' as u8, 'S' as u8, 'T' as u8, 'R' as u8, 'E' as u8, 'A' as u8,
            'M' as u8, '_' as u8, '2' as u8,
        ];

        const LEN_TV: usize = 10;

        const INFO_TV: [u8; 48] = [
            0x58, 0x20, 0x71, 0xa6, 0xc7, 0xc5, 0xba, 0x9a, 0xd4, 0x7f, 0xe7, 0x2d, 0xa4, 0xdc,
            0x35, 0x9b, 0xf6, 0xb2, 0x76, 0xd3, 0x51, 0x59, 0x68, 0x71, 0x1b, 0x9a, 0x91, 0x1c,
            0x71, 0xfc, 0x09, 0x6a, 0xee, 0x0e, 0x6b, 0x4b, 0x45, 0x59, 0x53, 0x54, 0x52, 0x45,
            0x41, 0x4d, 0x5f, 0x32, 0x40, 0x0a,
        ];

        const KEYSTREAM_2_TV: [u8; 10] =
            [0x0a, 0xb8, 0xc2, 0x0e, 0x84, 0x9e, 0x52, 0xf5, 0x9d, 0xfb];

        let mut output = [0x00 as u8; 10];

        edhoc_kdf(
            PRK_2E_TV,
            TH_2_TV,
            LABEL_TV,
            11,
            [0x00],
            0,
            LEN_TV,
            &mut output,
        );

        assert_eq!(KEYSTREAM_2_TV, output);
    }
}
