//#![no_std]

const MESSAGE_2_LEN: usize = 45;

const EDHOC_METHOD: u8 = 3; // stat-stat is the only supported method
const EDHOC_SUPPORTED_SUITES: [u8; 1] = [2];
const EDHOC_CID: i8 = 12;

const P256_ELEM_LEN: usize = 32;
const SHA256_DIGEST_LEN: usize = 32;
const MAC_LENGTH_2: usize = 8;

// ciphertext is message_len -1 for c_r, -2 for cbor magic numbers
const CIPHERTEXT_2_LEN: usize = MESSAGE_2_LEN - P256_ELEM_LEN - 1 - 2;
const PLAINTEXT_2_LEN: usize = CIPHERTEXT_2_LEN;

// maximum supported length of connection identifier for R
const MAX_KDF_CONTEXT_LEN: usize = 120;
const MAX_KDF_LABEL_LEN: usize = 11; // for "KEYSTREAM_2"
const MAX_BUFFER_LEN: usize = 150;

const CBOR_BYTE_STRING: u8 = 0x58;
const CBOR_SHORT_TEXT_STRING: u8 = 0x60;
const CBOR_SHORT_BYTE_STRING: u8 = 0x40;

pub fn encode_message_1(
    method: u8,
    suites: &[u8],
    g_x: [u8; P256_ELEM_LEN],
    c_i: i8,
    output: &mut [u8],
    output_len: &mut usize,
) {
    output[0] = method; // CBOR unsigned int less than 24 is encoded verbatim
    output[1] = 0x80 | suites.len() as u8;
    for i in 2..suites.len() + 2 {
        output[i] = suites[i - 2];
    }
    output[suites.len() + 2] = CBOR_BYTE_STRING; // CBOR byte string magic number
    output[suites.len() + 3] = P256_ELEM_LEN as u8; // length of the byte string
    for i in suites.len() + 4..suites.len() + 4 + P256_ELEM_LEN {
        // copy byte string
        output[i] = g_x[i - suites.len() - 4];
    }
    if c_i >= 0 {
        output[suites.len() + 4 + P256_ELEM_LEN] = c_i as u8; // CBOR uint less than 24 is encoded verbatim
    } else {
        output[suites.len() + 4 + P256_ELEM_LEN] = 0x20 | (-1 + (c_i * (-1))) as u8;
    }
    *output_len = suites.len() + 5 + P256_ELEM_LEN;
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
    g_y: [u8; P256_ELEM_LEN],
    c_r: &[i8],
    id_cred_r: &[u8],
    cred_r: &[u8],
    g_r_offset: usize,
    ciphertext_2: [u8; CIPHERTEXT_2_LEN],
    h_message_1: [u8; SHA256_DIGEST_LEN],
    plaintext_2: &mut [u8; PLAINTEXT_2_LEN],
) {
    let mut g_xy = [0x00 as u8; P256_ELEM_LEN];
    let mut th_2 = [0x00 as u8; SHA256_DIGEST_LEN];

    // compute the shared secret
    p256_ecdh(&x, &g_y, &mut g_xy);
    // compute prk_2e as PRK_2e = HMAC-SHA-256( salt, G_XY )
    let mut prk_2e: [u8; P256_ELEM_LEN] = [0x00; P256_ELEM_LEN];
    hkdf_extract(&[], g_xy, &mut prk_2e);
    // compute the transcript hash th_2
    compute_th_2(h_message_1, g_y, &c_r, &mut th_2);
    // compute g_rx from static R's public key and private ephemeral key
    let mut g_rx = [0x00 as u8; P256_ELEM_LEN];
    p256_ecdh(
        &x,
        &cred_r[g_r_offset..g_r_offset + P256_ELEM_LEN],
        &mut g_rx,
    );
    // compute prk_3e2m = Extract( PRK_2e, G_RX )=
    let mut prk_3e2m: [u8; P256_ELEM_LEN] = [0x00; P256_ELEM_LEN];
    hkdf_extract(&prk_2e, g_rx, &mut prk_3e2m);

    // compute MAC_2
    let mut mac_2: [u8; MAC_LENGTH_2] = [0x00; MAC_LENGTH_2];
    let label_mac_2 = ['M' as u8, 'A' as u8, 'C' as u8, '_' as u8, '2' as u8];
    let mut context: [u8; MAX_BUFFER_LEN] = [0x00; MAX_BUFFER_LEN];
    // encode context in line
    context[0] = id_cred_r.len() as u8 | CBOR_SHORT_BYTE_STRING;
    for i in 1..id_cred_r.len() + 1 {
        context[i] = id_cred_r[i - 1];
    }
    context[id_cred_r.len() + 1] = CBOR_BYTE_STRING;
    context[id_cred_r.len() + 2] = cred_r.len() as u8;
    for i in id_cred_r.len() + 3..id_cred_r.len() + 3 + cred_r.len() {
        context[i] = cred_r[i - id_cred_r.len() - 3];
    }
    let context_len = id_cred_r.len() + 4 + cred_r.len();
    edhoc_kdf(
        prk_3e2m,
        h_message_1,
        &label_mac_2,
        &context[0..context_len],
        MAC_LENGTH_2,
        &mut mac_2,
    );

    // KEYSTREAM_2 = EDHOC-KDF( PRK_2e, TH_2, "KEYSTREAM_2", h'', plaintext_length )
    let mut keystream_2: [u8; CIPHERTEXT_2_LEN] = [0x00; CIPHERTEXT_2_LEN];
    let label_keystream_2 = [
        'K' as u8, 'E' as u8, 'Y' as u8, 'S' as u8, 'T' as u8, 'R' as u8, 'E' as u8, 'A' as u8,
        'M' as u8, '_' as u8, '2' as u8,
    ];
    edhoc_kdf(
        prk_2e,
        th_2,
        &label_keystream_2,
        &[],
        CIPHERTEXT_2_LEN,
        &mut keystream_2,
    );

    // decrypt ciphertext_2
    for i in 0..CIPHERTEXT_2_LEN {
        plaintext_2[i] = ciphertext_2[i] ^ keystream_2[i];
    }
}

fn compute_th_2(
    h_message_1: [u8; SHA256_DIGEST_LEN],
    g_y: [u8; P256_ELEM_LEN],
    c_r: &[i8],
    output: &mut [u8; SHA256_DIGEST_LEN],
) {
    let mut message = [0x00; MAX_BUFFER_LEN];
    let mut len = 0;
    message[0] = CBOR_BYTE_STRING;
    message[1] = SHA256_DIGEST_LEN as u8;
    for i in 2..SHA256_DIGEST_LEN + 2 {
        message[i] = h_message_1[i - 2];
    }
    message[SHA256_DIGEST_LEN + 2] = CBOR_BYTE_STRING;
    message[SHA256_DIGEST_LEN + 3] = P256_ELEM_LEN as u8;
    for i in SHA256_DIGEST_LEN + 4..SHA256_DIGEST_LEN + 4 + P256_ELEM_LEN {
        message[i] = g_y[i - SHA256_DIGEST_LEN - 4];
    }
    if c_r.len() > 1 {
        message[SHA256_DIGEST_LEN + 4 + P256_ELEM_LEN] = CBOR_SHORT_BYTE_STRING | (c_r.len() as u8);
        for i in
            SHA256_DIGEST_LEN + P256_ELEM_LEN + 5..SHA256_DIGEST_LEN + P256_ELEM_LEN + 5 + c_r.len()
        {
            message[i] = c_r[i - SHA256_DIGEST_LEN - P256_ELEM_LEN - 5] as u8;
        }
        len = SHA256_DIGEST_LEN + P256_ELEM_LEN + 6 + c_r.len();
    } else {
        if c_r[0] >= 0 {
            message[SHA256_DIGEST_LEN + 4 + P256_ELEM_LEN] = c_r[0] as u8;
        } else {
            message[SHA256_DIGEST_LEN + 4 + P256_ELEM_LEN] = 0x20 | (-1 + (c_r[0] * (-1))) as u8;
        }
        len = SHA256_DIGEST_LEN + 5 + P256_ELEM_LEN;
    }

    sha256_digest(&message[0..len], output);
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

pub fn p256_ecdh(private_key: &[u8], public_key: &[u8], secret: &mut [u8; P256_ELEM_LEN]) {
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

fn hkdf_extract(salt: &[u8], ikm: [u8; P256_ELEM_LEN], okm: &mut [u8; P256_ELEM_LEN]) {
    use hacspec_hkdf::*;
    use hacspec_lib::prelude::*;

    let ikm_byteseq: Seq<U8> = Seq::<U8>::from_public_slice(&ikm);
    let salt_byteseq: Seq<U8> = Seq::<U8>::from_public_slice(&salt);

    let okm_byteseq = extract(&salt_byteseq, &ikm_byteseq);

    for i in 0..okm_byteseq.len() {
        okm[i] = okm_byteseq[i].declassify();
    }
}

pub fn edhoc_kdf(
    prk: [u8; P256_ELEM_LEN],
    transcript_hash: [u8; SHA256_DIGEST_LEN],
    label: &[u8],
    context: &[u8],
    length: usize,
    output: &mut [u8],
) {
    use hacspec_hkdf::*;
    use hacspec_lib::prelude::*;

    assert!(context.len() <= MAX_KDF_CONTEXT_LEN);
    assert!(label.len() <= MAX_KDF_LABEL_LEN);

    const MAX_INFO_LEN: usize = 2 + SHA256_DIGEST_LEN + // 32-byte digest as bstr
						 1 + MAX_KDF_LABEL_LEN +     // label <24 bytes as tstr
						 1 + MAX_KDF_CONTEXT_LEN +   // context <24 bytes as bstr
						 1; // length as u8

    let mut info = [0x00 as u8; MAX_INFO_LEN];

    // construct info with inline cbor encoding
    info[0] = CBOR_BYTE_STRING;
    info[1] = SHA256_DIGEST_LEN as u8;
    for i in 2..SHA256_DIGEST_LEN + 2 {
        info[i] = transcript_hash[i - 2];
    }
    info[SHA256_DIGEST_LEN + 2] = label.len() as u8 | CBOR_SHORT_TEXT_STRING;
    for i in SHA256_DIGEST_LEN + 3..SHA256_DIGEST_LEN + 3 + label.len() {
        info[i] = label[i - SHA256_DIGEST_LEN - 3];
    }
    info[SHA256_DIGEST_LEN + 3 + label.len()] = context.len() as u8 | CBOR_SHORT_BYTE_STRING;
    for i in
        SHA256_DIGEST_LEN + 4 + label.len()..SHA256_DIGEST_LEN + 4 + label.len() + context.len()
    {
        info[i] = context[i - SHA256_DIGEST_LEN - 4 - label.len()];
    }
    info[SHA256_DIGEST_LEN + 4 + label.len() + context.len()] = length as u8;

    let info_len = SHA256_DIGEST_LEN + 5 + label.len() + context.len();

    // call kdf-expand
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
}

fn main() {
    let g_x: [u8; P256_ELEM_LEN] = [0x00; P256_ELEM_LEN];
    let mut message_1: [u8; MAX_BUFFER_LEN] = [0x00; MAX_BUFFER_LEN];
    let mut message_1_len: usize = 0;
    let mut digest_message_1: [u8; SHA256_DIGEST_LEN] = [0x00; SHA256_DIGEST_LEN];
    // TODO load hardcoded static DH key
    // TODO generate private and public key
    encode_message_1(
        EDHOC_METHOD,
        &EDHOC_SUPPORTED_SUITES,
        g_x,
        EDHOC_CID,
        &mut message_1,
        &mut message_1_len,
    );
    sha256_digest(&message_1, &mut digest_message_1);
    // TODO send message_1 over the wire
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    // test vectors (TV)
    const METHOD_TV: u8 = 0x03;
    const SUITES_I_TV: [u8; 2] = hex!("0602");
    const X_TV: [u8; P256_ELEM_LEN] =
        hex!("368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525");
    const G_X_TV: [u8; P256_ELEM_LEN] =
        hex!("8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6");
    const C_I_TV: i8 = -24;
    const EAD_1_TV: [u8; 0] = [];
    const MESSAGE_1_TV: [u8; 39] =
        hex!("0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637");
    const Y_TV: [u8; P256_ELEM_LEN] =
        hex!("e2f4126777205e853b437d6eaca1e1f753cdcc3e2c69fa884b0a1a640977e418");
    const G_Y_TV: [u8; P256_ELEM_LEN] =
        hex!("419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5");
    const G_XY_TV: [u8; P256_ELEM_LEN] =
        hex!("2f0cb7e860ba538fbf5c8bded009f6259b4b628fe1eb7dbe9378e5ecf7a824ba");
    const SALT_TV: [u8; 0] = []; // TODO test vectors give 32 zeros. check whether it influences the results
    const PRK_2E_TV: [u8; P256_ELEM_LEN] =
        hex!("fd9eef627487e40390cae922512db5a647c08dc90deb22b72ece6f156ff1c396");
    const R_TV: [u8; P256_ELEM_LEN] =
        hex!("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");
    const G_R_TV: [u8; P256_ELEM_LEN] =
        hex!("bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0");
    const G_RX_TV: [u8; P256_ELEM_LEN] =
        hex!("f2b6eea02220b95eee5a0bc701f074e00a843ea02422f60825fb269b3e161423");
    const PRK_3E2M_TV: [u8; P256_ELEM_LEN] =
        hex!("af4b5918682adf4c96fd7305b69f8fb78efc9a230dd21f4c61be7d3c109446b3");
    const C_R_TV: [i8; 1] = [-8];
    const H_MESSAGE_1_TV: [u8; SHA256_DIGEST_LEN] =
        hex!("ca02cabda5a8902749b42f711050bb4dbd52153e87527594b39f50cdf019888c");
    const TH_2_TV: [u8; SHA256_DIGEST_LEN] =
        hex!("9b99cfd7afdcbcc9950a6373507f2a81013319625697e4f9bf7a448fc8e633ca");
    const ID_CRED_R_TV: [u8; 3] = hex!("a10432");
    const CRED_R_TV : [u8; 94] = hex!("a2026b6578616d706c652e65647508a101a5010202322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
    const MAC_2_TV: [u8; MAC_LENGTH_2] = hex!("5030aac4c84b1f5f");
    const PLAINTEXT_2_TV: [u8; PLAINTEXT_2_LEN] = hex!("32485030aac4c84b1f5f");
    const KEYSTREAM_2_TV: [u8; PLAINTEXT_2_LEN] = hex!("7b86c04af73b50d31b6f");
    const CIPHERTEXT_2_TV: [u8; CIPHERTEXT_2_LEN] = hex!("49ce907a5dff98980430");
    const MESSAGE_2_TV : [u8; MESSAGE_2_LEN] = hex!("582a419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d549ce907a5dff9898043027");

    #[test]
    fn test_encode_message_1() {
        let mut message_1_buf = [0xff as u8; MAX_BUFFER_LEN];
        let mut message_1_len = 0;
        encode_message_1(
            METHOD_TV,
            &SUITES_I_TV,
            G_X_TV,
            C_I_TV,
            &mut message_1_buf,
            &mut message_1_len,
        );
        assert_eq!(message_1_len, MESSAGE_1_TV.len());
        for i in 0..message_1_len {
            assert_eq!(message_1_buf[i], MESSAGE_1_TV[i]);
        }
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
        decrypt_ciphertext_2(
            X_TV,
            G_Y_TV,
            &C_R_TV,
            &ID_CRED_R_TV,
            &CRED_R_TV,
            27, // offset of G_R within CRED_R
            CIPHERTEXT_2_TV,
            H_MESSAGE_1_TV,
            &mut plaintext_2_buf,
        );

        assert_eq!(PLAINTEXT_2_TV, plaintext_2_buf);
    }

    #[test]
    fn test_sha256_digest() {
        let mut digest = [0x00 as u8; SHA256_DIGEST_LEN];

        sha256_digest(&MESSAGE_1_TV, &mut digest);
        assert_eq!(digest, H_MESSAGE_1_TV);
    }

    #[test]
    fn test_compute_th_2() {
        let mut th_2 = [0x00; SHA256_DIGEST_LEN];
        compute_th_2(H_MESSAGE_1_TV, G_Y_TV, &C_R_TV, &mut th_2);
        assert_eq!(th_2, TH_2_TV);
    }

    #[test]
    fn test_p256_ecdh() {
        let mut secret = [0x00 as u8; P256_ELEM_LEN];
        p256_ecdh(&X_TV, &G_Y_TV, &mut secret);
        assert!(G_XY_TV == secret);
    }

    #[test]
    fn test_edhoc_kdf() {
        const LABEL_TV: [u8; 11] = [
            'K' as u8, 'E' as u8, 'Y' as u8, 'S' as u8, 'T' as u8, 'R' as u8, 'E' as u8, 'A' as u8,
            'M' as u8, '_' as u8, '2' as u8,
        ];
        const LEN_TV: usize = 10;

        let mut output = [0x00 as u8; 10];
        edhoc_kdf(PRK_2E_TV, TH_2_TV, &LABEL_TV, &[], LEN_TV, &mut output);
        assert_eq!(KEYSTREAM_2_TV, output);
    }
}
