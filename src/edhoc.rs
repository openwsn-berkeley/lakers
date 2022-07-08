#![no_std]

use hacspec_aes::*;
use hacspec_aes_ccm::*;
use hacspec_hkdf::*;
use hacspec_lib::*;
use hacspec_p256::*;
use hacspec_sha256::*;
pub mod consts;

use consts::*;

#[derive(Default)]
pub struct State(
    BytesP256ElemLen, // x, ephemeral key of the initiator
    BytesP256ElemLen, // prk_2e
    BytesP256ElemLen, // prk_3e2m
    BytesP256ElemLen, // prk_4x3m
    BytesHashLen,     // h_message_1
    BytesHashLen,     // th_2
    BytesHashLen,     // th_3
    BytesHashLen,     // th_4
);

pub fn edhoc_exporter(
    state: State,
    label: &BytesMaxLabelBuffer,
    label_len: usize,
    context: &BytesMaxContextBuffer,
    context_len: usize,
    length: usize,
    mut output: BytesMaxBuffer,
) -> BytesMaxBuffer {
    let State(x, prk_2e, prk_3e2m, prk_4x3m, h_message_1, th_2, th_3, th_4) = state;

    output = edhoc_kdf(
        &prk_4x3m,
        &th_4,
        label,
        label_len,
        context,
        context_len,
        length,
        output,
    );

    output
}

// must hold MESSAGE_1_LEN
pub fn prepare_message_1(
    mut state: State,
    mut buffer: BytesMaxBuffer,
) -> (State, BytesMaxBuffer, usize) {
    let State(mut x, prk_2e, prk_3e2m, prk_4x3m, mut h_message_1, th_2, th_3, th_4) = state;

    // TODO generate ephemeral key
    x = X;

    let (buffer, message_1_len) =
        encode_message_1(U8(EDHOC_METHOD), &EDHOC_SUPPORTED_SUITES, &G_X, C_I, buffer);

    h_message_1 = BytesHashLen::from_seq(&hash(&ByteSeq::from_slice(&buffer, 0, message_1_len)));

    state = construct_state(x, prk_2e, prk_3e2m, prk_4x3m, h_message_1, th_2, th_3, th_4);

    (state, buffer, message_1_len)
}

// message_3 must hold MESSAGE_3_LEN
// returns c_r
pub fn process_message_2(mut state: State, message_2: &BytesMessage2) -> (State, BytesCidR, U8) {
    let mut g_y = BytesP256ElemLen::new();
    let mut ciphertext_2 = BytesCiphertext2::new();
    let mut c_r = BytesCidR::new();

    let State(x, mut prk_2e, mut prk_3e2m, mut prk_4x3m, h_message_1, mut th_2, mut th_3, th_4) =
        state;

    let (g_y, ciphertext_2, c_r) = parse_message_2(message_2, g_y, ciphertext_2, c_r);

    // compute prk_2e
    let mut plaintext_2 = BytesPlaintext2::new();
    prk_2e = compute_prk_2e(&x, &g_y, prk_2e);
    plaintext_2 = decrypt_ciphertext_2(
        &prk_2e,
        &g_y,
        &c_r,
        &ciphertext_2,
        &h_message_1,
        plaintext_2,
    );

    // decode plaintext_2
    let mut id_cred_r = U8(0 as u8);
    let mut mac_2 = BytesMac2::new();
    let mut ead_2 = BytesEad2::new();
    let (id_cred_r, mac_2, ead_2) = decode_plaintext_2(&plaintext_2, id_cred_r, mac_2, ead_2);

    // verify mac_2
    prk_3e2m = compute_prk_3e2m(&prk_2e, &x, &G_R, prk_3e2m);
    th_2 = compute_th_2(&h_message_1, &g_y, &c_r, th_2);

    let mut cred_r = BytesMaxBuffer::new();
    cred_r = cred_r.update(0, &CRED_R);
    let verified =
        compute_and_verify_mac_2(&prk_3e2m, &ID_CRED_R, &cred_r, CRED_R.len(), &th_2, &mac_2);

    // XXX if not verified return an error

    // step is actually from processing of message_3
    // but we do it here to avoid storing ciphertext in State
    let mut ciphertext_2_buf = BytesMaxBuffer::new();
    ciphertext_2_buf = ciphertext_2_buf.update(0, &ciphertext_2);
    th_3 = compute_th_3_th_4(&th_2, &ciphertext_2_buf, ciphertext_2.len(), th_3);
    // message 3 processing
    prk_4x3m = compute_prk_4x3m(&prk_3e2m, &I, &g_y, prk_4x3m);

    state = construct_state(x, prk_2e, prk_3e2m, prk_4x3m, h_message_1, th_2, th_3, th_4);

    (state, c_r, id_cred_r)
}

// message_3 must hold MESSAGE_3_LEN
pub fn prepare_message_3(
    mut state: State,
    id_cred_i: &BytesIdCred,
    cred_i: &BytesMaxBuffer,
    mut message_3: BytesMessage3,
) -> (State, BytesMessage3) {

    let State(x, prk_2e, prk_3e2m, prk_4x3m, h_message_1, th_2, th_3, mut th_4) = state;

    let mut mac_3 = BytesMac3::new();
    let mut cred_i_buf = BytesMaxBuffer::new();
    cred_i_buf = cred_i_buf.update(0, cred_i);
    mac_3 = compute_mac_3(
        &prk_4x3m,
        &th_3,
        id_cred_i,
        &cred_i_buf,
        cred_i.len(),
        mac_3,
    );

    message_3 = compute_bstr_ciphertext_3(&prk_3e2m, &th_3, id_cred_i, &mac_3, message_3);

    // FIXME hack: skipping first byte of message_3 to get to ciphertext
    let mut ciphertext_3 = BytesMaxBuffer::new();
    ciphertext_3 = ciphertext_3.update_slice(0, &message_3, 1, MESSAGE_3_LEN - 1);
    th_4 = compute_th_3_th_4(
        &th_3,
        &ciphertext_3,
        MESSAGE_3_LEN - 1,
        th_4,
    );

    state = construct_state(x, prk_2e, prk_3e2m, prk_4x3m, h_message_1, th_2, th_3, th_4);

    (state, message_3)
}

pub fn construct_state(
    x: BytesP256ElemLen,
    prk_2e: BytesP256ElemLen,
    prk_3e2m: BytesP256ElemLen,
    prk_4x3m: BytesP256ElemLen,
    h_message_1: BytesHashLen,
    th_2: BytesHashLen,
    th_3: BytesHashLen,
    th_4: BytesHashLen,
) -> State {
    State(x, prk_2e, prk_3e2m, prk_4x3m, h_message_1, th_2, th_3, th_4)
}

pub fn encode_message_1(
    method: U8,
    suites: &BytesSupportedSuites,
    g_x: &BytesP256ElemLen,
    c_i: i8,
    mut output: BytesMaxBuffer,
) -> (BytesMaxBuffer, usize) {
    output[0] = method; // CBOR unsigned int less than 24 is encoded verbatim

    let mut index: usize = 0;

    output[1] = suites[0];
    output[2] = U8(CBOR_BYTE_STRING); // CBOR byte string magic number
    output[3] = U8(P256_ELEM_LEN as u8); // length of the byte string
    output = output.update(4, g_x);
    if c_i >= 0i8 {
        output[4 + P256_ELEM_LEN] = U8(c_i as u8); // CBOR uint less than 24 is encoded verbatim
    } else {
        output[4 + P256_ELEM_LEN] = U8(0x20u8 | (-1i8 + -c_i) as u8);
    }

    (output, 5 + P256_ELEM_LEN)
}

pub fn parse_message_2(
    rcvd_message_2: &BytesMessage2,
    mut g_y: BytesP256ElemLen,
    mut ciphertext_2: BytesCiphertext2,
    mut c_r: BytesCidR,
) -> (BytesP256ElemLen, BytesCiphertext2, BytesCidR) {
    // FIXME decode negative integers as well
    c_r = BytesCidR([rcvd_message_2[MESSAGE_2_LEN - 1]]);
    g_y = g_y.update(0, &rcvd_message_2.slice(2, P256_ELEM_LEN));
    ciphertext_2 = ciphertext_2.update(
        0,
        &rcvd_message_2.slice(2 + P256_ELEM_LEN, CIPHERTEXT_2_LEN),
    );

    (g_y, ciphertext_2, c_r)
}

pub fn compute_th_2(
    h_message_1: &BytesHashLen,
    g_y: &BytesP256ElemLen,
    c_r: &BytesCidR,
    mut th_2: BytesHashLen,
) -> BytesHashLen {
    let mut message = BytesMaxBuffer::new();
    let mut len = 0;
    message[0] = U8(CBOR_BYTE_STRING);
    message[1] = U8(SHA256_DIGEST_LEN as u8);
    message = message.update(2, h_message_1);
    message[SHA256_DIGEST_LEN + 2] = U8(CBOR_BYTE_STRING);
    message[SHA256_DIGEST_LEN + 3] = U8(P256_ELEM_LEN as u8);
    message = message.update(SHA256_DIGEST_LEN + 4, g_y);

    let c_r: U8 = c_r[0];
    let c_r_declassified = c_r.declassify() as i8;
    if c_r_declassified >= 0i8 {
        message[SHA256_DIGEST_LEN + 4 + P256_ELEM_LEN] = c_r;
    } else {
        message[SHA256_DIGEST_LEN + 4 + P256_ELEM_LEN] =
            U8(0x20u8 | (-1i8 - c_r_declassified) as u8);
    }
    len = SHA256_DIGEST_LEN + 5 + P256_ELEM_LEN;

    th_2 = BytesHashLen::from_seq(&hash(&ByteSeq::from_slice(&message, 0, len)));

    th_2
}

pub fn compute_th_3_th_4(
    th: &BytesHashLen,
    ciphertext: &BytesMaxBuffer,
    ciphertext_len: usize,
    mut output: BytesHashLen,
) -> BytesHashLen {
    let mut message = BytesMaxBuffer::new();

    message[0] = U8(CBOR_BYTE_STRING);
    message[1] = U8(SHA256_DIGEST_LEN as u8);
    message = message.update(2, th);
    message[SHA256_DIGEST_LEN + 2] = U8(CBOR_MAJOR_BYTE_STRING | (ciphertext_len as u8));
    for i in SHA256_DIGEST_LEN + 3..SHA256_DIGEST_LEN + 3 + ciphertext_len {
        message[i] = ciphertext[i - SHA256_DIGEST_LEN - 3];
    }

    output = BytesHashLen::from_seq(&hash(&ByteSeq::from_slice(
        &message,
        0,
        SHA256_DIGEST_LEN + 3 + ciphertext_len,
    )));

    output
}

pub fn edhoc_kdf(
    prk: &BytesP256ElemLen,
    transcript_hash: &BytesHashLen,
    label: &BytesMaxLabelBuffer,
    label_len: usize,
    context: &BytesMaxContextBuffer,
    context_len: usize,
    length: usize,
    mut output: BytesMaxBuffer,
) -> BytesMaxBuffer {
    let mut info = BytesMaxInfoBuffer::new();
    let mut info_len = 0;

    // construct info with inline cbor encoding
    info[0] = U8(CBOR_BYTE_STRING);
    info[1] = U8(SHA256_DIGEST_LEN as u8);
    info = info.update(2, transcript_hash);
    info[SHA256_DIGEST_LEN + 2] = U8(label_len as u8 | CBOR_MAJOR_TEXT_STRING);
    info = info.update(SHA256_DIGEST_LEN + 3, label);

    if context_len < 24 {
        info[SHA256_DIGEST_LEN + 3 + label_len] = U8(context_len as u8 | CBOR_MAJOR_BYTE_STRING);
        for i in SHA256_DIGEST_LEN + 4 + label_len..SHA256_DIGEST_LEN + 4 + label_len + context_len
        {
            info[i] = context[i - SHA256_DIGEST_LEN - 4 - label_len];
        }
        info_len = SHA256_DIGEST_LEN + 4 + label_len + context_len;
    } else {
        info[SHA256_DIGEST_LEN + 3 + label_len] = U8(CBOR_BYTE_STRING);
        info[SHA256_DIGEST_LEN + 4 + label_len] = U8(context_len as u8);
        for i in SHA256_DIGEST_LEN + 5 + label_len..SHA256_DIGEST_LEN + 5 + label_len + context_len
        {
            info[i] = context[i - SHA256_DIGEST_LEN - 5 - label_len];
        }
        info_len = SHA256_DIGEST_LEN + 5 + label_len + context_len;
    }
    info[info_len] = U8(length as u8);
    info_len = info_len + 1;

    output = output.update(
        0,
        &expand(
            &ByteSeq::from_slice(prk, 0, prk.len()),
            &ByteSeq::from_slice(&info, 0, info_len),
            length,
        )
        .unwrap(),
    );

    output
}

// calculates ciphertext_3 wrapped in a cbor byte string
// output must hold MESSAGE_3_LEN
pub fn compute_bstr_ciphertext_3(
    prk_3e2m: &BytesP256ElemLen,
    th_3: &BytesHashLen,
    id_cred_i: &BytesIdCred,
    mac_3: &BytesMac3,
    mut output: BytesMessage3,
) -> BytesMessage3 {
    let mut LABEL_K_3 = BytesMaxLabelBuffer::new();
    LABEL_K_3[0] = U8(0x4bu8); // 'K'
    LABEL_K_3[1] = U8(0x5fu8); // '_'
    LABEL_K_3[2] = U8(0x33u8); // '3'

    let mut LABEL_IV_3 = BytesMaxLabelBuffer::new();
    LABEL_IV_3[0] = U8(0x49u8); // 'I'
    LABEL_IV_3[1] = U8(0x56u8); // 'V'
    LABEL_IV_3[2] = U8(0x5fu8); // '_'
    LABEL_IV_3[3] = U8(0x33u8); // '3'

    let mut ENCRYPT0 = Bytes8::new();
    ENCRYPT0[0] = U8(0x45u8); // 'E'
    ENCRYPT0[1] = U8(0x6eu8); // 'n'
    ENCRYPT0[2] = U8(0x63u8); // 'c'
    ENCRYPT0[3] = U8(0x72u8); // 'r'
    ENCRYPT0[4] = U8(0x79u8); // 'y'
    ENCRYPT0[5] = U8(0x70u8); // 'p'
    ENCRYPT0[6] = U8(0x74u8); // 't'
    ENCRYPT0[7] = U8(0x30u8); // '0'

    let mut k_3 = BytesMaxBuffer::new();
    let mut iv_3 = BytesMaxBuffer::new();
    let mut plaintext_3 = BytesPlaintext3::new();
    let mut enc_structure = BytesEncStructureLen::new();

    // K_3 = EDHOC-KDF( PRK_3e2m, TH_3, "K_3", h'', key_length )
    k_3 = edhoc_kdf(
        prk_3e2m,
        th_3,
        &LABEL_K_3,
        3,
        &BytesMaxContextBuffer::new(),
        0,
        AES_CCM_KEY_LEN,
        k_3,
    );
    // IV_3 = EDHOC-KDF( PRK_3e2m, TH_3, "IV_3", h'', iv_length )
    iv_3 = edhoc_kdf(
        prk_3e2m,
        th_3,
        &LABEL_IV_3,
        4,
        &BytesMaxContextBuffer::new(),
        0,
        AES_CCM_IV_LEN,
        iv_3,
    );
    // plaintext: P = ( ? PAD, ID_CRED_I / bstr / int, Signature_or_MAC_3, ? EAD_3 )
    plaintext_3[0] = id_cred_i[id_cred_i.len() - 1]; // hack: take the last byte of ID_CRED_I as KID
    plaintext_3[1] = U8(CBOR_MAJOR_BYTE_STRING | MAC_LENGTH_3 as u8);

    plaintext_3 = plaintext_3.update(2, mac_3);
    //    plaintext_3[2..(MAC_LENGTH_3 + 2)].copy_from_slice(&mac_3[..(MAC_LENGTH_3 + 2 - 2)]);
    // encode Enc_structure from draft-ietf-cose-rfc8152bis Section 5.3
    enc_structure[0] = U8(CBOR_MAJOR_ARRAY | 3 as u8); // 3 is the fixed number of elements in the array
    enc_structure[1] = U8(CBOR_MAJOR_TEXT_STRING | ENCRYPT0.len() as u8);
    //    enc_structure[2..(ENCRYPT0.len() + 2)].copy_from_slice(&ENCRYPT0[..(ENCRYPT0.len() + 2 - 2)]);
    enc_structure = enc_structure.update(2, &ENCRYPT0);
    enc_structure[ENCRYPT0.len() + 2] = U8(CBOR_MAJOR_BYTE_STRING | 0x00 as u8); // 0 for zero-length byte string
    enc_structure[ENCRYPT0.len() + 3] = U8(CBOR_BYTE_STRING); // byte string greater than 24
    enc_structure[ENCRYPT0.len() + 4] = U8(SHA256_DIGEST_LEN as u8);
    enc_structure = enc_structure.update(ENCRYPT0.len() + 5, th_3);

    output[0] = U8(CBOR_MAJOR_BYTE_STRING | CIPHERTEXT_3_LEN as u8);

    output = output.update(
        1,
        &encrypt_ccm(
            ByteSeq::from_slice(&enc_structure, 0, enc_structure.len()),
            ByteSeq::from_slice(&iv_3, 0, AES_CCM_IV_LEN),
            ByteSeq::from_slice(&plaintext_3, 0, PLAINTEXT_3_LEN),
            Key128::from_slice(&k_3, 0, AES_CCM_KEY_LEN),
            AES_CCM_TAG_LEN,
        ),
    );

    output
}

// output must hold id_cred.len() + cred.len()
fn encode_kdf_context(
    id_cred: &BytesIdCred,
    cred: &BytesMaxBuffer,
    cred_len: usize,
    mut output: BytesMaxContextBuffer,
    mut output_len: usize,
) -> (BytesMaxContextBuffer, usize) {
    // encode context in line
    // assumes ID_CRED_R and CRED_R are already CBOR-encoded
    output = output.update(0, id_cred);
    output = output.update_slice(id_cred.len(), cred, 0, cred_len);

    output_len = (id_cred.len() + cred_len) as usize;

    (output, output_len)
}

pub fn compute_mac_3(
    prk_4x3m: &BytesP256ElemLen,
    th_3: &BytesHashLen,
    id_cred_i: &BytesIdCred,
    cred_i: &BytesMaxBuffer,
    cred_i_len: usize,
    mut output: BytesMac3,
) -> BytesMac3 {
    let mut LABEL_MAC_3 = BytesMaxLabelBuffer::new();
    LABEL_MAC_3[0] = U8(0x4du8); // 'M'
    LABEL_MAC_3[1] = U8(0x41u8); // 'A'
    LABEL_MAC_3[2] = U8(0x43u8); // 'C'
    LABEL_MAC_3[3] = U8(0x5fu8); // '_'
    LABEL_MAC_3[4] = U8(0x33u8); // '3'

    // MAC_3 = EDHOC-KDF( PRK_4x3m, TH_3, "MAC_3", << ID_CRED_I, CRED_I, ? EAD_3 >>, mac_length_3 )

    let mut context = BytesMaxContextBuffer::new();
    let mut context_len: usize = 0;

    let (context, context_len) =
        encode_kdf_context(id_cred_i, cred_i, cred_i_len, context, context_len);

    // compute mac_3
    let mut output_buf = BytesMaxBuffer::new();
    output_buf = edhoc_kdf(
        prk_4x3m,
        th_3,
        &LABEL_MAC_3,
        5,
        &context,
        context_len,
        MAC_LENGTH_3,
        output_buf,
    );

    output = output.update_slice(0, &output_buf, 0, MAC_LENGTH_3);
    output
}

pub fn compute_and_verify_mac_2(
    prk_3e2m: &BytesP256ElemLen,
    id_cred_r: &BytesIdCred,
    cred_r: &BytesMaxBuffer,
    cred_r_len: usize,
    th_2: &BytesHashLen,
    rcvd_mac_2: &BytesMac2,
) -> bool {
    // compute MAC_2
    let mut mac_2 = BytesMaxBuffer::new();
    let mut label_mac_2 = BytesMaxLabelBuffer::new();
    label_mac_2[0] = U8(0x4du8); // 'M'
    label_mac_2[1] = U8(0x41u8); // 'A'
    label_mac_2[2] = U8(0x43u8); // 'C'
    label_mac_2[3] = U8(0x5fu8); // '_'
    label_mac_2[4] = U8(0x32u8); // '2'

    let mut context = BytesMaxContextBuffer::new();
    let mut context_len: usize = 0;

    let (context, context_len) =
        encode_kdf_context(id_cred_r, cred_r, cred_r_len, context, context_len);

    // compute mac_2
    mac_2 = edhoc_kdf(
        prk_3e2m,
        th_2,
        &label_mac_2,
        5,
        &context,
        context_len,
        MAC_LENGTH_2,
        mac_2,
    );

    let mut verified: bool = true;
    for i in 0..MAC_LENGTH_2 {
        if mac_2[i].declassify() == rcvd_mac_2[i].declassify() {
            verified = true;
        } else {
            verified = false;
        }
    }

    verified
}

pub fn decode_plaintext_2(
    plaintext_2: &BytesPlaintext2,
    mut id_cred_r: U8,
    mut mac_2: BytesMac2,
    mut ead_2: BytesEad2,
) -> (U8, BytesMac2, BytesEad2) {
    id_cred_r = plaintext_2[0];
    // skip cbor byte string byte as we know how long the string is
    mac_2 = mac_2.update_slice(0, plaintext_2, 2, MAC_LENGTH_2);
    // TODO zero out ead_2

    (id_cred_r, mac_2, ead_2)
}

pub fn decrypt_ciphertext_2(
    prk_2e: &BytesP256ElemLen,
    g_y: &BytesP256ElemLen,
    c_r: &BytesCidR,
    ciphertext_2: &BytesCiphertext2,
    h_message_1: &BytesHashLen,
    mut plaintext_2: BytesPlaintext2,
) -> BytesPlaintext2 {
    let mut th_2 = BytesHashLen::new();

    // compute the transcript hash th_2
    th_2 = compute_th_2(h_message_1, g_y, c_r, th_2);

    // KEYSTREAM_2 = EDHOC-KDF( PRK_2e, TH_2, "KEYSTREAM_2", h'', plaintext_length )
    let mut keystream_2 = BytesMaxBuffer::new();

    let mut label_keystream_2 = BytesMaxLabelBuffer::new();
    label_keystream_2[0] = U8(0x4bu8); // 'K'
    label_keystream_2[1] = U8(0x45u8); // 'E'
    label_keystream_2[2] = U8(0x59u8); // 'Y'
    label_keystream_2[3] = U8(0x53u8); // 'S'
    label_keystream_2[4] = U8(0x54u8); // 'T'
    label_keystream_2[5] = U8(0x52u8); // 'R'
    label_keystream_2[6] = U8(0x45u8); // 'E'
    label_keystream_2[7] = U8(0x41u8); // 'A'
    label_keystream_2[8] = U8(0x4du8); // 'M'
    label_keystream_2[9] = U8(0x5fu8); // '_'
    label_keystream_2[10] = U8(0x32u8); // '2'

    keystream_2 = edhoc_kdf(
        prk_2e,
        &th_2,
        &label_keystream_2,
        11,
        &BytesMaxContextBuffer::new(),
        0,
        CIPHERTEXT_2_LEN,
        keystream_2,
    );

    // decrypt ciphertext_2
    for i in 0..CIPHERTEXT_2_LEN {
        plaintext_2[i] = ciphertext_2[i] ^ keystream_2[i];
    }

    plaintext_2
}

pub fn compute_prk_4x3m(
    prk_3e2m: &BytesP256ElemLen,
    i: &BytesP256ElemLen,
    g_y: &BytesP256ElemLen,
    mut prk_4x3m: BytesP256ElemLen,
) -> BytesP256ElemLen {
    // compute g_rx from static R's public key and private ephemeral key
    let mut g_iy = BytesP256ElemLen::new();
    g_iy = p256_ecdh(i, g_y, g_iy);
    prk_4x3m = BytesP256ElemLen::from_seq(&extract(
        &ByteSeq::from_slice(prk_3e2m, 0, prk_3e2m.len()),
        &ByteSeq::from_slice(&g_iy, 0, g_iy.len()),
    ));

    prk_4x3m
}

pub fn compute_prk_3e2m(
    prk_2e: &BytesP256ElemLen,
    x: &BytesP256ElemLen,
    g_r: &BytesP256ElemLen,
    mut prk_3e2m: BytesP256ElemLen,
) -> BytesP256ElemLen {
    // compute g_rx from static R's public key and private ephemeral key
    let mut g_rx = BytesP256ElemLen::new();
    g_rx = p256_ecdh(x, g_r, g_rx);
    prk_3e2m = BytesP256ElemLen::from_seq(&extract(
        &ByteSeq::from_slice(prk_2e, 0, prk_2e.len()),
        &ByteSeq::from_slice(&g_rx, 0, g_rx.len()),
    ));

    prk_3e2m
}

pub fn compute_prk_2e(
    x: &BytesP256ElemLen,
    g_y: &BytesP256ElemLen,
    mut prk_2e: BytesP256ElemLen,
) -> BytesP256ElemLen {
    let mut g_xy = BytesP256ElemLen::new();
    // compute the shared secret
    g_xy = p256_ecdh(x, g_y, g_xy);
    // compute prk_2e as PRK_2e = HMAC-SHA-256( salt, G_XY )
    prk_2e = BytesP256ElemLen::from_seq(&extract(
        &ByteSeq::new(0),
        &ByteSeq::from_slice(&g_xy, 0, g_xy.len()),
    ));

    prk_2e
}

fn p256_ecdh(
    private_key: &BytesP256ElemLen,
    public_key: &BytesP256ElemLen,
    mut secret: BytesP256ElemLen,
) -> BytesP256ElemLen {
    let scalar = P256Scalar::from_byte_seq_be(private_key);
    let point = (
        P256FieldElement::from_byte_seq_be(public_key),
        p256_calculate_w(P256FieldElement::from_byte_seq_be(public_key)),
    );

    // we only care about the x coordinate
    let (x, y) = p256_point_mul(scalar, point).unwrap();

    secret = BytesP256ElemLen::from_seq(&x.to_byte_seq_be());
    secret
}
