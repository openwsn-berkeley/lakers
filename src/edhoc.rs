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
    label: U8,
    context: &BytesMaxContextBuffer,
    context_len: usize,
    length: usize,
) -> BytesMaxBuffer {
    let State(_x, _prk_2e, _prk_3e2m, prk_4x3m, _h_message_1, _th_2, _th_3, th_4) = state;

    let output = edhoc_kdf(&prk_4x3m, label, context, context_len, length);

    output
}

// must hold MESSAGE_1_LEN
pub fn prepare_message_1(mut state: State) -> (State, BytesMaxBuffer, usize) {
    let State(x, prk_2e, prk_3e2m, prk_4x3m, h_message_1, th_2, th_3, th_4) = state;

    // TODO generate ephemeral key
    let x = X;

    let (buffer, message_1_len) =
        encode_message_1(U8(EDHOC_METHOD), &EDHOC_SUPPORTED_SUITES, &G_X, &C_I);

    let h_message_1 =
        BytesHashLen::from_seq(&hash(&ByteSeq::from_slice(&buffer, 0, message_1_len)));

    state = construct_state(x, prk_2e, prk_3e2m, prk_4x3m, h_message_1, th_2, th_3, th_4);

    (state, buffer, message_1_len)
}

// message_3 must hold MESSAGE_3_LEN
// returns c_r
pub fn process_message_2(
    mut state: State,
    message_2: &BytesMessage2,
) -> (State, bool, BytesCid, U8) {
    let State(x, mut prk_2e, mut prk_3e2m, mut prk_4x3m, h_message_1, mut th_2, mut th_3, th_4) =
        state;

    let (g_y, ciphertext_2, c_r) = parse_message_2(message_2);

    // compute prk_2e
    prk_2e = compute_prk_2e(&x, &g_y);
    let (plaintext_2, plaintext_2_len) =
        decrypt_ciphertext_2(&prk_2e, &g_y, &c_r, &ciphertext_2, &h_message_1);

    // decode plaintext_2
    let (id_cred_r, mac_2, _ead_2) = decode_plaintext_2(&plaintext_2, plaintext_2_len);

    // verify mac_2
    prk_3e2m = compute_prk_3e2m(&prk_2e, &x, &G_R);
    th_2 = compute_th_2(&g_y, &c_r, &h_message_1);

    let mut cred_r = BytesMaxBuffer::new();
    cred_r = cred_r.update(0, &CRED_R);
    let verified =
        compute_and_verify_mac_2(&prk_3e2m, &ID_CRED_R, &cred_r, CRED_R.len(), &th_2, &mac_2);

    // XXX if not verified return an error
    // step is actually from processing of message_3
    // but we do it here to avoid storing ciphertext in State
    let mut ciphertext_2_buf = BytesMaxBuffer::new();
    ciphertext_2_buf = ciphertext_2_buf.update(0, &ciphertext_2);
    th_3 = compute_th_3_th_4(&th_2, &plaintext_2, plaintext_2.len());
    // message 3 processing
    prk_4x3m = compute_prk_4x3m(&prk_3e2m, &I, &g_y);

    state = construct_state(x, prk_2e, prk_3e2m, prk_4x3m, h_message_1, th_2, th_3, th_4);

    (state, verified, c_r, id_cred_r)
}

// message_3 must hold MESSAGE_3_LEN
pub fn prepare_message_3(
    mut state: State,
    id_cred_i: &BytesIdCred,
    cred_i: &BytesMaxBuffer,
) -> (State, BytesMessage3) {
    let State(x, prk_2e, prk_3e2m, prk_4x3m, h_message_1, th_2, th_3, mut th_4) = state;

    let mut cred_i_buf = BytesMaxBuffer::new();
    cred_i_buf = cred_i_buf.update(0, cred_i);
    let mac_3 = compute_mac_3(&prk_4x3m, &th_3, id_cred_i, &cred_i_buf, cred_i.len());

    let message_3 = compute_bstr_ciphertext_3(&prk_3e2m, &th_3, id_cred_i, &mac_3);

    // FIXME hack: skipping first byte of message_3 to get to ciphertext
    let mut ciphertext_3 = BytesMaxBuffer::new();
    ciphertext_3 = ciphertext_3.update_slice(0, &message_3, 1, MESSAGE_3_LEN - 1);
    th_4 = compute_th_3_th_4(&th_3, &ciphertext_3, MESSAGE_3_LEN - 1);

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

fn encode_message_1(
    method: U8,
    suites: &BytesSupportedSuites,
    g_x: &BytesP256ElemLen,
    c_i: &BytesCid,
) -> (BytesMaxBuffer, usize) {
    let mut output = BytesMaxBuffer::new();

    output[0] = method; // CBOR unsigned int less than 24 is encoded verbatim
    output[1] = suites[0];
    output[2] = U8(CBOR_BYTE_STRING); // CBOR byte string magic number
    output[3] = U8(P256_ELEM_LEN as u8); // length of the byte string
    output = output.update(4, g_x);
    output = output.update(4 + P256_ELEM_LEN, c_i);

    (output, 4 + P256_ELEM_LEN + c_i.len())
}

fn parse_message_2(
    rcvd_message_2: &BytesMessage2,
) -> (BytesP256ElemLen, BytesCiphertext2, BytesCid) {
    // FIXME decode negative integers as well
    let c_r = BytesCid([rcvd_message_2[MESSAGE_2_LEN - 1]]);
    let mut g_y = BytesP256ElemLen::new();
    let mut ciphertext_2 = BytesCiphertext2::new();
    g_y = g_y.update(0, &rcvd_message_2.slice(2, P256_ELEM_LEN));
    ciphertext_2 = ciphertext_2.update(
        0,
        &rcvd_message_2.slice(2 + P256_ELEM_LEN, CIPHERTEXT_2_LEN),
    );

    (g_y, ciphertext_2, c_r)
}

fn compute_th_2(
    g_y: &BytesP256ElemLen,
    c_r: &BytesCid,
    h_message_1: &BytesHashLen,
) -> BytesHashLen {
    let mut message = BytesMaxBuffer::new();
    message[0] = U8(CBOR_BYTE_STRING);
    message[1] = U8(P256_ELEM_LEN as u8);
    message = message.update(2, g_y);
    message = message.update(2 + P256_ELEM_LEN, c_r);
    message[2 + P256_ELEM_LEN + c_r.len()] = U8(CBOR_BYTE_STRING);
    message[3 + P256_ELEM_LEN + c_r.len()] = U8(SHA256_DIGEST_LEN as u8);
    message = message.update(4 + P256_ELEM_LEN + c_r.len(), h_message_1);

    let len = 4 + P256_ELEM_LEN + c_r.len() + SHA256_DIGEST_LEN;

    let th_2 = BytesHashLen::from_seq(&hash(&ByteSeq::from_slice(&message, 0, len)));

    th_2
}

fn compute_th_3_th_4(
    th: &BytesHashLen,
    plaintext: &BytesMaxBuffer,
    plaintext_len: usize,
) -> BytesHashLen {
    let mut message = BytesMaxBuffer::new();

    message[0] = U8(CBOR_BYTE_STRING);
    message[1] = U8(SHA256_DIGEST_LEN as u8);
    message = message.update(2, th);
    for i in SHA256_DIGEST_LEN + 2..SHA256_DIGEST_LEN + 2 + plaintext_len {
        message[i] = plaintext[i - SHA256_DIGEST_LEN - 2];
    }

    let output = BytesHashLen::from_seq(&hash(&ByteSeq::from_slice(
        &message,
        0,
        SHA256_DIGEST_LEN + 2 + plaintext_len,
    )));

    output
}

fn edhoc_kdf(
    prk: &BytesP256ElemLen,
    label: U8,
    context: &BytesMaxContextBuffer,
    context_len: usize,
    length: usize,
) -> BytesMaxBuffer {
    let mut info = BytesMaxInfoBuffer::new();
    let mut info_len = 0;

    // construct info with inline cbor encoding
    info[0] = label;
    if context_len < 24 {
        info[1] = U8(context_len as u8 | CBOR_MAJOR_BYTE_STRING);
        info = info.update_slice(2, context, 0, context_len);
        info_len = 2 + context_len;
    } else {
        info[1] = U8(CBOR_BYTE_STRING);
        info[2] = U8(context_len as u8);
        info = info.update_slice(3, context, 0, context_len);
        info_len = 3 + context_len;
    }
    info[info_len] = U8(length as u8);
    info_len = info_len + 1;

    let mut output = BytesMaxBuffer::new();
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
fn compute_bstr_ciphertext_3(
    prk_3e2m: &BytesP256ElemLen,
    th_3: &BytesHashLen,
    id_cred_i: &BytesIdCred,
    mac_3: &BytesMac3,
) -> BytesMessage3 {
    let mut encrypt0 = Bytes8::new();
    encrypt0[0] = U8(0x45u8); // 'E'
    encrypt0[1] = U8(0x6eu8); // 'n'
    encrypt0[2] = U8(0x63u8); // 'c'
    encrypt0[3] = U8(0x72u8); // 'r'
    encrypt0[4] = U8(0x79u8); // 'y'
    encrypt0[5] = U8(0x70u8); // 'p'
    encrypt0[6] = U8(0x74u8); // 't'
    encrypt0[7] = U8(0x30u8); // '0'

    let mut plaintext_3 = BytesPlaintext3::new();
    let mut enc_structure = BytesEncStructureLen::new();
    let mut th_3_context = BytesMaxContextBuffer::new();
    th_3_context = th_3_context.update(0, th_3);

    // K_3 = EDHOC-KDF( PRK_3e2m, 3, TH_3,      key_length )
    let k_3 = edhoc_kdf(
        prk_3e2m,
        U8(3),
        &th_3_context,
        SHA256_DIGEST_LEN,
        AES_CCM_KEY_LEN,
    );
    // IV_3 = EDHOC-KDF( PRK_3e2m, 4, TH_3,      iv_length )
    let iv_3 = edhoc_kdf(
        prk_3e2m,
        U8(4),
        &th_3_context,
        SHA256_DIGEST_LEN,
        AES_CCM_IV_LEN,
    );
    // plaintext: P = ( ? PAD, ID_CRED_I / bstr / int, Signature_or_MAC_3, ? EAD_3 )
    plaintext_3[0] = id_cred_i[id_cred_i.len() - 1]; // hack: take the last byte of ID_CRED_I as KID
    plaintext_3[1] = U8(CBOR_MAJOR_BYTE_STRING | MAC_LENGTH_3 as u8);

    plaintext_3 = plaintext_3.update(2, mac_3);
    // encode Enc_structure from draft-ietf-cose-rfc8152bis Section 5.3
    enc_structure[0] = U8(CBOR_MAJOR_ARRAY | 3 as u8); // 3 is the fixed number of elements in the array
    enc_structure[1] = U8(CBOR_MAJOR_TEXT_STRING | encrypt0.len() as u8);
    enc_structure = enc_structure.update(2, &encrypt0);
    enc_structure[encrypt0.len() + 2] = U8(CBOR_MAJOR_BYTE_STRING | 0x00 as u8); // 0 for zero-length byte string
    enc_structure[encrypt0.len() + 3] = U8(CBOR_BYTE_STRING); // byte string greater than 24
    enc_structure[encrypt0.len() + 4] = U8(SHA256_DIGEST_LEN as u8);
    enc_structure = enc_structure.update(encrypt0.len() + 5, th_3);

    let mut output = BytesMessage3::new();
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
    th: &BytesHashLen,
    cred: &BytesMaxBuffer,
    cred_len: usize,
) -> (BytesMaxContextBuffer, usize) {
    // encode context in line
    // assumes ID_CRED_R and CRED_R are already CBOR-encoded
    let mut output = BytesMaxContextBuffer::new();
    output = output.update(0, id_cred);
    output[id_cred.len()] = U8(CBOR_BYTE_STRING);
    output[id_cred.len() + 1] = U8(SHA256_DIGEST_LEN as u8);
    output = output.update(id_cred.len() + 2, th);
    output = output.update_slice(id_cred.len() + 2 + SHA256_DIGEST_LEN, cred, 0, cred_len);

    let output_len = (id_cred.len() + 2 + SHA256_DIGEST_LEN + cred_len) as usize;

    (output, output_len)
}

fn compute_mac_3(
    prk_4x3m: &BytesP256ElemLen,
    th_3: &BytesHashLen,
    id_cred_i: &BytesIdCred,
    cred_i: &BytesMaxBuffer,
    cred_i_len: usize,
) -> BytesMac3 {
    // MAC_3 = EDHOC-KDF( PRK_4e3m, 6, context_3, mac_length_3 )
    let (context, context_len) = encode_kdf_context(id_cred_i, th_3, cred_i, cred_i_len);

    // compute mac_3
    let output_buf = edhoc_kdf(
        prk_4x3m,
        U8(5), // length of "MAC_3"
        &context,
        context_len,
        MAC_LENGTH_3,
    );

    let mut output = BytesMac3::new();
    output = output.update_slice(0, &output_buf, 0, MAC_LENGTH_3);
    output
}

fn compute_and_verify_mac_2(
    prk_3e2m: &BytesP256ElemLen,
    id_cred_r: &BytesIdCred,
    cred_r: &BytesMaxBuffer,
    cred_r_len: usize,
    th_2: &BytesHashLen,
    rcvd_mac_2: &BytesMac2,
) -> bool {
    // compute MAC_2
    let (context, context_len) = encode_kdf_context(id_cred_r, th_2, cred_r, cred_r_len);

    // MAC_2 = EDHOC-KDF( PRK_3e2m, 2, context_2, mac_length_2 )
    let mac_2 = edhoc_kdf(prk_3e2m, U8(2), &context, context_len, MAC_LENGTH_2);

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

fn decode_plaintext_2(
    plaintext_2: &BytesMaxBuffer,
    _plaintext_2_len: usize,
) -> (U8, BytesMac2, BytesEad2) {
    let id_cred_r = plaintext_2[0];
    // skip cbor byte string byte as we know how long the string is
    let mut mac_2 = BytesMac2::new();
    mac_2 = mac_2.update_slice(0, plaintext_2, 2, MAC_LENGTH_2);
    // FIXME we don't support ead_2 parsing for now
    let ead_2 = BytesEad2::new();

    (id_cred_r, mac_2, ead_2)
}

fn decrypt_ciphertext_2(
    prk_2e: &BytesP256ElemLen,
    g_y: &BytesP256ElemLen,
    c_r: &BytesCid,
    ciphertext_2: &BytesCiphertext2,
    h_message_1: &BytesHashLen,
) -> (BytesMaxBuffer, usize) {
    // compute the transcript hash th_2
    let th_2 = compute_th_2(g_y, c_r, h_message_1);
    let mut th_2_context = BytesMaxContextBuffer::new();
    th_2_context = th_2_context.update(0, &th_2);

    // KEYSTREAM_2 = EDHOC-KDF( PRK_2e,   0, TH_2,      plaintext_length )
    let keystream_2 = edhoc_kdf(
        prk_2e,
        U8(0),
        &th_2_context,
        SHA256_DIGEST_LEN,
        CIPHERTEXT_2_LEN,
    );

    let mut plaintext_2 = BytesMaxBuffer::new();
    // decrypt ciphertext_2
    for i in 0..CIPHERTEXT_2_LEN {
        plaintext_2[i] = ciphertext_2[i] ^ keystream_2[i];
    }

    (plaintext_2, CIPHERTEXT_2_LEN)
}

fn compute_prk_4x3m(
    prk_3e2m: &BytesP256ElemLen,
    i: &BytesP256ElemLen,
    g_y: &BytesP256ElemLen,
) -> BytesP256ElemLen {
    // compute g_rx from static R's public key and private ephemeral key
    let g_iy = p256_ecdh(i, g_y);
    let prk_4x3m = BytesP256ElemLen::from_seq(&extract(
        &ByteSeq::from_slice(prk_3e2m, 0, prk_3e2m.len()),
        &ByteSeq::from_slice(&g_iy, 0, g_iy.len()),
    ));

    prk_4x3m
}

fn compute_prk_3e2m(
    prk_2e: &BytesP256ElemLen,
    x: &BytesP256ElemLen,
    g_r: &BytesP256ElemLen,
) -> BytesP256ElemLen {
    // compute g_rx from static R's public key and private ephemeral key
    let g_rx = p256_ecdh(x, g_r);
    let prk_3e2m = BytesP256ElemLen::from_seq(&extract(
        &ByteSeq::from_slice(prk_2e, 0, prk_2e.len()),
        &ByteSeq::from_slice(&g_rx, 0, g_rx.len()),
    ));

    prk_3e2m
}

fn compute_prk_2e(x: &BytesP256ElemLen, g_y: &BytesP256ElemLen) -> BytesP256ElemLen {
    // compute the shared secret
    let g_xy = p256_ecdh(x, g_y);
    // compute prk_2e as PRK_2e = HMAC-SHA-256( salt, G_XY )
    let prk_2e = BytesP256ElemLen::from_seq(&extract(
        &ByteSeq::new(0),
        &ByteSeq::from_slice(&g_xy, 0, g_xy.len()),
    ));

    prk_2e
}

fn p256_ecdh(private_key: &BytesP256ElemLen, public_key: &BytesP256ElemLen) -> BytesP256ElemLen {
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

#[cfg(test)]
mod tests {
    use super::*;
    array!(BytesMessage1Tv, 37, U8);
    // test vectors (TV)

    const METHOD_TV: u8 = 0x03;
    // manually modified test vector to include a single supported cipher suite
    const SUITES_I_TV: &str = "02";
    const G_X_TV: &str = "8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6";
    const C_I_TV: &str = "37";
    // manually modified test vector to include a single supported cipher suite
    const MESSAGE_1_TV: &str =
        "030258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637";
    const G_Y_TV: &str = "419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5";
    const C_R_TV: &str = "27";
    const MESSAGE_2_TV: &str =
    "582a419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d58b8fec6b1f0580c5043927";
    const CIPHERTEXT_2_TV: &str = "8b8fec6b1f0580c50439";
    const H_MESSAGE_1_TV: &str = "ca02cabda5a8902749b42f711050bb4dbd52153e87527594b39f50cdf019888c";
    const TH_2_TV: &str = "9d2af3a3d3fc06aea8110f14ba12ad0b4fb7e5cdf59c7df1cf2dfe9c2024439c";
    const TH_3_TV: &str = "085de16d9c8235cbf57c46d06d16d456a6c0ad81aa4b448b6abc98dcba6125eb";
    const CIPHERTEXT_3_TV: &str = "c25c8420036764462f57357986616c8d21b0";
    const TH_4_TV: &str = "a4097a6b9e39f7d3dc4f8af2c4a8645b373d7af586f415df626e16b6ac2755d3";
    const PRK_2E_TV: &str = "fd9eef627487e40390cae922512db5a647c08dc90deb22b72ece6f156ff1c396";
    const KEYSTREAM_2_TV: &str = "b9c7416aa3354654154f";
    const PRK_3E2M_TV: &str = "7e230e62b909ca7492367aaa8a229f6306c5ac67482184b33362d28d177a56e9";
    const CONTEXT_INFO_MAC_2_TV : &str = "a104413258209d2af3a3d3fc06aea8110f14ba12ad0b4fb7e5cdf59c7df1cf2dfe9c2024439ca2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072";
    const MAC_2_TV: &str = "ad01bc30c6911176";
    const ID_CRED_I_TV: &str = "a104412b";
    const MAC_3_TV: &str = "354f0bc2741eeac6";
    const MESSAGE_3_TV: &str = "2752c25c8420036764462f57357986616c8d21b0";
    const PRK_4X3M_TV: &str = "9eda8cd755ae3b80b47e8ddbb8d7c5fe2b62b462e4bcba2c6c8ea36ee5fb604d";
    const CRED_I_TV : &str = "A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8";
    const ID_CRED_R_TV: &str = "a1044132";
    const CRED_R_TV : &str = "A2026B6578616D706C652E65647508A101A501020241322001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072";
    const PLAINTEXT_2_TV: &str = "3248ad01bc30c6911176";
    const I_TV: &str = "fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b";
    const X_TV: &str = "368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525";
    const G_R_TV: &str = "bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0";
    const PLAINTEXT_3_TV: &str = "2b48354f0bc2741eeac6";

    #[test]
    fn test_encode_message_1() {
        let method_tv = U8(METHOD_TV);
        let suites_i_tv = BytesSupportedSuites::from_hex(SUITES_I_TV);
        let g_x_tv = BytesP256ElemLen::from_hex(G_X_TV);
        let c_i_tv = BytesCid::from_hex(C_I_TV);
        let message_1_tv = BytesMessage1Tv::from_hex(MESSAGE_1_TV);

        let (message_1, message_1_len) =
            encode_message_1(method_tv, &suites_i_tv, &g_x_tv, &c_i_tv);

        assert_eq!(message_1_len, message_1_tv.len());
        for i in 0..message_1_tv.len() {
            assert_eq!(message_1[i].declassify(), message_1_tv[i].declassify());
        }
    }

    #[test]
    fn test_parse_message_2() {
        let message_2_tv = BytesMessage2::from_hex(MESSAGE_2_TV);
        let g_y_tv = BytesP256ElemLen::from_hex(G_Y_TV);
        let ciphertext_2_tv = BytesCiphertext2::from_hex(CIPHERTEXT_2_TV);

        let (g_y, ciphertext_2, _c_r) = parse_message_2(&message_2_tv);

        assert_bytes_eq!(g_y, g_y_tv);
        assert_bytes_eq!(ciphertext_2, ciphertext_2_tv);
    }

    #[test]
    fn test_compute_th_2() {
        let h_message_1_tv = BytesHashLen::from_hex(H_MESSAGE_1_TV);
        let g_y_tv = BytesP256ElemLen::from_hex(G_Y_TV);
        let c_r_tv = BytesCid::from_hex(C_R_TV);
        let th_2_tv = BytesHashLen::from_hex(TH_2_TV);

        let th_2 = compute_th_2(&g_y_tv, &c_r_tv, &h_message_1_tv);
        assert_bytes_eq!(th_2, th_2_tv);
    }

    #[test]
    fn test_compute_th_3_th_4() {
        let th_2_tv = BytesHashLen::from_hex(TH_2_TV);
        let th_3_tv = BytesHashLen::from_hex(TH_3_TV);
        let mut plaintext_2_tv = BytesMaxBuffer::new();
        plaintext_2_tv = plaintext_2_tv.update(0, &BytesPlaintext2::from_hex(PLAINTEXT_2_TV));
        let mut plaintext_3_tv = BytesMaxBuffer::new();
        plaintext_3_tv = plaintext_3_tv.update(0, &BytesPlaintext3::from_hex(PLAINTEXT_3_TV));
        let th_4_tv = BytesHashLen::from_hex(TH_4_TV);

        let th_3 = compute_th_3_th_4(&th_2_tv, &plaintext_2_tv, PLAINTEXT_2_LEN);
        assert_bytes_eq!(th_3, th_3_tv);

        let th_4 = compute_th_3_th_4(&th_3_tv, &plaintext_3_tv, PLAINTEXT_3_LEN);
        assert_bytes_eq!(th_4, th_4_tv);
    }

    #[test]
    fn test_edhoc_kdf() {
        let mut th_2_context_tv = BytesMaxContextBuffer::new();
        th_2_context_tv = th_2_context_tv.update(0, &ByteSeq::from_hex(TH_2_TV));
        let prk_2e_tv = BytesP256ElemLen::from_hex(PRK_2E_TV);
        let keystream_2_tv = BytesPlaintext2::from_hex(KEYSTREAM_2_TV);
        const LEN_TV: usize = 10;

        let output = edhoc_kdf(
            &prk_2e_tv,
            U8(0),
            &th_2_context_tv,
            SHA256_DIGEST_LEN,
            LEN_TV,
        );
        for i in 0..keystream_2_tv.len() {
            assert_eq!(keystream_2_tv[i].declassify(), output[i].declassify());
        }

        let prk_3e2m_tv = BytesP256ElemLen::from_hex(PRK_3E2M_TV);
        let mut context_info_mac_2 = BytesMaxContextBuffer::new();
        context_info_mac_2 =
            context_info_mac_2.update(0, &ByteSeq::from_hex(CONTEXT_INFO_MAC_2_TV));
        let mac_2_tv = BytesMac2::from_hex(MAC_2_TV);

        let output_2 = edhoc_kdf(
            &prk_3e2m_tv,
            U8(2), // length of "MAC_2"
            &context_info_mac_2,
            CONTEXT_INFO_MAC_2_TV.len() / 2, // divide by two to get num of bytes from hex string
            MAC_LENGTH_2,
        );

        for i in 0..MAC_2_TV.len() / 2 {
            assert_eq!(mac_2_tv[i].declassify(), output_2[i].declassify());
        }
    }

    #[test]
    fn test_compute_bstr_ciphertext_3() {
        let prk_3e2m_tv = BytesP256ElemLen::from_hex(PRK_3E2M_TV);
        let th_3_tv = BytesHashLen::from_hex(TH_3_TV);
        let id_cred_i_tv = BytesIdCred::from_hex(ID_CRED_I_TV);
        let mac_3_tv = BytesMac3::from_hex(MAC_3_TV);
        let message_3_tv = BytesMessage3::from_hex(MESSAGE_3_TV);

        let bstr_ciphertext_3 =
            compute_bstr_ciphertext_3(&prk_3e2m_tv, &th_3_tv, &id_cred_i_tv, &mac_3_tv);
        assert_bytes_eq!(bstr_ciphertext_3, message_3_tv);
    }

    #[test]
    fn test_compute_mac_3() {
        let prk_4x3m_tv = BytesP256ElemLen::from_hex(PRK_4X3M_TV);
        let th_3_tv = BytesHashLen::from_hex(TH_3_TV);
        let id_cred_i_tv = BytesIdCred::from_hex(ID_CRED_I_TV);
        let mut cred_i_tv = BytesMaxBuffer::new();
        cred_i_tv = cred_i_tv.update(0, &ByteSeq::from_hex(CRED_I_TV));
        let mac_3_tv = BytesMac3::from_hex(MAC_3_TV);

        let mac_3 = compute_mac_3(
            &prk_4x3m_tv,
            &th_3_tv,
            &id_cred_i_tv,
            &cred_i_tv,
            CRED_I_TV.len() / 2, // divide by two to get num of bytes from hex string
        );
        assert_bytes_eq!(mac_3, mac_3_tv);
    }

    #[test]
    fn test_compute_and_verify_mac_2() {
        let prk_3e2m_tv = BytesP256ElemLen::from_hex(PRK_3E2M_TV);
        let id_cred_r_tv = BytesIdCred::from_hex(ID_CRED_R_TV);
        let mut cred_r_tv = BytesMaxBuffer::new();
        cred_r_tv = cred_r_tv.update(0, &ByteSeq::from_hex(CRED_R_TV));
        let th_2_tv = BytesHashLen::from_hex(TH_2_TV);
        let mac_2_tv = BytesMac2::from_hex(MAC_2_TV);

        assert!(compute_and_verify_mac_2(
            &prk_3e2m_tv,
            &id_cred_r_tv,
            &cred_r_tv,
            CRED_R_TV.len() / 2,
            &th_2_tv,
            &mac_2_tv
        ));
    }

    #[test]
    fn test_decode_plaintext_2() {
        let mut plaintext_2_tv = BytesMaxBuffer::new();
        plaintext_2_tv = plaintext_2_tv.update(0, &ByteSeq::from_hex(PLAINTEXT_2_TV));
        let id_cred_r_tv = BytesIdCred::from_hex(ID_CRED_R_TV);
        let mac_2_tv = BytesMac2::from_hex(MAC_2_TV);
        let ead_2_tv = BytesEad2::new();

        let (id_cred_r, mac_2, ead_2) = decode_plaintext_2(&plaintext_2_tv, PLAINTEXT_2_LEN);
        assert_eq!(U8::declassify(id_cred_r), U8::declassify(id_cred_r_tv[3]));
        assert_bytes_eq!(mac_2, mac_2_tv);
        assert_bytes_eq!(ead_2, ead_2_tv);
    }

    #[test]
    fn test_decrypt_ciphertext_2() {
        let prk_2e_tv = BytesP256ElemLen::from_hex(PRK_2E_TV);
        let g_y_tv = BytesP256ElemLen::from_hex(G_Y_TV);
        let c_r_tv = BytesCid::from_hex(C_R_TV);
        let ciphertext_2_tv = BytesCiphertext2::from_hex(CIPHERTEXT_2_TV);
        let h_message_1_tv = BytesHashLen::from_hex(H_MESSAGE_1_TV);
        let plaintext_2_tv = BytesPlaintext2::from_hex(PLAINTEXT_2_TV);

        let (plaintext_2, plaintext_2_len) = decrypt_ciphertext_2(
            &prk_2e_tv,
            &g_y_tv,
            &c_r_tv,
            &ciphertext_2_tv,
            &h_message_1_tv,
        );
        assert_bytes_eq!(plaintext_2_tv, plaintext_2);
    }

    #[test]
    fn test_compute_prk_4x3m() {
        let prk_3e2m_tv = BytesP256ElemLen::from_hex(PRK_3E2M_TV);
        let i_tv = BytesP256ElemLen::from_hex(I_TV);
        let g_y_tv = BytesP256ElemLen::from_hex(G_Y_TV);
        let prk_4x3m_tv = BytesP256ElemLen::from_hex(PRK_4X3M_TV);

        let prk_4x3m = compute_prk_4x3m(&prk_3e2m_tv, &i_tv, &g_y_tv);
        assert_bytes_eq!(prk_4x3m, prk_4x3m_tv);
    }

    #[test]
    fn test_compute_prk_3e2m() {
        let prk_2e_tv = BytesP256ElemLen::from_hex(PRK_2E_TV);
        let x_tv = BytesP256ElemLen::from_hex(X_TV);
        let g_r_tv = BytesP256ElemLen::from_hex(G_R_TV);
        let prk_3e2m_tv = BytesP256ElemLen::from_hex(PRK_3E2M_TV);

        let prk_3e2m = compute_prk_3e2m(&prk_2e_tv, &x_tv, &g_r_tv);
        assert_bytes_eq!(prk_3e2m, prk_3e2m_tv);
    }

    #[test]
    fn test_compute_prk_2e() {
        let x_tv = BytesP256ElemLen::from_hex(X_TV);
        let g_y_tv = BytesP256ElemLen::from_hex(G_Y_TV);
        let prk_2e_tv = BytesP256ElemLen::from_hex(PRK_2E_TV);

        let prk_2e = compute_prk_2e(&x_tv, &g_y_tv);
        assert_bytes_eq!(prk_2e, prk_2e_tv);
    }
}
