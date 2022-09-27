#![cfg_attr(not(feature = "native"), no_std)]

mod accelerator;
pub mod consts;

use consts::*;
pub use accelerator::Accelerator;

#[cfg(feature = "native")]
pub use accelerator::NativeAccelerator;

#[derive(Default)]
pub struct State {
    x: [u8; P256_ELEM_LEN],
    prk_2e: [u8; P256_ELEM_LEN],
    prk_3e2m: [u8; P256_ELEM_LEN],
    prk_4x3m: [u8; P256_ELEM_LEN],
    h_message_1: [u8; SHA256_DIGEST_LEN],
    th_2: [u8; SHA256_DIGEST_LEN],
    th_3: [u8; SHA256_DIGEST_LEN],
    th_4: [u8; SHA256_DIGEST_LEN],
}

pub fn edhoc_exporter<A: Accelerator>(
    acc: &mut A,
    state: &mut State,
    label: &[u8],
    context: &[u8],
    length: usize,
    output: &mut [u8],
) {
    edhoc_kdf(
        acc,
        state.prk_4x3m,
        state.th_4,
        label,
        context,
        length,
        output,
    );
}

// must hold MESSAGE_1_LEN
pub fn prepare_message_1<'a, A: Accelerator>(
    acc: &mut A, // Change to the specific crypto engine.
    state: &mut State,
    buffer: &'a mut [u8],
) -> &'a [u8] {
    // TODO generate ephemeral key
    state.x = X;
    let message_1_len = encode_message_1(EDHOC_METHOD, &EDHOC_SUPPORTED_SUITES, G_X, C_I, buffer);

    acc.sha256_digest(&buffer[0..message_1_len], &mut state.h_message_1);

    &buffer[0..message_1_len]
}

// message_3 must hold MESSAGE_3_LEN
// returns c_r
pub fn process_message_2<A: Accelerator>(acc: &mut A, state: &mut State, message_2: &[u8]) -> u8 {
    let mut g_y: [u8; P256_ELEM_LEN] = [0x00; P256_ELEM_LEN];
    let mut ciphertext_2: [u8; CIPHERTEXT_2_LEN] = [0x00; CIPHERTEXT_2_LEN];
    let mut c_r: u8 = 0x00;

    parse_message_2(message_2, &mut g_y, &mut ciphertext_2, &mut c_r);

    // compute prk_2e
    let mut plaintext_2: [u8; PLAINTEXT_2_LEN] = [0x00; PLAINTEXT_2_LEN];
    compute_prk_2e(acc, state.x, g_y, &mut state.prk_2e);
    decrypt_ciphertext_2(
        acc,
        state.prk_2e,
        g_y,
        &[c_r as i8],
        ciphertext_2,
        state.h_message_1,
        &mut plaintext_2,
    );

    // decode plaintext_2
    let mut id_cred_r: u8 = 0x00;
    let mut mac_2: [u8; MAC_LENGTH_2] = [0x00; MAC_LENGTH_2];
    let mut ead_2: [u8; 0] = [];
    decode_plaintext_2(&plaintext_2, &mut id_cred_r, &mut mac_2, &mut ead_2);

    // FIXME pass this to the application instead of verifying it here
    if id_cred_r != ID_CRED_R[2] {
        panic!("Unknown authentication peer!");
    }
    // verify mac_2
    compute_prk_3e2m(acc, state.prk_2e, state.x, G_R, &mut state.prk_3e2m);
    compute_th_2(acc, state.h_message_1, g_y, &[c_r as i8], &mut state.th_2);
    compute_and_verify_mac_2(
        acc,
        state.prk_3e2m,
        &ID_CRED_R[..],
        &CRED_R[..],
        state.th_2,
        mac_2,
    );

    // step is actually from processing of message_3
    // but we do it here to avoid storing ciphertext in State
    compute_th_3_th_4(acc, state.th_2, &ciphertext_2, &mut state.th_3);
    // message 3 processing
    compute_prk_4x3m(acc, state.prk_3e2m, I, g_y, &mut state.prk_4x3m);
    c_r
}

// message_3 must hold MESSAGE_3_LEN
pub fn prepare_message_3<'a, A: Accelerator>(
    acc: &mut A,
    state: &mut State,
    id_cred_i: &[u8],
    cred_i: &[u8],
    message_3: &'a mut [u8],
) -> &'a [u8] {
    let mut mac_3: [u8; MAC_LENGTH_3] = [0x00; MAC_LENGTH_3];
    compute_mac_3(
        acc,
        state.prk_4x3m,
        state.th_3,
        id_cred_i,
        cred_i,
        &mut mac_3,
    );

    compute_bstr_ciphertext_3(acc, state.prk_3e2m, state.th_3, id_cred_i, mac_3, message_3);

    // FIXME hack: skipping first byte of message_3 to get to ciphertext
    compute_th_3_th_4(
        acc,
        state.th_3,
        &message_3[1..MESSAGE_3_LEN],
        &mut state.th_4,
    );
    &message_3[0..MESSAGE_3_LEN]
}

fn encode_message_1(
    method: u8,
    suites: &[u8],
    g_x: [u8; P256_ELEM_LEN],
    c_i: i8,
    output: &mut [u8],
) -> usize {
    output[0] = method; // CBOR unsigned int less than 24 is encoded verbatim

    let index: usize;

    if suites.len() == 1 {
        output[1] = suites[0];
        index = 2;
    } else {
        output[1] = 0x80 | suites.len() as u8;
        output[2..(suites.len() + 2)].copy_from_slice(&suites[..(suites.len() + 2 - 2)]);
        index = suites.len() + 2;
    }
    output[index] = CBOR_BYTE_STRING; // CBOR byte string magic number
    output[index + 1] = P256_ELEM_LEN as u8; // length of the byte string
    for i in index + 2..index + 2 + P256_ELEM_LEN {
        // copy byte string
        output[i] = g_x[i - index - 2];
    }
    if c_i >= 0 {
        output[index + 2 + P256_ELEM_LEN] = c_i as u8; // CBOR uint less than 24 is encoded verbatim
    } else {
        output[index + 2 + P256_ELEM_LEN] = 0x20 | (-1 + -c_i) as u8;
    }
    (index + 3 + P256_ELEM_LEN) as usize
}

pub fn parse_message_2(
    rcvd_message_2: &[u8],
    g_y_buf: &mut [u8; P256_ELEM_LEN],
    ciphertext_2_buf: &mut [u8; CIPHERTEXT_2_LEN],
    c_r: &mut u8,
) {
    assert!(rcvd_message_2.len() == MESSAGE_2_LEN);

    // FIXME decode negative integers as well
    *c_r = rcvd_message_2[MESSAGE_2_LEN - 1];

    g_y_buf[..P256_ELEM_LEN].copy_from_slice(&rcvd_message_2[2..(P256_ELEM_LEN + 2)]);

    for i in 0..CIPHERTEXT_2_LEN {
        ciphertext_2_buf[i] = rcvd_message_2[i + 2 + P256_ELEM_LEN];
    }
}

fn compute_prk_2e<A: Accelerator>(
    acc: &mut A,
    x: [u8; P256_ELEM_LEN],
    g_y: [u8; P256_ELEM_LEN],
    prk_2e: &mut [u8; P256_ELEM_LEN],
) {
    let mut g_xy = [0x00_u8; P256_ELEM_LEN];
    // compute the shared secret
    acc.p256_ecdh(&x, &g_y, &mut g_xy);
    // compute prk_2e as PRK_2e = HMAC-SHA-256( salt, G_XY )
    acc.hkdf_extract(&[], g_xy, prk_2e);
}

fn compute_prk_3e2m<A: Accelerator>(
    acc: &mut A,
    prk_2e: [u8; P256_ELEM_LEN],
    x: [u8; P256_ELEM_LEN],
    g_r: [u8; P256_ELEM_LEN],
    prk_3e2m: &mut [u8; P256_ELEM_LEN],
) {
    // compute g_rx from static R's public key and private ephemeral key
    let mut g_rx = [0x00_u8; P256_ELEM_LEN];
    acc.p256_ecdh(&x, &g_r, &mut g_rx);
    acc.hkdf_extract(&prk_2e, g_rx, prk_3e2m);
}

fn compute_prk_4x3m<A: Accelerator>(
    acc: &mut A,
    prk_3e2m: [u8; P256_ELEM_LEN],
    i: [u8; P256_ELEM_LEN],
    g_y: [u8; P256_ELEM_LEN],
    prk_4x3m: &mut [u8; P256_ELEM_LEN],
) {
    // compute g_rx from static R's public key and private ephemeral key
    let mut g_iy = [0x00_u8; P256_ELEM_LEN];
    acc.p256_ecdh(&i, &g_y, &mut g_iy);
    acc.hkdf_extract(&prk_3e2m, g_iy, prk_4x3m);
}

fn decrypt_ciphertext_2<A: Accelerator>(
    acc: &mut A,
    prk_2e: [u8; P256_ELEM_LEN],
    g_y: [u8; P256_ELEM_LEN],
    c_r: &[i8],
    ciphertext_2: [u8; CIPHERTEXT_2_LEN],
    h_message_1: [u8; SHA256_DIGEST_LEN],
    plaintext_2: &mut [u8; PLAINTEXT_2_LEN],
) {
    let mut th_2 = [0x00_u8; SHA256_DIGEST_LEN];

    // compute the transcript hash th_2
    compute_th_2(acc, h_message_1, g_y, &c_r, &mut th_2);

    // KEYSTREAM_2 = EDHOC-KDF( PRK_2e, TH_2, "KEYSTREAM_2", h'', plaintext_length )
    let mut keystream_2: [u8; CIPHERTEXT_2_LEN] = [0x00; CIPHERTEXT_2_LEN];
    // FIXME consider using "KEYSTREAM_2".as_bytes()
    let label_keystream_2 = [
        b'K', b'E', b'Y', b'S', b'T', b'R', b'E', b'A', b'M', b'_', b'2',
    ];
    edhoc_kdf(
        acc,
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

fn decode_plaintext_2(
    plaintext_2: &[u8],
    id_cred_r: &mut u8,
    mac_2: &mut [u8; MAC_LENGTH_2],
    ead_2: &mut [u8],
) {
    *id_cred_r = plaintext_2[0];
    // skip cbor byte string byte as we know how long the string is
    mac_2[..(MAC_LENGTH_2 + 2 - 2)].copy_from_slice(&plaintext_2[2..(MAC_LENGTH_2 + 2)]);
    // zero out ead_2
    for b in &mut ead_2[..] {
        *b = 0x00;
    }
}

fn compute_and_verify_mac_2<A: Accelerator>(
    acc: &mut A,
    prk_3e2m: [u8; P256_ELEM_LEN],
    id_cred_r: &[u8],
    cred_r: &[u8],
    th_2: [u8; SHA256_DIGEST_LEN],
    rcvd_mac_2: [u8; MAC_LENGTH_2],
) -> bool {
    // compute MAC_2
    let mut mac_2: [u8; MAC_LENGTH_2] = [0x00; MAC_LENGTH_2];
    let label_mac_2 = [b'M', b'A', b'C', b'_', b'2'];
    let mut context: [u8; MAX_BUFFER_LEN] = [0x00; MAX_BUFFER_LEN];
    let mut context_len: usize = 0;

    encode_kdf_context(id_cred_r, cred_r, &mut context, &mut context_len);

    // compute mac_2
    edhoc_kdf(
        acc,
        prk_3e2m,
        th_2,
        &label_mac_2,
        &context[0..context_len],
        MAC_LENGTH_2,
        &mut mac_2,
    );

    let mut verified: bool = true;
    for i in 0..MAC_LENGTH_2 {
        if mac_2[i] != rcvd_mac_2[i] {
            verified = false;
        }
    }
    verified
}

fn compute_mac_3<A: Accelerator>(
    acc: &mut A,
    prk_4x3m: [u8; P256_ELEM_LEN],
    th_3: [u8; SHA256_DIGEST_LEN],
    id_cred_i: &[u8],
    cred_i: &[u8],
    output: &mut [u8; MAC_LENGTH_3],
) {
    const LABEL_MAC_3: [u8; 5] = [b'M', b'A', b'C', b'_', b'3'];

    // MAC_3 = EDHOC-KDF( PRK_4x3m, TH_3, "MAC_3", << ID_CRED_I, CRED_I, ? EAD_3 >>, mac_length_3 )

    let mut context: [u8; MAX_BUFFER_LEN] = [0x00; MAX_BUFFER_LEN];
    let mut context_len: usize = 0;

    encode_kdf_context(id_cred_i, cred_i, &mut context, &mut context_len);

    // compute mac_3
    edhoc_kdf(
        acc,
        prk_4x3m,
        th_3,
        &LABEL_MAC_3,
        &context[0..context_len],
        MAC_LENGTH_3,
        output,
    );
}

// calculates ciphertext_3 wrapped in a cbor byte string
// output must hold MESSAGE_3_LEN
fn compute_bstr_ciphertext_3<A: Accelerator>(
    acc: &mut A,
    prk_3e2m: [u8; P256_ELEM_LEN],
    th_3: [u8; SHA256_DIGEST_LEN],
    id_cred_i: &[u8],
    mac_3: [u8; MAC_LENGTH_3],
    output: &mut [u8],
) {
    const LABEL_K_3: [u8; 3] = [b'K', b'_', b'3'];
    const LABEL_IV_3: [u8; 4] = [b'I', b'V', b'_', b'3'];
    const ENCRYPT0: [u8; 8] = [b'E', b'n', b'c', b'r', b'y', b'p', b't', b'0'];
    const ENC_STRUCTURE_LEN: usize = ENCRYPT0.len() + 5 + SHA256_DIGEST_LEN; // dependent on the encoding below

    let mut k_3: [u8; AES_CCM_KEY_LEN] = [0x00; AES_CCM_KEY_LEN];
    let mut iv_3: [u8; AES_CCM_IV_LEN] = [0x00; AES_CCM_IV_LEN];
    let mut plaintext_3: [u8; PLAINTEXT_3_LEN] = [0x00; PLAINTEXT_3_LEN];
    let mut enc_structure: [u8; ENC_STRUCTURE_LEN] = [0x00; ENC_STRUCTURE_LEN];

    // K_3 = EDHOC-KDF( PRK_3e2m, TH_3, "K_3", h'', key_length )
    edhoc_kdf(
        acc,
        prk_3e2m,
        th_3,
        &LABEL_K_3,
        &[],
        AES_CCM_KEY_LEN,
        &mut k_3,
    );
    // IV_3 = EDHOC-KDF( PRK_3e2m, TH_3, "IV_3", h'', iv_length )
    edhoc_kdf(
        acc,
        prk_3e2m,
        th_3,
        &LABEL_IV_3,
        &[],
        AES_CCM_IV_LEN,
        &mut iv_3,
    );
    // plaintext: P = ( ? PAD, ID_CRED_I / bstr / int, Signature_or_MAC_3, ? EAD_3 )
    plaintext_3[0] = id_cred_i[id_cred_i.len() - 1]; // hack: take the last byte of ID_CRED_I as KID
    plaintext_3[1] = CBOR_MAJOR_BYTE_STRING | MAC_LENGTH_3 as u8;
    plaintext_3[2..(MAC_LENGTH_3 + 2)].copy_from_slice(&mac_3[..(MAC_LENGTH_3 + 2 - 2)]);
    // encode Enc_structure from draft-ietf-cose-rfc8152bis Section 5.3
    enc_structure[0] = CBOR_MAJOR_ARRAY | 3; // 3 is the fixed number of elements in the array
    enc_structure[1] = CBOR_MAJOR_TEXT_STRING | ENCRYPT0.len() as u8;
    enc_structure[2..(ENCRYPT0.len() + 2)].copy_from_slice(&ENCRYPT0[..(ENCRYPT0.len() + 2 - 2)]);
    enc_structure[ENCRYPT0.len() + 2] = CBOR_MAJOR_BYTE_STRING | 0x00; // 0 for zero-length byte string
    enc_structure[ENCRYPT0.len() + 3] = CBOR_BYTE_STRING; // byte string greater than 24
    enc_structure[ENCRYPT0.len() + 4] = SHA256_DIGEST_LEN as u8;
    for i in ENCRYPT0.len() + 5..ENCRYPT0.len() + 5 + SHA256_DIGEST_LEN {
        enc_structure[i] = th_3[i - ENCRYPT0.len() - 5];
    }

    output[0] = CBOR_MAJOR_BYTE_STRING | CIPHERTEXT_3_LEN as u8;
    acc.aes_ccm_encrypt(
        k_3,
        iv_3,
        AES_CCM_TAG_LEN,
        &enc_structure,
        &plaintext_3,
        &mut output[1..MESSAGE_3_LEN],
    );
}

// output must hold id_cred.len() + cred.len()
fn encode_kdf_context(id_cred: &[u8], cred: &[u8], output: &mut [u8], output_len: &mut usize) {
    // encode context in line
    // assumes ID_CRED_R and CRED_R are already CBOR-encoded
    output[..id_cred.len()].copy_from_slice(id_cred);
    for i in id_cred.len()..id_cred.len() + cred.len() {
        output[i] = cred[i - id_cred.len()];
    }

    *output_len = (id_cred.len() + cred.len()) as usize;
}

fn compute_th_2<A: Accelerator>(
    acc: &mut A,
    h_message_1: [u8; SHA256_DIGEST_LEN],
    g_y: [u8; P256_ELEM_LEN],
    c_r: &[i8],
    output: &mut [u8; SHA256_DIGEST_LEN],
) {
    let mut message = [0x00; MAX_BUFFER_LEN];
    let len;
    message[0] = CBOR_BYTE_STRING;
    message[1] = SHA256_DIGEST_LEN as u8;
    message[2..(SHA256_DIGEST_LEN + 2)]
        .copy_from_slice(&h_message_1[..(SHA256_DIGEST_LEN + 2 - 2)]);
    message[SHA256_DIGEST_LEN + 2] = CBOR_BYTE_STRING;
    message[SHA256_DIGEST_LEN + 3] = P256_ELEM_LEN as u8;
    for i in SHA256_DIGEST_LEN + 4..SHA256_DIGEST_LEN + 4 + P256_ELEM_LEN {
        message[i] = g_y[i - SHA256_DIGEST_LEN - 4];
    }
    if c_r.len() > 1 {
        message[SHA256_DIGEST_LEN + 4 + P256_ELEM_LEN] = CBOR_MAJOR_BYTE_STRING | (c_r.len() as u8);
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
            message[SHA256_DIGEST_LEN + 4 + P256_ELEM_LEN] = 0x20 | (-1 + -c_r[0]) as u8;
        }
        len = SHA256_DIGEST_LEN + 5 + P256_ELEM_LEN;
    }

    acc.sha256_digest(&message[0..len], output);
}

fn compute_th_3_th_4<A: Accelerator>(
    acc: &mut A,
    th: [u8; SHA256_DIGEST_LEN],
    ciphertext: &[u8],
    output: &mut [u8; SHA256_DIGEST_LEN],
) {
    let mut message = [0x00; MAX_BUFFER_LEN];

    message[0] = CBOR_BYTE_STRING;
    message[1] = SHA256_DIGEST_LEN as u8;
    message[2..(SHA256_DIGEST_LEN + 2)].copy_from_slice(&th[..(SHA256_DIGEST_LEN + 2 - 2)]);
    message[SHA256_DIGEST_LEN + 2] = CBOR_MAJOR_BYTE_STRING | (ciphertext.len() as u8);
    for i in SHA256_DIGEST_LEN + 3..SHA256_DIGEST_LEN + 3 + ciphertext.len() {
        message[i] = ciphertext[i - SHA256_DIGEST_LEN - 3];
    }

    acc.sha256_digest(
        &message[0..SHA256_DIGEST_LEN + 3 + ciphertext.len()],
        output,
    );
}

fn edhoc_kdf<A: Accelerator>(
    acc: &mut A,
    prk: [u8; P256_ELEM_LEN],
    transcript_hash: [u8; SHA256_DIGEST_LEN],
    label: &[u8],
    context: &[u8],
    length: usize,
    output: &mut [u8],
) {
    assert!(context.len() <= MAX_KDF_CONTEXT_LEN);
    assert!(label.len() <= MAX_KDF_LABEL_LEN);

    const MAX_INFO_LEN: usize = 2 + SHA256_DIGEST_LEN + // 32-byte digest as bstr
						 1 + MAX_KDF_LABEL_LEN +     // label <24 bytes as tstr
						 1 + MAX_KDF_CONTEXT_LEN +   // context <24 bytes as bstr
						 1; // length as u8

    let mut info = [0x00_u8; MAX_INFO_LEN];
    let mut info_len;

    // construct info with inline cbor encoding
    info[0] = CBOR_BYTE_STRING;
    info[1] = SHA256_DIGEST_LEN as u8;
    info[2..(SHA256_DIGEST_LEN + 2)]
        .copy_from_slice(&transcript_hash[..(SHA256_DIGEST_LEN + 2 - 2)]);
    info[SHA256_DIGEST_LEN + 2] = label.len() as u8 | CBOR_MAJOR_TEXT_STRING;
    for i in SHA256_DIGEST_LEN + 3..SHA256_DIGEST_LEN + 3 + label.len() {
        info[i] = label[i - SHA256_DIGEST_LEN - 3];
    }

    if context.len() < 24 {
        info[SHA256_DIGEST_LEN + 3 + label.len()] = context.len() as u8 | CBOR_MAJOR_BYTE_STRING;
        for i in
            SHA256_DIGEST_LEN + 4 + label.len()..SHA256_DIGEST_LEN + 4 + label.len() + context.len()
        {
            info[i] = context[i - SHA256_DIGEST_LEN - 4 - label.len()];
        }
        info_len = SHA256_DIGEST_LEN + 4 + label.len() + context.len();
    } else {
        info[SHA256_DIGEST_LEN + 3 + label.len()] = CBOR_BYTE_STRING;
        info[SHA256_DIGEST_LEN + 4 + label.len()] = context.len() as u8;
        for i in
            SHA256_DIGEST_LEN + 5 + label.len()..SHA256_DIGEST_LEN + 5 + label.len() + context.len()
        {
            info[i] = context[i - SHA256_DIGEST_LEN - 5 - label.len()];
        }
        info_len = SHA256_DIGEST_LEN + 5 + label.len() + context.len();
    }
    info[info_len] = length as u8;
    info_len += 1;
    acc.hkdf_expand(prk, &info[0..info_len], length, output);
}

#[cfg(all(feature = "native", test))]
mod tests {
    use super::*;
    use hexlit::hex;

    fn accelerator() -> impl Accelerator {
        crate::accelerator::NativeAccelerator::new()
    }

    // test vectors (TV)
    const METHOD_TV: u8 = 0x03;
    const SUITES_I_TV: [u8; 2] = hex!("0602");
    const X_TV: [u8; P256_ELEM_LEN] =
        hex!("368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525");
    const G_X_TV: [u8; P256_ELEM_LEN] =
        hex!("8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6");
    const C_I_TV: i8 = -24;
    const MESSAGE_1_TV: [u8; 39] =
        hex!("0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637");
    const G_Y_TV: [u8; P256_ELEM_LEN] =
        hex!("419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5");
    const G_XY_TV: [u8; P256_ELEM_LEN] =
        hex!("2f0cb7e860ba538fbf5c8bded009f6259b4b628fe1eb7dbe9378e5ecf7a824ba");
    const PRK_2E_TV: [u8; P256_ELEM_LEN] =
        hex!("fd9eef627487e40390cae922512db5a647c08dc90deb22b72ece6f156ff1c396");
    const G_R_TV: [u8; P256_ELEM_LEN] =
        hex!("bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0");
    const PRK_3E2M_TV: [u8; P256_ELEM_LEN] =
        hex!("af4b5918682adf4c96fd7305b69f8fb78efc9a230dd21f4c61be7d3c109446b3");
    const C_R_TV: [i8; 1] = [-8];
    const H_MESSAGE_1_TV: [u8; SHA256_DIGEST_LEN] =
        hex!("ca02cabda5a8902749b42f711050bb4dbd52153e87527594b39f50cdf019888c");
    const TH_2_TV: [u8; SHA256_DIGEST_LEN] =
        hex!("9b99cfd7afdcbcc9950a6373507f2a81013319625697e4f9bf7a448fc8e633ca");
    const ID_CRED_R_TV: [u8; 3] = hex!("a10432");
    const CRED_R_TV : [u8; 94] = hex!("a2026b6578616d706c652e65647508a101a5010202322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
    const MAC_2_TV: [u8; MAC_LENGTH_2] = hex!("3324d5a4afcd4326");
    const PLAINTEXT_2_TV: [u8; PLAINTEXT_2_LEN] = hex!("32483324d5a4afcd4326");
    const KEYSTREAM_2_TV: [u8; PLAINTEXT_2_LEN] = hex!("7b86c04af73b50d31b6f");
    const CIPHERTEXT_2_TV: [u8; CIPHERTEXT_2_LEN] = hex!("49cef36e229fff1e5849");
    const MESSAGE_2_TV : [u8; MESSAGE_2_LEN] = hex!("582a419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d549cef36e229fff1e584927");
    const I_TV: [u8; P256_ELEM_LEN] =
        hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
    const EAD_2_TV: [u8; 0] = hex!("");
    const CONTEXT_INFO_MAC_2: [u8; 97] = hex!("A10432A2026B6578616D706C652E65647508A101A5010202322001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");
    const TH_3_TV: [u8; SHA256_DIGEST_LEN] =
        hex!("426f8f65c17f6210392e9a16d51fe07160a25ac6fda440cfb13ec196231f3624");
    const PRK_4X3M_TV: [u8; P256_ELEM_LEN] =
        hex!("4a40f2aca7e1d9dbaf2b276bce75f0ce6d513f75a95af8905f2a14f2493b2477");
    const ID_CRED_I_TV: [u8; 3] = hex!("a1042b");
    const CRED_I_TV: [u8; 106] = hex!("a2027734322d35302d33312d46462d45462d33372d33322d333908a101a50102022b2001215820ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb62258206e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8");
    const MAC_3_TV: [u8; MAC_LENGTH_3] = hex!("4cd53d74f0a6ed8b");
    const CIPHERTEXT_3_TV: [u8; CIPHERTEXT_3_LEN] = hex!("885c63fd0b17f2c3f8f10bc8bf3f470ec8a1");
    const MESSAGE_3_TV: [u8; MESSAGE_3_LEN] = hex!("52885c63fd0b17f2c3f8f10bc8bf3f470ec8a1");
    const TH_4_TV: [u8; SHA256_DIGEST_LEN] =
        hex!("ba682e7165e9d484bd2ebb031c09da1ea5b82eb332439c4c7ec73c2c239e3450");

    #[test]
    fn test_encode_message_1() {
        let mut message_1_buf = [0xff as u8; MAX_BUFFER_LEN];
        let message_1_len =
            encode_message_1(METHOD_TV, &SUITES_I_TV, G_X_TV, C_I_TV, &mut message_1_buf);
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
        let mut acc = accelerator();
        let mut plaintext_2_buf = [0x00 as u8; PLAINTEXT_2_LEN];
        decrypt_ciphertext_2(
            &mut acc,
            PRK_2E_TV,
            G_Y_TV,
            &C_R_TV,
            CIPHERTEXT_2_TV,
            H_MESSAGE_1_TV,
            &mut plaintext_2_buf,
        );

        assert_eq!(PLAINTEXT_2_TV, plaintext_2_buf);
    }

    #[test]
    fn test_sha256_digest() {
        let mut acc = accelerator();
        let mut digest = [0x00 as u8; SHA256_DIGEST_LEN];

        acc.sha256_digest(&MESSAGE_1_TV, &mut digest);
        assert_eq!(digest, H_MESSAGE_1_TV);
    }

    #[test]
    fn test_compute_th_2() {
        let mut acc = accelerator();
        let mut th_2 = [0x00; SHA256_DIGEST_LEN];
        compute_th_2(&mut acc, H_MESSAGE_1_TV, G_Y_TV, &C_R_TV, &mut th_2);
        assert_eq!(th_2, TH_2_TV);
    }

    #[test]
    fn test_compute_th_3_th_4() {
        let mut acc = accelerator();
        let mut th_3 = [0x00; SHA256_DIGEST_LEN];
        compute_th_3_th_4(&mut acc, TH_2_TV, &CIPHERTEXT_2_TV, &mut th_3);
        assert_eq!(th_3, TH_3_TV);

        let mut th_4 = [0x00; SHA256_DIGEST_LEN];
        compute_th_3_th_4(&mut acc, TH_3_TV, &CIPHERTEXT_3_TV, &mut th_4);
        assert_eq!(th_4, TH_4_TV);
    }

    #[test]
    fn test_p256_ecdh() {
        let mut acc = accelerator();
        let mut secret = [0x00 as u8; P256_ELEM_LEN];
        acc.p256_ecdh(&X_TV, &G_Y_TV, &mut secret);
        assert!(G_XY_TV == secret);
    }

    #[test]
    fn test_edhoc_kdf() {
        let mut acc = accelerator();
        const LABEL_TV: [u8; 11] = [
            'K' as u8, 'E' as u8, 'Y' as u8, 'S' as u8, 'T' as u8, 'R' as u8, 'E' as u8, 'A' as u8,
            'M' as u8, '_' as u8, '2' as u8,
        ];
        const LEN_TV: usize = 10;

        let mut output = [0x00 as u8; 10];
        edhoc_kdf(
            &mut acc,
            PRK_2E_TV,
            TH_2_TV,
            &LABEL_TV,
            &[],
            LEN_TV,
            &mut output,
        );
        assert_eq!(KEYSTREAM_2_TV, output);

        const LABEL_MAC_2_TV: [u8; 5] = ['M' as u8, 'A' as u8, 'C' as u8, '_' as u8, '2' as u8];
        let mut output_2: [u8; MAC_LENGTH_2] = [0x00; MAC_LENGTH_2];
        edhoc_kdf(
            &mut acc,
            PRK_3E2M_TV,
            TH_2_TV,
            &LABEL_MAC_2_TV,
            &CONTEXT_INFO_MAC_2,
            MAC_LENGTH_2,
            &mut output_2,
        );
        assert_eq!(MAC_2_TV, output_2);
    }

    #[test]
    fn test_decode_plaintext_2() {
        let mut id_cred_r: u8 = 0;
        let mut mac_2: [u8; MAC_LENGTH_2] = [0x00; MAC_LENGTH_2];
        let mut ead_2: [u8; 0] = [];
        decode_plaintext_2(&PLAINTEXT_2_TV, &mut id_cred_r, &mut mac_2, &mut ead_2);
        assert_eq!(id_cred_r, ID_CRED_R_TV[2]);
        assert_eq!(mac_2, MAC_2_TV);
        assert_eq!(ead_2, EAD_2_TV);
    }

    #[test]
    fn test_compute_prk_2e() {
        let mut acc = accelerator();
        let mut prk_2e: [u8; P256_ELEM_LEN] = [0x00; P256_ELEM_LEN];
        compute_prk_2e(&mut acc, X_TV, G_Y_TV, &mut prk_2e);
        assert_eq!(prk_2e, PRK_2E_TV);
    }

    #[test]
    fn test_compute_and_verify_mac_2() {
        let mut acc = accelerator();
        assert!(compute_and_verify_mac_2(
            &mut acc,
            PRK_3E2M_TV,
            &ID_CRED_R_TV,
            &CRED_R_TV,
            TH_2_TV,
            MAC_2_TV
        ));
    }

    #[test]
    fn test_compute_mac_3() {
        let mut acc = accelerator();
        let mut mac_3: [u8; MAC_LENGTH_3] = [0x00; MAC_LENGTH_3];
        compute_mac_3(
            &mut acc,
            PRK_4X3M_TV,
            TH_3_TV,
            &ID_CRED_I_TV,
            &CRED_I_TV,
            &mut mac_3,
        );
        assert_eq!(mac_3, MAC_3_TV, "{:#?} {:#?}", mac_3, MAC_3_TV);
    }

    #[test]
    fn test_compute_prk_3e2m() {
        let mut acc = accelerator();
        let mut prk_3e2m: [u8; P256_ELEM_LEN] = [0x00; P256_ELEM_LEN];
        compute_prk_3e2m(&mut acc, PRK_2E_TV, X_TV, G_R_TV, &mut prk_3e2m);
        assert_eq!(prk_3e2m, PRK_3E2M_TV);
    }

    #[test]
    fn test_compute_prk_4x3m() {
        let mut acc = accelerator();
        let mut prk_4x3m: [u8; P256_ELEM_LEN] = [0x00; P256_ELEM_LEN];
        compute_prk_4x3m(&mut acc, PRK_3E2M_TV, I_TV, G_Y_TV, &mut prk_4x3m);
        assert_eq!(prk_4x3m, PRK_4X3M_TV);
    }
    #[test]
    fn test_compute_bstr_ciphertext_3() {
        let mut acc = accelerator();
        let mut bstr_ciphertext_3: [u8; MESSAGE_3_LEN] = [0x00; MESSAGE_3_LEN];
        compute_bstr_ciphertext_3(
            &mut acc,
            PRK_3E2M_TV,
            TH_3_TV,
            &ID_CRED_I_TV,
            MAC_3_TV,
            &mut bstr_ciphertext_3,
        );
        assert_eq!(bstr_ciphertext_3, MESSAGE_3_TV);
    }
}
