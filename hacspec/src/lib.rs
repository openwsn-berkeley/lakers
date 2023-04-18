#![no_std]

use edhoc_consts::*;
use edhoc_crypto::*;
use hacspec_lib::*;

pub fn edhoc_exporter(
    state: State,
    label: U8,
    context: &BytesMaxContextBuffer,
    context_len: usize,
    length: usize,
) -> (EDHOCError, State, BytesMaxBuffer) {
    let State(
        current_state,
        _x_or_y,
        _c_i,
        _gy_or_gx,
        _prk_3e2m,
        _prk_4e3m,
        _prk_out,
        prk_exporter,
        _h_message_1,
        _th_3,
    ) = state;

    let mut output = BytesMaxBuffer::new();
    let mut error = EDHOCError::UnknownError;

    if current_state == EDHOCState::Completed {
        output = edhoc_kdf(&prk_exporter, label, context, context_len, length);
        error = EDHOCError::Success;
    } else {
        error = EDHOCError::WrongState;
    }

    (error, state, output)
}

pub fn r_process_message_1(mut state: State, message_1: &BytesMessage1) -> (EDHOCError, State) {
    let State(
        mut current_state,
        _y,
        mut c_i,
        g_x,
        _prk_3e2m,
        _prk_4e3m,
        _prk_out,
        _prk_exporter,
        mut h_message_1,
        _th_3,
    ) = state;

    let mut error = EDHOCError::UnknownError;

    if current_state == EDHOCState::Start {
        // Step 1: decode message_1
        // g_x will be saved to the state
        let (method, supported_suites, g_x, c_i) = parse_message_1(message_1);

        // verify that the method is supported
        if method.declassify() == EDHOC_METHOD {
            // Step 2: verify that the selected cipher suite is supported
            if supported_suites[0u8].declassify() == EDHOC_SUPPORTED_SUITES[0u8].declassify() {
                // Step 3: If EAD is present make it available to the application
                // TODO we do not support EAD for now

                // hash message_1 and save the hash to the state to avoid saving the whole message
                h_message_1 = sha256_digest(
                    &BytesMaxBuffer::from_slice(message_1, 0, message_1.len()),
                    message_1.len(),
                );

                error = EDHOCError::Success;
                current_state = EDHOCState::ProcessedMessage1;

                state = construct_state(
                    current_state,
                    _y,
                    c_i,
                    g_x,
                    _prk_3e2m,
                    _prk_4e3m,
                    _prk_out,
                    _prk_exporter,
                    h_message_1,
                    _th_3,
                );
            } else {
                error = EDHOCError::UnsupportedCipherSuite;
            }
        } else {
            error = EDHOCError::UnsupportedMethod;
        }
    } else {
        error = EDHOCError::WrongState;
    }

    (error, state)
}

pub fn r_prepare_message_2(
    mut state: State,
    id_cred_r: &BytesIdCred,
    cred_r: &BytesMaxBuffer,
    cred_r_len: usize,
    r: &BytesP256ElemLen, // R's static private DH key
    y: BytesP256ElemLen,
    g_y: BytesP256ElemLen,
) -> (EDHOCError, State, BytesMessage2, U8) {
    let State(
        mut current_state,
        mut _y,
        _c_i,
        g_x,
        mut prk_3e2m,
        _prk_4e3m,
        _prk_out,
        _prk_exporter,
        h_message_1,
        mut th_3,
    ) = state;

    let mut error = EDHOCError::UnknownError;
    let mut message_2 = BytesMessage2::new();
    let mut c_r = U8(0xffu8); // invalid c_r

    if current_state == EDHOCState::ProcessedMessage1 {
        // FIXME generate a connection identifier to multiplex sessions
        c_r = C_R;

        // compute TH_2
        let th_2 = compute_th_2(&g_y, c_r, &h_message_1);

        // compute prk_3e2m
        let prk_2e = compute_prk_2e(&y, &g_x, &th_2);
        let salt_3e2m = compute_salt_3e2m(&prk_2e, &th_2);
        prk_3e2m = compute_prk_3e2m(&salt_3e2m, r, &g_x);

        // compute MAC_2
        let mac_2 = compute_mac_2(&prk_3e2m, id_cred_r, cred_r, cred_r_len, &th_2);

        // compute ciphertext_2
        let plaintext_2 = encode_plaintext_2(id_cred_r, &mac_2, &BytesEad2::new());

        // step is actually from processing of message_3
        // but we do it here to avoid storing plaintext_2 in State
        th_3 = compute_th_3(&th_2, &plaintext_2, cred_r, cred_r_len);

        let (ciphertext_2, ciphertext_2_len) = encrypt_decrypt_ciphertext_2(
            &prk_2e,
            &th_2,
            &BytesCiphertext2::from_slice(&plaintext_2, 0, plaintext_2.len()),
        );

        message_2 = encode_message_2(
            &g_y,
            &BytesCiphertext2::from_slice(&ciphertext_2, 0, ciphertext_2_len),
            c_r,
        );

        error = EDHOCError::Success;
        current_state = EDHOCState::WaitMessage3;

        state = construct_state(
            current_state,
            y,
            _c_i,
            g_x,
            prk_3e2m,
            _prk_4e3m,
            _prk_out,
            _prk_exporter,
            h_message_1,
            th_3,
        );
    } else {
        error = EDHOCError::WrongState;
    }

    (error, state, message_2, c_r)
}

// FIXME fetch ID_CRED_I and CRED_I based on kid
pub fn r_process_message_3(
    mut state: State,
    message_3: &BytesMessage3,
    id_cred_i_expected: &BytesIdCred,
    cred_i_expected: &BytesMaxBuffer,
    cred_i_len: usize,
    g_i: &BytesP256ElemLen, // I's public DH key
) -> (EDHOCError, State, BytesHashLen) {
    let State(
        mut current_state,
        y,
        _c_i,
        _g_x,
        prk_3e2m,
        mut prk_4e3m,
        mut prk_out,
        mut prk_exporter,
        _h_message_1,
        th_3,
    ) = state;

    let mut error = EDHOCError::UnknownError;

    if current_state == EDHOCState::WaitMessage3 {
        let (err, plaintext_3) = decrypt_message_3(&prk_3e2m, &th_3, message_3);

        if err == EDHOCError::Success {
            let (kid, mac_3) = decode_plaintext_3(&plaintext_3);

            // compare the kid received with the kid expected in id_cred_i
            if kid.declassify() == id_cred_i_expected[id_cred_i_expected.len() - 1].declassify() {
                // compute salt_4e3m
                let salt_4e3m = compute_salt_4e3m(&prk_3e2m, &th_3);
                // TODO compute prk_4e3m
                prk_4e3m = compute_prk_4e3m(&salt_4e3m, &y, g_i);

                // compute mac_3
                let expected_mac_3 = compute_mac_3(
                    &prk_4e3m,
                    &th_3,
                    id_cred_i_expected,
                    cred_i_expected,
                    cred_i_len,
                );

                // verify mac_3
                if mac_3.declassify_eq(&expected_mac_3) {
                    error = EDHOCError::Success;
                    let th_4 = compute_th_4(&th_3, &plaintext_3, cred_i_expected, cred_i_len);

                    // compute prk_out
                    // PRK_out = EDHOC-KDF( PRK_4e3m, 7, TH_4, hash_length )
                    let prk_out_buf = edhoc_kdf(
                        &prk_4e3m,
                        U8(7 as u8),
                        &BytesMaxContextBuffer::from_slice(&th_4, 0, th_4.len()),
                        th_4.len(),
                        SHA256_DIGEST_LEN,
                    );
                    prk_out = prk_out.update_slice(0, &prk_out_buf, 0, SHA256_DIGEST_LEN);

                    // compute prk_exporter from prk_out
                    // PRK_exporter  = EDHOC-KDF( PRK_out, 10, h'', hash_length )
                    let prk_exporter_buf = edhoc_kdf(
                        &prk_out,
                        U8(10 as u8),
                        &BytesMaxContextBuffer::new(),
                        0,
                        SHA256_DIGEST_LEN,
                    );
                    prk_exporter =
                        prk_exporter.update_slice(0, &prk_exporter_buf, 0, SHA256_DIGEST_LEN);

                    error = EDHOCError::Success;
                    current_state = EDHOCState::Completed;

                    state = construct_state(
                        current_state,
                        y,
                        _c_i,
                        _g_x,
                        prk_3e2m,
                        prk_4e3m,
                        prk_out,
                        prk_exporter,
                        _h_message_1,
                        th_3,
                    );
                } else {
                    error = EDHOCError::MacVerificationFailed;
                }
            } else {
                error = EDHOCError::UnknownPeer;
            }
        } else {
            // error handling for err = decrypt_message_3(&prk_3e2m, &th_3, message_3);
            error = err;
        }
    } else {
        error = EDHOCError::WrongState;
    }

    (error, state, prk_out)
}

// must hold MESSAGE_1_LEN
pub fn i_prepare_message_1(
    mut state: State,
    x: BytesP256ElemLen,
    g_x: BytesP256ElemLen,
) -> (EDHOCError, State, BytesMessage1) {
    let State(
        mut current_state,
        mut _x,
        mut c_i,
        _g_y,
        _prk_3e2m,
        _prk_4e3m,
        _prk_out,
        _prk_exporter,
        mut h_message_1,
        _th_3,
    ) = state;

    let mut error = EDHOCError::UnknownError;

    let mut message_1 = BytesMessage1::new();

    if current_state == EDHOCState::Start {
        // we only support a single cipher suite which is already CBOR-encoded
        let selected_suites = EDHOC_SUPPORTED_SUITES;

        // Choose a connection identifier C_I and store it for the length of the protocol.
        c_i = C_I;

        // Encode message_1 as a sequence of CBOR encoded data items as specified in Section 5.2.1
        message_1 = encode_message_1(U8(EDHOC_METHOD), &selected_suites, &g_x, c_i);

        // hash message_1 here to avoid saving the whole message in the state
        h_message_1 = sha256_digest(
            &BytesMaxBuffer::from_slice(&message_1, 0, message_1.len()),
            message_1.len(),
        );
        error = EDHOCError::Success;
        current_state = EDHOCState::WaitMessage2;

        state = construct_state(
            current_state,
            x,
            c_i,
            _g_y,
            _prk_3e2m,
            _prk_4e3m,
            _prk_out,
            _prk_exporter,
            h_message_1,
            _th_3,
        );
    } else {
        error = EDHOCError::WrongState;
    }

    (error, state, message_1)
}

// message_3 must hold MESSAGE_3_LEN
// returns c_r
pub fn i_process_message_2(
    mut state: State,
    message_2: &BytesMessage2,
    id_cred_r_expected: &BytesIdCred,
    cred_r_expected: &BytesMaxBuffer,
    cred_r_len: usize,
    g_r: &BytesP256ElemLen, // R's static public DH key
    i: &BytesP256ElemLen,   // I's static private DH key
) -> (EDHOCError, State, U8, U8) {
    let State(
        mut current_state,
        x,
        _c_i,
        g_y,
        mut prk_3e2m,
        mut prk_4e3m,
        _prk_out,
        _prk_exporter,
        h_message_1,
        mut th_3,
    ) = state;

    // init error
    let mut error = EDHOCError::UnknownError;
    let mut c_r = U8(0xffu8); // invalidate c_r
    let mut kid = U8(0xffu8); // invalidate kid

    if current_state == EDHOCState::WaitMessage2 {
        let (g_y, ciphertext_2, c_r_2) = parse_message_2(message_2);
        c_r = c_r_2;

        let th_2 = compute_th_2(&g_y, c_r, &h_message_1);

        // compute prk_2e
        let prk_2e = compute_prk_2e(&x, &g_y, &th_2);

        let (plaintext_2, plaintext_2_len) =
            encrypt_decrypt_ciphertext_2(&prk_2e, &th_2, &ciphertext_2);

        // decode plaintext_2
        let (kid, mac_2, _ead_2) = decode_plaintext_2(&plaintext_2, plaintext_2_len);

        if kid.declassify() == id_cred_r_expected[id_cred_r_expected.len() - 1].declassify() {
            // verify mac_2
            let salt_3e2m = compute_salt_3e2m(&prk_2e, &th_2);

            prk_3e2m = compute_prk_3e2m(&salt_3e2m, &x, g_r);

            let expected_mac_2 = compute_mac_2(
                &prk_3e2m,
                id_cred_r_expected,
                cred_r_expected,
                cred_r_len,
                &th_2,
            );

            if mac_2.declassify_eq(&expected_mac_2) {
                // step is actually from processing of message_3
                // but we do it here to avoid storing plaintext_2 in State
                th_3 = compute_th_3(
                    &th_2,
                    &BytesPlaintext2::from_slice(&plaintext_2, 0, plaintext_2_len),
                    cred_r_expected,
                    cred_r_len,
                );
                // message 3 processing

                let salt_4e3m = compute_salt_4e3m(&prk_3e2m, &th_3);

                prk_4e3m = compute_prk_4e3m(&salt_4e3m, i, &g_y);

                error = EDHOCError::Success;
                current_state = EDHOCState::ProcessedMessage2;

                state = construct_state(
                    current_state,
                    x,
                    _c_i,
                    g_y,
                    prk_3e2m,
                    prk_4e3m,
                    _prk_out,
                    _prk_exporter,
                    h_message_1,
                    th_3,
                );
            } else {
                error = EDHOCError::MacVerificationFailed;
            }
        } else {
            // Unknown peer
            error = EDHOCError::UnknownPeer;
        }
    } else {
        error = EDHOCError::WrongState;
    }

    (error, state, c_r, kid)
}

// message_3 must hold MESSAGE_3_LEN
pub fn i_prepare_message_3(
    mut state: State,
    id_cred_i: &BytesIdCred,
    cred_i: &BytesMaxBuffer,
    cred_i_len: usize,
) -> (EDHOCError, State, BytesMessage3, BytesHashLen) {
    let State(
        mut current_state,
        _x,
        _c_i,
        _g_y,
        prk_3e2m,
        prk_4e3m,
        mut prk_out,
        mut prk_exporter,
        _h_message_1,
        th_3,
    ) = state;

    let mut error = EDHOCError::UnknownError;
    let mut message_3 = BytesMessage3::new();

    if current_state == EDHOCState::ProcessedMessage2 {
        let mac_3 = compute_mac_3(&prk_4e3m, &th_3, id_cred_i, cred_i, cred_i_len);
        let plaintext_3 = encode_plaintext_3(id_cred_i, &mac_3);
        message_3 = encrypt_message_3(&prk_3e2m, &th_3, &plaintext_3);

        let th_4 = compute_th_4(&th_3, &plaintext_3, cred_i, cred_i_len);

        // compute prk_out
        // PRK_out = EDHOC-KDF( PRK_4e3m, 7, TH_4, hash_length )
        let prk_out_buf = edhoc_kdf(
            &prk_4e3m,
            U8(7 as u8),
            &BytesMaxContextBuffer::from_slice(&th_4, 0, th_4.len()),
            th_4.len(),
            SHA256_DIGEST_LEN,
        );
        prk_out = prk_out.update_slice(0, &prk_out_buf, 0, SHA256_DIGEST_LEN);

        // compute prk_exporter from prk_out
        // PRK_exporter  = EDHOC-KDF( PRK_out, 10, h'', hash_length )
        let prk_exporter_buf = edhoc_kdf(
            &prk_out,
            U8(10 as u8),
            &BytesMaxContextBuffer::new(),
            0,
            SHA256_DIGEST_LEN,
        );
        prk_exporter = prk_exporter.update_slice(0, &prk_exporter_buf, 0, SHA256_DIGEST_LEN);
        error = EDHOCError::Success;
        current_state = EDHOCState::Completed;

        state = construct_state(
            current_state,
            _x,
            _c_i,
            _g_y,
            prk_3e2m,
            prk_4e3m,
            prk_out,
            prk_exporter,
            _h_message_1,
            th_3,
        );
    } else {
        error = EDHOCError::WrongState;
    }

    (error, state, message_3, prk_out)
}

pub fn construct_state(
    state: EDHOCState,
    x_or_y: BytesP256ElemLen,
    c_i: U8,
    gx_or_gy: BytesP256ElemLen,
    prk_3e2m: BytesHashLen,
    prk_4e3m: BytesHashLen,
    prk_out: BytesHashLen,
    prk_exporter: BytesHashLen,
    h_message_1: BytesHashLen,
    th_3: BytesHashLen,
) -> State {
    State(
        state,
        x_or_y,
        c_i,
        gx_or_gy,
        prk_3e2m,
        prk_4e3m,
        prk_out,
        prk_exporter,
        h_message_1,
        th_3,
    )
}

fn parse_message_1(
    rcvd_message_1: &BytesMessage1,
) -> (U8, BytesSupportedSuites, BytesP256ElemLen, U8) {
    let method = rcvd_message_1[0];
    // FIXME as we only support a fixed-sized incoming message_1,
    // we parse directly the selected cipher suite
    let selected_suite = BytesSupportedSuites::from_slice(rcvd_message_1, 1, 1);
    let g_x = BytesP256ElemLen::from_slice(rcvd_message_1, 4, P256_ELEM_LEN);
    let c_i = rcvd_message_1[MESSAGE_1_LEN - 1];

    (method, selected_suite, g_x, c_i)
}

fn encode_message_1(
    method: U8,
    suites: &BytesSupportedSuites,
    g_x: &BytesP256ElemLen,
    c_i: U8,
) -> BytesMessage1 {
    let mut output = BytesMessage1::new();

    output[0] = method; // CBOR unsigned int less than 24 is encoded verbatim
    output[1] = suites[0];
    output[2] = U8(CBOR_BYTE_STRING); // CBOR byte string magic number
    output[3] = U8(P256_ELEM_LEN as u8); // length of the byte string
    output = output.update(4, g_x);
    output[4 + P256_ELEM_LEN] = c_i;

    output
}

fn parse_message_2(rcvd_message_2: &BytesMessage2) -> (BytesP256ElemLen, BytesCiphertext2, U8) {
    // FIXME decode negative integers as well
    let g_y = BytesP256ElemLen::from_slice(rcvd_message_2, 2, P256_ELEM_LEN);
    let ciphertext_2 =
        BytesCiphertext2::from_slice(rcvd_message_2, 2 + P256_ELEM_LEN, CIPHERTEXT_2_LEN);
    let c_r = rcvd_message_2[MESSAGE_2_LEN - 1];

    (g_y, ciphertext_2, c_r)
}

fn encode_message_2(
    g_y: &BytesP256ElemLen,
    ciphertext_2: &BytesCiphertext2,
    c_r: U8,
) -> BytesMessage2 {
    let mut output = BytesMessage2::new();

    output[0] = U8(CBOR_BYTE_STRING);
    output[1] = U8(P256_ELEM_LEN as u8 + CIPHERTEXT_2_LEN as u8);
    output = output.update(2, g_y);
    output = output.update(2 + P256_ELEM_LEN, ciphertext_2);
    output[2 + P256_ELEM_LEN + CIPHERTEXT_2_LEN] = c_r;

    output
}

fn compute_th_2(g_y: &BytesP256ElemLen, c_r: U8, h_message_1: &BytesHashLen) -> BytesHashLen {
    let mut message = BytesMaxBuffer::new();
    message[0] = U8(CBOR_BYTE_STRING);
    message[1] = U8(P256_ELEM_LEN as u8);
    message = message.update(2, g_y);
    message[2 + P256_ELEM_LEN] = c_r;
    message[3 + P256_ELEM_LEN] = U8(CBOR_BYTE_STRING);
    message[4 + P256_ELEM_LEN] = U8(SHA256_DIGEST_LEN as u8);
    message = message.update(5 + P256_ELEM_LEN, h_message_1);

    let len = 5 + P256_ELEM_LEN + SHA256_DIGEST_LEN;

    let th_2 = sha256_digest(&message, len);

    th_2
}

fn compute_th_3(
    th_2: &BytesHashLen,
    plaintext_2: &BytesPlaintext2,
    cred_r: &BytesMaxBuffer,
    cred_r_len: usize,
) -> BytesHashLen {
    let mut message = BytesMaxBuffer::new();

    message[0] = U8(CBOR_BYTE_STRING);
    message[1] = U8(th_2.len() as u8);
    message = message.update(2, th_2);
    message = message.update(2 + th_2.len(), plaintext_2);
    message = message.update_slice(2 + th_2.len() + plaintext_2.len(), cred_r, 0, cred_r_len);

    let output = sha256_digest(&message, th_2.len() + 2 + plaintext_2.len() + cred_r_len);

    output
}

fn compute_th_4(
    th_3: &BytesHashLen,
    plaintext_3: &BytesPlaintext3,
    cred_i: &BytesMaxBuffer,
    cred_i_len: usize,
) -> BytesHashLen {
    let mut message = BytesMaxBuffer::new();

    message[0] = U8(CBOR_BYTE_STRING);
    message[1] = U8(th_3.len() as u8);
    message = message.update(2, th_3);
    message = message.update(2 + th_3.len(), plaintext_3);
    message = message.update_slice(2 + th_3.len() + plaintext_3.len(), cred_i, 0, cred_i_len);

    let output = sha256_digest(&message, th_3.len() + 2 + plaintext_3.len() + cred_i_len);

    output
}

fn edhoc_kdf(
    prk: &BytesHashLen,
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
    if length < 24 {
        info[info_len] = U8(length as u8);
        info_len = info_len + 1;
    } else {
        info[info_len] = U8(CBOR_UINT_1BYTE);
        info[info_len + 1] = U8(length as u8);
        info_len = info_len + 2;
    }

    let output = hkdf_expand(prk, &info, info_len, length);

    output
}

fn decode_plaintext_3(plaintext_3: &BytesPlaintext3) -> (U8, BytesMac3) {
    let kid = plaintext_3[0usize];
    // skip the CBOR magic byte as we know how long the MAC is
    let mac_3 = BytesMac3::from_slice(plaintext_3, 2, MAC_LENGTH_3);

    (kid, mac_3)
}

fn encode_plaintext_3(id_cred_i: &BytesIdCred, mac_3: &BytesMac3) -> BytesPlaintext3 {
    let mut plaintext_3 = BytesPlaintext3::new();

    // plaintext: P = ( ? PAD, ID_CRED_I / bstr / int, Signature_or_MAC_3, ? EAD_3 )
    plaintext_3[0] = id_cred_i[id_cred_i.len() - 1]; // hack: take the last byte of ID_CRED_I as KID
    plaintext_3[1] = U8(CBOR_MAJOR_BYTE_STRING | MAC_LENGTH_3 as u8);
    plaintext_3 = plaintext_3.update(2, mac_3);

    plaintext_3
}

fn encode_enc_structure(th_3: &BytesHashLen) -> BytesEncStructureLen {
    let mut encrypt0 = Bytes8::new();
    encrypt0[0] = U8(0x45u8); // 'E'
    encrypt0[1] = U8(0x6eu8); // 'n'
    encrypt0[2] = U8(0x63u8); // 'c'
    encrypt0[3] = U8(0x72u8); // 'r'
    encrypt0[4] = U8(0x79u8); // 'y'
    encrypt0[5] = U8(0x70u8); // 'p'
    encrypt0[6] = U8(0x74u8); // 't'
    encrypt0[7] = U8(0x30u8); // '0'

    let mut enc_structure = BytesEncStructureLen::new();

    // encode Enc_structure from draft-ietf-cose-rfc8152bis Section 5.3
    enc_structure[0] = U8(CBOR_MAJOR_ARRAY | 3 as u8); // 3 is the fixed number of elements in the array
    enc_structure[1] = U8(CBOR_MAJOR_TEXT_STRING | encrypt0.len() as u8);
    enc_structure = enc_structure.update(2, &encrypt0);
    enc_structure[encrypt0.len() + 2] = U8(CBOR_MAJOR_BYTE_STRING | 0x00 as u8); // 0 for zero-length byte string
    enc_structure[encrypt0.len() + 3] = U8(CBOR_BYTE_STRING); // byte string greater than 24
    enc_structure[encrypt0.len() + 4] = U8(SHA256_DIGEST_LEN as u8);
    enc_structure = enc_structure.update(encrypt0.len() + 5, th_3);

    enc_structure
}

fn compute_k_3_iv_3(
    prk_3e2m: &BytesHashLen,
    th_3: &BytesHashLen,
) -> (BytesCcmKeyLen, BytesCcmIvLen) {
    // K_3 = EDHOC-KDF( PRK_3e2m, 3, TH_3,      key_length )
    let k_3 = BytesCcmKeyLen::from_slice(
        &edhoc_kdf(
            prk_3e2m,
            U8(3 as u8),
            &BytesMaxContextBuffer::from_slice(th_3, 0, th_3.len()),
            th_3.len(),
            AES_CCM_KEY_LEN,
        ),
        0,
        AES_CCM_KEY_LEN,
    );
    // IV_3 = EDHOC-KDF( PRK_3e2m, 4, TH_3,      iv_length )
    let iv_3 = BytesCcmIvLen::from_slice(
        &edhoc_kdf(
            prk_3e2m,
            U8(4 as u8),
            &BytesMaxContextBuffer::from_slice(th_3, 0, th_3.len()),
            th_3.len(),
            AES_CCM_IV_LEN,
        ),
        0,
        AES_CCM_IV_LEN,
    );

    (k_3, iv_3)
}

// calculates ciphertext_3 wrapped in a cbor byte string
// output must hold MESSAGE_3_LEN
fn encrypt_message_3(
    prk_3e2m: &BytesHashLen,
    th_3: &BytesHashLen,
    plaintext_3: &BytesPlaintext3,
) -> BytesMessage3 {
    let mut output = BytesMessage3::new();
    output[0] = U8(CBOR_MAJOR_BYTE_STRING | CIPHERTEXT_3_LEN as u8);

    let enc_structure = encode_enc_structure(th_3);

    let (k_3, iv_3) = compute_k_3_iv_3(prk_3e2m, th_3);

    output = output.update(
        1,
        &aes_ccm_encrypt_tag_8(&k_3, &iv_3, &enc_structure, plaintext_3),
    );

    output
}

fn decrypt_message_3(
    prk_3e2m: &BytesHashLen,
    th_3: &BytesHashLen,
    message_3: &BytesMessage3,
) -> (EDHOCError, BytesPlaintext3) {
    let mut error = EDHOCError::UnknownError;
    let mut plaintext_3 = BytesPlaintext3::new();

    // decode message_3
    let len = message_3[0usize] ^ U8(CBOR_MAJOR_BYTE_STRING);

    // compare parsed length with the expected length of the ciphertext
    if len.declassify() as usize == CIPHERTEXT_3_LEN {
        let ciphertext_3 = BytesCiphertext3::from_slice(message_3, 1, CIPHERTEXT_3_LEN);

        let (k_3, iv_3) = compute_k_3_iv_3(prk_3e2m, th_3);

        let enc_structure = encode_enc_structure(th_3);

        let (err, p3) = aes_ccm_decrypt_tag_8(&k_3, &iv_3, &enc_structure, &ciphertext_3);
        error = err;
        plaintext_3 = plaintext_3.update(0, &p3);
    } else {
        error = EDHOCError::ParsingError;
    }
    (error, plaintext_3)
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
    prk_4e3m: &BytesHashLen,
    th_3: &BytesHashLen,
    id_cred_i: &BytesIdCred,
    cred_i: &BytesMaxBuffer,
    cred_i_len: usize,
) -> BytesMac3 {
    // MAC_3 = EDHOC-KDF( PRK_4e3m, 6, context_3, mac_length_3 )
    let (context, context_len) = encode_kdf_context(id_cred_i, th_3, cred_i, cred_i_len);

    // compute mac_3
    let output_buf = edhoc_kdf(
        prk_4e3m,
        U8(6 as u8), // registered label for "MAC_3"
        &context,
        context_len,
        MAC_LENGTH_3,
    );

    let output = BytesMac3::from_slice(&output_buf, 0, MAC_LENGTH_3);
    output
}

fn compute_mac_2(
    prk_3e2m: &BytesHashLen,
    id_cred_r: &BytesIdCred,
    cred_r: &BytesMaxBuffer,
    cred_r_len: usize,
    th_2: &BytesHashLen,
) -> BytesMac2 {
    // compute MAC_2
    let (context, context_len) = encode_kdf_context(id_cred_r, th_2, cred_r, cred_r_len);

    // MAC_2 = EDHOC-KDF( PRK_3e2m, 2, context_2, mac_length_2 )
    let mac_2 = BytesMac2::from_slice(
        &edhoc_kdf(prk_3e2m, U8(2 as u8), &context, context_len, MAC_LENGTH_2),
        0,
        MAC_LENGTH_2,
    );

    mac_2
}

fn decode_plaintext_2(
    plaintext_2: &BytesMaxBuffer,
    _plaintext_2_len: usize,
) -> (U8, BytesMac2, BytesEad2) {
    let id_cred_r = plaintext_2[0];
    // skip cbor byte string byte as we know how long the string is
    let mac_2 = BytesMac2::from_slice(plaintext_2, 2, MAC_LENGTH_2);
    // FIXME we don't support ead_2 parsing for now
    let ead_2 = BytesEad2::new();

    (id_cred_r, mac_2, ead_2)
}

fn encode_plaintext_2(
    id_cred_r: &BytesIdCred,
    mac_2: &BytesMac2,
    ead_2: &BytesEad2,
) -> BytesPlaintext2 {
    let mut plaintext_2 = BytesPlaintext2::new();
    plaintext_2[0] = id_cred_r[id_cred_r.len() - 1];
    plaintext_2[1] = U8(CBOR_MAJOR_BYTE_STRING | MAC_LENGTH_2 as u8);
    plaintext_2 = plaintext_2.update(2, mac_2);
    plaintext_2 = plaintext_2.update(2 + mac_2.len(), ead_2);

    plaintext_2
}

fn encrypt_decrypt_ciphertext_2(
    prk_2e: &BytesHashLen,
    th_2: &BytesHashLen,
    ciphertext_2: &BytesCiphertext2,
) -> (BytesMaxBuffer, usize) {
    // convert the transcript hash th_2 to BytesMaxContextBuffer type
    let th_2_context = BytesMaxContextBuffer::from_slice(th_2, 0, th_2.len());

    // KEYSTREAM_2 = EDHOC-KDF( PRK_2e,   0, TH_2,      plaintext_length )
    let keystream_2 = edhoc_kdf(
        prk_2e,
        U8(0 as u8),
        &th_2_context,
        SHA256_DIGEST_LEN,
        CIPHERTEXT_2_LEN,
    );

    let mut plaintext_2 = BytesMaxBuffer::new();
    // decrypt/encrypt ciphertext_2
    for i in 0..CIPHERTEXT_2_LEN {
        plaintext_2[i] = ciphertext_2[i] ^ keystream_2[i];
    }

    (plaintext_2, CIPHERTEXT_2_LEN)
}

fn compute_salt_4e3m(prk_3e2m: &BytesHashLen, th_3: &BytesHashLen) -> BytesHashLen {
    let th_3_context = BytesMaxContextBuffer::from_slice(th_3, 0, th_3.len());
    let salt_4e3m_buf = edhoc_kdf(
        prk_3e2m,
        U8(5 as u8),
        &th_3_context,
        th_3.len(),
        SHA256_DIGEST_LEN,
    );
    let mut salt_4e3m = BytesHashLen::new();
    salt_4e3m = salt_4e3m.update_slice(0, &salt_4e3m_buf, 0, SHA256_DIGEST_LEN);

    salt_4e3m
}

fn compute_prk_4e3m(
    salt_4e3m: &BytesHashLen,
    i: &BytesP256ElemLen,
    g_y: &BytesP256ElemLen,
) -> BytesHashLen {
    // compute g_rx from static R's public key and private ephemeral key
    let g_iy = p256_ecdh(i, g_y);
    let prk_4e3m = hkdf_extract(salt_4e3m, &g_iy);

    prk_4e3m
}

fn compute_salt_3e2m(prk_2e: &BytesHashLen, th_2: &BytesHashLen) -> BytesHashLen {
    let th_2_context = BytesMaxContextBuffer::from_slice(th_2, 0, th_2.len());

    let salt_3e2m_buf = edhoc_kdf(
        prk_2e,
        U8(1 as u8),
        &th_2_context,
        SHA256_DIGEST_LEN,
        SHA256_DIGEST_LEN,
    );

    let mut salt_3e2m = BytesHashLen::new();
    salt_3e2m = salt_3e2m.update_slice(0, &salt_3e2m_buf, 0, SHA256_DIGEST_LEN);

    salt_3e2m
}

fn compute_prk_3e2m(
    salt_3e2m: &BytesHashLen,
    x: &BytesP256ElemLen,
    g_r: &BytesP256ElemLen,
) -> BytesHashLen {
    // compute g_rx from static R's public key and private ephemeral key
    let g_rx = p256_ecdh(x, g_r);
    let prk_3e2m = hkdf_extract(salt_3e2m, &g_rx);

    prk_3e2m
}

fn compute_prk_2e(
    x: &BytesP256ElemLen,
    g_y: &BytesP256ElemLen,
    th_2: &BytesHashLen,
) -> BytesHashLen {
    // compute the shared secret
    let g_xy = p256_ecdh(x, g_y);
    // compute prk_2e as PRK_2e = HMAC-SHA-256( salt, G_XY )
    let prk_2e = hkdf_extract(th_2, &g_xy);

    prk_2e
}

#[cfg(test)]
mod tests {
    use super::*;
    // test vectors (TV)

    const METHOD_TV: u8 = 0x03;
    // manually modified test vector to include a single supported cipher suite
    const SUITES_I_TV: &str = "02";
    const G_X_TV: &str = "8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6";
    const C_I_TV: u8 = 0x37;
    // manually modified test vector to include a single supported cipher suite
    const MESSAGE_1_TV: &str =
        "030258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637";
    const G_Y_TV: &str = "419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5";
    const C_R_TV: u8 = 0x27;
    const MESSAGE_2_TV: &str =
    "582a419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5042459e2da6c75143f3527";
    const CIPHERTEXT_2_TV: &str = "042459e2da6c75143f35";
    const H_MESSAGE_1_TV: &str = "ca02cabda5a8902749b42f711050bb4dbd52153e87527594b39f50cdf019888c";
    const TH_2_TV: &str = "9d2af3a3d3fc06aea8110f14ba12ad0b4fb7e5cdf59c7df1cf2dfe9c2024439c";
    const TH_3_TV: &str = "b778f602331ff68ac402a6511b9de285bedf6eab3e9ed12dfe22a53eeda7de48";
    const CIPHERTEXT_3_TV: &str = "c2b62835dc9b1f53419c1d3a2261eeed3505";
    const TH_4_TV: &str = "1f57dabf8f26da0657d9840c9b1077c1d4c47db243a8b41360a98ec4cb706b70";
    const PRK_2E_TV: &str = "e01fa14dd56e308267a1a812a9d0b95341e394abc7c5c39dd71885f7d4cd5bf3";
    const KEYSTREAM_2_TV: &str = "366c89337ff80c69359a";
    const PRK_3E2M_TV: &str = "412d60cdf99dc7490754c969ad4c46b1350b908433ebf3fe063be8627fb35b3b";
    const CONTEXT_INFO_MAC_2_TV: &str = "a104413258209d2af3a3d3fc06aea8110f14ba12ad0b4fb7e5cdf59c7df1cf2dfe9c2024439ca2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072";
    const MAC_2_TV: &str = "d0d1a594797d0aaf";
    const ID_CRED_I_TV: &str = "a104412b";
    const MAC_3_TV: &str = "ddf106b86fd22fe4";
    const MESSAGE_3_TV: &str = "52c2b62835dc9b1f53419c1d3a2261eeed3505";
    const PRK_4E3M_TV: &str = "7d0159bbe45473c9402e0d42dbceb45dca05b744cae1e083e58315b8aa47ceec";
    const CRED_I_TV : &str = "A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8";
    const ID_CRED_R_TV: &str = "a1044132";
    const CRED_R_TV : &str = "A2026B6578616D706C652E65647508A101A501020241322001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072";
    const PLAINTEXT_2_TV: &str = "3248d0d1a594797d0aaf";
    const I_TV: &str = "fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b";
    const X_TV: &str = "368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525";
    const G_R_TV: &str = "bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0";
    const PLAINTEXT_3_TV: &str = "2b48ddf106b86fd22fe4";
    const SALT_3E2M_TV: &str = "a4f767b3469a6e6ae5fcbf273839fa87c41f462b03ad1ca7ce8f37c95366d8d1";
    const SALT_4E3M_TV: &str = "8c60d4357fba5f694a81482c4d38a1000bc3e3e2a29406d18153ffc3595c17ba";
    const G_XY_TV: &str = "2f0cb7e860ba538fbf5c8bded009f6259b4b628fe1eb7dbe9378e5ecf7a824ba";

    #[test]
    fn test_ecdh() {
        let x_tv = BytesP256ElemLen::from_hex(X_TV);
        let g_y_tv = BytesP256ElemLen::from_hex(G_Y_TV);
        let g_xy_tv = BytesP256ElemLen::from_hex(G_XY_TV);

        let g_xy = p256_ecdh(&x_tv, &g_y_tv);

        assert_bytes_eq!(g_xy, g_xy_tv);
    }

    #[test]
    fn test_encode_message_1() {
        let method_tv = U8(METHOD_TV);
        let suites_i_tv = BytesSupportedSuites::from_hex(SUITES_I_TV);
        let g_x_tv = BytesP256ElemLen::from_hex(G_X_TV);
        let c_i_tv = U8(C_I_TV);
        let message_1_tv = BytesMessage1::from_hex(MESSAGE_1_TV);

        let message_1 = encode_message_1(method_tv, &suites_i_tv, &g_x_tv, c_i_tv);

        assert_bytes_eq!(message_1, message_1_tv);
    }

    #[test]
    fn test_parse_message_1() {
        let message_1_tv = BytesMessage1::from_hex(MESSAGE_1_TV);
        let method_tv = METHOD_TV;
        let supported_suites_tv = BytesSupportedSuites::from_hex(SUITES_I_TV);
        let g_x_tv = BytesP256ElemLen::from_hex(G_X_TV);
        let c_i_tv = U8(C_I_TV);

        let (method, supported_suites, g_x, c_i) = parse_message_1(&message_1_tv);

        assert_eq!(method.declassify(), method_tv);
        assert_bytes_eq!(supported_suites, supported_suites_tv);
        assert_bytes_eq!(g_x, g_x_tv);
        assert_eq!(c_i.declassify(), c_i_tv.declassify());
    }

    #[test]
    fn test_encode_message_2() {
        let message_2_tv = BytesMessage2::from_hex(MESSAGE_2_TV);
        let g_y_tv = BytesP256ElemLen::from_hex(G_Y_TV);
        let ciphertext_2_tv = BytesCiphertext2::from_hex(CIPHERTEXT_2_TV);
        let c_r_tv = U8(C_R_TV);

        let message_2 = encode_message_2(&g_y_tv, &ciphertext_2_tv, c_r_tv);

        assert_bytes_eq!(message_2, message_2_tv);
    }

    #[test]
    fn test_parse_message_2() {
        let message_2_tv = BytesMessage2::from_hex(MESSAGE_2_TV);
        let g_y_tv = BytesP256ElemLen::from_hex(G_Y_TV);
        let ciphertext_2_tv = BytesCiphertext2::from_hex(CIPHERTEXT_2_TV);
        let c_r_tv = U8(C_R_TV);

        let (g_y, ciphertext_2, c_r) = parse_message_2(&message_2_tv);

        assert_bytes_eq!(g_y, g_y_tv);
        assert_bytes_eq!(ciphertext_2, ciphertext_2_tv);
        assert_eq!(c_r.declassify(), c_r_tv.declassify());
    }

    #[test]
    fn test_compute_th_2() {
        let h_message_1_tv = BytesHashLen::from_hex(H_MESSAGE_1_TV);
        let g_y_tv = BytesP256ElemLen::from_hex(G_Y_TV);
        let c_r_tv = U8(C_R_TV);
        let th_2_tv = BytesHashLen::from_hex(TH_2_TV);

        let th_2 = compute_th_2(&g_y_tv, c_r_tv, &h_message_1_tv);
        assert_bytes_eq!(th_2, th_2_tv);
    }

    #[test]
    fn test_compute_th_3() {
        let th_2_tv = BytesHashLen::from_hex(TH_2_TV);
        let th_3_tv = BytesHashLen::from_hex(TH_3_TV);
        let plaintext_2_tv = BytesPlaintext2::from_hex(PLAINTEXT_2_TV);
        let cred_r_tv =
            BytesMaxBuffer::from_slice(&ByteSeq::from_hex(CRED_R_TV), 0, CRED_R_TV.len() / 2);

        let th_3 = compute_th_3(&th_2_tv, &plaintext_2_tv, &cred_r_tv, CRED_R_TV.len() / 2);
        assert_bytes_eq!(th_3, th_3_tv);
    }

    #[test]
    fn test_compute_th_4() {
        let th_3_tv = BytesHashLen::from_hex(TH_3_TV);
        let plaintext_3_tv = BytesPlaintext3::from_hex(PLAINTEXT_3_TV);
        let th_4_tv = BytesHashLen::from_hex(TH_4_TV);
        let cred_i_tv =
            BytesMaxBuffer::from_slice(&ByteSeq::from_hex(CRED_I_TV), 0, CRED_I_TV.len() / 2);

        let th_4 = compute_th_4(&th_3_tv, &plaintext_3_tv, &cred_i_tv, CRED_I_TV.len() / 2);
        assert_bytes_eq!(th_4, th_4_tv);
    }

    #[test]
    fn test_edhoc_kdf() {
        let th_2_context_tv =
            BytesMaxContextBuffer::from_slice(&ByteSeq::from_hex(TH_2_TV), 0, TH_2_TV.len() / 2);
        let prk_2e_tv = BytesHashLen::from_hex(PRK_2E_TV);
        let keystream_2_tv = BytesPlaintext2::from_hex(KEYSTREAM_2_TV);
        const LEN_TV: usize = PLAINTEXT_2_LEN;

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

        let prk_3e2m_tv = BytesHashLen::from_hex(PRK_3E2M_TV);
        let context_info_mac_2 = BytesMaxContextBuffer::from_slice(
            &ByteSeq::from_hex(CONTEXT_INFO_MAC_2_TV),
            0,
            CONTEXT_INFO_MAC_2_TV.len() / 2,
        );
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
    fn test_encrypt_message_3() {
        let prk_3e2m_tv = BytesHashLen::from_hex(PRK_3E2M_TV);
        let th_3_tv = BytesHashLen::from_hex(TH_3_TV);
        let plaintext_3_tv = BytesPlaintext3::from_hex(PLAINTEXT_3_TV);
        let message_3_tv = BytesMessage3::from_hex(MESSAGE_3_TV);

        let message_3 = encrypt_message_3(&prk_3e2m_tv, &th_3_tv, &plaintext_3_tv);
        assert_bytes_eq!(message_3, message_3_tv);
    }

    #[test]
    fn test_decrypt_message_3() {
        let message_3_tv = BytesMessage3::from_hex(MESSAGE_3_TV);
        let prk_3e2m_tv = BytesHashLen::from_hex(PRK_3E2M_TV);
        let th_3_tv = BytesHashLen::from_hex(TH_3_TV);
        let plaintext_3_tv = BytesPlaintext3::from_hex(PLAINTEXT_3_TV);

        let (error, plaintext_3) = decrypt_message_3(&prk_3e2m_tv, &th_3_tv, &message_3_tv);

        assert_eq!(error, EDHOCError::Success);
        assert_bytes_eq!(plaintext_3, plaintext_3_tv);
    }

    #[test]
    fn test_compute_mac_3() {
        let prk_4e3m_tv = BytesHashLen::from_hex(PRK_4E3M_TV);
        let th_3_tv = BytesHashLen::from_hex(TH_3_TV);
        let id_cred_i_tv = BytesIdCred::from_hex(ID_CRED_I_TV);
        let cred_i_tv =
            BytesMaxBuffer::from_slice(&ByteSeq::from_hex(CRED_I_TV), 0, CRED_I_TV.len() / 2);
        let mac_3_tv = BytesMac3::from_hex(MAC_3_TV);

        let mac_3 = compute_mac_3(
            &prk_4e3m_tv,
            &th_3_tv,
            &id_cred_i_tv,
            &cred_i_tv,
            CRED_I_TV.len() / 2, // divide by two to get num of bytes from hex string
        );
        assert_bytes_eq!(mac_3, mac_3_tv);
    }

    #[test]
    fn test_compute_and_verify_mac_2() {
        let prk_3e2m_tv = BytesHashLen::from_hex(PRK_3E2M_TV);
        let id_cred_r_tv = BytesIdCred::from_hex(ID_CRED_R_TV);
        let cred_r_tv =
            BytesMaxBuffer::from_slice(&ByteSeq::from_hex(CRED_R_TV), 0, CRED_R_TV.len() / 2);
        let th_2_tv = BytesHashLen::from_hex(TH_2_TV);
        let mac_2_tv = BytesMac2::from_hex(MAC_2_TV);

        let rcvd_mac_2 = compute_mac_2(
            &prk_3e2m_tv,
            &id_cred_r_tv,
            &cred_r_tv,
            CRED_R_TV.len() / 2,
            &th_2_tv,
        );

        assert_bytes_eq!(rcvd_mac_2, mac_2_tv);
    }

    #[test]
    fn test_encode_plaintext_2() {
        let plaintext_2_tv = BytesPlaintext2::from_hex(PLAINTEXT_2_TV);
        let id_cred_r_tv = BytesIdCred::from_hex(ID_CRED_R_TV);
        let mac_2_tv = BytesMac2::from_hex(MAC_2_TV);

        let plaintext_2 = encode_plaintext_2(&id_cred_r_tv, &mac_2_tv, &BytesEad2::new());

        assert_bytes_eq!(plaintext_2, plaintext_2_tv);
    }

    #[test]
    fn test_decode_plaintext_2() {
        let plaintext_2_tv = BytesMaxBuffer::from_slice(
            &ByteSeq::from_hex(PLAINTEXT_2_TV),
            0,
            PLAINTEXT_2_TV.len() / 2,
        );
        let id_cred_r_tv = BytesIdCred::from_hex(ID_CRED_R_TV);
        let mac_2_tv = BytesMac2::from_hex(MAC_2_TV);
        let ead_2_tv = BytesEad2::new();

        let (id_cred_r, mac_2, ead_2) = decode_plaintext_2(&plaintext_2_tv, PLAINTEXT_2_LEN);
        assert_eq!(U8::declassify(id_cred_r), U8::declassify(id_cred_r_tv[3]));
        assert_bytes_eq!(mac_2, mac_2_tv);
        assert_bytes_eq!(ead_2, ead_2_tv);
    }

    #[test]
    fn test_encrypt_decrypt_ciphertext_2() {
        let prk_2e_tv = BytesHashLen::from_hex(PRK_2E_TV);
        let th_2_tv = BytesHashLen::from_hex(TH_2_TV);
        let ciphertext_2_tv = BytesCiphertext2::from_hex(CIPHERTEXT_2_TV);
        let plaintext_2_tv = BytesPlaintext2::from_hex(PLAINTEXT_2_TV);

        // test decryption
        let (plaintext_2, plaintext_2_len) =
            encrypt_decrypt_ciphertext_2(&prk_2e_tv, &th_2_tv, &ciphertext_2_tv);

        assert_eq!(plaintext_2_len, PLAINTEXT_2_LEN);
        for i in 0..PLAINTEXT_2_LEN {
            assert_eq!(plaintext_2[i].declassify(), plaintext_2_tv[i].declassify());
        }

        let plaintext_2_tmp = BytesCiphertext2::from_slice(&plaintext_2, 0, plaintext_2_len);

        // test encryption
        let (ciphertext_2, ciphertext_2_len) =
            encrypt_decrypt_ciphertext_2(&prk_2e_tv, &th_2_tv, &plaintext_2_tmp);

        assert_eq!(ciphertext_2_len, CIPHERTEXT_2_LEN);
        for i in 0..CIPHERTEXT_2_LEN {
            assert_eq!(
                ciphertext_2[i].declassify(),
                ciphertext_2_tv[i].declassify()
            );
        }
    }

    #[test]
    fn test_compute_prk_4e3m() {
        let salt_4e3m_tv = BytesHashLen::from_hex(SALT_4E3M_TV);
        let i_tv = BytesP256ElemLen::from_hex(I_TV);
        let g_y_tv = BytesP256ElemLen::from_hex(G_Y_TV);
        let prk_4e3m_tv = BytesHashLen::from_hex(PRK_4E3M_TV);

        let prk_4e3m = compute_prk_4e3m(&salt_4e3m_tv, &i_tv, &g_y_tv);
        assert_bytes_eq!(prk_4e3m, prk_4e3m_tv);
    }

    #[test]
    fn test_compute_prk_3e2m() {
        let salt_3e2m_tv = BytesHashLen::from_hex(SALT_3E2M_TV);
        let x_tv = BytesP256ElemLen::from_hex(X_TV);
        let g_r_tv = BytesP256ElemLen::from_hex(G_R_TV);
        let prk_3e2m_tv = BytesHashLen::from_hex(PRK_3E2M_TV);

        let prk_3e2m = compute_prk_3e2m(&salt_3e2m_tv, &x_tv, &g_r_tv);
        assert_bytes_eq!(prk_3e2m, prk_3e2m_tv);
    }

    #[test]
    fn test_compute_prk_2e() {
        let x_tv = BytesP256ElemLen::from_hex(X_TV);
        let g_y_tv = BytesP256ElemLen::from_hex(G_Y_TV);
        let th_2_tv = BytesHashLen::from_hex(TH_2_TV);
        let prk_2e_tv = BytesHashLen::from_hex(PRK_2E_TV);

        let prk_2e = compute_prk_2e(&x_tv, &g_y_tv, &th_2_tv);
        assert_bytes_eq!(prk_2e, prk_2e_tv);
    }

    #[test]
    fn test_encode_plaintext_3() {
        let id_cred_i_tv = BytesIdCred::from_hex(ID_CRED_I_TV);
        let mac_3_tv = BytesMac3::from_hex(MAC_3_TV);
        let plaintext_3_tv = BytesPlaintext3::from_hex(PLAINTEXT_3_TV);

        let plaintext_3 = encode_plaintext_3(&id_cred_i_tv, &mac_3_tv);
        assert_bytes_eq!(plaintext_3, plaintext_3_tv);
    }

    #[test]
    fn test_decode_plaintext_3() {
        let plaintext_3_tv = BytesPlaintext3::from_hex(PLAINTEXT_3_TV);
        let mac_3_tv = BytesMac3::from_hex(MAC_3_TV);
        let kid_tv = BytesIdCred::from_hex(ID_CRED_I_TV);
        let kid_tv = kid_tv[kid_tv.len() - 1];

        let (kid, mac_3) = decode_plaintext_3(&plaintext_3_tv);

        assert_bytes_eq!(mac_3, mac_3_tv);
        assert_eq!(kid.declassify(), kid_tv.declassify());
    }
}
