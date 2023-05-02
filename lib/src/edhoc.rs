#![no_std]

use edhoc_consts::*;
use edhoc_crypto::*;

pub fn edhoc_exporter(
    state: State,
    label: U8,
    context: &BytesMaxContextBuffer,
    context_len: usize,
    length: usize,
) -> Result<(State, BytesMaxBuffer), EDHOCError> {
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

    let mut output: BytesMaxBuffer = [0x00; MAX_BUFFER_LEN];
    let mut error = EDHOCError::UnknownError;

    if current_state == EDHOCState::Completed {
        output = edhoc_kdf(&prk_exporter, label, context, context_len, length);
        Ok((state, output))
    } else {
        Err(EDHOCError::WrongState)
    }
}

pub fn r_process_message_1(
    mut state: State,
    message_1: &BytesMessage1,
) -> Result<State, EDHOCError> {
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
        if method == EDHOC_METHOD {
            // Step 2: verify that the selected cipher suite is supported
            if supported_suites[0] == EDHOC_SUPPORTED_SUITES[0] {
                // Step 3: If EAD is present make it available to the application
                // TODO we do not support EAD for now

                // hash message_1 and save the hash to the state to avoid saving the whole message
                let mut message_1_buf: BytesMaxBuffer = [0x00; MAX_BUFFER_LEN];
                message_1_buf[..message_1.len()].copy_from_slice(&message_1[..]);
                h_message_1 = sha256_digest(&message_1_buf, message_1.len());

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

    match error {
        EDHOCError::Success => Ok(state),
        _ => Err(error),
    }
}

pub fn r_prepare_message_2(
    mut state: State,
    id_cred_r: &BytesIdCred,
    cred_r: &BytesMaxBuffer,
    cred_r_len: usize,
    r: &BytesP256ElemLen, // R's static private DH key
    y: BytesP256ElemLen,
    g_y: BytesP256ElemLen,
) -> Result<(State, BytesMessage2, U8), EDHOCError> {
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
    let mut message_2: BytesMessage2 = [0x00u8; MESSAGE_2_LEN];
    let mut c_r = 0xffu8; // invalid c_r

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
        let plaintext_2 = encode_plaintext_2(id_cred_r, &mac_2, &[]);

        // step is actually from processing of message_3
        // but we do it here to avoid storing plaintext_2 in State
        th_3 = compute_th_3(&th_2, &plaintext_2, cred_r, cred_r_len);

        let mut ct: BytesCiphertext2 = [0x00; CIPHERTEXT_2_LEN];
        ct[..].copy_from_slice(&plaintext_2[..]);

        let (ciphertext_2, ciphertext_2_len) = encrypt_decrypt_ciphertext_2(&prk_2e, &th_2, &ct);

        ct[..].copy_from_slice(&ciphertext_2[..ciphertext_2_len]);

        message_2 = encode_message_2(&g_y, &ct, c_r);

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

    match error {
        EDHOCError::Success => Ok((state, message_2, c_r)),
        _ => Err(error),
    }
}

// FIXME fetch ID_CRED_I and CRED_I based on kid
pub fn r_process_message_3(
    mut state: State,
    message_3: &BytesMessage3,
    id_cred_i_expected: &BytesIdCred,
    cred_i_expected: &BytesMaxBuffer,
    cred_i_len: usize,
    g_i: &BytesP256ElemLen, // I's public DH key
) -> Result<(State, BytesHashLen), EDHOCError> {
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
        let plaintext_3 = decrypt_message_3(&prk_3e2m, &th_3, message_3);

        if plaintext_3.is_ok() {
            let plaintext_3 = plaintext_3.unwrap();
            let (kid, mac_3) = decode_plaintext_3(&plaintext_3);

            // compare the kid received with the kid expected in id_cred_i
            if kid == id_cred_i_expected[id_cred_i_expected.len() - 1] {
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
                if mac_3 == expected_mac_3 {
                    error = EDHOCError::Success;
                    let th_4 = compute_th_4(&th_3, &plaintext_3, cred_i_expected, cred_i_len);

                    let mut th_4_buf: BytesMaxContextBuffer = [0x00; MAX_KDF_CONTEXT_LEN];
                    th_4_buf[..th_4.len()].copy_from_slice(&th_4[..]);
                    // compute prk_out
                    // PRK_out = EDHOC-KDF( PRK_4e3m, 7, TH_4, hash_length )
                    let prk_out_buf =
                        edhoc_kdf(&prk_4e3m, 7u8, &th_4_buf, th_4.len(), SHA256_DIGEST_LEN);
                    prk_out[..SHA256_DIGEST_LEN].copy_from_slice(&prk_out_buf[..SHA256_DIGEST_LEN]);

                    // compute prk_exporter from prk_out
                    // PRK_exporter  = EDHOC-KDF( PRK_out, 10, h'', hash_length )
                    let prk_exporter_buf = edhoc_kdf(
                        &prk_out,
                        10u8,
                        &[0x00u8; MAX_KDF_CONTEXT_LEN],
                        0,
                        SHA256_DIGEST_LEN,
                    );
                    prk_exporter[..SHA256_DIGEST_LEN]
                        .copy_from_slice(&prk_exporter_buf[..SHA256_DIGEST_LEN]);

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
            error = plaintext_3.err().expect("error handling error");
        }
    } else {
        error = EDHOCError::WrongState;
    }

    match error {
        EDHOCError::Success => Ok((state, prk_out)),
        _ => Err(error),
    }
}

// must hold MESSAGE_1_LEN
pub fn i_prepare_message_1(
    mut state: State,
    x: BytesP256ElemLen,
    g_x: BytesP256ElemLen,
) -> Result<(State, BytesMessage1), EDHOCError> {
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

    let mut message_1: BytesMessage1 = [0x00u8; MESSAGE_1_LEN];

    if current_state == EDHOCState::Start {
        // we only support a single cipher suite which is already CBOR-encoded
        let selected_suites = EDHOC_SUPPORTED_SUITES;

        // Choose a connection identifier C_I and store it for the length of the protocol.
        c_i = C_I;

        // Encode message_1 as a sequence of CBOR encoded data items as specified in Section 5.2.1
        message_1 = encode_message_1(EDHOC_METHOD, &selected_suites, &g_x, c_i);

        let mut message_1_buf: BytesMaxBuffer = [0x00; MAX_BUFFER_LEN];
        message_1_buf[..message_1.len()].copy_from_slice(&message_1[..]);

        // hash message_1 here to avoid saving the whole message in the state
        h_message_1 = sha256_digest(&message_1_buf, message_1.len());
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

    match error {
        EDHOCError::Success => Ok((state, message_1)),
        _ => Err(error),
    }
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
) -> Result<(State, U8, U8), EDHOCError> {
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
    let mut c_r = 0xffu8; // invalidate c_r
    let mut kid = 0xffu8; // invalidate kid

    if current_state == EDHOCState::WaitMessage2 {
        let (g_y, ciphertext_2, c_r_2) = parse_message_2(message_2);
        c_r = c_r_2;

        let th_2 = compute_th_2(&g_y, c_r, &h_message_1);

        // compute prk_2e
        let prk_2e = compute_prk_2e(&x, &g_y, &th_2);

        let (plaintext_2, plaintext_2_len) =
            encrypt_decrypt_ciphertext_2(&prk_2e, &th_2, &ciphertext_2);

        // decode plaintext_2
        let plaintext_2_decoded = decode_plaintext_2(&plaintext_2, plaintext_2_len);

        if plaintext_2_decoded.is_ok() {
            let (kid, mac_2, _ead_2) = plaintext_2_decoded.unwrap();

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

            if mac_2 == expected_mac_2 {
                if kid == id_cred_r_expected[id_cred_r_expected.len() - 1] {
                    // step is actually from processing of message_3
                    // but we do it here to avoid storing plaintext_2 in State
                    let mut pt2: BytesPlaintext2 = [0x00; PLAINTEXT_2_LEN];
                    pt2[..].copy_from_slice(&plaintext_2[..plaintext_2_len]);
                    th_3 = compute_th_3(&th_2, &pt2, cred_r_expected, cred_r_len);
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
                    // Unknown peer
                    error = EDHOCError::UnknownPeer;
                }
            } else {
                error = EDHOCError::MacVerificationFailed;
            }
        } else {
            error = EDHOCError::ParsingError;
        }
    } else {
        error = EDHOCError::WrongState;
    }

    match error {
        EDHOCError::Success => Ok((state, c_r, kid)),
        _ => Err(error),
    }
}

// message_3 must hold MESSAGE_3_LEN
pub fn i_prepare_message_3(
    mut state: State,
    id_cred_i: &BytesIdCred,
    cred_i: &BytesMaxBuffer,
    cred_i_len: usize,
) -> Result<(State, BytesMessage3, BytesHashLen), EDHOCError> {
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
    let mut message_3: BytesMessage3 = [0x00; MESSAGE_3_LEN];

    if current_state == EDHOCState::ProcessedMessage2 {
        let mac_3 = compute_mac_3(&prk_4e3m, &th_3, id_cred_i, cred_i, cred_i_len);
        let plaintext_3 = encode_plaintext_3(id_cred_i, &mac_3);
        message_3 = encrypt_message_3(&prk_3e2m, &th_3, &plaintext_3);

        let th_4 = compute_th_4(&th_3, &plaintext_3, cred_i, cred_i_len);

        let mut th_4_buf: BytesMaxContextBuffer = [0x00; MAX_KDF_CONTEXT_LEN];
        th_4_buf[..th_4.len()].copy_from_slice(&th_4[..]);

        // compute prk_out
        // PRK_out = EDHOC-KDF( PRK_4e3m, 7, TH_4, hash_length )
        let prk_out_buf = edhoc_kdf(&prk_4e3m, 7u8, &th_4_buf, th_4.len(), SHA256_DIGEST_LEN);
        prk_out[..SHA256_DIGEST_LEN].copy_from_slice(&prk_out_buf[..SHA256_DIGEST_LEN]);

        // compute prk_exporter from prk_out
        // PRK_exporter  = EDHOC-KDF( PRK_out, 10, h'', hash_length )
        let prk_exporter_buf = edhoc_kdf(
            &prk_out,
            10u8,
            &[0x00; MAX_KDF_CONTEXT_LEN],
            0,
            SHA256_DIGEST_LEN,
        );
        prk_exporter[..SHA256_DIGEST_LEN].copy_from_slice(&prk_exporter_buf[..SHA256_DIGEST_LEN]);
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

    match error {
        EDHOCError::Success => Ok((state, message_3, prk_out)),
        _ => Err(error),
    }
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
    // // FIXME as we only support a fixed-sized incoming message_1,
    // // we parse directly the selected cipher suite
    let mut selected_suite: BytesSupportedSuites = [0x00; SUPPORTED_SUITES_LEN];

    let suites_size =
        match rcvd_message_1[1] {
            0x00..=0x17 => {
                selected_suite[..].copy_from_slice(&rcvd_message_1[1..2]);
                1
            },
            0x80..=0x97 => {
                let suites_size: usize = (rcvd_message_1[1] - 0x80).into();
                // FIXME: will fail if suites_size > SUPPORTED_SUITES_LEN
                selected_suite[..].copy_from_slice(&rcvd_message_1[2..2+suites_size]);
                suites_size + 1
            },
            _ => panic!("Invalid CBOR encoding of the selected cipher suite"),
        };
    // TODO: check if selected_suite satisfies EDHOC requirements (EDHOCSuite)

    let mut g_x: BytesP256ElemLen = [0x00; P256_ELEM_LEN];
    g_x.copy_from_slice(&rcvd_message_1[suites_size + 3..suites_size + 3 + P256_ELEM_LEN]);
    let c_i = rcvd_message_1[MESSAGE_1_LEN - 1];

    (method, selected_suite, g_x, c_i)
}

fn encode_message_1(
    method: U8,
    suites: &BytesSupportedSuites,
    g_x: &BytesP256ElemLen,
    c_i: U8,
) -> BytesMessage1 {
    let mut output: BytesMessage1 = [0x00; MESSAGE_1_LEN];

    output[0] = method; // CBOR unsigned int less than 24 is encoded verbatim
    output[1] = suites[0];
    output[2] = CBOR_BYTE_STRING; // CBOR byte string magic number
    output[3] = P256_ELEM_LEN as u8; // length of the byte string
    output[4..4 + P256_ELEM_LEN].copy_from_slice(&g_x[..]);
    output[4 + P256_ELEM_LEN] = c_i;

    output
}

fn parse_message_2(rcvd_message_2: &BytesMessage2) -> (BytesP256ElemLen, BytesCiphertext2, U8) {
    // FIXME decode negative integers as well
    let mut g_y: BytesP256ElemLen = [0x00; P256_ELEM_LEN];
    let mut ciphertext_2: BytesCiphertext2 = [0x00; CIPHERTEXT_2_LEN];
    g_y[..].copy_from_slice(&rcvd_message_2[2..2 + P256_ELEM_LEN]);
    ciphertext_2[..]
        .copy_from_slice(&rcvd_message_2[2 + P256_ELEM_LEN..2 + P256_ELEM_LEN + CIPHERTEXT_2_LEN]);
    let c_r = rcvd_message_2[MESSAGE_2_LEN - 1];

    (g_y, ciphertext_2, c_r)
}

fn encode_message_2(
    g_y: &BytesP256ElemLen,
    ciphertext_2: &BytesCiphertext2,
    c_r: U8,
) -> BytesMessage2 {
    let mut output: BytesMessage2 = [0x00; MESSAGE_2_LEN];

    output[0] = CBOR_BYTE_STRING;
    output[1] = P256_ELEM_LEN as u8 + CIPHERTEXT_2_LEN as u8;
    output[2..2 + P256_ELEM_LEN].copy_from_slice(&g_y[..]);
    output[2 + P256_ELEM_LEN..2 + P256_ELEM_LEN + CIPHERTEXT_2_LEN].copy_from_slice(ciphertext_2);
    output[2 + P256_ELEM_LEN + CIPHERTEXT_2_LEN] = c_r;

    output
}

fn compute_th_2(g_y: &BytesP256ElemLen, c_r: U8, h_message_1: &BytesHashLen) -> BytesHashLen {
    let mut message: BytesMaxBuffer = [0x00; MAX_BUFFER_LEN];
    message[0] = CBOR_BYTE_STRING;
    message[1] = P256_ELEM_LEN as u8;
    message[2..2 + P256_ELEM_LEN].copy_from_slice(g_y);
    message[2 + P256_ELEM_LEN] = c_r;
    message[3 + P256_ELEM_LEN] = CBOR_BYTE_STRING;
    message[4 + P256_ELEM_LEN] = SHA256_DIGEST_LEN as u8;
    message[5 + P256_ELEM_LEN..5 + P256_ELEM_LEN + SHA256_DIGEST_LEN]
        .copy_from_slice(&h_message_1[..]);

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
    let mut message: BytesMaxBuffer = [0x00; MAX_BUFFER_LEN];

    message[0] = CBOR_BYTE_STRING;
    message[1] = th_2.len() as u8;
    message[2..2 + th_2.len()].copy_from_slice(&th_2[..]);
    message[2 + th_2.len()..2 + th_2.len() + plaintext_2.len()].copy_from_slice(&plaintext_2[..]);
    message[2 + th_2.len() + plaintext_2.len()..2 + th_2.len() + plaintext_2.len() + cred_r_len]
        .copy_from_slice(&cred_r[..cred_r_len]);

    let output = sha256_digest(&message, th_2.len() + 2 + plaintext_2.len() + cred_r_len);

    output
}

fn compute_th_4(
    th_3: &BytesHashLen,
    plaintext_3: &BytesPlaintext3,
    cred_i: &BytesMaxBuffer,
    cred_i_len: usize,
) -> BytesHashLen {
    let mut message: BytesMaxBuffer = [0x00; MAX_BUFFER_LEN];

    message[0] = CBOR_BYTE_STRING;
    message[1] = th_3.len() as u8;
    message[2..2 + th_3.len()].copy_from_slice(&th_3[..]);
    message[2 + th_3.len()..2 + th_3.len() + plaintext_3.len()].copy_from_slice(&plaintext_3[..]);
    message[2 + th_3.len() + plaintext_3.len()..2 + th_3.len() + plaintext_3.len() + cred_i_len]
        .copy_from_slice(&cred_i[..cred_i_len]);

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
    let mut info: BytesMaxInfoBuffer = [0x00; MAX_INFO_LEN];
    let mut info_len = 0;

    // construct info with inline cbor encoding
    info[0] = label;
    if context_len < 24 {
        info[1] = context_len as u8 | CBOR_MAJOR_BYTE_STRING;
        info[2..2 + context_len].copy_from_slice(&context[..context_len]);
        info_len = 2 + context_len;
    } else {
        info[1] = CBOR_BYTE_STRING;
        info[2] = context_len as u8;
        info[3..3 + context_len].copy_from_slice(&context[..context_len]);
        info_len = 3 + context_len;
    }
    if length < 24 {
        info[info_len] = length as u8;
        info_len = info_len + 1;
    } else {
        info[info_len] = CBOR_UINT_1BYTE;
        info[info_len + 1] = length as u8;
        info_len = info_len + 2;
    }

    let output = hkdf_expand(prk, &info, info_len, length);

    output
}

fn decode_plaintext_3(plaintext_3: &BytesPlaintext3) -> (U8, BytesMac3) {
    let kid = plaintext_3[0usize];
    // skip the CBOR magic byte as we know how long the MAC is
    let mut mac_3: BytesMac3 = [0x00; MAC_LENGTH_3];
    mac_3[..].copy_from_slice(&plaintext_3[2..2 + MAC_LENGTH_3]);

    (kid, mac_3)
}

fn encode_plaintext_3(id_cred_i: &BytesIdCred, mac_3: &BytesMac3) -> BytesPlaintext3 {
    let mut plaintext_3: BytesPlaintext3 = [0x00; PLAINTEXT_3_LEN];

    // plaintext: P = ( ? PAD, ID_CRED_I / bstr / int, Signature_or_MAC_3, ? EAD_3 )
    plaintext_3[0] = id_cred_i[id_cred_i.len() - 1]; // hack: take the last byte of ID_CRED_I as KID
    plaintext_3[1] = CBOR_MAJOR_BYTE_STRING | MAC_LENGTH_3 as u8;
    plaintext_3[2..2 + mac_3.len()].copy_from_slice(&mac_3[..]);

    plaintext_3
}

fn encode_enc_structure(th_3: &BytesHashLen) -> BytesEncStructureLen {
    let mut encrypt0: Bytes8 = [0x00; 8];
    encrypt0[0] = 0x45u8; // 'E'
    encrypt0[1] = 0x6eu8; // 'n'
    encrypt0[2] = 0x63u8; // 'c'
    encrypt0[3] = 0x72u8; // 'r'
    encrypt0[4] = 0x79u8; // 'y'
    encrypt0[5] = 0x70u8; // 'p'
    encrypt0[6] = 0x74u8; // 't'
    encrypt0[7] = 0x30u8; // '0'

    let mut enc_structure: BytesEncStructureLen = [0x00; ENC_STRUCTURE_LEN];

    // encode Enc_structure from draft-ietf-cose-rfc8152bis Section 5.3
    enc_structure[0] = CBOR_MAJOR_ARRAY | 3 as u8; // 3 is the fixed number of elements in the array
    enc_structure[1] = CBOR_MAJOR_TEXT_STRING | encrypt0.len() as u8;
    enc_structure[2..2 + encrypt0.len()].copy_from_slice(&encrypt0[..]);
    enc_structure[encrypt0.len() + 2] = CBOR_MAJOR_BYTE_STRING | 0x00 as u8; // 0 for zero-length byte string
    enc_structure[encrypt0.len() + 3] = CBOR_BYTE_STRING; // byte string greater than 24
    enc_structure[encrypt0.len() + 4] = SHA256_DIGEST_LEN as u8;
    enc_structure[encrypt0.len() + 5..encrypt0.len() + 5 + th_3.len()].copy_from_slice(&th_3[..]);

    enc_structure
}

fn compute_k_3_iv_3(
    prk_3e2m: &BytesHashLen,
    th_3: &BytesHashLen,
) -> (BytesCcmKeyLen, BytesCcmIvLen) {
    // K_3 = EDHOC-KDF( PRK_3e2m, 3, TH_3,      key_length )
    let mut k_3: BytesCcmKeyLen = [0x00; AES_CCM_KEY_LEN];
    let mut th_3_buf: BytesMaxContextBuffer = [0x00; MAX_KDF_CONTEXT_LEN];
    th_3_buf[..th_3.len()].copy_from_slice(&th_3[..]);
    let k_3_buf = edhoc_kdf(prk_3e2m, 3u8, &th_3_buf, th_3.len(), AES_CCM_KEY_LEN);
    k_3[..].copy_from_slice(&k_3_buf[..AES_CCM_KEY_LEN]);

    // IV_3 = EDHOC-KDF( PRK_3e2m, 4, TH_3,      iv_length )
    let mut iv_3: BytesCcmIvLen = [0x00; AES_CCM_IV_LEN];
    let iv_3_buf = edhoc_kdf(prk_3e2m, 4u8, &th_3_buf, th_3.len(), AES_CCM_IV_LEN);
    iv_3[..].copy_from_slice(&iv_3_buf[..AES_CCM_IV_LEN]);

    (k_3, iv_3)
}

// calculates ciphertext_3 wrapped in a cbor byte string
// output must hold MESSAGE_3_LEN
fn encrypt_message_3(
    prk_3e2m: &BytesHashLen,
    th_3: &BytesHashLen,
    plaintext_3: &BytesPlaintext3,
) -> BytesMessage3 {
    let mut output: BytesMessage3 = [0x00; MESSAGE_3_LEN];
    output[0] = CBOR_MAJOR_BYTE_STRING | CIPHERTEXT_3_LEN as u8;

    let enc_structure = encode_enc_structure(th_3);

    let (k_3, iv_3) = compute_k_3_iv_3(prk_3e2m, th_3);

    output[1..].copy_from_slice(&aes_ccm_encrypt_tag_8(
        &k_3,
        &iv_3,
        &enc_structure,
        plaintext_3,
    ));

    output
}

fn decrypt_message_3(
    prk_3e2m: &BytesHashLen,
    th_3: &BytesHashLen,
    message_3: &BytesMessage3,
) -> Result<BytesPlaintext3, EDHOCError> {
    let mut error = EDHOCError::UnknownError;
    let mut plaintext_3: BytesPlaintext3 = [0x00; PLAINTEXT_3_LEN];

    // decode message_3
    let len = message_3[0usize] ^ CBOR_MAJOR_BYTE_STRING;

    // compare parsed length with the expected length of the ciphertext
    if len as usize == CIPHERTEXT_3_LEN {
        let mut ciphertext_3: BytesCiphertext3 = [0x00; CIPHERTEXT_3_LEN];
        ciphertext_3[..].copy_from_slice(&message_3[1..1 + CIPHERTEXT_3_LEN]);

        let (k_3, iv_3) = compute_k_3_iv_3(prk_3e2m, th_3);

        let enc_structure = encode_enc_structure(th_3);

        let p3 = aes_ccm_decrypt_tag_8(&k_3, &iv_3, &enc_structure, &ciphertext_3);

        if p3.is_ok() {
            error = EDHOCError::Success;
            plaintext_3[..].copy_from_slice(&p3.unwrap());
        } else {
            error = p3.err().expect("error handling error");
        }
    } else {
        error = EDHOCError::ParsingError;
    }

    match error {
        EDHOCError::Success => Ok(plaintext_3),
        _ => Err(error),
    }
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
    let mut output: BytesMaxContextBuffer = [0x00; MAX_KDF_CONTEXT_LEN];
    output[..id_cred.len()].copy_from_slice(&id_cred[..]);
    output[id_cred.len()] = CBOR_BYTE_STRING;
    output[id_cred.len() + 1] = SHA256_DIGEST_LEN as u8;
    output[id_cred.len() + 2..id_cred.len() + 2 + th.len()].copy_from_slice(&th[..]);
    output[id_cred.len() + 2 + th.len()..id_cred.len() + 2 + th.len() + cred_len]
        .copy_from_slice(&cred[..cred_len]);

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
        6u8, // registered label for "MAC_3"
        &context,
        context_len,
        MAC_LENGTH_3,
    );

    let mut output: BytesMac3 = [0x00; MAC_LENGTH_3];
    output[..MAC_LENGTH_3].copy_from_slice(&output_buf[..MAC_LENGTH_3]);
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
    let mut mac_2: BytesMac2 = [0x00; MAC_LENGTH_2];
    mac_2[..].copy_from_slice(
        &edhoc_kdf(prk_3e2m, 2 as u8, &context, context_len, MAC_LENGTH_2)[..MAC_LENGTH_2],
    );

    mac_2
}

fn decode_plaintext_2(
    plaintext_2: &BytesMaxBuffer,
    plaintext_2_len: usize,
) -> Result<(U8, BytesMac2, BytesEad2), EDHOCError> {
    if plaintext_2_len == PLAINTEXT_2_LEN {
        let id_cred_r = plaintext_2[0];
        // skip cbor byte string byte as we know how long the string is
        let mut mac_2: BytesMac2 = [0x00; MAC_LENGTH_2];
        mac_2[..].copy_from_slice(&plaintext_2[2..2 + MAC_LENGTH_2]);
        // FIXME we don't support ead_2 parsing for now
        let ead_2: BytesEad2 = [0x00; 0];

        Ok((id_cred_r, mac_2, ead_2))
    } else {
        Err(EDHOCError::ParsingError)
    }
}

fn encode_plaintext_2(
    id_cred_r: &BytesIdCred,
    mac_2: &BytesMac2,
    ead_2: &BytesEad2,
) -> BytesPlaintext2 {
    let mut plaintext_2: BytesPlaintext2 = [0x00; PLAINTEXT_2_LEN];
    plaintext_2[0] = id_cred_r[id_cred_r.len() - 1];
    plaintext_2[1] = CBOR_MAJOR_BYTE_STRING | MAC_LENGTH_2 as u8;
    plaintext_2[2..2 + mac_2.len()].copy_from_slice(&mac_2[..]);
    plaintext_2[2 + mac_2.len()..2 + mac_2.len() + ead_2.len()].copy_from_slice(&ead_2[..]);

    plaintext_2
}

fn encrypt_decrypt_ciphertext_2(
    prk_2e: &BytesHashLen,
    th_2: &BytesHashLen,
    ciphertext_2: &BytesCiphertext2,
) -> (BytesMaxBuffer, usize) {
    // convert the transcript hash th_2 to BytesMaxContextBuffer type
    let mut th_2_context: BytesMaxContextBuffer = [0x00; MAX_KDF_CONTEXT_LEN];
    th_2_context[..th_2.len()].copy_from_slice(&th_2[..]);

    // KEYSTREAM_2 = EDHOC-KDF( PRK_2e,   0, TH_2,      plaintext_length )
    let keystream_2 = edhoc_kdf(
        prk_2e,
        0u8,
        &th_2_context,
        SHA256_DIGEST_LEN,
        CIPHERTEXT_2_LEN,
    );

    let mut plaintext_2: BytesMaxBuffer = [0x00; MAX_BUFFER_LEN];
    // decrypt/encrypt ciphertext_2
    for i in 0..CIPHERTEXT_2_LEN {
        plaintext_2[i] = ciphertext_2[i] ^ keystream_2[i];
    }

    (plaintext_2, CIPHERTEXT_2_LEN)
}

fn compute_salt_4e3m(prk_3e2m: &BytesHashLen, th_3: &BytesHashLen) -> BytesHashLen {
    let mut th_3_context: BytesMaxContextBuffer = [0x00; MAX_KDF_CONTEXT_LEN];
    th_3_context[..th_3.len()].copy_from_slice(&th_3[..]);
    let salt_4e3m_buf = edhoc_kdf(prk_3e2m, 5u8, &th_3_context, th_3.len(), SHA256_DIGEST_LEN);
    let mut salt_4e3m: BytesHashLen = [0x00; SHA256_DIGEST_LEN];
    salt_4e3m[..].copy_from_slice(&salt_4e3m_buf[..SHA256_DIGEST_LEN]);

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
    let mut th_2_context: BytesMaxContextBuffer = [0x00; MAX_KDF_CONTEXT_LEN];
    th_2_context[..th_2.len()].copy_from_slice(&th_2[..]);

    let salt_3e2m_buf = edhoc_kdf(
        prk_2e,
        1u8,
        &th_2_context,
        SHA256_DIGEST_LEN,
        SHA256_DIGEST_LEN,
    );

    let mut salt_3e2m: BytesHashLen = [0x00; SHA256_DIGEST_LEN];
    salt_3e2m[..].copy_from_slice(&salt_3e2m_buf[..SHA256_DIGEST_LEN]);

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
    use hexlit::hex;
    // test vectors (TV)

    const METHOD_TV: u8 = 0x03;
    // manually modified test vector to include a single supported cipher suite
    const SUITES_I_TV: BytesSupportedSuites = hex!("02");
    const G_X_TV: BytesP256ElemLen =
        hex!("8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6");
    const C_I_TV: u8 = 0x37;
    // manually modified test vector to include a single supported cipher suite
    const MESSAGE_1_TV: BytesMessage1 =
        hex!("030258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637");
    // // manually modified test vector to include a single supported cipher suite, encoded as array
    // const MESSAGE_1_TV_B: BytesMessage1 =
    //     hex!("03810258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637");
    const G_Y_TV: BytesP256ElemLen =
        hex!("419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5");
    const C_R_TV: u8 = 0x27;
    const MESSAGE_2_TV: BytesMessage2 = hex!(
    "582a419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5042459e2da6c75143f3527");
    const CIPHERTEXT_2_TV: BytesCiphertext2 = hex!("042459e2da6c75143f35");
    const H_MESSAGE_1_TV: BytesHashLen =
        hex!("ca02cabda5a8902749b42f711050bb4dbd52153e87527594b39f50cdf019888c");
    const TH_2_TV: BytesHashLen =
        hex!("9d2af3a3d3fc06aea8110f14ba12ad0b4fb7e5cdf59c7df1cf2dfe9c2024439c");
    const TH_3_TV: BytesHashLen =
        hex!("b778f602331ff68ac402a6511b9de285bedf6eab3e9ed12dfe22a53eeda7de48");
    const CIPHERTEXT_3_TV: BytesCiphertext3 = hex!("c2b62835dc9b1f53419c1d3a2261eeed3505");
    const TH_4_TV: BytesHashLen =
        hex!("1f57dabf8f26da0657d9840c9b1077c1d4c47db243a8b41360a98ec4cb706b70");
    const PRK_2E_TV: BytesP256ElemLen =
        hex!("e01fa14dd56e308267a1a812a9d0b95341e394abc7c5c39dd71885f7d4cd5bf3");
    const KEYSTREAM_2_TV: BytesPlaintext2 = hex!("366c89337ff80c69359a");
    const PRK_3E2M_TV: BytesP256ElemLen =
        hex!("412d60cdf99dc7490754c969ad4c46b1350b908433ebf3fe063be8627fb35b3b");
    const CONTEXT_INFO_MAC_2_TV: [u8; 133] = hex!("a104413258209d2af3a3d3fc06aea8110f14ba12ad0b4fb7e5cdf59c7df1cf2dfe9c2024439ca2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
    const MAC_2_TV: BytesMac2 = hex!("d0d1a594797d0aaf");
    const ID_CRED_I_TV: BytesIdCred = hex!("a104412b");
    const MAC_3_TV: BytesMac3 = hex!("ddf106b86fd22fe4");
    const MESSAGE_3_TV: BytesMessage3 = hex!("52c2b62835dc9b1f53419c1d3a2261eeed3505");
    const PRK_4E3M_TV: BytesP256ElemLen =
        hex!("7d0159bbe45473c9402e0d42dbceb45dca05b744cae1e083e58315b8aa47ceec");
    const CRED_I_TV : [u8; 107] = hex!("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
    const ID_CRED_R_TV: BytesIdCred = hex!("a1044132");
    const CRED_R_TV : [u8; 95] = hex!("A2026B6578616D706C652E65647508A101A501020241322001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");
    const PLAINTEXT_2_TV: BytesPlaintext2 = hex!("3248d0d1a594797d0aaf");
    const I_TV: BytesP256ElemLen =
        hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
    const X_TV: BytesP256ElemLen =
        hex!("368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525");
    const G_R_TV: BytesP256ElemLen =
        hex!("bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0");
    const PLAINTEXT_3_TV: BytesPlaintext3 = hex!("2b48ddf106b86fd22fe4");
    const SALT_3E2M_TV: BytesHashLen =
        hex!("a4f767b3469a6e6ae5fcbf273839fa87c41f462b03ad1ca7ce8f37c95366d8d1");
    const SALT_4E3M_TV: BytesHashLen =
        hex!("8c60d4357fba5f694a81482c4d38a1000bc3e3e2a29406d18153ffc3595c17ba");
    const G_XY_TV: BytesP256ElemLen =
        hex!("2f0cb7e860ba538fbf5c8bded009f6259b4b628fe1eb7dbe9378e5ecf7a824ba");

    #[test]
    fn test_ecdh() {
        let g_xy = p256_ecdh(&X_TV, &G_Y_TV);

        assert_eq!(g_xy, G_XY_TV);
    }

    #[test]
    fn test_encode_message_1() {
        let message_1 = encode_message_1(METHOD_TV, &SUITES_I_TV, &G_X_TV, C_I_TV);

        assert_eq!(message_1, MESSAGE_1_TV);
    }

    #[test]
    fn test_parse_message_1() {
        let (method, supported_suites, g_x, c_i) = parse_message_1(&MESSAGE_1_TV);

        assert_eq!(method, METHOD_TV);
        assert_eq!(supported_suites, SUITES_I_TV);
        assert_eq!(g_x, G_X_TV);
        assert_eq!(c_i, C_I_TV);

        // let (method, supported_suites, g_x, c_i) = parse_message_1(&MESSAGE_1_TV_B);
    }

    #[test]
    fn test_encode_message_2() {
        let message_2 = encode_message_2(&G_Y_TV, &CIPHERTEXT_2_TV, C_R_TV);

        assert_eq!(message_2, MESSAGE_2_TV);
    }

    #[test]
    fn test_parse_message_2() {
        let (g_y, ciphertext_2, c_r) = parse_message_2(&MESSAGE_2_TV);

        assert_eq!(g_y, G_Y_TV);
        assert_eq!(ciphertext_2, CIPHERTEXT_2_TV);
        assert_eq!(c_r, C_R_TV);
    }

    #[test]
    fn test_compute_th_2() {
        let th_2 = compute_th_2(&G_Y_TV, C_R_TV, &H_MESSAGE_1_TV);
        assert_eq!(th_2, TH_2_TV);
    }

    #[test]
    fn test_compute_th_3() {
        let mut cred_r_tv: BytesMaxBuffer = [0x00u8; MAX_BUFFER_LEN];
        cred_r_tv[..CRED_R_TV.len()].copy_from_slice(&CRED_R_TV[..]);

        let th_3 = compute_th_3(&TH_2_TV, &PLAINTEXT_2_TV, &cred_r_tv, CRED_R_TV.len());
        assert_eq!(th_3, TH_3_TV);
    }

    #[test]
    fn test_compute_th_4() {
        let mut cred_i_tv: BytesMaxBuffer = [0x00u8; MAX_BUFFER_LEN];
        cred_i_tv[..CRED_I_TV.len()].copy_from_slice(&CRED_I_TV[..]);

        let th_4 = compute_th_4(&TH_3_TV, &PLAINTEXT_3_TV, &cred_i_tv, CRED_I_TV.len());
        assert_eq!(th_4, TH_4_TV);
    }

    #[test]
    fn test_edhoc_kdf() {
        let mut th_2_context_tv: BytesMaxContextBuffer = [0x00u8; MAX_KDF_CONTEXT_LEN];
        th_2_context_tv[..TH_2_TV.len()].copy_from_slice(&TH_2_TV[..]);
        const LEN_TV: usize = PLAINTEXT_2_LEN;

        let output = edhoc_kdf(&PRK_2E_TV, 0u8, &th_2_context_tv, SHA256_DIGEST_LEN, LEN_TV);
        for i in 0..KEYSTREAM_2_TV.len() {
            assert_eq!(KEYSTREAM_2_TV[i], output[i]);
        }

        let mut context_info_mac_2: BytesMaxContextBuffer = [0x00u8; MAX_KDF_CONTEXT_LEN];
        context_info_mac_2[..CONTEXT_INFO_MAC_2_TV.len()]
            .copy_from_slice(&CONTEXT_INFO_MAC_2_TV[..]);

        let output_2 = edhoc_kdf(
            &PRK_3E2M_TV,
            2u8,
            &context_info_mac_2,
            CONTEXT_INFO_MAC_2_TV.len(),
            MAC_LENGTH_2,
        );

        for i in 0..MAC_2_TV.len() {
            assert_eq!(MAC_2_TV[i], output_2[i]);
        }
    }

    #[test]
    fn test_encrypt_message_3() {
        let message_3 = encrypt_message_3(&PRK_3E2M_TV, &TH_3_TV, &PLAINTEXT_3_TV);
        assert_eq!(message_3, MESSAGE_3_TV);
    }

    #[test]
    fn test_decrypt_message_3() {
        let plaintext_3 = decrypt_message_3(&PRK_3E2M_TV, &TH_3_TV, &MESSAGE_3_TV);

        assert!(plaintext_3.is_ok());
        assert_eq!(plaintext_3.unwrap(), PLAINTEXT_3_TV);
    }

    #[test]
    fn test_compute_mac_3() {
        let mut cred_i_tv: BytesMaxBuffer = [0x00u8; MAX_BUFFER_LEN];
        cred_i_tv[..CRED_I_TV.len()].copy_from_slice(&CRED_I_TV[..]);

        let mac_3 = compute_mac_3(
            &PRK_4E3M_TV,
            &TH_3_TV,
            &ID_CRED_I_TV,
            &cred_i_tv,
            CRED_I_TV.len(),
        );
        assert_eq!(mac_3, MAC_3_TV);
    }

    #[test]
    fn test_compute_and_verify_mac_2() {
        let mut cred_r_tv: BytesMaxBuffer = [0x00u8; MAX_BUFFER_LEN];
        cred_r_tv[..CRED_R_TV.len()].copy_from_slice(&CRED_R_TV[..]);

        let rcvd_mac_2 = compute_mac_2(
            &PRK_3E2M_TV,
            &ID_CRED_R_TV,
            &cred_r_tv,
            CRED_R_TV.len(),
            &TH_2_TV,
        );

        assert_eq!(rcvd_mac_2, MAC_2_TV);
    }

    #[test]
    fn test_encode_plaintext_2() {
        let plaintext_2 = encode_plaintext_2(&ID_CRED_R_TV, &MAC_2_TV, &[]);

        assert_eq!(plaintext_2, PLAINTEXT_2_TV);
    }

    #[test]
    fn test_decode_plaintext_2() {
        let mut plaintext_2_tv: BytesMaxBuffer = [0x00u8; MAX_BUFFER_LEN];
        plaintext_2_tv[..PLAINTEXT_2_TV.len()].copy_from_slice(&PLAINTEXT_2_TV[..]);
        let ead_2_tv = [0x00u8; 0];

        let plaintext_2 = decode_plaintext_2(&plaintext_2_tv, PLAINTEXT_2_LEN);
        assert!(plaintext_2.is_ok());
        let (id_cred_r, mac_2, ead_2) = plaintext_2.unwrap();
        assert_eq!(id_cred_r, ID_CRED_R_TV[3]);
        assert_eq!(mac_2, MAC_2_TV);
        assert_eq!(ead_2, ead_2_tv);

        let plaintext_2_wrong_len = decode_plaintext_2(&plaintext_2_tv, PLAINTEXT_2_LEN + 1);
        assert_eq!(plaintext_2_wrong_len.unwrap_err(), EDHOCError::ParsingError);
    }

    #[test]
    fn test_encrypt_decrypt_ciphertext_2() {
        // test decryption
        let (plaintext_2, plaintext_2_len) =
            encrypt_decrypt_ciphertext_2(&PRK_2E_TV, &TH_2_TV, &CIPHERTEXT_2_TV);

        assert_eq!(plaintext_2_len, PLAINTEXT_2_LEN);
        for i in 0..PLAINTEXT_2_LEN {
            assert_eq!(plaintext_2[i], PLAINTEXT_2_TV[i]);
        }

        let mut plaintext_2_tmp: BytesCiphertext2 = [0x00u8; CIPHERTEXT_2_LEN];
        plaintext_2_tmp[..plaintext_2_len].copy_from_slice(&plaintext_2[..plaintext_2_len]);

        // test encryption
        let (ciphertext_2, ciphertext_2_len) =
            encrypt_decrypt_ciphertext_2(&PRK_2E_TV, &TH_2_TV, &plaintext_2_tmp);

        assert_eq!(ciphertext_2_len, CIPHERTEXT_2_LEN);
        for i in 0..CIPHERTEXT_2_LEN {
            assert_eq!(ciphertext_2[i], CIPHERTEXT_2_TV[i]);
        }
    }

    #[test]
    fn test_compute_prk_4e3m() {
        let prk_4e3m = compute_prk_4e3m(&SALT_4E3M_TV, &I_TV, &G_Y_TV);
        assert_eq!(prk_4e3m, PRK_4E3M_TV);
    }

    #[test]
    fn test_compute_prk_3e2m() {
        let prk_3e2m = compute_prk_3e2m(&SALT_3E2M_TV, &X_TV, &G_R_TV);
        assert_eq!(prk_3e2m, PRK_3E2M_TV);
    }

    #[test]
    fn test_compute_prk_2e() {
        let prk_2e = compute_prk_2e(&X_TV, &G_Y_TV, &TH_2_TV);
        assert_eq!(prk_2e, PRK_2E_TV);
    }

    #[test]
    fn test_encode_plaintext_3() {
        let plaintext_3 = encode_plaintext_3(&ID_CRED_I_TV, &MAC_3_TV);
        assert_eq!(plaintext_3, PLAINTEXT_3_TV);
    }

    #[test]
    fn test_decode_plaintext_3() {
        let kid_tv = ID_CRED_I_TV[ID_CRED_I_TV.len() - 1];

        let (kid, mac_3) = decode_plaintext_3(&PLAINTEXT_3_TV);

        assert_eq!(mac_3, MAC_3_TV);
        assert_eq!(kid, kid_tv);
    }
}
