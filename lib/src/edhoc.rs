#![no_std]

use edhoc_consts::*;
use edhoc_crypto::*;
use edhoc_ead::*;

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
    message_1: &BufferMessage1,
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
        let res = parse_message_1(message_1);

        if res.is_ok() {
            let (method, suites_i, suites_i_len, g_x, c_i, ead_1) = res.unwrap();
            // verify that the method is supported
            if method == EDHOC_METHOD {
                // Step 2: verify that the selected cipher suite is supported
                if suites_i[suites_i_len - 1] == EDHOC_SUPPORTED_SUITES[0] {
                    // Step 3: If EAD is present make it available to the application
                    let ead_success = if let Some(ead_1) = ead_1 {
                        r_process_ead_1(ead_1).is_ok()
                    } else {
                        true
                    };
                    if ead_success {
                        // hash message_1 and save the hash to the state to avoid saving the whole message
                        let mut message_1_buf: BytesMaxBuffer = [0x00; MAX_BUFFER_LEN];
                        message_1_buf[..message_1.len]
                            .copy_from_slice(&message_1.content[..message_1.len]);
                        h_message_1 = sha256_digest(&message_1_buf, message_1.len);

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
                        error = EDHOCError::EADError;
                    }
                } else {
                    error = EDHOCError::UnsupportedCipherSuite;
                }
            } else {
                error = EDHOCError::UnsupportedMethod;
            }
        } else {
            error = res.unwrap_err();
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
) -> Result<(State, BufferMessage2, U8), EDHOCError> {
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
    let mut message_2: BufferMessage2 = BufferMessage2::new();
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

        let ead_2 = r_prepare_ead_2();

        // compute ciphertext_2
        let plaintext_2 = encode_plaintext_2(id_cred_r, &mac_2, &ead_2);

        // step is actually from processing of message_3
        // but we do it here to avoid storing plaintext_2 in State
        th_3 = compute_th_3(&th_2, &plaintext_2, cred_r, cred_r_len);

        let mut ct: BufferCiphertext2 = BufferCiphertext2::new();
        ct.len = plaintext_2.len;
        ct.content[..ct.len].copy_from_slice(&plaintext_2.content[..ct.len]);

        let (ciphertext_2, ciphertext_2_len) = encrypt_decrypt_ciphertext_2(&prk_2e, &th_2, &ct);

        ct.content[..ct.len].copy_from_slice(&ciphertext_2[..ct.len]);

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
    message_3: &BufferMessage3,
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
            let decoded_p3_res = decode_plaintext_3(&plaintext_3);

            if decoded_p3_res.is_ok() {
                let (kid, mac_3, ead_3) = decoded_p3_res.unwrap();

                // Step 3: If EAD is present make it available to the application
                let ead_success = if let Some(ead_3) = ead_3 {
                    r_process_ead_3(ead_3).is_ok()
                } else {
                    true
                };
                if ead_success {
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
                            let th_4 =
                                compute_th_4(&th_3, &plaintext_3, cred_i_expected, cred_i_len);

                            let mut th_4_buf: BytesMaxContextBuffer = [0x00; MAX_KDF_CONTEXT_LEN];
                            th_4_buf[..th_4.len()].copy_from_slice(&th_4[..]);
                            // compute prk_out
                            // PRK_out = EDHOC-KDF( PRK_4e3m, 7, TH_4, hash_length )
                            let prk_out_buf =
                                edhoc_kdf(&prk_4e3m, 7u8, &th_4_buf, th_4.len(), SHA256_DIGEST_LEN);
                            prk_out[..SHA256_DIGEST_LEN]
                                .copy_from_slice(&prk_out_buf[..SHA256_DIGEST_LEN]);

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
                    error = EDHOCError::EADError;
                }
            } else {
                error = decoded_p3_res.unwrap_err();
            }
        } else {
            // error handling for err = decrypt_message_3(&prk_3e2m, &th_3, message_3);
            error = plaintext_3.unwrap_err();
        }
    } else {
        error = EDHOCError::WrongState;
    }

    match error {
        EDHOCError::Success => Ok((state, prk_out)),
        _ => Err(error),
    }
}

pub fn i_prepare_message_1(
    mut state: State,
    x: BytesP256ElemLen,
    g_x: BytesP256ElemLen,
) -> Result<(State, BufferMessage1), EDHOCError> {
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

    let mut message_1: BufferMessage1 = BufferMessage1::new();

    if current_state == EDHOCState::Start {
        // we only support a single cipher suite which is already CBOR-encoded
        let mut suites_i: BytesSuites = [0x0; SUITES_LEN];
        suites_i[0..EDHOC_SUPPORTED_SUITES.len()].copy_from_slice(&EDHOC_SUPPORTED_SUITES[..]);

        // Choose a connection identifier C_I and store it for the length of the protocol.
        c_i = C_I;

        let ead_1 = i_prepare_ead_1();

        // Encode message_1 as a sequence of CBOR encoded data items as specified in Section 5.2.1
        message_1 = encode_message_1(
            EDHOC_METHOD,
            &suites_i,
            EDHOC_SUPPORTED_SUITES.len(),
            &g_x,
            c_i,
            &ead_1,
        );

        let mut message_1_buf: BytesMaxBuffer = [0x00; MAX_BUFFER_LEN];
        message_1_buf[..message_1.len].copy_from_slice(&message_1.content[..message_1.len]);

        // hash message_1 here to avoid saving the whole message in the state
        h_message_1 = sha256_digest(&message_1_buf, message_1.len);
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

// returns c_r
pub fn i_process_message_2(
    mut state: State,
    message_2: &BufferMessage2,
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
        let res = parse_message_2(message_2);
        if res.is_ok() {
            let (g_y, ciphertext_2, c_r_2) = res.unwrap();
            c_r = c_r_2;

            let th_2 = compute_th_2(&g_y, c_r, &h_message_1);

            // compute prk_2e
            let prk_2e = compute_prk_2e(&x, &g_y, &th_2);

            let (plaintext_2, plaintext_2_len) =
                encrypt_decrypt_ciphertext_2(&prk_2e, &th_2, &ciphertext_2);

            // decode plaintext_2
            let plaintext_2_decoded = decode_plaintext_2(&plaintext_2, plaintext_2_len);

            if plaintext_2_decoded.is_ok() {
                let (kid, mac_2, ead_2) = plaintext_2_decoded.unwrap();

                // Step 3: If EAD is present make it available to the application
                let ead_success = if let Some(ead_2) = ead_2 {
                    i_process_ead_2(ead_2).is_ok()
                } else {
                    true
                };
                if ead_success {
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
                            let mut pt2: BufferPlaintext2 = BufferPlaintext2::new();
                            pt2.content[..plaintext_2_len]
                                .copy_from_slice(&plaintext_2[..plaintext_2_len]);
                            pt2.len = plaintext_2_len;
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
                    error = EDHOCError::EADError;
                }
            } else {
                error = EDHOCError::ParsingError;
            }
        } else {
            error = res.unwrap_err();
        }
    } else {
        error = EDHOCError::WrongState;
    }

    match error {
        EDHOCError::Success => Ok((state, c_r, kid)),
        _ => Err(error),
    }
}

pub fn i_prepare_message_3(
    mut state: State,
    id_cred_i: &BytesIdCred,
    cred_i: &BytesMaxBuffer,
    cred_i_len: usize,
) -> Result<(State, BufferMessage3, BytesHashLen), EDHOCError> {
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
    let mut message_3: BufferMessage3 = BufferMessage3::new();

    if current_state == EDHOCState::ProcessedMessage2 {
        let mac_3 = compute_mac_3(&prk_4e3m, &th_3, id_cred_i, cred_i, cred_i_len);

        let ead_3 = i_prepare_ead_3();

        let plaintext_3 = encode_plaintext_3(id_cred_i, &mac_3, &ead_3);
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

fn parse_suites_i(
    rcvd_message_1: &BufferMessage1,
) -> Result<(BytesSuites, usize, usize), EDHOCError> {
    let mut error: EDHOCError = EDHOCError::UnknownError;
    let mut raw_suites_len = 0;
    let mut suites_i = [0u8; SUITES_LEN];
    let mut suites_i_len: usize = 0;

    // match based on first byte of SUITES_I, which can be either an int or an array
    match rcvd_message_1.content[1] {
        // CBOR unsigned integer (0..=23)
        0x00..=0x17 => {
            suites_i[0] = rcvd_message_1.content[1];
            suites_i_len = 1;
            raw_suites_len = 1;
            error = EDHOCError::Success;
        }
        // CBOR unsigned integer (one-byte uint8_t follows)
        0x18 => {
            suites_i[0] = rcvd_message_1.content[2];
            suites_i_len = 1;
            raw_suites_len = 2;
            error = EDHOCError::Success;
        }
        // CBOR array (0..=23 data items follow)
        0x80..=0x97 => {
            // the CBOR array length is encoded in the first byte, so we extract it
            let suites_len: usize = (rcvd_message_1.content[1] - CBOR_MAJOR_ARRAY).into();
            raw_suites_len = 1; // account for the CBOR_MAJOR_ARRAY byte
            if suites_len <= EDHOC_SUITES.len() {
                let mut j: usize = 0; // index for addressing cipher suites
                while j < suites_len {
                    raw_suites_len += 1;
                    // match based on cipher suite identifier
                    match rcvd_message_1.content[raw_suites_len] {
                        // CBOR unsigned integer (0..23)
                        0x00..=0x17 => {
                            suites_i[j] = rcvd_message_1.content[raw_suites_len];
                            suites_i_len += 1;
                        }
                        // CBOR unsigned integer (one-byte uint8_t follows)
                        0x18 => {
                            raw_suites_len += 1; // account for the 0x18 tag byte
                            suites_i[j] = rcvd_message_1.content[raw_suites_len];
                            suites_i_len += 1;
                        }
                        _ => {
                            error = EDHOCError::ParsingError;
                            break;
                        }
                    }
                    j += 1;
                }
                error = EDHOCError::Success;
            } else {
                error = EDHOCError::ParsingError;
            }
        }
        _ => error = EDHOCError::ParsingError,
    };

    match error {
        EDHOCError::Success => Ok((suites_i, suites_i_len, raw_suites_len)),
        _ => Err(error),
    }
}

fn parse_ead(message: &EdhocMessageBuffer, offset: usize) -> Result<Option<EADItem>, EDHOCError> {
    let mut error: EDHOCError = EDHOCError::UnknownError;
    let mut ead_item = None::<EADItem>;
    let mut ead_value = None::<EdhocMessageBuffer>;

    // assuming label is a single byte integer (negative or positive)
    let label = message.content[offset];
    let res_label = match label {
        // CBOR unsigned integer (0..=23)
        label @ 0x00..=0x17 => Ok((label as u8, false)),
        // CBOR negative integer (-1..=-24)
        label @ 0x20..=0x37 => Ok((label - (CBOR_NEG_INT_1BYTE_START - 1), true)),
        _ => Err(EDHOCError::ParsingError),
    };

    if res_label.is_ok() {
        let (label, is_critical) = res_label.unwrap();
        if message.len > (offset + 1) { // EAD value is present
            let mut buffer = EdhocMessageBuffer::new();
            buffer.content[..message.len - (offset + 1)]
                .copy_from_slice(&message.content[offset + 1..message.len]);
            buffer.len = message.len - (offset + 1);
            ead_value = Some(buffer);
        }
        ead_item = Some(EADItem {
            label,
            is_critical,
            value: ead_value,
        });
        error = EDHOCError::Success;
    } else {
        error = res_label.unwrap_err();
    }

    match error {
        EDHOCError::Success => Ok(ead_item),
        _ => Err(error),
    }
}

fn parse_message_1(
    rcvd_message_1: &BufferMessage1,
) -> Result<
    (
        U8,
        BytesSuites,
        usize,
        BytesP256ElemLen,
        U8,
        Option<EADItem>,
    ),
    EDHOCError,
> {
    let mut error: EDHOCError = EDHOCError::UnknownError;
    let mut g_x: BytesP256ElemLen = [0x00; P256_ELEM_LEN];
    let mut suites_i: BytesSuites = [0u8; SUITES_LEN];
    let mut suites_i_len: usize = 0;
    let mut raw_suites_len: usize = 0;
    let mut c_i = 0;
    let mut ead_1 = None::<EADItem>;

    let method = rcvd_message_1.content[0];

    let res_suites = parse_suites_i(rcvd_message_1);

    if res_suites.is_ok() {
        (suites_i, suites_i_len, raw_suites_len) = res_suites.unwrap();

        g_x.copy_from_slice(
            &rcvd_message_1.content[3 + raw_suites_len..3 + raw_suites_len + P256_ELEM_LEN],
        );

        c_i = rcvd_message_1.content[3 + raw_suites_len + P256_ELEM_LEN];

        // if there is still more to parse, the rest will be the EAD_1
        if rcvd_message_1.len > (4 + raw_suites_len + P256_ELEM_LEN) {
            // NOTE: since the current implementation only supports one EAD handler,
            // we assume only one EAD item
            let ead_res = parse_ead(rcvd_message_1, 4 + raw_suites_len + P256_ELEM_LEN);
            if ead_res.is_ok() {
                ead_1 = ead_res.unwrap();
                error = EDHOCError::Success;
            } else {
                error = ead_res.unwrap_err();
            }
        } else if rcvd_message_1.len == (4 + raw_suites_len + P256_ELEM_LEN) {
            error = EDHOCError::Success;
        } else {
            error = EDHOCError::ParsingError;
        }
    } else {
        error = res_suites.unwrap_err();
    }

    match error {
        EDHOCError::Success => Ok((method, suites_i, suites_i_len, g_x, c_i, ead_1)),
        _ => Err(error),
    }
}

fn encode_ead_item(ead_1: &EADItem) -> EdhocMessageBuffer {
    let mut output = EdhocMessageBuffer::new();

    // encode label
    if ead_1.is_critical {
        output.content[0] = ead_1.label + CBOR_NEG_INT_1BYTE_START - 1;
    } else {
        output.content[0] = ead_1.label;
    }
    output.len = 1;

    // encode value
    if let Some(ead_1_value) = &ead_1.value {
        output.content[1..1 + ead_1_value.len]
            .copy_from_slice(&ead_1_value.content[..ead_1_value.len]);
        output.len += ead_1_value.len;
    }

    output
}

fn encode_message_1(
    method: U8,
    suites: &BytesSuites,
    suites_len: usize,
    g_x: &BytesP256ElemLen,
    c_i: U8,
    ead_1: &Option<EADItem>,
) -> BufferMessage1 {
    let mut output = BufferMessage1::new();
    let mut raw_suites_len: usize = 0;

    output.content[0] = method; // CBOR unsigned int less than 24 is encoded verbatim

    if suites_len == 1 {
        // only one suite, will be encoded as a single integer
        if suites[0] <= CBOR_UINT_1BYTE {
            output.content[1] = suites[0];
            raw_suites_len = 1;
        } else {
            output.content[1] = CBOR_UINT_1BYTE;
            output.content[2] = suites[0]; // assume it is smaller than 255, which all suites are
            raw_suites_len = 2;
        }
    } else {
        // several suites, will be encoded as an array
        output.content[1] = CBOR_MAJOR_ARRAY + (suites_len as u8);
        raw_suites_len += 1;
        let mut i: usize = 0;
        while i < suites_len {
            if suites[i] <= CBOR_UINT_1BYTE {
                output.content[1 + raw_suites_len] = suites[i];
                raw_suites_len += 1;
            } else {
                output.content[1 + raw_suites_len] = CBOR_UINT_1BYTE;
                output.content[2 + raw_suites_len] = suites[i];
                raw_suites_len += 2;
            }
            i += 1;
        }
    };

    output.content[1 + raw_suites_len] = CBOR_BYTE_STRING; // CBOR byte string magic number
    output.content[2 + raw_suites_len] = P256_ELEM_LEN as u8; // length of the byte string
    output.content[3 + raw_suites_len..3 + raw_suites_len + P256_ELEM_LEN]
        .copy_from_slice(&g_x[..]);
    output.content[3 + raw_suites_len + P256_ELEM_LEN] = c_i;
    output.len = 3 + raw_suites_len + P256_ELEM_LEN + 1;

    if let Some(ead_1) = ead_1 {
        let ead_1 = encode_ead_item(ead_1);
        output.content[output.len..output.len + ead_1.len]
            .copy_from_slice(&ead_1.content[..ead_1.len]);
        output.len += ead_1.len;
    }

    output
}

fn parse_message_2(
    rcvd_message_2: &BufferMessage2,
    // ) -> Result<(BytesP256ElemLen, BufferCiphertext2, U8), EDHOCError> {
) -> Result<(BytesP256ElemLen, BufferCiphertext2, U8), EDHOCError> {
    // FIXME decode negative integers as well
    let mut g_y: BytesP256ElemLen = [0x00; P256_ELEM_LEN];
    g_y[..].copy_from_slice(&rcvd_message_2.content[2..2 + P256_ELEM_LEN]);

    let mut ciphertext_2: BufferCiphertext2 = BufferCiphertext2::new();
    ciphertext_2.len = rcvd_message_2.len - 1 - P256_ELEM_LEN - 2; // len - cr_len - gy_len - 2
    ciphertext_2.content[..ciphertext_2.len].copy_from_slice(
        &rcvd_message_2.content[2 + P256_ELEM_LEN..2 + P256_ELEM_LEN + ciphertext_2.len],
    );

    let c_r = rcvd_message_2.content[2 + P256_ELEM_LEN + ciphertext_2.len];

    Ok((g_y, ciphertext_2, c_r))
}

fn encode_message_2(
    g_y: &BytesP256ElemLen,
    ciphertext_2: &BufferCiphertext2,
    c_r: U8,
) -> BufferMessage2 {
    let mut output: BufferMessage2 = BufferMessage2::new();

    output.content[0] = CBOR_BYTE_STRING;
    output.content[1] = P256_ELEM_LEN as u8 + ciphertext_2.len as u8;
    output.content[2..2 + P256_ELEM_LEN].copy_from_slice(&g_y[..]);
    output.content[2 + P256_ELEM_LEN..2 + P256_ELEM_LEN + ciphertext_2.len]
        .copy_from_slice(&ciphertext_2.content[..ciphertext_2.len]);
    output.content[2 + P256_ELEM_LEN + ciphertext_2.len] = c_r;

    output.len = 2 + P256_ELEM_LEN + ciphertext_2.len + 1;
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
    plaintext_2: &BufferPlaintext2,
    cred_r: &BytesMaxBuffer,
    cred_r_len: usize,
) -> BytesHashLen {
    let mut message: BytesMaxBuffer = [0x00; MAX_BUFFER_LEN];

    message[0] = CBOR_BYTE_STRING;
    message[1] = th_2.len() as u8;
    message[2..2 + th_2.len()].copy_from_slice(&th_2[..]);
    message[2 + th_2.len()..2 + th_2.len() + plaintext_2.len]
        .copy_from_slice(&plaintext_2.content[..plaintext_2.len]);
    message[2 + th_2.len() + plaintext_2.len..2 + th_2.len() + plaintext_2.len + cred_r_len]
        .copy_from_slice(&cred_r[..cred_r_len]);

    let output = sha256_digest(&message, th_2.len() + 2 + plaintext_2.len + cred_r_len);

    output
}

fn compute_th_4(
    th_3: &BytesHashLen,
    plaintext_3: &BufferPlaintext3,
    cred_i: &BytesMaxBuffer,
    cred_i_len: usize,
) -> BytesHashLen {
    let mut message: BytesMaxBuffer = [0x00; MAX_BUFFER_LEN];

    message[0] = CBOR_BYTE_STRING;
    message[1] = th_3.len() as u8;
    message[2..2 + th_3.len()].copy_from_slice(&th_3[..]);
    message[2 + th_3.len()..2 + th_3.len() + plaintext_3.len]
        .copy_from_slice(&plaintext_3.content[..plaintext_3.len]);
    message[2 + th_3.len() + plaintext_3.len..2 + th_3.len() + plaintext_3.len + cred_i_len]
        .copy_from_slice(&cred_i[..cred_i_len]);

    let output = sha256_digest(&message, th_3.len() + 2 + plaintext_3.len + cred_i_len);

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

fn decode_plaintext_3(
    plaintext_3: &BufferPlaintext3,
) -> Result<(U8, BytesMac3, Option<EADItem>), EDHOCError> {
    let mut ead_3 = None::<EADItem>;
    let mut error = EDHOCError::UnknownError;

    let kid = plaintext_3.content[0usize];
    // skip the CBOR magic byte as we know how long the MAC is
    let mut mac_3: BytesMac3 = [0x00; MAC_LENGTH_3];
    mac_3[..].copy_from_slice(&plaintext_3.content[2..2 + MAC_LENGTH_3]);

    // if there is still more to parse, the rest will be the EAD_3
    if plaintext_3.len > (2 + MAC_LENGTH_3) {
        // NOTE: since the current implementation only supports one EAD handler,
        // we assume only one EAD item
        let ead_res = parse_ead(plaintext_3, 2 + MAC_LENGTH_3);
        if ead_res.is_ok() {
            ead_3 = ead_res.unwrap();
            error = EDHOCError::Success;
        } else {
            error = ead_res.unwrap_err();
        }
    } else if plaintext_3.len == (2 + MAC_LENGTH_3) {
        error = EDHOCError::Success;
    } else {
        error = EDHOCError::ParsingError;
    }

    match error {
        EDHOCError::Success => Ok((kid, mac_3, ead_3)),
        _ => Err(error),
    }
}

fn encode_plaintext_3(
    id_cred_i: &BytesIdCred,
    mac_3: &BytesMac3,
    ead_3: &Option<EADItem>,
) -> BufferPlaintext3 {
    let mut plaintext_3: BufferPlaintext3 = BufferPlaintext3::new();

    // plaintext: P = ( ? PAD, ID_CRED_I / bstr / int, Signature_or_MAC_3, ? EAD_3 )
    plaintext_3.content[0] = id_cred_i[id_cred_i.len() - 1]; // hack: take the last byte of ID_CRED_I as KID
    plaintext_3.content[1] = CBOR_MAJOR_BYTE_STRING | MAC_LENGTH_3 as u8;
    plaintext_3.content[2..2 + mac_3.len()].copy_from_slice(&mac_3[..]);
    plaintext_3.len = 2 + mac_3.len();

    if let Some(ead_3) = ead_3 {
        let ead_3 = encode_ead_item(ead_3);
        plaintext_3.content[plaintext_3.len..plaintext_3.len + ead_3.len]
            .copy_from_slice(&ead_3.content[..ead_3.len]);
        plaintext_3.len += ead_3.len;
    }

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
fn encrypt_message_3(
    prk_3e2m: &BytesHashLen,
    th_3: &BytesHashLen,
    plaintext_3: &BufferPlaintext3,
) -> BufferMessage3 {
    let mut output: BufferMessage3 = BufferMessage3::new();
    output.len = 1 + plaintext_3.len + AES_CCM_TAG_LEN;
    output.content[0] = CBOR_MAJOR_BYTE_STRING | (plaintext_3.len + AES_CCM_TAG_LEN) as u8; // FIXME if plaintext_3.len + AES_CCM_TAG_LEN > 23, then should use CBOR_BYTE_STRING

    let enc_structure = encode_enc_structure(th_3);

    let (k_3, iv_3) = compute_k_3_iv_3(prk_3e2m, th_3);

    let ciphertext_3 = aes_ccm_encrypt_tag_8(&k_3, &iv_3, &enc_structure, plaintext_3);

    output.content[1..output.len].copy_from_slice(&ciphertext_3.content[..ciphertext_3.len]);

    output
}

fn decrypt_message_3(
    prk_3e2m: &BytesHashLen,
    th_3: &BytesHashLen,
    message_3: &BufferMessage3,
) -> Result<BufferPlaintext3, EDHOCError> {
    let mut error = EDHOCError::UnknownError;
    let mut plaintext_3: BufferPlaintext3 = BufferPlaintext3::new();

    // decode message_3
    let len = (message_3.content[0usize] ^ CBOR_MAJOR_BYTE_STRING) as usize;

    let mut ciphertext_3: BufferCiphertext3 = BufferCiphertext3::new();
    ciphertext_3.len = len;
    ciphertext_3.content[..len].copy_from_slice(&message_3.content[1..1 + len]);

    let (k_3, iv_3) = compute_k_3_iv_3(prk_3e2m, th_3);

    let enc_structure = encode_enc_structure(th_3);

    let p3 = aes_ccm_decrypt_tag_8(&k_3, &iv_3, &enc_structure, &ciphertext_3);

    if p3.is_ok() {
        error = EDHOCError::Success;
        let p3 = p3.unwrap();
        plaintext_3.content[..p3.len].copy_from_slice(&p3.content[..p3.len]);
        plaintext_3.len = p3.len;
    } else {
        error = p3.unwrap_err();
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
) -> Result<(U8, BytesMac2, Option<EADItem>), EDHOCError> {
    let mut error = EDHOCError::UnknownError;
    let mut ead_2 = None::<EADItem>;

    let id_cred_r = plaintext_2[0];
    // skip cbor byte string byte as we know how long the string is
    let mut mac_2: BytesMac2 = [0x00; MAC_LENGTH_2];
    mac_2[..].copy_from_slice(&plaintext_2[2..2 + MAC_LENGTH_2]);

    // if there is still more to parse, the rest will be the EAD_2
    if plaintext_2_len > (2 + MAC_LENGTH_2) {
        // NOTE: since the current implementation only supports one EAD handler,
        // we assume only one EAD item
        let ead_res = parse_ead(
            &plaintext_2[..plaintext_2_len]
                .try_into()
                .expect("too long"),
            2 + MAC_LENGTH_2,
        );
        if ead_res.is_ok() {
            ead_2 = ead_res.unwrap();
            error = EDHOCError::Success;
        } else {
            error = ead_res.unwrap_err();
        }
    } else if plaintext_2_len == (2 + MAC_LENGTH_2) {
        error = EDHOCError::Success;
    } else {
        error = EDHOCError::ParsingError;
    }

    match error {
        EDHOCError::Success => Ok((id_cred_r, mac_2, ead_2)),
        _ => Err(error),
    }
}

fn encode_plaintext_2(
    id_cred_r: &BytesIdCred,
    mac_2: &BytesMac2,
    ead_2: &Option<EADItem>,
) -> BufferPlaintext2 {
    let mut plaintext_2: BufferPlaintext2 = BufferPlaintext2::new();
    plaintext_2.content[0] = id_cred_r[id_cred_r.len() - 1];
    plaintext_2.content[1] = CBOR_MAJOR_BYTE_STRING | MAC_LENGTH_2 as u8;
    plaintext_2.content[2..2 + mac_2.len()].copy_from_slice(&mac_2[..]);
    plaintext_2.len = 2 + mac_2.len();

    if let Some(ead_2) = ead_2 {
        let ead_2 = encode_ead_item(ead_2);
        plaintext_2.content[plaintext_2.len..plaintext_2.len + ead_2.len]
            .copy_from_slice(&ead_2.content[..ead_2.len]);
        plaintext_2.len += ead_2.len;
    }

    plaintext_2
}

fn encrypt_decrypt_ciphertext_2(
    prk_2e: &BytesHashLen,
    th_2: &BytesHashLen,
    ciphertext_2: &BufferCiphertext2,
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
        ciphertext_2.len,
    );

    let mut plaintext_2: BytesMaxBuffer = [0x00; MAX_BUFFER_LEN];
    // decrypt/encrypt ciphertext_2
    for i in 0..ciphertext_2.len {
        plaintext_2[i] = ciphertext_2.content[i] ^ keystream_2[i];
    }

    (plaintext_2, ciphertext_2.len)
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
    const SUPPORTED_SUITES_I_TV: BytesSupportedSuites = hex!("02");
    const SUITES_I_TV: BytesSuites = hex!("060200000000000000");
    const G_X_TV: BytesP256ElemLen =
        hex!("8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6");
    const C_I_TV: u8 = 0x37;
    const MESSAGE_1_TV: &str =
        "0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637";
    // below are a few truncated messages for the purpose of testing cipher suites
    // message with one cipher suite (23..=255)
    const MESSAGE_1_TV_SUITE_ONLY_A: &str = "031818";
    // message with an array having two cipher suites with small values (0..=23)
    const MESSAGE_1_TV_SUITE_ONLY_B: &str = "03820201";
    // message with an array having two cipher suites, where one is a large value (23..=255)
    const MESSAGE_1_TV_SUITE_ONLY_C: &str = "0382021819";
    // message with an array having too many cipher suites (more than 9)
    const MESSAGE_1_TV_SUITE_ONLY_ERR: &str = "038A02020202020202020202";
    const EAD_DUMMY_LABEL_TV: u8 = 0x01;
    const EAD_DUMMY_VALUE_TV: &str = "cccccc";
    const EAD_DUMMY_CRITICAL_TV: &str = "20cccccc";
    const MESSAGE_1_WITH_DUMMY_EAD_NO_VALUE_TV: &str =
        "0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b63701";
    const MESSAGE_1_WITH_DUMMY_EAD_TV: &str =
        "0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b63701cccccc";
    const MESSAGE_1_WITH_DUMMY_CRITICAL_EAD_TV: &str =
        "0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b63720cccccc";
    const PLAINTEXT_2_WITH_DUMMY_CRITICAL_EAD_TV: &str = "3248d0d1a594797d0aaf20cccccc";
    const PLAINTEXT_3_WITH_DUMMY_CRITICAL_EAD_TV: &str = "2b48ddf106b86fd22fe420cccccc";
    const G_Y_TV: BytesP256ElemLen =
        hex!("419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5");
    const C_R_TV: u8 = 0x27;
    const MESSAGE_2_TV: &str = "582a419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5042459e2da6c75143f3527";
    const CIPHERTEXT_2_TV: &str = "042459e2da6c75143f35";
    const H_MESSAGE_1_TV: BytesHashLen =
        hex!("ca02cabda5a8902749b42f711050bb4dbd52153e87527594b39f50cdf019888c");
    const TH_2_TV: BytesHashLen =
        hex!("9d2af3a3d3fc06aea8110f14ba12ad0b4fb7e5cdf59c7df1cf2dfe9c2024439c");
    const TH_3_TV: BytesHashLen =
        hex!("b778f602331ff68ac402a6511b9de285bedf6eab3e9ed12dfe22a53eeda7de48");
    const CIPHERTEXT_3_TV: &str = "c2b62835dc9b1f53419c1d3a2261eeed3505";
    const TH_4_TV: BytesHashLen =
        hex!("1f57dabf8f26da0657d9840c9b1077c1d4c47db243a8b41360a98ec4cb706b70");
    const PRK_2E_TV: BytesP256ElemLen =
        hex!("e01fa14dd56e308267a1a812a9d0b95341e394abc7c5c39dd71885f7d4cd5bf3");
    const CIPHERTEXT_2_LEN_TV: usize = MESSAGE_2_TV.len() / 2 - P256_ELEM_LEN - 1 - 2;
    const PLAINTEXT_2_LEN_TV: usize = CIPHERTEXT_2_LEN_TV;
    const KEYSTREAM_2_TV: [u8; PLAINTEXT_2_LEN_TV] = hex!("366c89337ff80c69359a");
    const PRK_3E2M_TV: BytesP256ElemLen =
        hex!("412d60cdf99dc7490754c969ad4c46b1350b908433ebf3fe063be8627fb35b3b");
    const CONTEXT_INFO_MAC_2_TV: [u8; 133] = hex!("a104413258209d2af3a3d3fc06aea8110f14ba12ad0b4fb7e5cdf59c7df1cf2dfe9c2024439ca2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
    const MAC_2_TV: BytesMac2 = hex!("d0d1a594797d0aaf");
    const ID_CRED_I_TV: BytesIdCred = hex!("a104412b");
    const MAC_3_TV: BytesMac3 = hex!("ddf106b86fd22fe4");
    const MESSAGE_3_TV: &str = "52c2b62835dc9b1f53419c1d3a2261eeed3505";
    const PRK_4E3M_TV: BytesP256ElemLen =
        hex!("7d0159bbe45473c9402e0d42dbceb45dca05b744cae1e083e58315b8aa47ceec");
    const CRED_I_TV : [u8; 107] = hex!("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
    const ID_CRED_R_TV: BytesIdCred = hex!("a1044132");
    const CRED_R_TV : [u8; 95] = hex!("A2026B6578616D706C652E65647508A101A501020241322001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");
    const PLAINTEXT_2_TV: &str = "3248d0d1a594797d0aaf";
    const I_TV: BytesP256ElemLen =
        hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
    const X_TV: BytesP256ElemLen =
        hex!("368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525");
    const G_R_TV: BytesP256ElemLen =
        hex!("bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0");
    const PLAINTEXT_3_TV: &str = "2b48ddf106b86fd22fe4";
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
        let suites_i_tv_len: usize = 2;
        let message_1 = encode_message_1(
            METHOD_TV,
            &SUITES_I_TV,
            suites_i_tv_len,
            &G_X_TV,
            C_I_TV,
            &None::<EADItem>,
        );

        assert_eq!(message_1.len, 39);
        assert_eq!(message_1, BufferMessage1::from_hex(MESSAGE_1_TV));
    }

    #[test]
    fn test_parse_suites_i() {
        let message_1_tv = BufferMessage1::from_hex(MESSAGE_1_TV);

        let res = parse_suites_i(&message_1_tv);
        assert!(res.is_ok());
        let (suites_i, suites_i_len, raw_suites_len) = res.unwrap();
        assert_eq!(suites_i, SUITES_I_TV);

        let res = parse_suites_i(&BufferMessage1::from_hex(MESSAGE_1_TV_SUITE_ONLY_A));
        assert!(res.is_ok());
        let (suites_i, suites_i_len, raw_suites_len) = res.unwrap();
        assert_eq!(suites_i[0], 0x18);

        let (suites_i, suites_i_len, raw_suites_len) =
            parse_suites_i(&BufferMessage1::from_hex(MESSAGE_1_TV_SUITE_ONLY_B)).unwrap();
        assert_eq!(suites_i_len, 2);
        assert_eq!(raw_suites_len, 3);
        assert_eq!(suites_i[0], 0x02);
        assert_eq!(suites_i[1], 0x01);

        let (suites_i, suites_i_len, raw_suites_len) =
            parse_suites_i(&BufferMessage1::from_hex(MESSAGE_1_TV_SUITE_ONLY_C)).unwrap();
        assert_eq!(suites_i_len, 2);
        assert_eq!(raw_suites_len, 4);
        assert_eq!(suites_i[0], 0x02);
        assert_eq!(suites_i[1], 0x19);

        let res = parse_suites_i(&BufferMessage1::from_hex(MESSAGE_1_TV_SUITE_ONLY_ERR));
        assert_eq!(res.unwrap_err(), EDHOCError::ParsingError);
    }

    #[test]
    fn test_parse_message_1() {
        let message_1_tv = BufferMessage1::from_hex(MESSAGE_1_TV);

        let res = parse_message_1(&message_1_tv);
        assert!(res.is_ok());
        let (method, suites_i, suites_i_len, g_x, c_i, ead_1) = res.unwrap();

        assert_eq!(method, METHOD_TV);
        assert_eq!(suites_i, SUITES_I_TV);
        assert_eq!(g_x, G_X_TV);
        assert_eq!(c_i, C_I_TV);
        assert!(ead_1.is_none());
    }

    #[test]
    fn test_encode_message_2() {
        let ciphertext_2_tv = BufferCiphertext2::from_hex(CIPHERTEXT_2_TV);
        let message_2 = encode_message_2(&G_Y_TV, &ciphertext_2_tv, C_R_TV);

        assert_eq!(message_2, BufferMessage2::from_hex(MESSAGE_2_TV));
    }

    #[test]
    fn test_parse_message_2() {
        let ciphertext_2_tv = BufferCiphertext2::from_hex(CIPHERTEXT_2_TV);
        let ret = parse_message_2(&BufferMessage2::from_hex(MESSAGE_2_TV));
        assert!(ret.is_ok());
        let (g_y, ciphertext_2, c_r) = ret.unwrap();

        assert_eq!(g_y, G_Y_TV);
        assert_eq!(ciphertext_2, ciphertext_2_tv);
        assert_eq!(c_r, C_R_TV);
    }

    #[test]
    fn test_compute_th_2() {
        let th_2 = compute_th_2(&G_Y_TV, C_R_TV, &H_MESSAGE_1_TV);
        assert_eq!(th_2, TH_2_TV);
    }

    #[test]
    fn test_compute_th_3() {
        let plaintext_2_tv = BufferPlaintext2::from_hex(PLAINTEXT_2_TV);
        let mut cred_r_tv: BytesMaxBuffer = [0x00u8; MAX_BUFFER_LEN];
        cred_r_tv[..CRED_R_TV.len()].copy_from_slice(&CRED_R_TV[..]);

        let th_3 = compute_th_3(&TH_2_TV, &plaintext_2_tv, &cred_r_tv, CRED_R_TV.len());
        assert_eq!(th_3, TH_3_TV);
    }

    #[test]
    fn test_compute_th_4() {
        let plaintext_3_tv = BufferPlaintext3::from_hex(PLAINTEXT_3_TV);
        let mut cred_i_tv: BytesMaxBuffer = [0x00u8; MAX_BUFFER_LEN];
        cred_i_tv[..CRED_I_TV.len()].copy_from_slice(&CRED_I_TV[..]);

        let th_4 = compute_th_4(&TH_3_TV, &plaintext_3_tv, &cred_i_tv, CRED_I_TV.len());
        assert_eq!(th_4, TH_4_TV);
    }

    #[test]
    fn test_edhoc_kdf() {
        let mut th_2_context_tv: BytesMaxContextBuffer = [0x00u8; MAX_KDF_CONTEXT_LEN];
        th_2_context_tv[..TH_2_TV.len()].copy_from_slice(&TH_2_TV[..]);
        const LEN_TV: usize = PLAINTEXT_2_LEN_TV;

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
        let plaintext_3_tv = BufferPlaintext3::from_hex(PLAINTEXT_3_TV);
        let message_3_tv = BufferMessage3::from_hex(MESSAGE_3_TV);

        let message_3 = encrypt_message_3(&PRK_3E2M_TV, &TH_3_TV, &plaintext_3_tv);
        assert_eq!(message_3, message_3_tv);
    }

    #[test]
    fn test_decrypt_message_3() {
        let plaintext_3_tv = BufferPlaintext3::from_hex(PLAINTEXT_3_TV);
        let message_3_tv = BufferMessage3::from_hex(MESSAGE_3_TV);

        let plaintext_3 = decrypt_message_3(&PRK_3E2M_TV, &TH_3_TV, &message_3_tv);
        assert!(plaintext_3.is_ok());
        assert_eq!(plaintext_3.unwrap(), plaintext_3_tv);
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
        let plaintext_2_tv = BufferPlaintext2::from_hex(PLAINTEXT_2_TV);
        let plaintext_2 = encode_plaintext_2(&ID_CRED_R_TV, &MAC_2_TV, &None::<EADItem>);

        assert_eq!(plaintext_2, plaintext_2_tv);
    }

    #[test]
    fn test_decode_plaintext_2() {
        let plaintext_2_tv = BufferPlaintext2::from_hex(PLAINTEXT_2_TV);
        let mut plaintext_2_tv_buffer: BytesMaxBuffer = [0x00u8; MAX_BUFFER_LEN];
        plaintext_2_tv_buffer[..plaintext_2_tv.len]
            .copy_from_slice(&plaintext_2_tv.content[..plaintext_2_tv.len]);
        let ead_2_tv = [0x00u8; 0];

        let plaintext_2 = decode_plaintext_2(&plaintext_2_tv_buffer, PLAINTEXT_2_LEN_TV);
        assert!(plaintext_2.is_ok());
        let (id_cred_r, mac_2, ead_2) = plaintext_2.unwrap();
        assert_eq!(id_cred_r, ID_CRED_R_TV[3]);
        assert_eq!(mac_2, MAC_2_TV);
        assert!(ead_2.is_none());
    }

    #[test]
    fn test_encrypt_decrypt_ciphertext_2() {
        let plaintext_2_tv = BufferPlaintext2::from_hex(PLAINTEXT_2_TV);
        let ciphertext_2_tv = BufferPlaintext2::from_hex(CIPHERTEXT_2_TV);
        // test decryption
        let (plaintext_2, plaintext_2_len) =
            encrypt_decrypt_ciphertext_2(&PRK_2E_TV, &TH_2_TV, &ciphertext_2_tv);

        assert_eq!(plaintext_2_len, PLAINTEXT_2_LEN_TV);
        for i in 0..PLAINTEXT_2_LEN_TV {
            assert_eq!(plaintext_2[i], plaintext_2_tv.content[i]);
        }

        let mut plaintext_2_tmp: BufferCiphertext2 = BufferCiphertext2::new();
        plaintext_2_tmp.len = plaintext_2_len;
        plaintext_2_tmp.content[..plaintext_2_len].copy_from_slice(&plaintext_2[..plaintext_2_len]);

        // test encryption
        let (ciphertext_2, ciphertext_2_len) =
            encrypt_decrypt_ciphertext_2(&PRK_2E_TV, &TH_2_TV, &plaintext_2_tmp);

        assert_eq!(ciphertext_2_len, CIPHERTEXT_2_LEN_TV);
        for i in 0..CIPHERTEXT_2_LEN_TV {
            assert_eq!(ciphertext_2[i], ciphertext_2_tv.content[i]);
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
        let plaintext_3_tv = BufferPlaintext3::from_hex(PLAINTEXT_3_TV);
        let plaintext_3 = encode_plaintext_3(&ID_CRED_I_TV, &MAC_3_TV, &None::<EADItem>);
        assert_eq!(plaintext_3, plaintext_3_tv);
    }

    #[test]
    fn test_decode_plaintext_3() {
        let plaintext_3_tv = BufferPlaintext3::from_hex(PLAINTEXT_3_TV);
        let kid_tv = ID_CRED_I_TV[ID_CRED_I_TV.len() - 1];

        let (kid, mac_3, ead_3) = decode_plaintext_3(&plaintext_3_tv).unwrap();

        assert_eq!(mac_3, MAC_3_TV);
        assert_eq!(kid, kid_tv);
        assert!(ead_3.is_none());
    }

    #[test]
    fn test_encode_ead_item() {
        let ead_tv = EdhocMessageBuffer::from_hex(EAD_DUMMY_CRITICAL_TV);

        let ead_item = EADItem {
            label: EAD_DUMMY_LABEL_TV,
            is_critical: true,
            value: Some(EdhocMessageBuffer::from_hex(EAD_DUMMY_VALUE_TV)),
        };

        let ead_buffer = encode_ead_item(&ead_item);
        assert_eq!(ead_buffer.content, ead_tv.content);
    }

    #[test]
    fn test_encode_message_with_ead_item() {
        let method_tv = METHOD_TV;
        let suites_i_tv_len: usize = 2;
        let c_i_tv = C_I_TV;
        let message_1_ead_tv = BufferMessage1::from_hex(MESSAGE_1_WITH_DUMMY_CRITICAL_EAD_TV);
        let ead_item = EADItem {
            label: EAD_DUMMY_LABEL_TV,
            is_critical: true,
            value: Some(EdhocMessageBuffer::from_hex(EAD_DUMMY_VALUE_TV)),
        };

        let message_1 = encode_message_1(
            method_tv,
            &SUITES_I_TV,
            suites_i_tv_len,
            &G_X_TV,
            c_i_tv,
            &Some(ead_item),
        );

        assert_eq!(message_1.content, message_1_ead_tv.content);
    }

    #[test]
    fn test_parse_ead_item() {
        let message_tv_offset = MESSAGE_1_TV.len() / 2;
        let message_ead_tv = BufferMessage1::from_hex(MESSAGE_1_WITH_DUMMY_EAD_TV);
        let ead_value_tv = EdhocMessageBuffer::from_hex(EAD_DUMMY_VALUE_TV);

        let res = parse_ead(&message_ead_tv, message_tv_offset);
        assert!(res.is_ok());
        let ead_item = res.unwrap();
        assert!(ead_item.is_some());
        let ead_item = ead_item.unwrap();
        assert!(!ead_item.is_critical);
        assert_eq!(ead_item.label, EAD_DUMMY_LABEL_TV);
        assert_eq!(ead_item.value.unwrap().content, ead_value_tv.content);

        let message_ead_tv = BufferMessage1::from_hex(MESSAGE_1_WITH_DUMMY_CRITICAL_EAD_TV);

        let res = parse_ead(&message_ead_tv, message_tv_offset).unwrap();
        let ead_item = res.unwrap();
        assert!(ead_item.is_critical);
        assert_eq!(ead_item.label, EAD_DUMMY_LABEL_TV);
        assert_eq!(ead_item.value.unwrap().content, ead_value_tv.content);

        let message_ead_tv = BufferMessage1::from_hex(MESSAGE_1_WITH_DUMMY_EAD_NO_VALUE_TV);

        let res = parse_ead(&message_ead_tv, message_tv_offset).unwrap();
        let ead_item = res.unwrap();
        assert!(!ead_item.is_critical);
        assert_eq!(ead_item.label, EAD_DUMMY_LABEL_TV);
        assert!(ead_item.value.is_none());
    }

    #[test]
    fn test_parse_message_with_ead_item() {
        let message_1_ead_tv = BufferMessage1::from_hex(MESSAGE_1_WITH_DUMMY_CRITICAL_EAD_TV);
        let ead_value_tv = EdhocMessageBuffer::from_hex(EAD_DUMMY_VALUE_TV);

        let res = parse_message_1(&message_1_ead_tv);
        assert!(res.is_ok());
        let (_method, _suites_i, _suites_i_len, _g_x, _c_i, ead_1) = res.unwrap();
        let ead_1 = ead_1.unwrap();
        assert!(ead_1.is_critical);
        assert_eq!(ead_1.label, EAD_DUMMY_LABEL_TV);
        assert_eq!(ead_1.value.unwrap().content, ead_value_tv.content);
    }
}
