use core::marker::PhantomData;
use edhoc_consts::{Crypto as CryptoTrait, *};
use edhoc_ead::*;

pub fn edhoc_exporter(
    state: &State<Completed>,
    crypto: &mut impl CryptoTrait,
    label: u8,
    context: &BytesMaxContextBuffer,
    context_len: usize,
    length: usize,
) -> BytesMaxBuffer {
    let State(
        _current_state,
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

    edhoc_kdf(crypto, &prk_exporter, label, context, context_len, length)
}

pub fn edhoc_key_update(
    state: &mut State<Completed>,
    crypto: &mut impl CryptoTrait,
    context: &BytesMaxContextBuffer,
    context_len: usize,
) -> BytesHashLen {
    // FIXME: Normally we would decompose `state` here, but hax disallows aliasing a `mut` item.
    // The best fix for this is to change state from a tuple-struct to a regular struct.
    // In the code below, `state.6` means `mut prk_out` and `state.7` means `mut prk_exporter`

    // new PRK_out
    let prk_new_buf = edhoc_kdf(
        crypto,
        &state.6,
        11u8,
        context,
        context_len,
        SHA256_DIGEST_LEN,
    );
    state.6[..SHA256_DIGEST_LEN].copy_from_slice(&prk_new_buf[..SHA256_DIGEST_LEN]);

    // new PRK_exporter
    let prk_new_buf = edhoc_kdf(
        crypto,
        &state.6,
        10u8,
        &[0x00; MAX_KDF_CONTEXT_LEN],
        0,
        SHA256_DIGEST_LEN,
    );
    state.7[..SHA256_DIGEST_LEN].copy_from_slice(&prk_new_buf[..SHA256_DIGEST_LEN]);

    state.6
}

pub fn r_process_message_1(
    state: State<Start>,
    crypto: &mut impl CryptoTrait,
    message_1: &BufferMessage1,
) -> Result<State<ProcessedMessage1>, EDHOCError> {
    let State(
        _current_state,
        _y,
        _c_i,
        _g_x,
        _prk_3e2m,
        _prk_4e3m,
        _prk_out,
        _prk_exporter,
        _h_message_1,
        _th_3,
    ) = state;

    // Step 1: decode message_1
    // g_x will be saved to the state
    let res = parse_message_1(message_1);

    if let Ok((method, suites_i, suites_i_len, g_x, c_i, ead_1)) = res {
        // verify that the method is supported
        if method == EDHOC_METHOD {
            // Step 2: verify that the selected cipher suite is supported
            if suites_i[suites_i_len - 1] == EDHOC_SUPPORTED_SUITES[0] {
                // Step 3: If EAD is present make it available to the application
                let ead_success = if let Some(ead_1) = ead_1 {
                    r_process_ead_1(crypto, &ead_1, message_1).is_ok()
                } else {
                    true
                };
                if ead_success {
                    // hash message_1 and save the hash to the state to avoid saving the whole message
                    let mut message_1_buf: BytesMaxBuffer = [0x00; MAX_BUFFER_LEN];
                    message_1_buf[..message_1.len].copy_from_slice(message_1.as_slice());
                    let h_message_1 = crypto.sha256_digest(&message_1_buf, message_1.len);

                    let state = State(
                        PhantomData,
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
                    Ok(state)
                } else {
                    Err(EDHOCError::EADError)
                }
            } else {
                Err(EDHOCError::UnsupportedCipherSuite)
            }
        } else {
            Err(EDHOCError::UnsupportedMethod)
        }
    } else {
        Err(EDHOCError::ParsingError)
    }
}

pub fn r_prepare_message_2(
    state: State<ProcessedMessage1>,
    crypto: &mut impl CryptoTrait,
    cred_r: &[u8],
    r: &BytesP256ElemLen, // R's static private DH key
    y: BytesP256ElemLen,
    g_y: BytesP256ElemLen,
    c_r: u8,
) -> Result<(State<WaitMessage3>, BufferMessage2), EDHOCError> {
    let State(
        _current_state,
        mut _y,
        _c_i,
        g_x,
        _prk_3e2m,
        _prk_4e3m,
        _prk_out,
        _prk_exporter,
        h_message_1,
        _th_3,
    ) = state;

    // compute TH_2
    let th_2 = compute_th_2(crypto, &g_y, &h_message_1);

    // compute prk_3e2m
    let prk_2e = compute_prk_2e(crypto, &y, &g_x, &th_2);
    let salt_3e2m = compute_salt_3e2m(crypto, &prk_2e, &th_2);
    let prk_3e2m = compute_prk_3e2m(crypto, &salt_3e2m, r, &g_x);

    // compute MAC_2
    let mac_2 = compute_mac_2(crypto, &prk_3e2m, &get_id_cred(cred_r)?, cred_r, &th_2);

    let ead_2 = r_prepare_ead_2();

    let id_cred_r = if ead_2.is_some() {
        // NOTE: assume EAD_2 is for zeroconf
        IdCred::FullCredential(cred_r)
    } else {
        let (_g_r, kid) = parse_cred(cred_r)?;
        IdCred::CompactKid(kid)
    };

    // compute ciphertext_2
    let plaintext_2 = encode_plaintext_2(c_r, id_cred_r, &mac_2, &ead_2);

    // step is actually from processing of message_3
    // but we do it here to avoid storing plaintext_2 in State
    let th_3 = compute_th_3(crypto, &th_2, &plaintext_2, cred_r);

    let mut ct: BufferCiphertext2 = BufferCiphertext2::new();
    ct.len = plaintext_2.len;
    ct.content[..ct.len].copy_from_slice(plaintext_2.as_slice());

    let ciphertext_2 = encrypt_decrypt_ciphertext_2(crypto, &prk_2e, &th_2, ct);

    ct.content[..ct.len].copy_from_slice(ciphertext_2.as_slice());

    let message_2 = encode_message_2(&g_y, &ct);

    let state = State(
        PhantomData,
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

    Ok((state, message_2))
}

// FIXME fetch ID_CRED_I and CRED_I based on kid
pub fn r_process_message_3(
    state: State<WaitMessage3>,
    crypto: &mut impl CryptoTrait,
    message_3: &BufferMessage3,
    cred_i_expected: Option<&[u8]>,
) -> Result<(State<Completed>, BytesHashLen), EDHOCError> {
    let State(
        _current_state,
        y,
        _c_i,
        _g_x,
        prk_3e2m,
        _prk_4e3m,
        mut prk_out,
        mut prk_exporter,
        _h_message_1,
        th_3,
    ) = state;

    let plaintext_3 = decrypt_message_3(crypto, &prk_3e2m, &th_3, message_3);

    if let Ok(plaintext_3) = plaintext_3 {
        let decoded_p3_res = decode_plaintext_3(&plaintext_3);

        if let Ok((id_cred_i, mac_3, ead_3)) = decoded_p3_res {
            // The implementation currently supports the following two cases on handling the credentials:
            // 1. R receives a kid and has a corresponding CRED_x passed in as cred_i_expected
            // 2. R receives CRED_x by value in the message and uses it
            // TODO: add support for fetching CRED_x based on kid received in the message

            let cred_i = credential_check_or_fetch(cred_i_expected, id_cred_i);
            // IMPL: stop if credential_check_or_fetch returns Error

            if let Ok((valid_cred_i, g_i)) = cred_i {
                // Phase 2:
                // - Process EAD_X items that have not been processed yet, and that can be processed before message verification
                // IMPL: we are sure valid_cred_i is a full credential

                // Step 3: If EAD is present make it available to the application
                let ead_res = if let Some(ead_3) = ead_3 {
                    // IMPL: if EAD-zeroconf is present, then id_cred must contain a full credential
                    // at this point, in case of EAD = zeroconf, if it works it means that:
                    // - the Voucher has been verified
                    // - the received valid_cred_i (aka cred_i) has been authenticated
                    r_process_ead_3(ead_3)
                } else {
                    Ok(())
                };

                if ead_res.is_ok() {
                    // verify mac_3

                    // compute salt_4e3m
                    let salt_4e3m = compute_salt_4e3m(crypto, &prk_3e2m, &th_3);
                    // TODO compute prk_4e3m
                    let prk_4e3m = compute_prk_4e3m(crypto, &salt_4e3m, &y, &g_i);

                    // compute mac_3
                    let expected_mac_3 = compute_mac_3(
                        crypto,
                        &prk_4e3m,
                        &th_3,
                        &get_id_cred(valid_cred_i)?,
                        valid_cred_i,
                    );

                    // verify mac_3
                    if mac_3 == expected_mac_3 {
                        let th_4 = compute_th_4(crypto, &th_3, &plaintext_3, valid_cred_i);

                        let mut th_4_buf: BytesMaxContextBuffer = [0x00; MAX_KDF_CONTEXT_LEN];
                        th_4_buf[..th_4.len()].copy_from_slice(&th_4[..]);
                        // compute prk_out
                        // PRK_out = EDHOC-KDF( PRK_4e3m, 7, TH_4, hash_length )
                        let prk_out_buf = edhoc_kdf(
                            crypto,
                            &prk_4e3m,
                            7u8,
                            &th_4_buf,
                            th_4.len(),
                            SHA256_DIGEST_LEN,
                        );
                        prk_out[..SHA256_DIGEST_LEN]
                            .copy_from_slice(&prk_out_buf[..SHA256_DIGEST_LEN]);

                        // compute prk_exporter from prk_out
                        // PRK_exporter  = EDHOC-KDF( PRK_out, 10, h'', hash_length )
                        let prk_exporter_buf = edhoc_kdf(
                            crypto,
                            &prk_out,
                            10u8,
                            &[0x00u8; MAX_KDF_CONTEXT_LEN],
                            0,
                            SHA256_DIGEST_LEN,
                        );
                        prk_exporter[..SHA256_DIGEST_LEN]
                            .copy_from_slice(&prk_exporter_buf[..SHA256_DIGEST_LEN]);

                        let state = State(
                            PhantomData,
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
                        Ok((state, prk_out))
                    } else {
                        Err(EDHOCError::MacVerificationFailed)
                    }
                } else {
                    Err(EDHOCError::EADError)
                }
            } else {
                Err(cred_i.unwrap_err())
            }
        } else {
            Err(decoded_p3_res.unwrap_err())
        }
    } else {
        // error handling for err = decrypt_message_3(&prk_3e2m, &th_3, message_3);
        Err(plaintext_3.unwrap_err())
    }
}

pub fn i_prepare_message_1(
    state: State<Start>,
    crypto: &mut impl CryptoTrait,
    x: BytesP256ElemLen,
    g_x: BytesP256ElemLen,
    c_i: u8,
) -> Result<(State<WaitMessage2>, BufferMessage1), EDHOCError> {
    let State(
        _current_state,
        mut _x,
        mut _c_i,
        _g_y,
        _prk_3e2m,
        _prk_4e3m,
        _prk_out,
        _prk_exporter,
        _h_message_1,
        _th_3,
    ) = state;

    // we only support a single cipher suite which is already CBOR-encoded
    let mut suites_i: BytesSuites = [0x0; SUITES_LEN];
    suites_i[0..EDHOC_SUPPORTED_SUITES.len()].copy_from_slice(&EDHOC_SUPPORTED_SUITES[..]);

    let ead_1 = i_prepare_ead_1(crypto, &x, suites_i[suites_i.len() - 1]);

    // Encode message_1 as a sequence of CBOR encoded data items as specified in Section 5.2.1
    let message_1 = encode_message_1(
        EDHOC_METHOD,
        &suites_i,
        EDHOC_SUPPORTED_SUITES.len(),
        &g_x,
        c_i,
        &ead_1,
    );

    let mut message_1_buf: BytesMaxBuffer = [0x00; MAX_BUFFER_LEN];
    message_1_buf[..message_1.len].copy_from_slice(message_1.as_slice());

    // hash message_1 here to avoid saving the whole message in the state
    let h_message_1 = crypto.sha256_digest(&message_1_buf, message_1.len);

    let state = State(
        PhantomData,
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

    Ok((state, message_1))
}

// returns c_r
pub fn i_process_message_2(
    state: State<WaitMessage2>,
    crypto: &mut impl CryptoTrait,
    message_2: &BufferMessage2,
    cred_r_expected: Option<&[u8]>,
    i: &BytesP256ElemLen, // I's static private DH key
) -> Result<(State<ProcessedMessage2>, u8, u8), EDHOCError> {
    let State(
        _current_state,
        x,
        _c_i,
        _g_y,
        _prk_3e2m,
        _prk_4e3m,
        _prk_out,
        _prk_exporter,
        h_message_1,
        _th_3,
    ) = state;

    let mut kid = 0xffu8; // invalidate kid

    let res = parse_message_2(message_2);
    if let Ok((g_y, ciphertext_2)) = res {
        let th_2 = compute_th_2(crypto, &g_y, &h_message_1);

        // compute prk_2e
        let prk_2e = compute_prk_2e(crypto, &x, &g_y, &th_2);

        let plaintext_2 = encrypt_decrypt_ciphertext_2(crypto, &prk_2e, &th_2, ciphertext_2);

        // decode plaintext_2
        let plaintext_2_decoded = decode_plaintext_2(&plaintext_2);

        if let Ok((c_r_2, id_cred_r, mac_2, ead_2)) = plaintext_2_decoded {
            let c_r = c_r_2;

            let cred_r = credential_check_or_fetch(cred_r_expected, id_cred_r);
            // IMPL: stop if credential_check_or_fetch returns Error
            if let Ok((valid_cred_r, g_r)) = cred_r {
                // Phase 2:
                // - Process EAD_X items that have not been processed yet, and that can be processed before message verification
                // IMPL: we are sure valid_cred_r is a full credential

                // Step 3: If EAD is present make it available to the application
                let ead_res = if let Some(ead_2) = ead_2 {
                    // IMPL: if EAD-zeroconf is present, then id_cred must contain a full credential
                    // at this point, in case of EAD = zeroconf, if it works it means that:
                    // - the Voucher has been verified
                    // - the received valid_cred_r (aka cred_v) has been authenticated
                    i_process_ead_2(crypto, ead_2, valid_cred_r, &h_message_1)
                } else {
                    Ok(())
                };

                if ead_res.is_ok() {
                    // verify mac_2
                    let salt_3e2m = compute_salt_3e2m(crypto, &prk_2e, &th_2);

                    let prk_3e2m = compute_prk_3e2m(crypto, &salt_3e2m, &x, &g_r);

                    let expected_mac_2 = compute_mac_2(
                        crypto,
                        &prk_3e2m,
                        &get_id_cred(valid_cred_r)?,
                        &valid_cred_r,
                        &th_2,
                    );

                    if mac_2 == expected_mac_2 {
                        // step is actually from processing of message_3
                        // but we do it here to avoid storing plaintext_2 in State
                        let th_3 = compute_th_3(crypto, &th_2, &plaintext_2, &valid_cred_r);
                        // message 3 processing

                        let salt_4e3m = compute_salt_4e3m(crypto, &prk_3e2m, &th_3);

                        let prk_4e3m = compute_prk_4e3m(crypto, &salt_4e3m, i, &g_y);

                        let state = State(
                            PhantomData,
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

                        Ok((state, c_r, kid))
                    } else {
                        Err(EDHOCError::MacVerificationFailed)
                    }
                } else {
                    Err(EDHOCError::EADError)
                }
            } else {
                Err(cred_r.unwrap_err())
            }
        } else {
            Err(EDHOCError::ParsingError)
        }
    } else {
        Err(res.unwrap_err())
    }
}

pub fn i_prepare_message_3(
    state: State<ProcessedMessage2>,
    crypto: &mut impl CryptoTrait,
    id_cred_i: &BytesIdCred,
    cred_i: &[u8],
) -> Result<(State<Completed>, BufferMessage3, BytesHashLen), EDHOCError> {
    let State(
        _current_state,
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

    let mac_3 = compute_mac_3(crypto, &prk_4e3m, &th_3, id_cred_i, cred_i);

    let ead_3 = i_prepare_ead_3();

    let plaintext_3 = encode_plaintext_3(id_cred_i, &mac_3, &ead_3);
    let message_3 = encrypt_message_3(crypto, &prk_3e2m, &th_3, &plaintext_3);

    let th_4 = compute_th_4(crypto, &th_3, &plaintext_3, cred_i);

    let mut th_4_buf: BytesMaxContextBuffer = [0x00; MAX_KDF_CONTEXT_LEN];
    th_4_buf[..th_4.len()].copy_from_slice(&th_4[..]);

    // compute prk_out
    // PRK_out = EDHOC-KDF( PRK_4e3m, 7, TH_4, hash_length )
    let prk_out_buf = edhoc_kdf(
        crypto,
        &prk_4e3m,
        7u8,
        &th_4_buf,
        th_4.len(),
        SHA256_DIGEST_LEN,
    );
    prk_out[..SHA256_DIGEST_LEN].copy_from_slice(&prk_out_buf[..SHA256_DIGEST_LEN]);

    // compute prk_exporter from prk_out
    // PRK_exporter  = EDHOC-KDF( PRK_out, 10, h'', hash_length )
    let prk_exporter_buf = edhoc_kdf(
        crypto,
        &prk_out,
        10u8,
        &[0x00; MAX_KDF_CONTEXT_LEN],
        0,
        SHA256_DIGEST_LEN,
    );
    prk_exporter[..SHA256_DIGEST_LEN].copy_from_slice(&prk_exporter_buf[..SHA256_DIGEST_LEN]);

    let state = State(
        PhantomData,
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

    Ok((state, message_3, prk_out))
}

// Implements auth credential checking according to draft-tiloca-lake-implem-cons
fn credential_check_or_fetch<'a>(
    cred_expected: Option<&'a [u8]>,
    id_cred_received: IdCred<'a>,
) -> Result<(&'a [u8], BytesP256ElemLen), EDHOCError> {
    // Processing of auth credentials according to draft-tiloca-lake-implem-cons
    // Comments tagged with a number refer to steps in Section 4.3.1. of draft-tiloca-lake-implem-cons
    if let Some(cred_expected) = cred_expected {
        // 1. Does ID_CRED_X point to a stored authentication credential? YES
        // IMPL: compare cred_i_expected with id_cred
        //   IMPL: assume cred_i_expected is well formed
        let (public_key_expected, kid_expected) = parse_cred(cred_expected)?;
        let public_key = public_key_expected;
        let credentials_match = match id_cred_received {
            IdCred::CompactKid(kid_received) => kid_received == kid_expected,
            IdCred::FullCredential(cred_received) => cred_expected == cred_received,
        };

        // 2. Is this authentication credential still valid?
        // IMPL,TODO: check cred_r_expected is still valid

        // Continue by considering CRED_X as the authentication credential of the other peer.
        // IMPL: ready to proceed, including process ead_2

        if credentials_match {
            Ok((cred_expected, public_key))
        } else {
            Err(EDHOCError::UnknownPeer)
        }
    } else {
        // 1. Does ID_CRED_X point to a stored authentication credential? NO
        // IMPL: cred_i_expected provided by application is None
        //       id_cred must be a full credential
        if let IdCred::FullCredential(cred_received) = id_cred_received {
            // 3. Is the trust model Pre-knowledge-only? NO (hardcoded to NO for now)

            // 4. Is the trust model Pre-knowledge + TOFU? YES (hardcoded to YES for now)

            // 6. Validate CRED_X. Generally a CCS has to be validated only syntactically and semantically, unlike a certificate or a CWT.
            //    Is the validation successful?
            // IMPL: parse_cred(cred_r) and check it is valid
            match parse_cred(cred_received) {
                Ok((public_key_received, _kid_received)) => {
                    // 5. Is the authentication credential authorized for use in the context of this EDHOC session?
                    // IMPL,TODO: we just skip this step for now

                    // 7. Store CRED_X as valid and trusted.
                    //   Pair it with consistent credential identifiers, for each supported type of credential identifier.
                    // IMPL: cred_r = id_cred
                    let public_key = public_key_received;
                    Ok((cred_received, public_key))
                }
                Err(_) => Err(EDHOCError::UnknownPeer),
            }
        } else {
            // IMPL: should have gotten a full credential
            Err(EDHOCError::UnknownPeer)
        }
    }

    // 8. Is this authentication credential good to use in the context of this EDHOC session?
    // IMPL,TODO: we just skip this step for now
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
        output.content[1..1 + ead_1_value.len].copy_from_slice(ead_1_value.as_slice());
        output.len += ead_1_value.len;
    }

    output
}

fn encode_message_1(
    method: u8,
    suites: &BytesSuites,
    suites_len: usize,
    g_x: &BytesP256ElemLen,
    c_i: u8,
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
        for i in 0..suites_len {
            if suites[i] <= CBOR_UINT_1BYTE {
                output.content[1 + raw_suites_len] = suites[i];
                raw_suites_len += 1;
            } else {
                output.content[1 + raw_suites_len] = CBOR_UINT_1BYTE;
                output.content[2 + raw_suites_len] = suites[i];
                raw_suites_len += 2;
            }
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
        output.content[output.len..output.len + ead_1.len].copy_from_slice(ead_1.as_slice());
        output.len += ead_1.len;
    }

    output
}

fn encode_message_2(g_y: &BytesP256ElemLen, ciphertext_2: &BufferCiphertext2) -> BufferMessage2 {
    let mut output: BufferMessage2 = BufferMessage2::new();

    output.content[0] = CBOR_BYTE_STRING;
    output.content[1] = P256_ELEM_LEN as u8 + ciphertext_2.len as u8;
    output.content[2..2 + P256_ELEM_LEN].copy_from_slice(&g_y[..]);
    output.content[2 + P256_ELEM_LEN..2 + P256_ELEM_LEN + ciphertext_2.len]
        .copy_from_slice(ciphertext_2.as_slice());

    output.len = 2 + P256_ELEM_LEN + ciphertext_2.len;
    output
}

fn compute_th_2(
    crypto: &mut impl CryptoTrait,
    g_y: &BytesP256ElemLen,
    h_message_1: &BytesHashLen,
) -> BytesHashLen {
    let mut message: BytesMaxBuffer = [0x00; MAX_BUFFER_LEN];
    message[0] = CBOR_BYTE_STRING;
    message[1] = P256_ELEM_LEN as u8;
    message[2..2 + P256_ELEM_LEN].copy_from_slice(g_y);
    message[2 + P256_ELEM_LEN] = CBOR_BYTE_STRING;
    message[3 + P256_ELEM_LEN] = SHA256_DIGEST_LEN as u8;
    message[4 + P256_ELEM_LEN..4 + P256_ELEM_LEN + SHA256_DIGEST_LEN]
        .copy_from_slice(&h_message_1[..]);

    let len = 4 + P256_ELEM_LEN + SHA256_DIGEST_LEN;

    let th_2 = crypto.sha256_digest(&message, len);

    th_2
}

fn compute_th_3(
    crypto: &mut impl CryptoTrait,
    th_2: &BytesHashLen,
    plaintext_2: &BufferPlaintext2,
    cred_r: &[u8],
) -> BytesHashLen {
    let mut message: BytesMaxBuffer = [0x00; MAX_BUFFER_LEN];

    message[0] = CBOR_BYTE_STRING;
    message[1] = th_2.len() as u8;
    message[2..2 + th_2.len()].copy_from_slice(&th_2[..]);
    message[2 + th_2.len()..2 + th_2.len() + plaintext_2.len]
        .copy_from_slice(plaintext_2.as_slice());
    message[2 + th_2.len() + plaintext_2.len..2 + th_2.len() + plaintext_2.len + cred_r.len()]
        .copy_from_slice(cred_r);

    let output = crypto.sha256_digest(&message, th_2.len() + 2 + plaintext_2.len + cred_r.len());

    output
}

fn compute_th_4(
    crypto: &mut impl CryptoTrait,
    th_3: &BytesHashLen,
    plaintext_3: &BufferPlaintext3,
    cred_i: &[u8],
) -> BytesHashLen {
    let mut message: BytesMaxBuffer = [0x00; MAX_BUFFER_LEN];

    message[0] = CBOR_BYTE_STRING;
    message[1] = th_3.len() as u8;
    message[2..2 + th_3.len()].copy_from_slice(&th_3[..]);
    message[2 + th_3.len()..2 + th_3.len() + plaintext_3.len]
        .copy_from_slice(plaintext_3.as_slice());
    message[2 + th_3.len() + plaintext_3.len..2 + th_3.len() + plaintext_3.len + cred_i.len()]
        .copy_from_slice(cred_i);

    let output = crypto.sha256_digest(&message, th_3.len() + 2 + plaintext_3.len + cred_i.len());

    output
}

// TODO: consider moving this to a new 'edhoc crypto primitives' module
fn edhoc_kdf(
    crypto: &mut impl CryptoTrait,
    prk: &BytesHashLen,
    label: u8,
    context: &BytesMaxContextBuffer,
    context_len: usize,
    length: usize,
) -> BytesMaxBuffer {
    let (info, info_len) = encode_info(label, context, context_len, length);
    let output = crypto.hkdf_expand(prk, &info, info_len, length);
    output
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
            .copy_from_slice(ead_3.as_slice());
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
    crypto: &mut impl CryptoTrait,
    prk_3e2m: &BytesHashLen,
    th_3: &BytesHashLen,
) -> (BytesCcmKeyLen, BytesCcmIvLen) {
    // K_3 = EDHOC-KDF( PRK_3e2m, 3, TH_3,      key_length )
    let mut k_3: BytesCcmKeyLen = [0x00; AES_CCM_KEY_LEN];
    let mut th_3_buf: BytesMaxContextBuffer = [0x00; MAX_KDF_CONTEXT_LEN];
    th_3_buf[..th_3.len()].copy_from_slice(&th_3[..]);
    let k_3_buf = edhoc_kdf(
        crypto,
        prk_3e2m,
        3u8,
        &th_3_buf,
        th_3.len(),
        AES_CCM_KEY_LEN,
    );
    k_3[..].copy_from_slice(&k_3_buf[..AES_CCM_KEY_LEN]);

    // IV_3 = EDHOC-KDF( PRK_3e2m, 4, TH_3,      iv_length )
    let mut iv_3: BytesCcmIvLen = [0x00; AES_CCM_IV_LEN];
    let iv_3_buf = edhoc_kdf(crypto, prk_3e2m, 4u8, &th_3_buf, th_3.len(), AES_CCM_IV_LEN);
    iv_3[..].copy_from_slice(&iv_3_buf[..AES_CCM_IV_LEN]);

    (k_3, iv_3)
}

// calculates ciphertext_3 wrapped in a cbor byte string
fn encrypt_message_3(
    crypto: &mut impl CryptoTrait,
    prk_3e2m: &BytesHashLen,
    th_3: &BytesHashLen,
    plaintext_3: &BufferPlaintext3,
) -> BufferMessage3 {
    let mut output: BufferMessage3 = BufferMessage3::new();
    output.len = 1 + plaintext_3.len + AES_CCM_TAG_LEN;
    output.content[0] = CBOR_MAJOR_BYTE_STRING | (plaintext_3.len + AES_CCM_TAG_LEN) as u8; // FIXME if plaintext_3.len + AES_CCM_TAG_LEN > 23, then should use CBOR_BYTE_STRING

    let enc_structure = encode_enc_structure(th_3);

    let (k_3, iv_3) = compute_k_3_iv_3(crypto, prk_3e2m, th_3);

    let ciphertext_3 = crypto.aes_ccm_encrypt_tag_8(&k_3, &iv_3, &enc_structure[..], plaintext_3);

    output.content[1..output.len].copy_from_slice(ciphertext_3.as_slice());

    output
}

fn decrypt_message_3(
    crypto: &mut impl CryptoTrait,
    prk_3e2m: &BytesHashLen,
    th_3: &BytesHashLen,
    message_3: &BufferMessage3,
) -> Result<BufferPlaintext3, EDHOCError> {
    let mut plaintext_3: BufferPlaintext3 = BufferPlaintext3::new();

    // decode message_3
    let len = (message_3.content[0usize] ^ CBOR_MAJOR_BYTE_STRING) as usize;

    let mut ciphertext_3: BufferCiphertext3 = BufferCiphertext3::new();
    ciphertext_3.len = len;
    ciphertext_3.content[..len].copy_from_slice(&message_3.content[1..1 + len]);

    let (k_3, iv_3) = compute_k_3_iv_3(crypto, prk_3e2m, th_3);

    let enc_structure = encode_enc_structure(th_3);

    let p3 = crypto.aes_ccm_decrypt_tag_8(&k_3, &iv_3, &enc_structure, &ciphertext_3);

    if let Ok(p3) = p3 {
        plaintext_3.content[..p3.len].copy_from_slice(p3.as_slice());
        plaintext_3.len = p3.len;

        Ok(plaintext_3)
    } else {
        Err(p3.unwrap_err())
    }
}

// output must hold id_cred.len() + cred.len()
fn encode_kdf_context(
    id_cred: &BytesIdCred,
    th: &BytesHashLen,
    cred: &[u8],
) -> (BytesMaxContextBuffer, usize) {
    // encode context in line
    // assumes ID_CRED_R and CRED_R are already CBOR-encoded
    let mut output: BytesMaxContextBuffer = [0x00; MAX_KDF_CONTEXT_LEN];
    output[..id_cred.len()].copy_from_slice(&id_cred[..]);
    output[id_cred.len()] = CBOR_BYTE_STRING;
    output[id_cred.len() + 1] = SHA256_DIGEST_LEN as u8;
    output[id_cred.len() + 2..id_cred.len() + 2 + th.len()].copy_from_slice(&th[..]);
    output[id_cred.len() + 2 + th.len()..id_cred.len() + 2 + th.len() + cred.len()]
        .copy_from_slice(&cred);

    let output_len = (id_cred.len() + 2 + SHA256_DIGEST_LEN + cred.len()) as usize;

    (output, output_len)
}

fn compute_mac_3(
    crypto: &mut impl CryptoTrait,
    prk_4e3m: &BytesHashLen,
    th_3: &BytesHashLen,
    id_cred_i: &BytesIdCred,
    cred_i: &[u8],
) -> BytesMac3 {
    // MAC_3 = EDHOC-KDF( PRK_4e3m, 6, context_3, mac_length_3 )
    let (context, context_len) = encode_kdf_context(id_cred_i, th_3, cred_i);

    // compute mac_3
    let output_buf = edhoc_kdf(
        crypto,
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
    crypto: &mut impl CryptoTrait,
    prk_3e2m: &BytesHashLen,
    id_cred_r: &BytesIdCred,
    cred_r: &[u8],
    th_2: &BytesHashLen,
) -> BytesMac2 {
    // compute MAC_2
    let (context, context_len) = encode_kdf_context(id_cred_r, th_2, cred_r);

    // MAC_2 = EDHOC-KDF( PRK_3e2m, 2, context_2, mac_length_2 )
    let mut mac_2: BytesMac2 = [0x00; MAC_LENGTH_2];
    mac_2[..].copy_from_slice(
        &edhoc_kdf(
            crypto,
            prk_3e2m,
            2 as u8,
            &context,
            context_len,
            MAC_LENGTH_2,
        )[..MAC_LENGTH_2],
    );

    mac_2
}

fn encode_plaintext_2(
    c_r: u8,
    id_cred_r: IdCred,
    mac_2: &BytesMac2,
    ead_2: &Option<EADItem>,
) -> BufferPlaintext2 {
    let mut plaintext_2: BufferPlaintext2 = BufferPlaintext2::new();
    plaintext_2.content[0] = c_r;

    let offset_cred = match id_cred_r {
        IdCred::CompactKid(kid) => {
            plaintext_2.content[1] = kid;
            2
        }
        IdCred::FullCredential(cred) => {
            plaintext_2.content[1] = CBOR_BYTE_STRING;
            plaintext_2.content[2] = cred.len() as u8;
            plaintext_2.content[3..3 + cred.len()].copy_from_slice(cred);
            3 + cred.len()
        }
    };

    plaintext_2.content[offset_cred] = CBOR_MAJOR_BYTE_STRING | MAC_LENGTH_2 as u8;
    plaintext_2.content[1 + offset_cred..1 + offset_cred + mac_2.len()].copy_from_slice(&mac_2[..]);
    plaintext_2.len = 1 + offset_cred + mac_2.len();

    if let Some(ead_2) = ead_2 {
        let ead_2 = encode_ead_item(ead_2);
        plaintext_2.content[plaintext_2.len..plaintext_2.len + ead_2.len]
            .copy_from_slice(ead_2.as_slice());
        plaintext_2.len += ead_2.len;
    }

    plaintext_2
}

/// Apply the XOR base encryption for ciphertext_2 in place. This will decrypt (or decrypt) the bytes
/// in the ciphertext_2 argument (which may alternatively contain plaintext), returning the cipher
/// (or plain-)text.
fn encrypt_decrypt_ciphertext_2(
    crypto: &mut impl CryptoTrait,
    prk_2e: &BytesHashLen,
    th_2: &BytesHashLen,
    mut ciphertext_2: BufferCiphertext2,
) -> BufferCiphertext2 {
    // convert the transcript hash th_2 to BytesMaxContextBuffer type
    let mut th_2_context: BytesMaxContextBuffer = [0x00; MAX_KDF_CONTEXT_LEN];
    th_2_context[..th_2.len()].copy_from_slice(&th_2[..]);

    // KEYSTREAM_2 = EDHOC-KDF( PRK_2e,   0, TH_2,      plaintext_length )
    let keystream_2 = edhoc_kdf(
        crypto,
        prk_2e,
        0u8,
        &th_2_context,
        SHA256_DIGEST_LEN,
        ciphertext_2.len,
    );

    for i in 0..ciphertext_2.len {
        ciphertext_2.content[i] ^= keystream_2[i];
    }

    ciphertext_2
}

fn compute_salt_4e3m(
    crypto: &mut impl CryptoTrait,
    prk_3e2m: &BytesHashLen,
    th_3: &BytesHashLen,
) -> BytesHashLen {
    let mut th_3_context: BytesMaxContextBuffer = [0x00; MAX_KDF_CONTEXT_LEN];
    th_3_context[..th_3.len()].copy_from_slice(&th_3[..]);
    let salt_4e3m_buf = edhoc_kdf(
        crypto,
        prk_3e2m,
        5u8,
        &th_3_context,
        th_3.len(),
        SHA256_DIGEST_LEN,
    );
    let mut salt_4e3m: BytesHashLen = [0x00; SHA256_DIGEST_LEN];
    salt_4e3m[..].copy_from_slice(&salt_4e3m_buf[..SHA256_DIGEST_LEN]);

    salt_4e3m
}

fn compute_prk_4e3m(
    crypto: &mut impl CryptoTrait,
    salt_4e3m: &BytesHashLen,
    i: &BytesP256ElemLen,
    g_y: &BytesP256ElemLen,
) -> BytesHashLen {
    // compute g_rx from static R's public key and private ephemeral key
    let g_iy = crypto.p256_ecdh(i, g_y);
    let prk_4e3m = crypto.hkdf_extract(salt_4e3m, &g_iy);

    prk_4e3m
}

fn compute_salt_3e2m(
    crypto: &mut impl CryptoTrait,
    prk_2e: &BytesHashLen,
    th_2: &BytesHashLen,
) -> BytesHashLen {
    let mut th_2_context: BytesMaxContextBuffer = [0x00; MAX_KDF_CONTEXT_LEN];
    th_2_context[..th_2.len()].copy_from_slice(&th_2[..]);

    let salt_3e2m_buf = edhoc_kdf(
        crypto,
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
    crypto: &mut impl CryptoTrait,
    salt_3e2m: &BytesHashLen,
    x: &BytesP256ElemLen,
    g_r: &BytesP256ElemLen,
) -> BytesHashLen {
    // compute g_rx from static R's public key and private ephemeral key
    let g_rx = crypto.p256_ecdh(x, g_r);
    let prk_3e2m = crypto.hkdf_extract(salt_3e2m, &g_rx);

    prk_3e2m
}

fn compute_prk_2e(
    crypto: &mut impl CryptoTrait,
    x: &BytesP256ElemLen,
    g_y: &BytesP256ElemLen,
    th_2: &BytesHashLen,
) -> BytesHashLen {
    // compute the shared secret
    let g_xy = crypto.p256_ecdh(x, g_y);
    // compute prk_2e as PRK_2e = HMAC-SHA-256( salt, G_XY )
    let prk_2e = crypto.hkdf_extract(th_2, &g_xy);

    prk_2e
}

#[cfg(test)]
mod tests {
    use super::*;
    use edhoc_crypto::default_crypto;
    use hexlit::hex;
    // test vectors (TV)

    // message_1 (first_time)
    const METHOD_TV_FIRST_TIME: u8 = 0x03;
    const SUITES_I_TV_FIRST_TIME: BytesSuites = hex!("060000000000000000");
    const G_X_TV_FIRST_TIME: BytesP256ElemLen =
        hex!("741a13d7ba048fbb615e94386aa3b61bea5b3d8f65f32620b749bee8d278efa9");
    const C_I_TV_FIRST_TIME: u8 = 0x0e;
    const MESSAGE_1_TV_FIRST_TIME: &str =
        "03065820741a13d7ba048fbb615e94386aa3b61bea5b3d8f65f32620b749bee8d278efa90e";

    // message_1 (second time)
    const METHOD_TV: u8 = 0x03;
    // manually modified test vector to include a single supported cipher suite
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
    const MESSAGE_2_TV: &str = "582b419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d59862a11de42a95d785386a";
    const CIPHERTEXT_2_TV: &str = "9862a11de42a95d785386a";
    const H_MESSAGE_1_TV: BytesHashLen =
        hex!("ca02cabda5a8902749b42f711050bb4dbd52153e87527594b39f50cdf019888c");
    const TH_2_TV: BytesHashLen =
        hex!("356efd53771425e008f3fe3a86c83ff4c6b16e57028ff39d5236c182b202084b");
    const TH_3_TV: BytesHashLen =
        hex!("dfe5b065e64c72d226d500c12d49bee6dc4881ded0965e9bdf89d24a54f2e59a");
    const CIPHERTEXT_3_TV: &str = "473dd16077dd71d65b56e6bd71e7a49d6012";
    const TH_4_TV: BytesHashLen =
        hex!("baf60adbc500fce789af25b108ada2275575056c52c1c2036a2da4a643891cb4");
    const PRK_2E_TV: BytesP256ElemLen =
        hex!("5aa0d69f3e3d1e0c479f0b8a486690c9802630c3466b1dc92371c982563170b5");
    const CIPHERTEXT_2_LEN_TV: usize = MESSAGE_2_TV.len() / 2 - P256_ELEM_LEN - 2;
    const PLAINTEXT_2_LEN_TV: usize = CIPHERTEXT_2_LEN_TV;
    const KEYSTREAM_2_TV: [u8; PLAINTEXT_2_LEN_TV] = hex!("bf50e9e7bad0bb68173399");
    const PRK_3E2M_TV: BytesP256ElemLen =
        hex!("0ca3d3398296b3c03900987620c11f6fce70781c1d1219720f9ec08c122d8434");
    const CONTEXT_INFO_MAC_2_TV: [u8; 133] = hex!("a10441325820356efd53771425e008f3fe3a86c83ff4c6b16e57028ff39d5236c182b202084ba2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
    const MAC_2_TV: BytesMac2 = hex!("fa5efa2ebf920bf3");
    const ID_CRED_I_TV: BytesIdCred = hex!("a104412b");
    const MAC_3_TV: BytesMac3 = hex!("a5eeb9effdabfc39");
    const MESSAGE_3_TV: &str = "52473dd16077dd71d65b56e6bd71e7a49d6012";
    const PRK_4E3M_TV: BytesP256ElemLen =
        hex!("e9cb832a240095d3d0643dbe12e9e2e7b18f0360a3172cea7ac0013ee240e072");
    const CRED_I_TV : [u8; 107] = hex!("a2027734322d35302d33312d46462d45462d33372d33322d333908a101a5010202412b2001215820ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb62258206e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8");
    const ID_CRED_R_TV: BytesIdCred = hex!("a1044132");
    const CRED_R_TV : [u8; 95] = hex!("a2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
    const PLAINTEXT_2_TV: &str = "273248fa5efa2ebf920bf3";
    const SK_I_TV: BytesP256ElemLen =
        hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
    const X_TV: BytesP256ElemLen =
        hex!("368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525");
    const G_R_TV: BytesP256ElemLen =
        hex!("bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0");
    const PLAINTEXT_3_TV: &str = "2b48a5eeb9effdabfc39";
    const SALT_3E2M_TV: BytesHashLen =
        hex!("af4e103a47cb3cf32570d5c25ad27732bd8d8178e9a69d061c31a27f8e3ca926");
    const SALT_4E3M_TV: BytesHashLen =
        hex!("84f8a2a9534ddd78dcc7e76e0d4df60bfad7cd3ad6e1d531c7f373a7eda52d1c");
    const G_XY_TV: BytesP256ElemLen =
        hex!("2f0cb7e860ba538fbf5c8bded009f6259b4b628fe1eb7dbe9378e5ecf7a824ba");
    const PRK_OUT_TV: BytesHashLen =
        hex!("6b2dae4032306571cfbc2e4f94a255fb9f1f3fb29ca6f379fec989d4fa90dcf0");
    const PRK_EXPORTER_TV: BytesHashLen =
        hex!("4f0a5a823d06d0005e1becda8a6e61f3c8c67a8b15da7d44d3585ec5854e91e2");
    const OSCORE_MASTER_SECRET_TV: BytesCcmKeyLen = hex!("8c409a332223ad900e44f3434d2d2ce3");
    const OSCORE_MASTER_SALT_TV: Bytes8 = hex!("6163f44be862adfa");

    // invalid test vectors, should result in a parsing error
    const MESSAGE_1_INVALID_ARRAY_TV: &str =
        "8403025820741a13d7ba048fbb615e94386aa3b61bea5b3d8f65f32620b749bee8d278efa90e";
    const MESSAGE_1_INVALID_C_I_TV: &str =
        "03025820741a13d7ba048fbb615e94386aa3b61bea5b3d8f65f32620b749bee8d278efa9410e";
    const MESSAGE_1_INVALID_CIPHERSUITE_TV: &str =
        "0381025820741a13d7ba048fbb615e94386aa3b61bea5b3d8f65f32620b749bee8d278efa90e";
    const MESSAGE_1_INVALID_TEXT_EPHEMERAL_KEY_TV: &str =
        "0302782020616972207370656564206F66206120756E6C6164656E207377616C6C6F77200e";
    const MESSAGE_2_INVALID_NUMBER_OF_CBOR_SEQUENCE_TV: &str =
        "5820419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d54B9862a11de42a95d785386a";
    const PLAINTEXT_2_SURPLUS_MAP_ID_CRED_TV: &str = "27a10442321048fa5efa2ebf920bf3";
    const PLAINTEXT_2_SURPLUS_BSTR_ID_CRED_TV: &str = "27413248fa5efa2ebf920bf3";

    #[test]
    fn test_ecdh() {
        let g_xy = default_crypto().p256_ecdh(&X_TV, &G_Y_TV);

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
        // skip the fist byte (method)
        let mut decoder = CBORDecoder::new(&message_1_tv.content[1..message_1_tv.len]);
        let res = parse_suites_i(decoder);
        assert!(res.is_ok());
        let (suites_i, suites_i_len, _decoder) = res.unwrap();
        assert_eq!(suites_i, SUITES_I_TV);

        let message_1_tv = BufferMessage1::from_hex(MESSAGE_1_TV_SUITE_ONLY_A);
        // skip the fist byte (method)
        let mut decoder = CBORDecoder::new(&message_1_tv.content[1..message_1_tv.len]);
        let res = parse_suites_i(decoder);
        assert!(res.is_ok());
        let (suites_i, suites_i_len, _decoder) = res.unwrap();
        assert_eq!(suites_i[0], 0x18);

        // let (suites_i, suites_i_len, raw_suites_len) =
        //     parse_suites_i(&BufferMessage1::from_hex(MESSAGE_1_TV_SUITE_ONLY_B)).unwrap();

        let message_1_tv = BufferMessage1::from_hex(MESSAGE_1_TV_SUITE_ONLY_B);
        // skip the fist byte (method)
        let mut decoder = CBORDecoder::new(&message_1_tv.content[1..message_1_tv.len]);
        let res = parse_suites_i(decoder);
        assert!(res.is_ok());
        let (suites_i, suites_i_len, _decoder) = res.unwrap();
        assert_eq!(suites_i_len, 2);
        assert_eq!(suites_i[0], 0x02);
        assert_eq!(suites_i[1], 0x01);

        let message_1_tv = BufferMessage1::from_hex(MESSAGE_1_TV_SUITE_ONLY_C);
        // skip the fist byte (method)
        let mut decoder = CBORDecoder::new(&message_1_tv.content[1..message_1_tv.len]);
        let res = parse_suites_i(decoder);
        assert!(res.is_ok());
        let (suites_i, suites_i_len, _decoder) = res.unwrap();
        assert_eq!(suites_i_len, 2);
        assert_eq!(suites_i[0], 0x02);
        assert_eq!(suites_i[1], 0x19);

        let message_1_tv = BufferMessage1::from_hex(MESSAGE_1_TV_SUITE_ONLY_ERR);
        // skip the fist byte (method)
        let mut decoder = CBORDecoder::new(&message_1_tv.content[1..message_1_tv.len]);
        let res = parse_suites_i(decoder);
        assert_eq!(res.unwrap_err(), EDHOCError::ParsingError);
    }

    #[test]
    fn test_parse_message_1() {
        let message_1_tv_first_time = BufferMessage1::from_hex(MESSAGE_1_TV_FIRST_TIME);
        let message_1_tv = BufferMessage1::from_hex(MESSAGE_1_TV);

        // first time message_1 parsing
        let res = parse_message_1(&message_1_tv_first_time);
        assert!(res.is_ok());
        let (method, suites_i, suites_i_len, g_x, c_i, ead_1) = res.unwrap();

        assert_eq!(method, METHOD_TV_FIRST_TIME);
        assert_eq!(suites_i, SUITES_I_TV_FIRST_TIME);
        assert_eq!(g_x, G_X_TV_FIRST_TIME);
        assert_eq!(c_i, C_I_TV_FIRST_TIME);
        assert!(ead_1.is_none());

        // second time message_1
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
    fn test_parse_message_1_invalid_traces() {
        let message_1_tv: EdhocMessageBuffer = BufferMessage1::from_hex(MESSAGE_1_INVALID_ARRAY_TV);
        assert_eq!(
            parse_message_1(&message_1_tv).unwrap_err(),
            EDHOCError::ParsingError
        );

        let message_1_tv = BufferMessage1::from_hex(MESSAGE_1_INVALID_C_I_TV);
        assert_eq!(
            parse_message_1(&message_1_tv).unwrap_err(),
            EDHOCError::ParsingError
        );

        let message_1_tv = BufferMessage1::from_hex(MESSAGE_1_INVALID_CIPHERSUITE_TV);
        assert_eq!(
            parse_message_1(&message_1_tv).unwrap_err(),
            EDHOCError::ParsingError
        );

        let message_1_tv = BufferMessage1::from_hex(MESSAGE_1_INVALID_TEXT_EPHEMERAL_KEY_TV);
        assert_eq!(
            parse_message_1(&message_1_tv).unwrap_err(),
            EDHOCError::ParsingError
        );
    }

    #[test]
    fn test_parse_message_2_invalid_traces() {
        let message_2_tv = BufferMessage1::from_hex(MESSAGE_2_INVALID_NUMBER_OF_CBOR_SEQUENCE_TV);
        assert_eq!(
            parse_message_2(&message_2_tv).unwrap_err(),
            EDHOCError::ParsingError
        );
    }

    #[test]
    fn test_encode_message_2() {
        let ciphertext_2_tv = BufferCiphertext2::from_hex(CIPHERTEXT_2_TV);
        let message_2 = encode_message_2(&G_Y_TV, &ciphertext_2_tv);

        assert_eq!(message_2, BufferMessage2::from_hex(MESSAGE_2_TV));
    }

    #[test]
    fn test_parse_message_2() {
        let ciphertext_2_tv = BufferCiphertext2::from_hex(CIPHERTEXT_2_TV);
        let ret = parse_message_2(&BufferMessage2::from_hex(MESSAGE_2_TV));
        assert!(ret.is_ok());
        let (g_y, ciphertext_2) = ret.unwrap();

        assert_eq!(g_y, G_Y_TV);
        assert_eq!(ciphertext_2, ciphertext_2_tv);
    }

    #[test]
    fn test_compute_th_2() {
        let th_2 = compute_th_2(&mut default_crypto(), &G_Y_TV, &H_MESSAGE_1_TV);
        assert_eq!(th_2, TH_2_TV);
    }

    #[test]
    fn test_compute_th_3() {
        let plaintext_2_tv = BufferPlaintext2::from_hex(PLAINTEXT_2_TV);

        let th_3 = compute_th_3(&mut default_crypto(), &TH_2_TV, &plaintext_2_tv, &CRED_R_TV);
        assert_eq!(th_3, TH_3_TV);
    }

    #[test]
    fn test_compute_th_4() {
        let plaintext_3_tv = BufferPlaintext3::from_hex(PLAINTEXT_3_TV);

        let th_4 = compute_th_4(&mut default_crypto(), &TH_3_TV, &plaintext_3_tv, &CRED_I_TV);
        assert_eq!(th_4, TH_4_TV);
    }

    #[test]
    fn test_edhoc_kdf() {
        let mut th_2_context_tv: BytesMaxContextBuffer = [0x00u8; MAX_KDF_CONTEXT_LEN];
        th_2_context_tv[..TH_2_TV.len()].copy_from_slice(&TH_2_TV[..]);
        const LEN_TV: usize = PLAINTEXT_2_LEN_TV;

        let output = edhoc_kdf(
            &mut default_crypto(),
            &PRK_2E_TV,
            0u8,
            &th_2_context_tv,
            SHA256_DIGEST_LEN,
            LEN_TV,
        );
        for i in 0..KEYSTREAM_2_TV.len() {
            assert_eq!(KEYSTREAM_2_TV[i], output[i]);
        }

        let mut context_info_mac_2: BytesMaxContextBuffer = [0x00u8; MAX_KDF_CONTEXT_LEN];
        context_info_mac_2[..CONTEXT_INFO_MAC_2_TV.len()]
            .copy_from_slice(&CONTEXT_INFO_MAC_2_TV[..]);

        let output_2 = edhoc_kdf(
            &mut default_crypto(),
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

        let message_3 = encrypt_message_3(
            &mut default_crypto(),
            &PRK_3E2M_TV,
            &TH_3_TV,
            &plaintext_3_tv,
        );
        assert_eq!(message_3, message_3_tv);
    }

    #[test]
    fn test_decrypt_message_3() {
        let plaintext_3_tv = BufferPlaintext3::from_hex(PLAINTEXT_3_TV);
        let message_3_tv = BufferMessage3::from_hex(MESSAGE_3_TV);

        let plaintext_3 =
            decrypt_message_3(&mut default_crypto(), &PRK_3E2M_TV, &TH_3_TV, &message_3_tv);
        assert!(plaintext_3.is_ok());
        assert_eq!(plaintext_3.unwrap(), plaintext_3_tv);
    }

    #[test]
    fn test_compute_mac_3() {
        let mac_3 = compute_mac_3(
            &mut default_crypto(),
            &PRK_4E3M_TV,
            &TH_3_TV,
            &ID_CRED_I_TV,
            &CRED_I_TV,
        );
        assert_eq!(mac_3, MAC_3_TV);
    }

    #[test]
    fn test_compute_and_verify_mac_2() {
        let rcvd_mac_2 = compute_mac_2(
            &mut default_crypto(),
            &PRK_3E2M_TV,
            &ID_CRED_R_TV,
            &CRED_R_TV,
            &TH_2_TV,
        );

        assert_eq!(rcvd_mac_2, MAC_2_TV);
    }

    #[test]
    fn test_encode_plaintext_2() {
        let plaintext_2_tv = BufferPlaintext2::from_hex(PLAINTEXT_2_TV);
        let plaintext_2 = encode_plaintext_2(
            C_R_TV,
            IdCred::CompactKid(ID_CRED_R_TV[ID_CRED_R_TV.len() - 1]),
            &MAC_2_TV,
            &None::<EADItem>,
        );

        assert_eq!(plaintext_2, plaintext_2_tv);
    }

    #[test]
    fn test_parse_plaintext_2_invalid_traces() {
        let plaintext_2_tv = BufferPlaintext2::from_hex(PLAINTEXT_2_SURPLUS_MAP_ID_CRED_TV);
        let ret = decode_plaintext_2(&plaintext_2_tv);
        assert_eq!(ret.unwrap_err(), EDHOCError::ParsingError);

        let plaintext_2_tv = BufferPlaintext2::from_hex(PLAINTEXT_2_SURPLUS_BSTR_ID_CRED_TV);
        let ret = decode_plaintext_2(&plaintext_2_tv);
        assert_eq!(ret.unwrap_err(), EDHOCError::ParsingError);
    }

    #[test]
    fn test_decode_plaintext_2() {
        let plaintext_2_tv = BufferPlaintext2::from_hex(PLAINTEXT_2_TV);
        let ead_2_tv = [0x00u8; 0];

        let plaintext_2 = decode_plaintext_2(&plaintext_2_tv);
        assert!(plaintext_2.is_ok());
        let (c_r, id_cred_r, mac_2, ead_2) = plaintext_2.unwrap();
        assert_eq!(c_r, C_R_TV);
        let id_cred_r = match id_cred_r {
            IdCred::CompactKid(id_cred_r) => id_cred_r,
            _ => panic!("Invalid ID_CRED_R"),
        };
        assert_eq!(id_cred_r, ID_CRED_R_TV[3]);
        assert_eq!(mac_2, MAC_2_TV);
        assert!(ead_2.is_none());
    }

    #[test]
    fn test_encrypt_decrypt_ciphertext_2() {
        let plaintext_2_tv = BufferPlaintext2::from_hex(PLAINTEXT_2_TV);
        let mut ciphertext_2_tv = BufferPlaintext2::from_hex(CIPHERTEXT_2_TV);
        // test decryption
        let plaintext_2 = encrypt_decrypt_ciphertext_2(
            &mut default_crypto(),
            &PRK_2E_TV,
            &TH_2_TV,
            ciphertext_2_tv,
        );

        assert_eq!(plaintext_2.len, PLAINTEXT_2_LEN_TV);
        for i in 0..PLAINTEXT_2_LEN_TV {
            assert_eq!(plaintext_2.content[i], plaintext_2_tv.content[i]);
        }

        // test encryption
        let ciphertext_2 =
            encrypt_decrypt_ciphertext_2(&mut default_crypto(), &PRK_2E_TV, &TH_2_TV, plaintext_2);

        assert_eq!(ciphertext_2.len, CIPHERTEXT_2_LEN_TV);
        for i in 0..CIPHERTEXT_2_LEN_TV {
            assert_eq!(ciphertext_2.content[i], ciphertext_2_tv.content[i]);
        }
    }

    #[test]
    fn test_compute_prk_4e3m() {
        let prk_4e3m = compute_prk_4e3m(&mut default_crypto(), &SALT_4E3M_TV, &SK_I_TV, &G_Y_TV);
        assert_eq!(prk_4e3m, PRK_4E3M_TV);
    }

    #[test]
    fn test_compute_prk_3e2m() {
        let prk_3e2m = compute_prk_3e2m(&mut default_crypto(), &SALT_3E2M_TV, &X_TV, &G_R_TV);
        assert_eq!(prk_3e2m, PRK_3E2M_TV);
    }

    #[test]
    fn test_compute_prk_2e() {
        let prk_2e = compute_prk_2e(&mut default_crypto(), &X_TV, &G_Y_TV, &TH_2_TV);
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

        let (id_cred_i, mac_3, ead_3) = decode_plaintext_3(&plaintext_3_tv).unwrap();

        let kid = match id_cred_i {
            IdCred::CompactKid(id_cred_i) => id_cred_i,
            _ => panic!("Invalid ID_CRED_I"),
        };

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

        let res = parse_ead(&message_ead_tv.content[message_tv_offset..message_ead_tv.len]);
        assert!(res.is_ok());
        let ead_item = res.unwrap();
        assert!(ead_item.is_some());
        let ead_item = ead_item.unwrap();
        assert!(!ead_item.is_critical);
        assert_eq!(ead_item.label, EAD_DUMMY_LABEL_TV);
        assert_eq!(ead_item.value.unwrap().content, ead_value_tv.content);

        let message_ead_tv = BufferMessage1::from_hex(MESSAGE_1_WITH_DUMMY_CRITICAL_EAD_TV);

        let res =
            parse_ead(&message_ead_tv.content[message_tv_offset..message_ead_tv.len]).unwrap();
        let ead_item = res.unwrap();
        assert!(ead_item.is_critical);
        assert_eq!(ead_item.label, EAD_DUMMY_LABEL_TV);
        assert_eq!(ead_item.value.unwrap().content, ead_value_tv.content);

        let message_ead_tv = BufferMessage1::from_hex(MESSAGE_1_WITH_DUMMY_EAD_NO_VALUE_TV);

        let res =
            parse_ead(&message_ead_tv.content[message_tv_offset..message_ead_tv.len]).unwrap();
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

    fn test_compute_prk_out() {
        let mut prk_out: BytesHashLen = [0x00; SHA256_DIGEST_LEN];
        let mut th_4_context: BytesMaxContextBuffer = [0x00; MAX_KDF_CONTEXT_LEN];
        th_4_context[..TH_4_TV.len()].copy_from_slice(&TH_4_TV[..]);

        let prk_out_buf = edhoc_kdf(
            &mut default_crypto(),
            &PRK_4E3M_TV,
            7u8,
            &th_4_context,
            TH_4_TV.len(),
            SHA256_DIGEST_LEN,
        );
        prk_out[..].copy_from_slice(&prk_out_buf[..SHA256_DIGEST_LEN]);

        assert_eq!(prk_out, PRK_OUT_TV);
    }

    #[test]
    fn test_compute_prk_exporter() {
        let mut prk_exporter: BytesHashLen = [0x00; SHA256_DIGEST_LEN];
        let prk_exporter_buf = edhoc_kdf(
            &mut default_crypto(),
            &PRK_OUT_TV,
            10u8,
            &[0x00; MAX_KDF_CONTEXT_LEN],
            0,
            SHA256_DIGEST_LEN,
        );
        prk_exporter[..].copy_from_slice(&prk_exporter_buf[..SHA256_DIGEST_LEN]);

        assert_eq!(prk_exporter, PRK_EXPORTER_TV);
    }

    #[test]
    fn test_compute_oscore_master_secret_salt() {
        let oscore_master_secret_buf = edhoc_kdf(
            &mut default_crypto(),
            &PRK_EXPORTER_TV,
            0u8,
            &[0x00; MAX_KDF_CONTEXT_LEN],
            0,
            OSCORE_MASTER_SECRET_TV.len(),
        );
        assert_eq!(
            &oscore_master_secret_buf[..OSCORE_MASTER_SECRET_TV.len()],
            &OSCORE_MASTER_SECRET_TV[..]
        );

        let oscore_master_salt_buf = edhoc_kdf(
            &mut default_crypto(),
            &PRK_EXPORTER_TV,
            1u8,
            &[0x00; MAX_KDF_CONTEXT_LEN],
            0,
            OSCORE_MASTER_SALT_TV.len(),
        );

        assert_eq!(
            &oscore_master_salt_buf[..OSCORE_MASTER_SALT_TV.len()],
            &OSCORE_MASTER_SALT_TV[..]
        );
    }
}
