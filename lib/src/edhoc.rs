use lakers_shared::{Crypto as CryptoTrait, *};

pub fn edhoc_exporter(
    state: &Completed,
    crypto: &mut impl CryptoTrait,
    label: u8,
    context: &BytesMaxContextBuffer,
    context_len: usize,
    length: usize,
) -> BytesMaxBuffer {
    edhoc_kdf(
        crypto,
        &state.prk_exporter,
        label,
        context,
        context_len,
        length,
    )
}

pub fn edhoc_key_update(
    state: &mut Completed,
    crypto: &mut impl CryptoTrait,
    context: &BytesMaxContextBuffer,
    context_len: usize,
) -> BytesHashLen {
    // new PRK_out
    let prk_new_buf = edhoc_kdf(
        crypto,
        &state.prk_out,
        11u8,
        context,
        context_len,
        SHA256_DIGEST_LEN,
    );
    state.prk_out[..SHA256_DIGEST_LEN].copy_from_slice(&prk_new_buf[..SHA256_DIGEST_LEN]);

    // new PRK_exporter
    let prk_new_buf = edhoc_kdf(
        crypto,
        &state.prk_out,
        10u8,
        &[0x00; MAX_KDF_CONTEXT_LEN],
        0,
        SHA256_DIGEST_LEN,
    );
    state.prk_exporter[..SHA256_DIGEST_LEN].copy_from_slice(&prk_new_buf[..SHA256_DIGEST_LEN]);

    state.prk_out
}

pub fn r_process_message_1(
    state: &ResponderStart,
    crypto: &mut impl CryptoTrait,
    message_1: &BufferMessage1,
) -> Result<(ProcessingM1, ConnId, Option<EADItem>), EDHOCError> {
    // Step 1: decode message_1
    // g_x will be saved to the state
    if let Ok((method, suites_i, g_x, c_i, ead_1)) = parse_message_1(message_1) {
        // verify that the method is supported
        if method == EDHOC_METHOD {
            // Step 2: verify that the selected cipher suite is supported
            if suites_i[suites_i.len() - 1] == EDHOC_SUPPORTED_SUITES[0] {
                // hash message_1 and save the hash to the state to avoid saving the whole message
                let mut message_1_buf: BytesMaxBuffer = [0x00; MAX_BUFFER_LEN];
                message_1_buf[..message_1.len].copy_from_slice(message_1.as_slice());
                let h_message_1 = crypto.sha256_digest(&message_1_buf, message_1.len);

                Ok((
                    ProcessingM1 {
                        y: state.y,
                        g_y: state.g_y,
                        c_i,
                        g_x,
                        h_message_1,
                    },
                    c_i,
                    ead_1,
                ))
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
    state: &ProcessingM1,
    crypto: &mut impl CryptoTrait,
    cred_r: Credential,
    r: &BytesP256ElemLen, // R's static private DH key
    c_r: ConnId,
    cred_transfer: CredentialTransfer,
    ead_2: &Option<EADItem>,
) -> Result<(WaitM3, BufferMessage2), EDHOCError> {
    // compute TH_2
    let th_2 = compute_th_2(crypto, &state.g_y, &state.h_message_1);

    // compute prk_3e2m
    let prk_2e = compute_prk_2e(crypto, &state.y, &state.g_x, &th_2);
    let salt_3e2m = compute_salt_3e2m(crypto, &prk_2e, &th_2);
    let prk_3e2m = compute_prk_3e2m(crypto, &salt_3e2m, r, &state.g_x);

    let id_cred_r = match cred_transfer {
        CredentialTransfer::ByValue => cred_r.by_value()?,
        CredentialTransfer::ByReference => cred_r.by_kid()?,
    };

    // compute MAC_2
    let mac_2 = compute_mac_2(
        crypto,
        &prk_3e2m,
        c_r,
        id_cred_r.as_full_value(),
        cred_r.bytes.as_slice(),
        &th_2,
        ead_2,
    );

    // compute ciphertext_2
    let plaintext_2 = encode_plaintext_2(c_r, id_cred_r.as_encoded_value(), &mac_2, &ead_2)?;

    // step is actually from processing of message_3
    // but we do it here to avoid storing plaintext_2 in State
    let th_3 = compute_th_3(crypto, &th_2, &plaintext_2, cred_r.bytes.as_slice());

    let mut ct: BufferCiphertext2 = BufferCiphertext2::new();
    ct.fill_with_slice(plaintext_2.as_slice()).unwrap(); // TODO(hax): can we prove with hax that this won't panic since they use the same underlying buffer length?

    let ciphertext_2 = encrypt_decrypt_ciphertext_2(crypto, &prk_2e, &th_2, &ct);

    ct.fill_with_slice(ciphertext_2.as_slice()).unwrap(); // TODO(hax): same as just above.

    let message_2 = encode_message_2(&state.g_y, &ct);

    Ok((
        WaitM3 {
            y: state.y,
            prk_3e2m: prk_3e2m,
            th_3: th_3,
        },
        message_2,
    ))
}

pub fn r_parse_message_3(
    state: &mut WaitM3,
    crypto: &mut impl CryptoTrait,
    message_3: &BufferMessage3,
) -> Result<(ProcessingM3, IdCred, Option<EADItem>), EDHOCError> {
    let plaintext_3 = decrypt_message_3(crypto, &state.prk_3e2m, &state.th_3, message_3);

    if let Ok(plaintext_3) = plaintext_3 {
        let decoded_p3_res = decode_plaintext_3(&plaintext_3);

        if let Ok((id_cred_i, mac_3, ead_3)) = decoded_p3_res {
            Ok((
                ProcessingM3 {
                    mac_3,
                    y: state.y,
                    prk_3e2m: state.prk_3e2m,
                    th_3: state.th_3,
                    id_cred_i: id_cred_i.clone(), // needed for compute_mac_3
                    plaintext_3, // NOTE: this is needed for th_4, which needs valid_cred_i, which is only available at the 'verify' step
                    ead_3: ead_3.clone(), // NOTE: this clone could be avoided by using a reference or an index to the ead_3 item in plaintext_3
                },
                id_cred_i,
                ead_3,
            ))
        } else {
            Err(decoded_p3_res.unwrap_err())
        }
    } else {
        // error handling for err = decrypt_message_3(&prk_3e2m, &th_3, message_3);
        Err(plaintext_3.unwrap_err())
    }
}

pub fn r_verify_message_3(
    state: &mut ProcessingM3,
    crypto: &mut impl CryptoTrait,
    valid_cred_i: Credential,
) -> Result<(Completed, BytesHashLen), EDHOCError> {
    // compute salt_4e3m
    let salt_4e3m = compute_salt_4e3m(crypto, &state.prk_3e2m, &state.th_3);

    let prk_4e3m = match valid_cred_i.key {
        CredentialKey::EC2Compact(public_key) => {
            compute_prk_4e3m(crypto, &salt_4e3m, &state.y, &public_key)
        }
        CredentialKey::Symmetric(_psk) => todo!("PSK not implemented"),
    };

    // compute mac_3
    let expected_mac_3 = compute_mac_3(
        crypto,
        &prk_4e3m,
        &state.th_3,
        state.id_cred_i.as_full_value(),
        valid_cred_i.bytes.as_slice(),
        &state.ead_3,
    );

    // verify mac_3
    if state.mac_3 == expected_mac_3 {
        let th_4 = compute_th_4(
            crypto,
            &state.th_3,
            &state.plaintext_3,
            valid_cred_i.bytes.as_slice(),
        );

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
        let mut prk_out: BytesHashLen = Default::default();
        prk_out[..SHA256_DIGEST_LEN].copy_from_slice(&prk_out_buf[..SHA256_DIGEST_LEN]);

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
        let mut prk_exporter = BytesHashLen::default();
        prk_exporter[..SHA256_DIGEST_LEN].copy_from_slice(&prk_exporter_buf[..SHA256_DIGEST_LEN]);

        Ok((
            Completed {
                prk_out,
                prk_exporter,
            },
            prk_out,
        ))
    } else {
        Err(EDHOCError::MacVerificationFailed)
    }
}

pub fn i_prepare_message_1(
    state: &InitiatorStart,
    crypto: &mut impl CryptoTrait,
    c_i: ConnId,
    ead_1: &Option<EADItem>, // FIXME: make it a list of EADItem
) -> Result<(WaitM2, BufferMessage1), EDHOCError> {
    // Encode message_1 as a sequence of CBOR encoded data items as specified in Section 5.2.1
    let message_1 = encode_message_1(state.method, &state.suites_i, &state.g_x, c_i, ead_1)?;

    let mut message_1_buf: BytesMaxBuffer = [0x00; MAX_BUFFER_LEN];
    message_1_buf[..message_1.len].copy_from_slice(message_1.as_slice());

    // hash message_1 here to avoid saving the whole message in the state
    let h_message_1 = crypto.sha256_digest(&message_1_buf, message_1.len);

    Ok((
        WaitM2 {
            x: state.x,
            h_message_1,
        },
        message_1,
    ))
}

// returns c_r
pub fn i_parse_message_2<'a>(
    state: &WaitM2,
    crypto: &mut impl CryptoTrait,
    message_2: &BufferMessage2,
) -> Result<(ProcessingM2, ConnId, IdCred, Option<EADItem>), EDHOCError> {
    let res = parse_message_2(message_2);
    if let Ok((g_y, ciphertext_2)) = res {
        let th_2 = compute_th_2(crypto, &g_y, &state.h_message_1);

        // compute prk_2e
        let prk_2e = compute_prk_2e(crypto, &state.x, &g_y, &th_2);

        let plaintext_2 = encrypt_decrypt_ciphertext_2(crypto, &prk_2e, &th_2, &ciphertext_2);

        // decode plaintext_2
        let plaintext_2_decoded = decode_plaintext_2(&plaintext_2);

        if let Ok((c_r_2, id_cred_r, mac_2, ead_2)) = plaintext_2_decoded {
            let state = ProcessingM2 {
                mac_2,
                prk_2e,
                th_2,
                x: state.x,
                g_y,
                plaintext_2: plaintext_2,
                c_r: c_r_2,
                id_cred_r: id_cred_r.clone(), // needed for compute_mac_2
                ead_2: ead_2.clone(),         // needed for compute_mac_2
            };

            Ok((state, c_r_2, id_cred_r, ead_2))
        } else {
            Err(EDHOCError::ParsingError)
        }
    } else {
        Err(res.unwrap_err())
    }
}

pub fn i_verify_message_2(
    state: &ProcessingM2,
    crypto: &mut impl CryptoTrait,
    valid_cred_r: Credential,
    i: &BytesP256ElemLen, // I's static private DH key
) -> Result<ProcessedM2, EDHOCError> {
    // verify mac_2
    let salt_3e2m = compute_salt_3e2m(crypto, &state.prk_2e, &state.th_2);

    let prk_3e2m = match valid_cred_r.key {
        CredentialKey::EC2Compact(public_key) => {
            compute_prk_3e2m(crypto, &salt_3e2m, &state.x, &public_key)
        }
        CredentialKey::Symmetric(_psk) => todo!("PSK not implemented"),
    };

    let expected_mac_2 = compute_mac_2(
        crypto,
        &prk_3e2m,
        state.c_r,
        state.id_cred_r.as_full_value(),
        valid_cred_r.bytes.as_slice(),
        &state.th_2,
        &state.ead_2,
    );

    if state.mac_2 == expected_mac_2 {
        // step is actually from processing of message_3
        // but we do it here to avoid storing plaintext_2 in State
        let th_3 = compute_th_3(
            crypto,
            &state.th_2,
            &state.plaintext_2,
            valid_cred_r.bytes.as_slice(),
        );
        // message 3 processing

        let salt_4e3m = compute_salt_4e3m(crypto, &prk_3e2m, &th_3);

        let prk_4e3m = compute_prk_4e3m(crypto, &salt_4e3m, i, &state.g_y);

        let state = ProcessedM2 {
            prk_3e2m: prk_3e2m,
            prk_4e3m: prk_4e3m,
            th_3: th_3,
        };

        Ok(state)
    } else {
        Err(EDHOCError::MacVerificationFailed)
    }
}

pub fn i_prepare_message_3(
    state: &ProcessedM2,
    crypto: &mut impl CryptoTrait,
    cred_i: Credential,
    cred_transfer: CredentialTransfer,
    ead_3: &Option<EADItem>, // FIXME: make it a list of EADItem
) -> Result<(Completed, BufferMessage3, BytesHashLen), EDHOCError> {
    let id_cred_i = match cred_transfer {
        CredentialTransfer::ByValue => cred_i.by_value()?,
        CredentialTransfer::ByReference => cred_i.by_kid()?,
    };

    let mac_3 = compute_mac_3(
        crypto,
        &state.prk_4e3m,
        &state.th_3,
        id_cred_i.as_full_value(),
        cred_i.bytes.as_slice(),
        ead_3,
    );

    let plaintext_3 = encode_plaintext_3(id_cred_i.as_encoded_value(), &mac_3, &ead_3)?;
    let message_3 = encrypt_message_3(crypto, &state.prk_3e2m, &state.th_3, &plaintext_3);

    let th_4 = compute_th_4(crypto, &state.th_3, &plaintext_3, cred_i.bytes.as_slice());

    let mut th_4_buf: BytesMaxContextBuffer = [0x00; MAX_KDF_CONTEXT_LEN];
    th_4_buf[..th_4.len()].copy_from_slice(&th_4[..]);

    // compute prk_out
    // PRK_out = EDHOC-KDF( PRK_4e3m, 7, TH_4, hash_length )
    let prk_out_buf = edhoc_kdf(
        crypto,
        &state.prk_4e3m,
        7u8,
        &th_4_buf,
        th_4.len(),
        SHA256_DIGEST_LEN,
    );
    let mut prk_out: BytesHashLen = Default::default();
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
    let mut prk_exporter: BytesHashLen = Default::default();
    prk_exporter[..SHA256_DIGEST_LEN].copy_from_slice(&prk_exporter_buf[..SHA256_DIGEST_LEN]);

    Ok((
        Completed {
            prk_out,
            prk_exporter,
        },
        message_3,
        prk_out,
    ))
}

fn encode_ead_item(ead_1: &EADItem) -> Result<EdhocMessageBuffer, EDHOCError> {
    let mut output = EdhocMessageBuffer::new();

    // encode label
    let res = if ead_1.is_critical {
        // ensure it won't overflow
        ead_1
            .label
            .checked_add(CBOR_NEG_INT_1BYTE_START)
            .and_then(|x| x.checked_sub(1))
    } else {
        Some(ead_1.label)
    };

    if let Some(label) = res {
        output.content[0] = label;
        output.len = 1;

        // encode value
        if let Some(ead_1_value) = &ead_1.value {
            if output.extend_from_slice(ead_1_value.as_slice()).is_ok() {
                Ok(output)
            } else {
                Err(EDHOCError::EadTooLongError)
            }
        } else {
            Ok(output)
        }
    } else {
        Err(EDHOCError::EadLabelTooLongError)
    }
}

fn encode_message_1(
    method: u8,
    suites: &EdhocBuffer<MAX_SUITES_LEN>,
    g_x: &BytesP256ElemLen,
    c_i: ConnId,
    ead_1: &Option<EADItem>,
) -> Result<BufferMessage1, EDHOCError> {
    let mut output = BufferMessage1::new();
    let mut raw_suites_len: usize = 0;

    output.content[0] = method; // CBOR unsigned int less than 24 is encoded verbatim

    if suites.len == 1 {
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
        output.content[1] = CBOR_MAJOR_ARRAY + (suites.len as u8);
        raw_suites_len += 1;
        for &suite in suites.as_slice().iter() {
            if suite <= CBOR_UINT_1BYTE {
                output.content[1 + raw_suites_len] = suite;
                raw_suites_len += 1;
            } else {
                output.content[1 + raw_suites_len] = CBOR_UINT_1BYTE;
                output.content[2 + raw_suites_len] = suite;
                raw_suites_len += 2;
            }
        }
    };

    output.content[1 + raw_suites_len] = CBOR_BYTE_STRING; // CBOR byte string magic number
    output.content[2 + raw_suites_len] = P256_ELEM_LEN as u8; // length of the byte string
    output.content[3 + raw_suites_len..3 + raw_suites_len + P256_ELEM_LEN]
        .copy_from_slice(&g_x[..]);
    let c_i = c_i.as_slice();
    output.len = 3 + raw_suites_len + P256_ELEM_LEN + c_i.len();
    output.content[3 + raw_suites_len + P256_ELEM_LEN..][..c_i.len()].copy_from_slice(c_i);

    if let Some(ead_1) = ead_1 {
        match encode_ead_item(ead_1) {
            Ok(ead_1) => output
                .extend_from_slice(ead_1.as_slice())
                .and(Ok(output))
                .or(Err(EDHOCError::EadTooLongError)),
            Err(e) => Err(e),
        }
    } else {
        Ok(output)
    }
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

    crypto.sha256_digest(&message, len)
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

    crypto.sha256_digest(&message, th_2.len() + 2 + plaintext_2.len + cred_r.len())
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

    crypto.sha256_digest(&message, th_3.len() + 2 + plaintext_3.len + cred_i.len())
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

    crypto.hkdf_expand(prk, &info, info_len, length)
}

fn encode_plaintext_3(
    id_cred_i: &[u8],
    mac_3: &BytesMac3,
    ead_3: &Option<EADItem>,
) -> Result<BufferPlaintext3, EDHOCError> {
    let mut plaintext_3: BufferPlaintext3 = BufferPlaintext3::new();

    // plaintext: P = ( ? PAD, ID_CRED_I / bstr / int, Signature_or_MAC_3, ? EAD_3 )
    // id_cred_i.write_to_message(&mut plaintext_3)?;
    plaintext_3
        .extend_from_slice(id_cred_i)
        .or(Err(EDHOCError::EncodingError))?;
    let offset_cred = plaintext_3.len;
    plaintext_3.content[offset_cred] = CBOR_MAJOR_BYTE_STRING | MAC_LENGTH_3 as u8;
    plaintext_3.content[offset_cred + 1..][..mac_3.len()].copy_from_slice(&mac_3[..]);
    plaintext_3.len = offset_cred + 1 + mac_3.len();

    if let Some(ead_3) = ead_3 {
        match encode_ead_item(ead_3) {
            Ok(ead_3) => plaintext_3
                .extend_from_slice(ead_3.as_slice())
                .and(Ok(plaintext_3))
                .or(Err(EDHOCError::EadTooLongError)),
            Err(e) => Err(e),
        }
    } else {
        Ok(plaintext_3)
    }
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
    enc_structure[0] = CBOR_MAJOR_ARRAY | 3_u8; // 3 is the fixed number of elements in the array
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
    let bytestring_length = plaintext_3.len + AES_CCM_TAG_LEN;
    let prefix_length;
    // FIXME: Reuse CBOR encoder
    if bytestring_length < 24 {
        output.content[0] = CBOR_MAJOR_BYTE_STRING | (bytestring_length) as u8;
        prefix_length = 1;
    } else {
        // FIXME: Assumes we don't exceed 256 bytes which is the current buffer size
        output.content[0] = CBOR_MAJOR_BYTE_STRING | 24;
        output.content[1] = bytestring_length as _;
        prefix_length = 2;
    };
    output.len = prefix_length + bytestring_length;
    // FIXME: Make the function fallible, especially with the prospect of algorithm agility
    assert!(
        output.len <= MAX_MESSAGE_SIZE_LEN,
        "Tried to encode a message that is too large."
    );

    let enc_structure = encode_enc_structure(th_3);

    let (k_3, iv_3) = compute_k_3_iv_3(crypto, prk_3e2m, th_3);

    let ciphertext_3 = crypto.aes_ccm_encrypt_tag_8(&k_3, &iv_3, &enc_structure[..], plaintext_3);

    output.content[prefix_length..][..ciphertext_3.len].copy_from_slice(ciphertext_3.as_slice());

    output
}

fn decrypt_message_3(
    crypto: &mut impl CryptoTrait,
    prk_3e2m: &BytesHashLen,
    th_3: &BytesHashLen,
    message_3: &BufferMessage3,
) -> Result<BufferPlaintext3, EDHOCError> {
    // decode message_3
    let bytestring_length: usize;
    let prefix_length;
    // FIXME: Reuse CBOR decoder
    if (0..=23).contains(&(message_3.content[0] ^ CBOR_MAJOR_BYTE_STRING)) {
        bytestring_length = (message_3.content[0] ^ CBOR_MAJOR_BYTE_STRING).into();
        prefix_length = 1;
    } else {
        // FIXME: Assumes we don't exceed 256 bytes which is the current buffer size
        bytestring_length = message_3.content[1].into();
        prefix_length = 2;
    }

    let mut ciphertext_3: BufferCiphertext3 = BufferCiphertext3::new();
    ciphertext_3.len = bytestring_length;
    ciphertext_3.content[..bytestring_length]
        .copy_from_slice(&message_3.content[prefix_length..][..bytestring_length]);

    let (k_3, iv_3) = compute_k_3_iv_3(crypto, prk_3e2m, th_3);

    let enc_structure = encode_enc_structure(th_3);

    crypto.aes_ccm_decrypt_tag_8(&k_3, &iv_3, &enc_structure, &ciphertext_3)
}

// output must hold id_cred.len() + cred.len()
fn encode_kdf_context(
    c_r: Option<ConnId>, // only present for MAC_2
    id_cred: &[u8],
    th: &BytesHashLen,
    cred: &[u8],
    ead: &Option<EADItem>,
) -> (BytesMaxContextBuffer, usize) {
    // encode context in line
    // assumes ID_CRED_R and CRED_R are already CBOR-encoded (and also EAD)
    let mut output: BytesMaxContextBuffer = [0x00; MAX_KDF_CONTEXT_LEN];

    let mut output_len = if let Some(c_r) = c_r {
        let c_r = c_r.as_slice();
        output[..c_r.len()].copy_from_slice(c_r);
        c_r.len()
    } else {
        0 // no u8 encoded
    };
    output[output_len..output_len + id_cred.len()].copy_from_slice(&id_cred);
    output[output_len + id_cred.len()] = CBOR_BYTE_STRING;
    output[output_len + id_cred.len() + 1] = SHA256_DIGEST_LEN as u8;
    output[output_len + id_cred.len() + 2..output_len + id_cred.len() + 2 + th.len()]
        .copy_from_slice(&th[..]);
    output[output_len + id_cred.len() + 2 + th.len()
        ..output_len + id_cred.len() + 2 + th.len() + cred.len()]
        .copy_from_slice(cred);

    output_len = output_len + id_cred.len() + 2 + th.len() + cred.len();

    output_len += if let Some(ead) = ead {
        let encoded_ead = encode_ead_item(ead).unwrap(); // NOTE: this re-encoding could be avoided by passing just a reference to ead in the decrypted plaintext
        output[output_len..output_len + encoded_ead.len].copy_from_slice(encoded_ead.as_slice());
        encoded_ead.len
    } else {
        0
    };

    (output, output_len)
}

fn compute_mac_3(
    crypto: &mut impl CryptoTrait,
    prk_4e3m: &BytesHashLen,
    th_3: &BytesHashLen,
    id_cred_i: &[u8],
    cred_i: &[u8],
    ead_3: &Option<EADItem>,
) -> BytesMac3 {
    // MAC_3 = EDHOC-KDF( PRK_4e3m, 6, context_3, mac_length_3 )
    let (context, context_len) = encode_kdf_context(None, id_cred_i, th_3, cred_i, ead_3);

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
    c_r: ConnId,
    id_cred_r: &[u8],
    cred_r: &[u8],
    th_2: &BytesHashLen,
    ead_2: &Option<EADItem>,
) -> BytesMac2 {
    // compute MAC_2
    let (context, context_len) = encode_kdf_context(Some(c_r), id_cred_r, th_2, cred_r, ead_2);

    // MAC_2 = EDHOC-KDF( PRK_3e2m, 2, context_2, mac_length_2 )
    let mut mac_2: BytesMac2 = [0x00; MAC_LENGTH_2];
    mac_2[..].copy_from_slice(
        &edhoc_kdf(crypto, prk_3e2m, 2_u8, &context, context_len, MAC_LENGTH_2)[..MAC_LENGTH_2],
    );

    mac_2
}

fn encode_plaintext_2(
    c_r: ConnId,
    id_cred_r: &[u8],
    mac_2: &BytesMac2,
    ead_2: &Option<EADItem>,
) -> Result<BufferPlaintext2, EDHOCError> {
    let mut plaintext_2: BufferPlaintext2 = BufferPlaintext2::new();
    let c_r = c_r.as_slice();

    plaintext_2
        .extend_from_slice(c_r)
        .or(Err(EDHOCError::EncodingError))?;
    // id_cred_r.write_to_message(&mut plaintext_2)?;
    plaintext_2
        .extend_from_slice(id_cred_r)
        .or(Err(EDHOCError::EncodingError))?;
    let offset_cred = plaintext_2.len;

    plaintext_2.content[offset_cred] = CBOR_MAJOR_BYTE_STRING | MAC_LENGTH_2 as u8;
    plaintext_2.content[1 + offset_cred..1 + offset_cred + mac_2.len()].copy_from_slice(&mac_2[..]);
    plaintext_2.len = 1 + offset_cred + mac_2.len();

    if let Some(ead_2) = ead_2 {
        match encode_ead_item(ead_2) {
            Ok(ead_2) => plaintext_2
                .extend_from_slice(ead_2.as_slice())
                .and(Ok(plaintext_2))
                .or(Err(EDHOCError::EadTooLongError)),
            Err(e) => Err(e),
        }
    } else {
        Ok(plaintext_2)
    }
}

/// Apply the XOR base encryption for ciphertext_2 in place. This will decrypt (or decrypt) the bytes
/// in the ciphertext_2 argument (which may alternatively contain plaintext), returning the cipher
/// (or plain-)text.
fn encrypt_decrypt_ciphertext_2(
    crypto: &mut impl CryptoTrait,
    prk_2e: &BytesHashLen,
    th_2: &BytesHashLen,
    ciphertext_2: &BufferCiphertext2,
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

    let mut result = BufferCiphertext2::default();
    for i in 0..ciphertext_2.len {
        result.content[i] = ciphertext_2.content[i] ^ keystream_2[i];
    }
    result.len = ciphertext_2.len;

    result
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

    crypto.hkdf_extract(salt_4e3m, &g_iy)
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

    crypto.hkdf_extract(salt_3e2m, &g_rx)
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

    crypto.hkdf_extract(th_2, &g_xy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexlit::hex;
    use lakers_crypto::default_crypto;
    // test vectors (TV)

    // message_1 (first_time)
    const METHOD_TV_FIRST_TIME: u8 = 0x03;
    const SUITES_I_TV_FIRST_TIME: &str = "06";
    const G_X_TV_FIRST_TIME: BytesP256ElemLen =
        hex!("741a13d7ba048fbb615e94386aa3b61bea5b3d8f65f32620b749bee8d278efa9");
    const C_I_TV_FIRST_TIME: ConnId = ConnId::from_int_raw(0x0e);
    const MESSAGE_1_TV_FIRST_TIME: &str =
        "03065820741a13d7ba048fbb615e94386aa3b61bea5b3d8f65f32620b749bee8d278efa90e";

    // message_1 (second time)
    const METHOD_TV: u8 = 0x03;
    // manually modified test vector to include a single supported cipher suite
    const SUITES_I_TV: &str = "0602";
    const G_X_TV: BytesP256ElemLen =
        hex!("8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6");
    const C_I_TV: ConnId = ConnId::from_int_raw(0x37);
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
    const G_Y_TV: BytesP256ElemLen =
        hex!("419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5");
    const C_R_TV: ConnId = ConnId::from_int_raw(0x27);
    const MESSAGE_2_TV: &str = "582b419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d59862a1eef9e0e7e1886fcd";
    const CIPHERTEXT_2_TV: &str = "9862a1eef9e0e7e1886fcd";
    const H_MESSAGE_1_TV: BytesHashLen =
        hex!("ca02cabda5a8902749b42f711050bb4dbd52153e87527594b39f50cdf019888c");
    const TH_2_TV: BytesHashLen =
        hex!("356efd53771425e008f3fe3a86c83ff4c6b16e57028ff39d5236c182b202084b");
    const TH_3_TV: BytesHashLen =
        hex!("adaf67a78a4bcc91e018f8882762a722000b2507039df0bc1bbf0c161bb3155c");
    const TH_4_TV: BytesHashLen =
        hex!("c902b1e3a4326c93c5551f5f3aa6c5ecc0246806765612e52b5d99e6059d6b6e");
    const PRK_2E_TV: BytesP256ElemLen =
        hex!("5aa0d69f3e3d1e0c479f0b8a486690c9802630c3466b1dc92371c982563170b5");
    const CIPHERTEXT_2_LEN_TV: usize = MESSAGE_2_TV.len() / 2 - P256_ELEM_LEN - 2;
    const PLAINTEXT_2_LEN_TV: usize = CIPHERTEXT_2_LEN_TV;
    const KEYSTREAM_2_TV: [u8; PLAINTEXT_2_LEN_TV] = hex!("bf50e9e7bad0bb68173399");
    const PRK_3E2M_TV: BytesP256ElemLen =
        hex!("0ca3d3398296b3c03900987620c11f6fce70781c1d1219720f9ec08c122d8434");
    const CONTEXT_INFO_MAC_2_TV: [u8; 134] = hex!("27a10441325820356efd53771425e008f3fe3a86c83ff4c6b16e57028ff39d5236c182b202084ba2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
    const MAC_2_TV: BytesMac2 = hex!("0943305c899f5c54");
    const ID_CRED_I_TV: BytesIdCred = hex!("a104412b");
    const MAC_3_TV: BytesMac3 = hex!("623c91df41e34c2f");
    const MESSAGE_3_TV: &str = "52e562097bc417dd5919485ac7891ffd90a9fc";
    const PRK_4E3M_TV: BytesP256ElemLen =
        hex!("81cc8a298e357044e3c466bb5c0a1e507e01d49238aeba138df94635407c0ff7");
    const CRED_I_TV : [u8; 107] = hex!("a2027734322d35302d33312d46462d45462d33372d33322d333908a101a5010202412b2001215820ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb62258206e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8");
    const ID_CRED_R_TV: BytesIdCred = hex!("a1044132");
    const CRED_R_TV : [u8; 95] = hex!("a2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
    const PLAINTEXT_2_TV: &str = "2732480943305c899f5c54";
    const SK_I_TV: BytesP256ElemLen =
        hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
    const X_TV: BytesP256ElemLen =
        hex!("368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525");
    const G_R_TV: BytesP256ElemLen =
        hex!("bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0");
    const PLAINTEXT_3_TV: &str = "2b48623c91df41e34c2f";
    const SALT_3E2M_TV: BytesHashLen =
        hex!("af4e103a47cb3cf32570d5c25ad27732bd8d8178e9a69d061c31a27f8e3ca926");
    const SALT_4E3M_TV: BytesHashLen =
        hex!("cfddf9515a7e46e7b4dbff31cbd56cd04ba332250de9ea5de1caf9f6d13914a7");
    const G_XY_TV: BytesP256ElemLen =
        hex!("2f0cb7e860ba538fbf5c8bded009f6259b4b628fe1eb7dbe9378e5ecf7a824ba");
    const PRK_OUT_TV: BytesHashLen =
        hex!("2c71afc1a9338a940bb3529ca734b886f30d1aba0b4dc51beeaeabdfea9ecbf8");
    const PRK_EXPORTER_TV: BytesHashLen =
        hex!("e14d06699cee248c5a04bf9227bbcd4ce394de7dcb56db43555474171e6446db");
    const OSCORE_MASTER_SECRET_TV: BytesCcmKeyLen = hex!("f9868f6a3aca78a05d1485b35030b162");
    const OSCORE_MASTER_SALT_TV: Bytes8 = hex!("ada24c7dbfc85eeb");

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
        let suites_i_tv = EdhocBuffer::from_hex(SUITES_I_TV);
        let message_1 =
            encode_message_1(METHOD_TV, &suites_i_tv, &G_X_TV, C_I_TV, &None::<EADItem>).unwrap();

        assert_eq!(message_1.len, 39);
        assert_eq!(message_1, BufferMessage1::from_hex(MESSAGE_1_TV));
    }

    #[test]
    fn test_parse_suites_i() {
        let message_1_tv = BufferMessage1::from_hex(MESSAGE_1_TV);
        let suites_i_tv = EdhocBuffer::from_hex(SUITES_I_TV);
        // skip the fist byte (method)
        let decoder = CBORDecoder::new(&message_1_tv.content[1..message_1_tv.len]);
        let res = parse_suites_i(decoder);
        assert!(res.is_ok());
        let (suites_i, _decoder) = res.unwrap();
        assert_eq!(suites_i, suites_i_tv);

        let message_1_tv = BufferMessage1::from_hex(MESSAGE_1_TV_SUITE_ONLY_A);
        // skip the fist byte (method)
        let decoder = CBORDecoder::new(&message_1_tv.content[1..message_1_tv.len]);
        let res = parse_suites_i(decoder);
        assert!(res.is_ok());
        let (suites_i, _decoder) = res.unwrap();
        assert_eq!(suites_i[0], 0x18);

        let message_1_tv = BufferMessage1::from_hex(MESSAGE_1_TV_SUITE_ONLY_B);
        // skip the fist byte (method)
        let decoder = CBORDecoder::new(&message_1_tv.content[1..message_1_tv.len]);
        let res = parse_suites_i(decoder);
        assert!(res.is_ok());
        let (suites_i, _decoder) = res.unwrap();
        assert_eq!(suites_i.len(), 2);
        assert_eq!(suites_i[0], 0x02);
        assert_eq!(suites_i[1], 0x01);

        let message_1_tv = BufferMessage1::from_hex(MESSAGE_1_TV_SUITE_ONLY_C);
        // skip the fist byte (method)
        let decoder = CBORDecoder::new(&message_1_tv.content[1..message_1_tv.len]);
        let res = parse_suites_i(decoder);
        assert!(res.is_ok());
        let (suites_i, _decoder) = res.unwrap();
        assert_eq!(suites_i.len(), 2);
        assert_eq!(suites_i[0], 0x02);
        assert_eq!(suites_i[1], 0x19);

        let message_1_tv = BufferMessage1::from_hex(MESSAGE_1_TV_SUITE_ONLY_ERR);
        // skip the fist byte (method)
        let decoder = CBORDecoder::new(&message_1_tv.content[1..message_1_tv.len]);
        let res = parse_suites_i(decoder);
        assert_eq!(res.unwrap_err(), EDHOCError::ParsingError);
    }

    #[test]
    fn test_parse_message_1() {
        let message_1_tv_first_time = BufferMessage1::from_hex(MESSAGE_1_TV_FIRST_TIME);
        let message_1_tv = BufferMessage1::from_hex(MESSAGE_1_TV);
        let suites_i_tv_first_time = EdhocBuffer::from_hex(SUITES_I_TV_FIRST_TIME);
        let suites_i_tv = EdhocBuffer::from_hex(SUITES_I_TV);

        // first time message_1 parsing
        let res = parse_message_1(&message_1_tv_first_time);
        assert!(res.is_ok());
        let (method, suites_i, g_x, c_i, ead_1) = res.unwrap();

        assert_eq!(method, METHOD_TV_FIRST_TIME);
        assert_eq!(suites_i, suites_i_tv_first_time);
        assert_eq!(g_x, G_X_TV_FIRST_TIME);
        assert_eq!(c_i, C_I_TV_FIRST_TIME);
        assert!(ead_1.is_none());

        // second time message_1
        let res = parse_message_1(&message_1_tv);
        assert!(res.is_ok());
        let (method, suites_i, g_x, c_i, ead_1) = res.unwrap();

        assert_eq!(method, METHOD_TV);
        assert_eq!(suites_i, suites_i_tv);
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
            &None,
        );
        assert_eq!(mac_3, MAC_3_TV);
    }

    #[test]
    fn test_compute_and_verify_mac_2() {
        let rcvd_mac_2 = compute_mac_2(
            &mut default_crypto(),
            &PRK_3E2M_TV,
            C_R_TV,
            &ID_CRED_R_TV,
            &CRED_R_TV,
            &TH_2_TV,
            &None,
        );

        assert_eq!(rcvd_mac_2, MAC_2_TV);
    }

    #[test]
    fn test_encode_plaintext_2() {
        let plaintext_2_tv = BufferPlaintext2::from_hex(PLAINTEXT_2_TV);
        let plaintext_2 = encode_plaintext_2(
            C_R_TV,
            IdCred::from_full_value(&ID_CRED_R_TV[..])
                .unwrap()
                .as_encoded_value(),
            &MAC_2_TV,
            &None::<EADItem>,
        )
        .unwrap();

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

        let plaintext_2 = decode_plaintext_2(&plaintext_2_tv);
        assert!(plaintext_2.is_ok());
        let (c_r, id_cred_r, mac_2, ead_2) = plaintext_2.unwrap();
        assert_eq!(c_r, C_R_TV);
        assert_eq!(id_cred_r.as_full_value(), ID_CRED_R_TV);
        assert_eq!(mac_2, MAC_2_TV);
        assert!(ead_2.is_none());
    }

    #[test]
    fn test_encrypt_decrypt_ciphertext_2() {
        let plaintext_2_tv = BufferPlaintext2::from_hex(PLAINTEXT_2_TV);
        let ciphertext_2_tv = BufferPlaintext2::from_hex(CIPHERTEXT_2_TV);
        // test decryption
        let plaintext_2 = encrypt_decrypt_ciphertext_2(
            &mut default_crypto(),
            &PRK_2E_TV,
            &TH_2_TV,
            &ciphertext_2_tv,
        );

        assert_eq!(plaintext_2.len, PLAINTEXT_2_LEN_TV);
        for i in 0..PLAINTEXT_2_LEN_TV {
            assert_eq!(plaintext_2.content[i], plaintext_2_tv.content[i]);
        }

        // test encryption
        let ciphertext_2 =
            encrypt_decrypt_ciphertext_2(&mut default_crypto(), &PRK_2E_TV, &TH_2_TV, &plaintext_2);

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
        let plaintext_3 = encode_plaintext_3(
            IdCred::from_full_value(&ID_CRED_I_TV[..])
                .unwrap()
                .as_encoded_value(),
            &MAC_3_TV,
            &None::<EADItem>,
        )
        .unwrap();
        assert_eq!(plaintext_3, plaintext_3_tv);
    }

    #[test]
    fn test_decode_plaintext_3() {
        let plaintext_3_tv = BufferPlaintext3::from_hex(PLAINTEXT_3_TV);

        let (id_cred_i, mac_3, ead_3) = decode_plaintext_3(&plaintext_3_tv).unwrap();

        assert_eq!(mac_3, MAC_3_TV);
        assert_eq!(id_cred_i.as_full_value(), ID_CRED_I_TV);
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

        let res = encode_ead_item(&ead_item);
        assert!(res.is_ok());
        let ead_buffer = res.unwrap();
        assert_eq!(ead_buffer.content, ead_tv.content);
    }

    #[test]
    fn test_encode_message_with_ead_item() {
        let method_tv = METHOD_TV;
        let suites_i_tv = EdhocBuffer::from_hex(SUITES_I_TV);
        let c_i_tv = C_I_TV;
        let message_1_ead_tv = BufferMessage1::from_hex(MESSAGE_1_WITH_DUMMY_CRITICAL_EAD_TV);
        let ead_item = EADItem {
            label: EAD_DUMMY_LABEL_TV,
            is_critical: true,
            value: Some(EdhocMessageBuffer::from_hex(EAD_DUMMY_VALUE_TV)),
        };

        let res = encode_message_1(method_tv, &suites_i_tv, &G_X_TV, c_i_tv, &Some(ead_item));
        assert!(res.is_ok());
        let message_1 = res.unwrap();

        assert_eq!(message_1.content, message_1_ead_tv.content);
    }

    #[test]
    fn test_encode_message_with_large_ead_item() {
        let method_tv = METHOD_TV;
        let suites_i_tv = EdhocBuffer::from_hex(SUITES_I_TV);
        let c_i_tv = C_I_TV;

        // the actual value will be zeroed since it doesn't matter in this test
        let mut ead_value = EdhocMessageBuffer::new();
        ead_value.len = MAX_MESSAGE_SIZE_LEN;

        let ead_item = EADItem {
            label: EAD_DUMMY_LABEL_TV,
            is_critical: true,
            value: Some(ead_value),
        };

        let res = encode_message_1(method_tv, &suites_i_tv, &G_X_TV, c_i_tv, &Some(ead_item));
        assert_eq!(res.unwrap_err(), EDHOCError::EadTooLongError);
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
        let (_method, _suites_i, _g_x, _c_i, ead_1) = res.unwrap();
        let ead_1 = ead_1.unwrap();
        assert!(ead_1.is_critical);
        assert_eq!(ead_1.label, EAD_DUMMY_LABEL_TV);
        assert_eq!(ead_1.value.unwrap().content, ead_value_tv.content);
    }

    #[test]
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
