#![cfg_attr(not(test), no_std)]

pub use {
    lakers_shared::Crypto as CryptoTrait, lakers_shared::State as EdhocState, lakers_shared::*,
};

#[cfg(any(feature = "ead-none", feature = "ead-zeroconf"))]
pub use lakers_ead::*;

mod edhoc;
use edhoc::*;

#[derive(Debug)]
pub struct EdhocInitiator<'a, Crypto: CryptoTrait> {
    state: Start,             // opaque state
    i: &'a [u8],              // private authentication key of I
    cred_i: &'a [u8],         // I's full credential
    cred_r: Option<&'a [u8]>, // R's full credential (if provided)
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocInitiatorPreparingM1<'a, Crypto: CryptoTrait> {
    state: PreparingM1,       // opaque state
    i: &'a [u8],              // private authentication key of I
    cred_i: &'a [u8],         // I's full credential
    cred_r: Option<&'a [u8]>, // R's full credential (if provided)
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocInitiatorWaitM2<'a, Crypto: CryptoTrait> {
    state: WaitM2,            // opaque state
    i: &'a [u8],              // private authentication key of I
    cred_i: &'a [u8],         // I's full credential
    cred_r: Option<&'a [u8]>, // R's full credential (if provided)
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocInitiatorProcessingM2<'a, Crypto: CryptoTrait> {
    state: ProcessingM2,      // opaque state
    i: &'a [u8],              // private authentication key of I
    cred_i: &'a [u8],         // I's full credential
    cred_r: Option<&'a [u8]>, // R's full credential (if provided)
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocInitiatorProcessedM2<'a, Crypto: CryptoTrait> {
    state: ProcessedM2, // opaque state
    cred_i: &'a [u8],   // I's full credential
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocInitiatorPreparingM3<'a, Crypto: CryptoTrait> {
    state: PreparingM3, // opaque state
    cred_i: &'a [u8],   // I's full credential
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocInitiatorDone<Crypto: CryptoTrait> {
    state: CompletedNew,
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocResponder<'a, Crypto: CryptoTrait> {
    state: Start,             // opaque state
    r: &'a [u8],              // private authentication key of R
    cred_r: &'a [u8],         // R's full credential
    cred_i: Option<&'a [u8]>, // I's full credential (if provided)
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocResponderProcessingM1<'a, Crypto: CryptoTrait> {
    state: ProcessingM1,      // opaque state
    r: &'a [u8],              // private authentication key of R
    cred_r: &'a [u8],         // R's full credential
    cred_i: Option<&'a [u8]>, // I's full credential (if provided)
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocResponderWaitM3<'a, Crypto: CryptoTrait> {
    state: WaitM3,            // opaque state
    cred_i: Option<&'a [u8]>, // I's full credential (if provided)
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocResponderProcessingM3<'a, Crypto: CryptoTrait> {
    state: ProcessingM3,      // opaque state
    cred_i: Option<&'a [u8]>, // I's full credential (if provided)
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocResponderDone<Crypto: CryptoTrait> {
    state: CompletedNew,
    crypto: Crypto,
}

impl<'a, Crypto: CryptoTrait> EdhocResponder<'a, Crypto> {
    pub fn new(
        state: Start,
        crypto: Crypto,
        r: &'a [u8],
        cred_r: &'a [u8],
        cred_i: Option<&'a [u8]>,
    ) -> Self {
        assert!(r.len() == P256_ELEM_LEN);

        EdhocResponder {
            state,
            r,
            cred_r,
            cred_i,
            crypto,
        }
    }

    pub fn process_message_1(
        mut self,
        message_1: &BufferMessage1,
    ) -> Result<(EdhocResponderProcessingM1<'a, Crypto>, Option<EADItem>), EDHOCError> {
        let (state, ead_1) = r_process_message_1(self.state, &mut self.crypto, message_1)?;

        Ok((
            EdhocResponderProcessingM1 {
                state,
                r: self.r,
                cred_r: self.cred_r,
                cred_i: self.cred_i,
                crypto: self.crypto,
            },
            ead_1,
        ))
    }
}

impl<'a, Crypto: CryptoTrait> EdhocResponderProcessingM1<'a, Crypto> {
    pub fn prepare_message_2(
        mut self,
        c_r: u8,
        id_cred_r: &IdCred,
        ead_2: &Option<EADItem>,
    ) -> Result<(EdhocResponderWaitM3<'a, Crypto>, BufferMessage2), EDHOCError> {
        let (y, g_y) = self.crypto.p256_generate_key_pair();

        match r_prepare_message_2(
            self.state,
            &mut self.crypto,
            self.cred_r,
            self.r.try_into().expect("Wrong length of private key"),
            y,
            g_y,
            c_r,
            id_cred_r,
            ead_2,
        ) {
            Ok((state, message_2)) => Ok((
                EdhocResponderWaitM3 {
                    state,
                    cred_i: self.cred_i,
                    crypto: self.crypto,
                },
                message_2,
            )),
            Err(error) => Err(error),
        }
    }
}

impl<'a, Crypto: CryptoTrait> EdhocResponderWaitM3<'a, Crypto> {
    pub fn process_message_3a(
        mut self,
        message_3: &'a BufferMessage3,
    ) -> Result<(EdhocResponderProcessingM3<Crypto>, Option<EADItem>), EDHOCError> {
        match r_process_message_3a(&mut self.state, &mut self.crypto, message_3) {
            Ok((state, ead_3)) => Ok((
                EdhocResponderProcessingM3 {
                    state,
                    crypto: self.crypto,
                    cred_i: self.cred_i,
                },
                ead_3,
            )),
            Err(error) => Err(error),
        }
    }
}

impl<'a, Crypto: CryptoTrait> EdhocResponderProcessingM3<'a, Crypto> {
    pub fn process_message_3b(
        mut self,
    ) -> Result<(EdhocResponderDone<Crypto>, [u8; SHA256_DIGEST_LEN]), EDHOCError> {
        match r_process_message_3b(&mut self.state, &mut self.crypto, self.cred_i.unwrap()) {
            Ok((state, prk_out)) => Ok((
                EdhocResponderDone {
                    state,
                    crypto: self.crypto,
                },
                prk_out,
            )),
            Err(error) => Err(error),
        }
    }
}

impl<Crypto: CryptoTrait> EdhocResponderDone<Crypto> {
    pub fn edhoc_exporter(
        &mut self,
        label: u8,
        context: &[u8],
        length: usize,
    ) -> [u8; MAX_BUFFER_LEN] {
        let mut context_buf: BytesMaxContextBuffer = [0x00u8; MAX_KDF_CONTEXT_LEN];
        context_buf[..context.len()].copy_from_slice(context);

        edhoc_exporter_new(
            &self.state,
            &mut self.crypto,
            label,
            &context_buf,
            context.len(),
            length,
        )
    }

    pub fn edhoc_key_update(&mut self, context: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
        let mut context_buf = [0x00u8; MAX_KDF_CONTEXT_LEN];
        context_buf[..context.len()].copy_from_slice(context);

        edhoc_key_update_new(
            &mut self.state,
            &mut self.crypto,
            &context_buf,
            context.len(),
        )
    }
}

impl<'a, Crypto: CryptoTrait> EdhocInitiator<'a, Crypto> {
    pub fn new(
        state: Start,
        crypto: Crypto,
        i: &'a [u8],
        cred_i: &'a [u8],
        cred_r: Option<&'a [u8]>,
    ) -> Self {
        assert!(i.len() == P256_ELEM_LEN);

        EdhocInitiator {
            state,
            i,
            cred_i,
            cred_r,
            crypto,
        }
    }

    pub fn prepare_message_1a(
        mut self,
        c_i: u8,
    ) -> Result<EdhocInitiatorPreparingM1<'a, Crypto>, EDHOCError> {
        let (x, g_x) = self.crypto.p256_generate_key_pair();

        match i_prepare_message_1a(self.state, &mut self.crypto, x, g_x, c_i) {
            Ok(state) => Ok(EdhocInitiatorPreparingM1 {
                state,
                i: self.i,
                cred_i: self.cred_i,
                cred_r: self.cred_r,
                crypto: self.crypto,
            }),
            Err(error) => Err(error),
        }
    }
}

impl<'a, Crypto: CryptoTrait> EdhocInitiatorPreparingM1<'a, Crypto> {
    pub fn prepare_message_1b(
        mut self,
        ead_1: &Option<EADItem>,
    ) -> Result<(EdhocInitiatorWaitM2<'a, Crypto>, EdhocMessageBuffer), EDHOCError> {
        match i_prepare_message_1b(self.state, &mut self.crypto, ead_1) {
            Ok((state, message_1)) => Ok((
                EdhocInitiatorWaitM2 {
                    state,
                    i: self.i,
                    cred_i: self.cred_i,
                    cred_r: self.cred_r,
                    crypto: self.crypto,
                },
                message_1,
            )),
            Err(error) => Err(error),
        }
    }
}

impl<'a, Crypto: CryptoTrait> EdhocInitiatorWaitM2<'a, Crypto> {
    pub fn process_message_2a(
        mut self,
        message_2: &'a BufferMessage2,
    ) -> Result<
        (
            EdhocInitiatorProcessingM2<'a, Crypto>,
            u8,
            IdCredOwned,
            Option<EADItem>,
        ),
        EDHOCError,
    > {
        match i_process_message_2a(self.state, &mut self.crypto, message_2) {
            Ok((state, c_r, id_cred_r, ead_2)) => Ok((
                EdhocInitiatorProcessingM2 {
                    state,
                    i: self.i,
                    cred_i: self.cred_i,
                    cred_r: self.cred_r,
                    crypto: self.crypto,
                },
                c_r,
                id_cred_r,
                ead_2,
            )),
            Err(error) => Err(error),
        }
    }
}

impl<'a, Crypto: CryptoTrait> EdhocInitiatorProcessingM2<'a, Crypto> {
    pub fn process_message_2b(
        mut self,
        valid_cred_r: &[u8],
    ) -> Result<EdhocInitiatorProcessedM2<'a, Crypto>, EDHOCError> {
        match i_process_message_2b(
            self.state,
            &mut self.crypto,
            valid_cred_r,
            self.i
                .try_into()
                .expect("Wrong length of initiator private key"),
        ) {
            Ok(state) => Ok(EdhocInitiatorProcessedM2 {
                state,
                cred_i: self.cred_i,
                crypto: self.crypto,
            }),
            Err(error) => Err(error),
        }
    }
}

impl<'a, Crypto: CryptoTrait> EdhocInitiatorProcessedM2<'a, Crypto> {
    pub fn prepare_message_3a(
        mut self,
    ) -> Result<EdhocInitiatorPreparingM3<'a, Crypto>, EDHOCError> {
        match i_prepare_message_3a(&mut self.state, &mut self.crypto, self.cred_i) {
            Ok(state) => Ok(EdhocInitiatorPreparingM3 {
                state,
                crypto: self.crypto,
                cred_i: self.cred_i,
            }),
            Err(error) => Err(error),
        }
    }
}

impl<'a, Crypto: CryptoTrait> EdhocInitiatorPreparingM3<'a, Crypto> {
    pub fn prepare_message_3b(
        mut self,
        ead_3: &Option<EADItem>,
    ) -> Result<
        (
            EdhocInitiatorDone<Crypto>,
            BufferMessage3,
            [u8; SHA256_DIGEST_LEN],
        ),
        EDHOCError,
    > {
        match i_prepare_message_3b(&mut self.state, &mut self.crypto, self.cred_i, ead_3) {
            Ok((state, message_3, prk_out)) => Ok((
                EdhocInitiatorDone {
                    state,
                    crypto: self.crypto,
                },
                message_3,
                prk_out,
            )),
            Err(error) => Err(error),
        }
    }
}

impl<Crypto: CryptoTrait> EdhocInitiatorDone<Crypto> {
    pub fn edhoc_exporter(
        &mut self,
        label: u8,
        context: &[u8],
        length: usize,
    ) -> [u8; MAX_BUFFER_LEN] {
        let mut context_buf: BytesMaxContextBuffer = [0x00u8; MAX_KDF_CONTEXT_LEN];
        context_buf[..context.len()].copy_from_slice(context);

        edhoc_exporter_new(
            &self.state,
            &mut self.crypto,
            label,
            &context_buf,
            context.len(),
            length,
        )
    }

    pub fn edhoc_key_update(&mut self, context: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
        let mut context_buf = [0x00u8; MAX_KDF_CONTEXT_LEN];
        context_buf[..context.len()].copy_from_slice(context);

        edhoc_key_update_new(
            &mut self.state,
            &mut self.crypto,
            &context_buf,
            context.len(),
        )
    }
}

pub fn generate_connection_identifier_cbor<Crypto: CryptoTrait>(crypto: &mut Crypto) -> u8 {
    let c_i = generate_connection_identifier(crypto);
    if c_i >= 0 && c_i <= 23 {
        c_i as u8 // verbatim encoding of single byte integer
    } else if c_i < 0 && c_i >= -24 {
        // negative single byte integer encoding
        CBOR_NEG_INT_1BYTE_START - 1 + c_i.unsigned_abs()
    } else {
        0
    }
}

/// generates an identifier that can be serialized as a single CBOR integer, i.e. -24 <= x <= 23
pub fn generate_connection_identifier<Crypto: CryptoTrait>(crypto: &mut Crypto) -> i8 {
    let mut conn_id = crypto.get_random_byte() as i8;
    while conn_id < -24 || conn_id > 23 {
        conn_id = crypto.get_random_byte() as i8;
    }
    conn_id
}

// Implements auth credential checking according to draft-tiloca-lake-implem-cons
pub fn credential_check_or_fetch_new<'a>(
    cred_expected: Option<EdhocMessageBuffer>,
    id_cred_received: IdCredOwned,
) -> Result<(EdhocMessageBuffer, BytesP256ElemLen), EDHOCError> {
    // Processing of auth credentials according to draft-tiloca-lake-implem-cons
    // Comments tagged with a number refer to steps in Section 4.3.1. of draft-tiloca-lake-implem-cons
    if let Some(cred_expected) = cred_expected {
        // 1. Does ID_CRED_X point to a stored authentication credential? YES
        // IMPL: compare cred_i_expected with id_cred
        //   IMPL: assume cred_i_expected is well formed
        let (public_key_expected, kid_expected) = parse_cred(cred_expected.as_slice())?;
        let public_key = public_key_expected;
        let credentials_match = match id_cred_received {
            IdCredOwned::CompactKid(kid_received) => kid_received == kid_expected,
            IdCredOwned::FullCredential(cred_received) => cred_expected == cred_received,
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
        if let IdCredOwned::FullCredential(cred_received) = id_cred_received {
            // 3. Is the trust model Pre-knowledge-only? NO (hardcoded to NO for now)

            // 4. Is the trust model Pre-knowledge + TOFU? YES (hardcoded to YES for now)

            // 6. Validate CRED_X. Generally a CCS has to be validated only syntactically and semantically, unlike a certificate or a CWT.
            //    Is the validation successful?
            // IMPL: parse_cred(cred_r) and check it is valid
            match parse_cred(cred_received.as_slice()) {
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

#[cfg(test)]
mod test {
    use super::*;

    use hexlit::hex;

    use lakers_crypto::default_crypto;

    const ID_CRED_I: &[u8] = &hex!("a104412b");
    const ID_CRED_R: &[u8] = &hex!("a104410a");
    const CRED_I: &[u8] = &hex!("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
    const I: &[u8] = &hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
    const R: &[u8] = &hex!("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");
    const G_I: &[u8] = &hex!("ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6"); // used
    const _G_I_Y_COORD: &[u8] =
        &hex!("6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8"); // not used
    const CRED_R: &[u8] = &hex!("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");
    const G_R: &[u8] = &hex!("bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0");
    const C_R_TV: [u8; 1] = hex!("27");

    const MESSAGE_1_TV_FIRST_TIME: &str =
        "03065820741a13d7ba048fbb615e94386aa3b61bea5b3d8f65f32620b749bee8d278efa90e";
    const MESSAGE_1_TV: &str =
        "0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637";

    #[test]
    fn test_new_initiator() {
        let state = Default::default();
        let _initiator = EdhocInitiator::new(state, default_crypto(), I, CRED_I, Some(CRED_R));
        let state = Default::default();
        let _initiator = EdhocInitiator::new(state, default_crypto(), I, CRED_I, None);
    }

    #[test]
    fn test_new_responder() {
        let state = Default::default();
        let _responder = EdhocResponder::new(state, default_crypto(), R, CRED_R, Some(CRED_I));
        let state = Default::default();
        let _responder = EdhocResponder::new(state, default_crypto(), R, CRED_R, None);
    }

    #[test]
    fn test_prepare_message_1() {
        let state = Default::default();
        let initiator = EdhocInitiator::new(state, default_crypto(), I, CRED_I, Some(CRED_R));

        let c_i = generate_connection_identifier_cbor(&mut default_crypto());
        let message_1 = initiator.prepare_message_1a(c_i);
        assert!(message_1.is_ok());
    }

    #[test]
    fn test_process_message_1() {
        let message_1_tv_first_time = EdhocMessageBuffer::from_hex(MESSAGE_1_TV_FIRST_TIME);
        let message_1_tv = EdhocMessageBuffer::from_hex(MESSAGE_1_TV);
        let state = Default::default();
        let responder = EdhocResponder::new(state, default_crypto(), R, CRED_R, Some(CRED_I));

        // process message_1 first time, when unsupported suite is selected
        let error = responder.process_message_1(&message_1_tv_first_time);
        assert!(error.is_err());
        assert_eq!(error.unwrap_err(), EDHOCError::UnsupportedCipherSuite);

        // We need to create a new responder -- no message is supposed to be processed twice by a
        // responder or initiator
        let state = Default::default();
        let responder = EdhocResponder::new(state, default_crypto(), R, CRED_R, Some(CRED_I));

        // process message_1 second time
        let error = responder.process_message_1(&message_1_tv);
        assert!(error.is_ok());
    }

    #[test]
    fn test_generate_connection_identifier() {
        let conn_id = generate_connection_identifier(&mut default_crypto());
        assert!(conn_id >= -24 && conn_id <= 23);
    }

    #[cfg(feature = "ead-none")]
    #[test]
    fn test_handshake() {
        let initiator = EdhocInitiator::new(
            Default::default(),
            default_crypto(),
            I,
            CRED_I,
            Some(CRED_R),
        );
        let responder = EdhocResponder::new(
            Default::default(),
            default_crypto(),
            R,
            CRED_R,
            Some(CRED_I),
        );

        let c_i: u8 = generate_connection_identifier_cbor(&mut default_crypto());
        let initiator = initiator.prepare_message_1a(c_i).unwrap();
        // NOTE: EADs would be prepared here
        // e.g. let ead_1 = i_prepare_ead_1(crypto, &x, suites_i[suites_i_len - 1]);
        let (initiator, result) = initiator.prepare_message_1b(&None).unwrap();

        let (responder, _ead_1) = responder.process_message_1(&result).unwrap();

        let c_r = generate_connection_identifier_cbor(&mut default_crypto());
        let kid = IdCred::CompactKid(parse_cred(CRED_R).unwrap().1);
        let (responder, message_2) = responder.prepare_message_2(c_r, &kid, &None).unwrap();

        assert!(c_r != 0xff);
        let (initiator, c_r, id_cred_r, _ead_2) = initiator.process_message_2a(&message_2).unwrap();
        let (valid_cred_r, g_r) =
            credential_check_or_fetch_new(Some(CRED_R.try_into().unwrap()), id_cred_r).unwrap();
        // Phase 2: Process EAD_X items that have not been processed yet, and that can be processed before message verification
        // i_process_ead_2(crypto, ead_2, valid_cred_r, &state.h_message_1)
        let initiator = initiator
            .process_message_2b(valid_cred_r.as_slice())
            .unwrap();

        let initiator = initiator.prepare_message_3a().unwrap();
        let (mut initiator, message_3, i_prk_out) = initiator.prepare_message_3b(&None).unwrap();

        let (responder, _ead_3) = responder.process_message_3a(&message_3).unwrap();
        // let cred_i = credential_check_or_fetch(cred_i_expected, id_cred_i);
        // r_process_ead_3(ead_3)
        let (mut responder, r_prk_out) = responder.process_message_3b().unwrap();

        // check that prk_out is equal at initiator and responder side
        assert_eq!(i_prk_out, r_prk_out);

        // derive OSCORE secret and salt at both sides and compare
        let i_oscore_secret = initiator.edhoc_exporter(0u8, &[], 16); // label is 0
        let i_oscore_salt = initiator.edhoc_exporter(1u8, &[], 8); // label is 1

        let r_oscore_secret = responder.edhoc_exporter(0u8, &[], 16); // label is 0
        let r_oscore_salt = responder.edhoc_exporter(1u8, &[], 8); // label is 1

        assert_eq!(i_oscore_secret, r_oscore_secret);
        assert_eq!(i_oscore_salt, r_oscore_salt);

        // test key update with context from draft-ietf-lake-traces
        let i_prk_out_new = initiator.edhoc_key_update(&[
            0xa0, 0x11, 0x58, 0xfd, 0xb8, 0x20, 0x89, 0x0c, 0xd6, 0xbe, 0x16, 0x96, 0x02, 0xb8,
            0xbc, 0xea,
        ]);
        let r_prk_out_new = responder.edhoc_key_update(&[
            0xa0, 0x11, 0x58, 0xfd, 0xb8, 0x20, 0x89, 0x0c, 0xd6, 0xbe, 0x16, 0x96, 0x02, 0xb8,
            0xbc, 0xea,
        ]);

        assert_eq!(i_prk_out_new, r_prk_out_new);
    }

    // U
    const ID_U_TV: &[u8] = &hex!("a104412b");

    // V -- nothing to do, will reuse CRED_R from above to act as CRED_V

    // W
    pub const W_TV: &[u8] =
        &hex!("4E5E15AB35008C15B89E91F9F329164D4AACD53D9923672CE0019F9ACD98573F");
    const G_W_TV: &[u8] = &hex!("FFA4F102134029B3B156890B88C9D9619501196574174DCB68A07DB0588E4D41");
    const LOC_W_TV: &[u8] = &hex!("636F61703A2F2F656E726F6C6C6D656E742E736572766572");

    // TODO: have a setup_test function that prepares the common objects for the ead tests
    #[cfg(feature = "ead-zeroconf")]
    #[test]
    fn test_ead_zeroconf() {
        // ==== initialize edhoc ====
        let initiator = EdhocInitiator::new(Default::default(), default_crypto(), I, CRED_I, None);
        let responder = EdhocResponder::new(
            Default::default(),
            default_crypto(),
            R,
            CRED_R,
            Some(CRED_I),
        );

        // ==== initialize ead-zeroconf ====
        let id_u: EdhocMessageBuffer = ID_U_TV.try_into().unwrap();
        let g_w: BytesP256ElemLen = G_W_TV.try_into().unwrap();
        let loc_w: EdhocMessageBuffer = LOC_W_TV.try_into().unwrap();

        ead_initiator_set_global_state(EADInitiatorState::new(id_u, g_w, loc_w));
        let ead_initiator_state = ead_initiator_get_global_state();
        assert_eq!(
            ead_initiator_state.protocol_state,
            EADInitiatorProtocolState::Start
        );

        ead_responder_set_global_state(EADResponderState::new());
        let ead_responder_state = ead_responder_get_global_state();
        assert_eq!(
            ead_responder_state.protocol_state,
            EADResponderProtocolState::Start
        );

        let mut acl = EdhocMessageBuffer::new();
        let (_g, kid_i) = parse_cred(CRED_I).unwrap();
        acl.push(kid_i).unwrap();
        mock_ead_server_set_global_state(MockEADServerState::new(
            CRED_R,
            W_TV.try_into().unwrap(),
            Some(acl),
        ));

        let c_i = generate_connection_identifier_cbor(&mut default_crypto());
        let (initiator, message_1) = initiator.prepare_message_1(c_i).unwrap();
        assert_eq!(
            ead_initiator_state.protocol_state,
            EADInitiatorProtocolState::WaitEAD2
        );

        // ==== begin edhoc with ead-zeroconf ====
        let responder = responder.process_message_1(&message_1).unwrap();
        assert_eq!(
            ead_responder_state.protocol_state,
            EADResponderProtocolState::ProcessedEAD1
        );

        let c_r = generate_connection_identifier_cbor(&mut default_crypto());
        let (responder, message_2) = responder.prepare_message_2(c_r).unwrap();
        assert_eq!(
            ead_responder_state.protocol_state,
            EADResponderProtocolState::Completed
        );

        let (initiator, _) = initiator.process_message_2(&message_2).unwrap();

        assert_eq!(
            ead_initiator_state.protocol_state,
            EADInitiatorProtocolState::Completed
        );

        let (initiator, message_3, i_prk_out) = initiator.prepare_message_3().unwrap();

        let (mut responder, r_prk_out) = responder.process_message_3(&message_3).unwrap();
        assert_eq!(i_prk_out, r_prk_out);
        assert_eq!(
            ead_responder_state.protocol_state,
            EADResponderProtocolState::Completed
        );
    }

    #[cfg(feature = "ead-zeroconf")]
    #[test]
    fn test_ead_zeroconf_not_authorized() {
        // ==== initialize edhoc ====
        let initiator = EdhocInitiator::new(Default::default(), default_crypto(), I, CRED_I, None);
        let responder = EdhocResponder::new(
            Default::default(),
            default_crypto(),
            R,
            CRED_R,
            Some(CRED_I),
        );

        // ==== initialize ead-zeroconf ====
        let id_u: EdhocMessageBuffer = ID_U_TV.try_into().unwrap();
        let g_w: BytesP256ElemLen = G_W_TV.try_into().unwrap();
        let loc_w: EdhocMessageBuffer = LOC_W_TV.try_into().unwrap();

        ead_initiator_set_global_state(EADInitiatorState::new(id_u, g_w, loc_w));
        let ead_initiator_state = ead_initiator_get_global_state();
        assert_eq!(
            ead_initiator_state.protocol_state,
            EADInitiatorProtocolState::Start
        );

        ead_responder_set_global_state(EADResponderState::new());
        let ead_responder_state = ead_responder_get_global_state();
        assert_eq!(
            ead_responder_state.protocol_state,
            EADResponderProtocolState::Start
        );

        let mut acl = EdhocMessageBuffer::new();
        let (_g, kid_i) = parse_cred(CRED_I).unwrap();
        let invalid_kid = kid_i + 1;
        acl.push(invalid_kid).unwrap();
        mock_ead_server_set_global_state(MockEADServerState::new(
            CRED_R,
            W_TV.try_into().unwrap(),
            Some(acl),
        ));

        let c_i = generate_connection_identifier_cbor(&mut default_crypto());
        let (initiator, message_1) = initiator.prepare_message_1(c_i).unwrap();
        assert_eq!(
            ead_initiator_state.protocol_state,
            EADInitiatorProtocolState::WaitEAD2
        );

        // ==== begin edhoc with ead-zeroconf ====
        assert_eq!(
            responder.process_message_1(&message_1).unwrap_err(),
            EDHOCError::EADError
        );
    }
}
