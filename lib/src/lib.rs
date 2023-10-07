#![cfg_attr(not(test), no_std)]

pub use {
    edhoc_consts::State as EdhocState, edhoc_consts::*, edhoc_crypto::*,
    EdhocInitiatorState as EdhocInitiator, EdhocResponderState as EdhocResponder,
};

#[cfg(any(feature = "ead-none", feature = "ead-zeroconf"))]
pub use edhoc_ead::*;

mod edhoc;
use edhoc::*;

mod c_wrapper;
use c_wrapper::*;

use edhoc_consts::*;

#[derive(Default, Debug)]
pub struct EdhocInitiatorState<'a> {
    state: State,        // opaque state
    i: &'a [u8],         // private authentication key of I
    g_r: &'a [u8],       // public authentication key of R
    id_cred_i: &'a [u8], // identifier of I's credential
    cred_i: &'a [u8],    // I's full credential
    id_cred_r: &'a [u8], // identifier of R's credential
    cred_r: &'a [u8],    // R's full credential
}

#[derive(Default, Debug)]
pub struct EdhocResponderState<'a> {
    state: State,        // opaque state
    r: &'a [u8],         // private authentication key of R
    g_i: &'a [u8],       // public authentication key of I
    id_cred_i: &'a [u8], // identifier of I's credential
    cred_i: &'a [u8],    // I's full credential
    id_cred_r: &'a [u8], // identifier of R's credential
    cred_r: &'a [u8],    // R's full credential
}

impl<'a> EdhocResponderState<'a> {
    pub fn to_c(self) -> EdhocResponderC {
        EdhocResponderC {
            state: self.state,
            r: self.r.as_ptr(),
            r_len: self.r.len(),
            g_i: self.g_i.as_ptr(),
            g_i_len: self.g_i.len(),
            id_cred_i: self.id_cred_i.as_ptr(),
            id_cred_i_len: self.id_cred_i.len(),
            cred_i: self.cred_i.as_ptr(),
            cred_i_len: self.cred_i.len(),
            id_cred_r: self.id_cred_r.as_ptr(),
            id_cred_r_len: self.id_cred_r.len(),
            cred_r: self.cred_r.as_ptr(),
            cred_r_len: self.cred_r.len(),
        }
    }

    pub fn new(
        state: State,
        r: &'a [u8],
        g_i: &'a [u8],
        id_cred_i: &'a [u8],
        cred_i: &'a [u8],
        id_cred_r: &'a [u8],
        cred_r: &'a [u8],
    ) -> EdhocResponderState<'a> {
        assert!(r.len() == P256_ELEM_LEN);
        assert!(g_i.len() == P256_ELEM_LEN);
        assert!(id_cred_i.len() == ID_CRED_LEN);
        assert!(id_cred_r.len() == ID_CRED_LEN);

        EdhocResponderState {
            state: state,
            r: r,
            g_i: g_i,
            id_cred_i: id_cred_i,
            cred_i: cred_i,
            id_cred_r: id_cred_r,
            cred_r: cred_r,
        }
    }

    /// Take out the state for passing into the low-level functions
    ///
    /// Use this in the state advancing functions when you only have &mut self need an owned State
    /// which you don't get because it is not Copy. (If State didn't have a Default implementation,
    /// we might use the `replace_with` crate). Note that in optimized builds, the default creation
    /// should only become active in the error path, because the compiler can see that the write is
    /// needless otherwise.
    ///
    /// Note that using this leaves a "no message was sent or received" state in self after an
    /// error. This is preferable over leaving in the old state (for it'd allow multiple attempts
    /// to perform the same operation, which EDHOC doesn't allow), but creating a state that errs
    /// on all later invocations would be even better.
    #[inline(always)]
    fn take_state(&mut self) -> State {
        core::mem::take(&mut self.state)
    }

    pub fn process_message_1(
        self: &mut EdhocResponderState<'a>,
        message_1: &BufferMessage1,
    ) -> Result<(), EDHOCError> {
        self.state = r_process_message_1(self.take_state(), message_1)?;

        Ok(())
    }

    pub fn prepare_message_2(
        self: &mut EdhocResponderState<'a>,
        c_r: u8,
    ) -> Result<BufferMessage2, EDHOCError> {
        let (y, g_y) = edhoc_crypto::p256_generate_key_pair();

        match r_prepare_message_2(
            self.take_state(),
            &self
                .id_cred_r
                .try_into()
                .expect("Wrong length of id_cred_r"),
            self.cred_r,
            self.r.try_into().expect("Wrong length of private key"),
            y,
            g_y,
            c_r,
        ) {
            Ok((state, message_2)) => {
                self.state = state;
                Ok(message_2)
            }
            Err(error) => Err(error),
        }
    }

    pub fn process_message_3(
        self: &mut EdhocResponderState<'a>,
        message_3: &BufferMessage3,
    ) -> Result<[u8; SHA256_DIGEST_LEN], EDHOCError> {
        match r_process_message_3(
            self.take_state(),
            message_3,
            &self
                .id_cred_i
                .try_into()
                .expect("Wrong length of id_cred_i"),
            self.cred_i,
            &self.g_i.try_into().expect("Wrong length of public key"),
        ) {
            Ok((state, prk_out)) => {
                self.state = state;
                Ok(prk_out)
            }
            Err(error) => Err(error),
        }
    }

    pub fn edhoc_exporter(
        self: &mut EdhocResponderState<'a>,
        label: u8,
        context: &[u8],
        length: usize,
    ) -> Result<[u8; MAX_BUFFER_LEN], EDHOCError> {
        let mut context_buf: BytesMaxContextBuffer = [0x00u8; MAX_KDF_CONTEXT_LEN];
        context_buf[..context.len()].copy_from_slice(context);

        match edhoc_exporter(
            self.take_state(),
            label,
            &context_buf,
            context.len(),
            length,
        ) {
            Ok((state, output)) => {
                self.state = state;
                Ok(output)
            }
            Err(error) => Err(error),
        }
    }

    pub fn edhoc_key_update(
        self: &mut EdhocResponderState<'a>,
        context: &[u8],
    ) -> Result<[u8; SHA256_DIGEST_LEN], EDHOCError> {
        let mut context_buf = [0x00u8; MAX_KDF_CONTEXT_LEN];
        context_buf[..context.len()].copy_from_slice(context);

        match edhoc_key_update(self.take_state(), &context_buf, context.len()) {
            Ok((state, prk_out_new)) => {
                self.state = state;
                Ok(prk_out_new)
            }
            Err(error) => Err(error),
        }
    }
}

impl<'a> EdhocInitiatorState<'a> {
    pub fn to_c(self) -> EdhocInitiatorC {
        EdhocInitiatorC {
            state: self.state,
            i: self.i.as_ptr(),
            i_len: self.i.len(),
            g_r: self.g_r.as_ptr(),
            g_r_len: self.g_r.len(),
            id_cred_i: self.id_cred_i.as_ptr(),
            id_cred_i_len: self.id_cred_i.len(),
            cred_i: self.cred_i.as_ptr(),
            cred_i_len: self.cred_i.len(),
            id_cred_r: self.id_cred_r.as_ptr(),
            id_cred_r_len: self.id_cred_r.len(),
            cred_r: self.cred_r.as_ptr(),
            cred_r_len: self.cred_r.len(),
        }
    }

    pub fn new(
        state: State,
        i: &'a [u8],
        g_r: &'a [u8],
        id_cred_i: &'a [u8],
        cred_i: &'a [u8],
        id_cred_r: &'a [u8],
        cred_r: &'a [u8],
    ) -> EdhocInitiatorState<'a> {
        assert!(i.len() == P256_ELEM_LEN);
        assert!(g_r.len() == P256_ELEM_LEN);
        assert!(id_cred_i.len() == ID_CRED_LEN);
        assert!(id_cred_r.len() == ID_CRED_LEN);

        EdhocInitiatorState {
            state: state,
            i: i,
            g_r: g_r,
            id_cred_i: id_cred_i,
            cred_i: cred_i,
            id_cred_r: id_cred_r,
            cred_r: cred_r,
        }
    }

    /// Take out the state for passing into the low-level functions
    ///
    /// Use this in the state advancing functions when you only have &mut self need an owned State
    /// which you don't get because it is not Copy. (If State didn't have a Default implementation,
    /// we might use the `replace_with` crate). Note that in optimized builds, the default creation
    /// should only become active in the error path, because the compiler can see that the write is
    /// needless otherwise.
    ///
    /// Note that using this leaves a "no message was sent or received" state in self after an
    /// error. This is preferable over leaving in the old state (for it'd allow multiple attempts
    /// to perform the same operation, which EDHOC doesn't allow), but creating a state that errs
    /// on all later invocations would be even better.
    #[inline(always)]
    fn take_state(&mut self) -> State {
        core::mem::take(&mut self.state)
    }

    pub fn prepare_message_1(
        self: &mut EdhocInitiatorState<'a>,
        c_i: u8,
    ) -> Result<BufferMessage1, EDHOCError> {
        let (x, g_x) = edhoc_crypto::p256_generate_key_pair();

        match i_prepare_message_1(self.take_state(), x, g_x, c_i) {
            Ok((state, message_1)) => {
                self.state = state;
                Ok(message_1)
            }
            Err(error) => Err(error),
        }
    }

    pub fn process_message_2(
        self: &mut EdhocInitiatorState<'a>,
        message_2: &BufferMessage2,
    ) -> Result<u8, EDHOCError> {
        match i_process_message_2(
            self.take_state(),
            message_2,
            &self
                .id_cred_r
                .try_into()
                .expect("Wrong length of id_cred_r"),
            self.cred_r,
            &self.g_r.try_into().expect("Wrong length of public key"),
            self.i
                .try_into()
                .expect("Provided initiator key (self.i) has the wrong length"),
        ) {
            Ok((state, c_r, _kid)) => {
                self.state = state;
                Ok(c_r)
            }
            Err(error) => Err(error),
        }
    }

    pub fn prepare_message_3(
        self: &mut EdhocInitiatorState<'a>,
    ) -> Result<(BufferMessage3, [u8; SHA256_DIGEST_LEN]), EDHOCError> {
        match i_prepare_message_3(
            self.take_state(),
            &self
                .id_cred_i
                .try_into()
                .expect("Wrong length of id_cred_i"),
            self.cred_i,
        ) {
            Ok((state, message_3, prk_out)) => {
                self.state = state;
                Ok((message_3, prk_out))
            }
            Err(error) => Err(error),
        }
    }

    pub fn edhoc_exporter(
        self: &mut EdhocInitiatorState<'a>,
        label: u8,
        context: &[u8],
        length: usize,
    ) -> Result<[u8; MAX_BUFFER_LEN], EDHOCError> {
        let mut context_buf: BytesMaxContextBuffer = [0x00u8; MAX_KDF_CONTEXT_LEN];
        context_buf[..context.len()].copy_from_slice(context);

        match edhoc_exporter(
            self.take_state(),
            label,
            &context_buf,
            context.len(),
            length,
        ) {
            Ok((state, output)) => {
                self.state = state;
                Ok(output)
            }
            Err(error) => Err(error),
        }
    }

    pub fn edhoc_key_update(
        self: &mut EdhocInitiatorState<'a>,
        context: &[u8],
    ) -> Result<[u8; SHA256_DIGEST_LEN], EDHOCError> {
        let mut context_buf = [0x00u8; MAX_KDF_CONTEXT_LEN];
        context_buf[..context.len()].copy_from_slice(context);

        match edhoc_key_update(self.take_state(), &context_buf, context.len()) {
            Ok((state, prk_out_new)) => {
                self.state = state;
                Ok(prk_out_new)
            }
            Err(error) => Err(error),
        }
    }
}

pub fn generate_connection_identifier_cbor() -> u8 {
    let c_i = generate_connection_identifier();
    if c_i >= 0 && c_i <= 23 {
        return c_i as u8; // verbatim encoding of single byte integer
    } else if c_i < 0 && c_i >= -24 {
        // negative single byte integer encoding
        return CBOR_NEG_INT_1BYTE_START - 1 + (c_i.abs() as u8);
    } else {
        return 0;
    }
}

/// generates an identifier that can be serialized as a single CBOR integer, i.e. -24 <= x <= 23
pub fn generate_connection_identifier() -> i8 {
    let mut conn_id = edhoc_crypto::get_random_byte() as i8;
    while conn_id < -24 || conn_id > 23 {
        conn_id = edhoc_crypto::get_random_byte() as i8;
    }
    conn_id
}

#[cfg(test)]
mod test {
    use super::*;
    use edhoc_consts::*;
    use hex::FromHex;
    use hexlit::hex;

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
        let state: EdhocState = Default::default();
        let _initiator = EdhocInitiator::new(state, I, G_R, ID_CRED_I, CRED_I, ID_CRED_R, CRED_R);
    }

    #[test]
    fn test_new_responder() {
        let state: EdhocState = Default::default();
        let _responder = EdhocResponder::new(state, R, G_I, ID_CRED_I, CRED_I, ID_CRED_R, CRED_R);
    }

    #[test]
    fn test_prepare_message_1() {
        let state: EdhocState = Default::default();
        let mut initiator =
            EdhocInitiator::new(state, I, G_R, ID_CRED_I, CRED_I, ID_CRED_R, CRED_R);

        let c_i = generate_connection_identifier_cbor();
        let message_1 = initiator.prepare_message_1(c_i);
        assert!(message_1.is_ok());
    }

    #[test]
    fn test_process_message_1() {
        let message_1_tv_first_time = EdhocMessageBuffer::from_hex(MESSAGE_1_TV_FIRST_TIME);
        let message_1_tv = EdhocMessageBuffer::from_hex(MESSAGE_1_TV);
        let state: EdhocState = Default::default();
        let mut responder =
            EdhocResponder::new(state, R, G_I, ID_CRED_I, CRED_I, ID_CRED_R, CRED_R);

        // process message_1 first time, when unsupported suite is selected
        let error = responder.process_message_1(&message_1_tv_first_time);
        assert!(error.is_err());
        assert_eq!(error.unwrap_err(), EDHOCError::UnsupportedCipherSuite);

        // process message_1 second time
        let error = responder.process_message_1(&message_1_tv);
        assert!(error.is_ok());
    }

    #[test]
    fn test_generate_connection_identifier() {
        let conn_id = generate_connection_identifier();
        assert!(conn_id >= -24 && conn_id <= 23);
    }

    #[test]
    fn test_handshake() {
        let state_initiator: EdhocState = Default::default();
        let mut initiator = EdhocInitiator::new(
            state_initiator,
            I,
            G_R,
            ID_CRED_I,
            CRED_I,
            ID_CRED_R,
            CRED_R,
        );
        let state_responder: EdhocState = Default::default();
        let mut responder = EdhocResponder::new(
            state_responder,
            R,
            G_I,
            ID_CRED_I,
            CRED_I,
            ID_CRED_R,
            CRED_R,
        );

        let c_i: u8 = generate_connection_identifier_cbor();
        let result = initiator.prepare_message_1(c_i); // to update the state
        assert!(result.is_ok());

        let error = responder.process_message_1(&result.unwrap());
        assert!(error.is_ok());

        let c_r = generate_connection_identifier_cbor();
        let ret = responder.prepare_message_2(c_r);
        assert!(ret.is_ok());

        let message_2 = ret.unwrap();

        assert!(c_r != 0xff);
        let _c_r = initiator.process_message_2(&message_2);
        assert!(_c_r.is_ok());

        let ret = initiator.prepare_message_3();
        assert!(ret.is_ok());

        let (message_3, i_prk_out) = ret.unwrap();

        let r_prk_out = responder.process_message_3(&message_3);
        assert!(r_prk_out.is_ok());

        // check that prk_out is equal at initiator and responder side
        assert_eq!(i_prk_out, r_prk_out.unwrap());

        // derive OSCORE secret and salt at both sides and compare
        let i_oscore_secret = initiator.edhoc_exporter(0u8, &[], 16); // label is 0
        assert!(i_oscore_secret.is_ok());
        let i_oscore_salt = initiator.edhoc_exporter(1u8, &[], 8); // label is 1
        assert!(i_oscore_salt.is_ok());

        let r_oscore_secret = responder.edhoc_exporter(0u8, &[], 16); // label is 0
        assert!(r_oscore_secret.is_ok());
        let r_oscore_salt = responder.edhoc_exporter(1u8, &[], 8); // label is 1
        assert!(r_oscore_salt.is_ok());

        assert_eq!(i_oscore_secret.unwrap(), r_oscore_secret.unwrap());
        assert_eq!(i_oscore_salt.unwrap(), r_oscore_salt.unwrap());

        // test key update with context from draft-ietf-lake-traces
        let i_prk_out_new = initiator.edhoc_key_update(&[
            0xa0, 0x11, 0x58, 0xfd, 0xb8, 0x20, 0x89, 0x0c, 0xd6, 0xbe, 0x16, 0x96, 0x02, 0xb8,
            0xbc, 0xea,
        ]);
        assert!(i_prk_out_new.is_ok());
        let r_prk_out_new = responder.edhoc_key_update(&[
            0xa0, 0x11, 0x58, 0xfd, 0xb8, 0x20, 0x89, 0x0c, 0xd6, 0xbe, 0x16, 0x96, 0x02, 0xb8,
            0xbc, 0xea,
        ]);
        assert!(r_prk_out_new.is_ok());

        assert_eq!(i_prk_out_new.unwrap(), r_prk_out_new.unwrap());
    }

    #[cfg(feature = "ead-zeroconf")]
    #[test]
    fn test_ead() {
        let state_initiator: EdhocState = Default::default();
        let mut initiator = EdhocInitiator::new(
            state_initiator,
            I,
            G_R,
            ID_CRED_I,
            CRED_I,
            ID_CRED_R,
            CRED_R,
        );
        let state_responder: EdhocState = Default::default();
        let mut responder = EdhocResponder::new(
            state_responder,
            R,
            G_I,
            ID_CRED_I,
            CRED_I,
            ID_CRED_R,
            CRED_R,
        );

        ead_initiator_set_global_state(EADInitiatorState::new());
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

        let c_i = generate_connection_identifier_cbor();
        let message_1 = initiator.prepare_message_1(c_i).unwrap();
        assert_eq!(
            ead_initiator_state.protocol_state,
            EADInitiatorProtocolState::WaitEAD2
        );

        responder.process_message_1(&message_1).unwrap();
        assert_eq!(
            ead_responder_state.protocol_state,
            EADResponderProtocolState::ProcessedEAD1
        );

        let c_r = generate_connection_identifier_cbor();
        let message_2 = responder.prepare_message_2(c_r).unwrap();
        assert_eq!(
            ead_responder_state.protocol_state,
            EADResponderProtocolState::Completed
        );

        initiator.process_message_2(&message_2).unwrap();
        assert_eq!(
            ead_initiator_state.protocol_state,
            EADInitiatorProtocolState::Completed
        );

        let (message_3, i_prk_out) = initiator.prepare_message_3().unwrap();

        let r_prk_out = responder.process_message_3(&message_3).unwrap();
        assert_eq!(i_prk_out, r_prk_out);
        assert_eq!(
            ead_responder_state.protocol_state,
            EADResponderProtocolState::Completed
        );
    }
}
