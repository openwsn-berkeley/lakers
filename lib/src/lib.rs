#[cfg(feature = "hacspec")]
pub use {
    edhoc_consts::*,
    edhoc_hacspec::State as EdhocState, hacspec::HacspecEdhocInitiator as EdhocInitiator,
    hacspec::HacspecEdhocResponder as EdhocResponder,
};

#[cfg(not(feature = "hacspec"))]
pub use {
    edhoc::EDHOCError as EdhocError, edhoc::State as EdhocState,
    rust::RustEdhocInitiator as EdhocInitiator, rust::RustEdhocResponder as EdhocResponder,
};

#[cfg(not(feature = "hacspec"))]
mod edhoc;

#[cfg(not(feature = "hacspec"))]
use edhoc::*;

#[cfg(feature = "hacspec")]
mod hacspec {
    use edhoc_consts::*;
    use edhoc_hacspec::*;
    use hacspec_lib::*;

    #[derive(Default, Copy, Clone, Debug)]
    pub struct HacspecEdhocInitiator<'a> {
        state: State,       // opaque state
        i: &'a str,         // private authentication key of I
        g_r: &'a str,       // public authentication key of R
        id_cred_i: &'a str, // identifier of I's credential
        cred_i: &'a str,    // I's full credential
        id_cred_r: &'a str, // identifier of R's credential
        cred_r: &'a str,    // R's full credential
    }

    #[derive(Default, Copy, Clone, Debug)]
    pub struct HacspecEdhocResponder<'a> {
        state: State,       // opaque state
        r: &'a str,         // private authentication key of R
        g_i: &'a str,       // public authentication key of I
        id_cred_i: &'a str, // identifier of I's credential
        cred_i: &'a str,    // I's full credential
        id_cred_r: &'a str, // identifier of R's credential
        cred_r: &'a str,    // R's full credential
    }

    impl<'a> HacspecEdhocResponder<'a> {
        pub fn new(
            state: State,
            r: &'a str,
            g_i: &'a str,
            id_cred_i: &'a str,
            cred_i: &'a str,
            id_cred_r: &'a str,
            cred_r: &'a str,
        ) -> HacspecEdhocResponder<'a> {
            assert!(r.len() == P256_ELEM_LEN * 2);
            assert!(g_i.len() == P256_ELEM_LEN * 2);
            assert!(id_cred_i.len() == ID_CRED_LEN * 2);
            assert!(id_cred_r.len() == ID_CRED_LEN * 2);

            HacspecEdhocResponder {
                state: state,
                r: r,
                g_i: g_i,
                id_cred_i: id_cred_i,
                cred_i: cred_i,
                id_cred_r: id_cred_r,
                cred_r: cred_r,
            }
        }

        pub fn process_message_1(
            self: &mut HacspecEdhocResponder<'a>,
            message_1: &[u8; MESSAGE_1_LEN],
        ) -> EDHOCError {
            let (error, state) = r_process_message_1(
                self.state,
                &BytesMessage1::from_public_slice(&message_1[..]),
            );
            self.state = state;
            error
        }

        pub fn prepare_message_2(
            self: &mut HacspecEdhocResponder<'a>,
        ) -> (EDHOCError, [u8; MESSAGE_2_LEN], u8) {
            // init hacspec structs for id_cred_r and cred_r
            let id_cred_r = BytesIdCred::from_hex(self.id_cred_r);
            let mut cred_r = BytesMaxBuffer::new();
            cred_r = cred_r.update(0, &ByteSeq::from_hex(self.cred_r));
            let cred_r_len = self.cred_r.len() / 2;

            // init hacspec structs for R's public static DH key
            let r = BytesP256ElemLen::from_hex(self.r);

            let (error, state, message_2, c_r) =
                r_prepare_message_2(self.state, &id_cred_r, &cred_r, cred_r_len, &r);
            self.state = state;

            let mut message_2_native: [u8; MESSAGE_2_LEN] = [0; MESSAGE_2_LEN];
            for i in 0..message_2.len() {
                message_2_native[i] = message_2[i].declassify();
            }

            (error, message_2_native, c_r.declassify())
        }

        pub fn process_message_3(
            self: &mut HacspecEdhocResponder<'a>,
            message_3: &[u8; MESSAGE_3_LEN],
        ) -> (EDHOCError, [u8; SHA256_DIGEST_LEN]) {
            // init hacspec structs for id_cred_r and cred_r
            let id_cred_i = BytesIdCred::from_hex(self.id_cred_i);
            let mut cred_i = BytesMaxBuffer::new();
            cred_i = cred_i.update(0, &ByteSeq::from_hex(self.cred_i));
            let cred_i_len = self.cred_i.len() / 2;

            // init hacspec structs for R's public static DH key
            let g_i = BytesP256ElemLen::from_hex(self.g_i);

            let (error, state, prk_out) = r_process_message_3(
                self.state,
                &BytesMessage3::from_public_slice(&message_3[..]),
                &id_cred_i,
                &cred_i,
                cred_i_len,
                &g_i,
            );
            self.state = state;

            let mut prk_out_native: [u8; SHA256_DIGEST_LEN] = [0; SHA256_DIGEST_LEN];
            for i in 0..prk_out_native.len() {
                prk_out_native[i] = prk_out[i].declassify();
            }

            (error, prk_out_native)
        }

        pub fn edhoc_exporter(
            self: &mut HacspecEdhocResponder<'a>,
            label: u8,
            context: &[u8],
            length: usize,
        ) -> (EDHOCError, [u8; MAX_BUFFER_LEN]) {
            // init hacspec struct for context
            let mut context_hacspec = BytesMaxContextBuffer::new();
            context_hacspec = context_hacspec.update(0, &ByteSeq::from_public_slice(context));

            let (error, state, output) = edhoc_exporter(
                self.state,
                U8(label),
                &context_hacspec,
                context.len(),
                length,
            );
            self.state = state;

            // FIXME use hacspec standard library functions once available
            let mut output_native: [u8; MAX_BUFFER_LEN] = [0; MAX_BUFFER_LEN];
            assert!(output.len() == output_native.len());
            for i in 0..output.len() {
                output_native[i] = output[i].declassify();
            }

            (error, output_native)
        }
    }

    impl<'a> HacspecEdhocInitiator<'a> {
        pub fn new(
            state: State,
            i: &'a str,
            g_r: &'a str,
            id_cred_i: &'a str,
            cred_i: &'a str,
            id_cred_r: &'a str,
            cred_r: &'a str,
        ) -> HacspecEdhocInitiator<'a> {
            assert!(i.len() == P256_ELEM_LEN * 2);
            assert!(g_r.len() == P256_ELEM_LEN * 2);
            assert!(id_cred_i.len() == ID_CRED_LEN * 2);
            assert!(id_cred_r.len() == ID_CRED_LEN * 2);

            HacspecEdhocInitiator {
                state: state,
                i: i,
                g_r: g_r,
                id_cred_i: id_cred_i,
                cred_i: cred_i,
                id_cred_r: id_cred_r,
                cred_r: cred_r,
            }
        }

        pub fn prepare_message_1(
            self: &mut HacspecEdhocInitiator<'a>,
        ) -> (EDHOCError, [u8; MESSAGE_1_LEN]) {
            let (error, state, message_1) = edhoc_hacspec::i_prepare_message_1(self.state);
            self.state = state;

            // convert message_1 into native Rust array
            let mut message_native: [u8; MESSAGE_1_LEN] = [0; MESSAGE_1_LEN];

            assert!(message_1.len() == message_native.len());
            for i in 0..message_1.len() {
                message_native[i] = message_1[i].declassify();
            }

            (error, message_native)
        }

        pub fn process_message_2(
            self: &mut HacspecEdhocInitiator<'a>,
            message_2: &[u8; MESSAGE_2_LEN],
        ) -> (EDHOCError, u8) {
            // init hacspec struct for I, I's private static DH key
            let i = BytesP256ElemLen::from_hex(self.i);

            // init hacspec structs for id_cred_r and cred_r
            let id_cred_r = BytesIdCred::from_hex(self.id_cred_r);
            let mut cred_r = BytesMaxBuffer::new();
            cred_r = cred_r.update(0, &ByteSeq::from_hex(self.cred_r));
            let cred_r_len = self.cred_r.len() / 2;

            // init hacspec structs for R's public static DH key
            let g_r = BytesP256ElemLen::from_hex(self.g_r);

            // init hacspec struct for message_2
            let message_2_hacspec = BytesMessage2::from_public_slice(&message_2[..]);

            let (error, state, c_r, _id_cred_r) = edhoc_hacspec::i_process_message_2(
                self.state,
                &message_2_hacspec,
                &id_cred_r,
                &cred_r,
                cred_r_len,
                &g_r,
                &i,
            );
            self.state = state;

            (error, c_r.declassify())
        }

        pub fn prepare_message_3(
            self: &mut HacspecEdhocInitiator<'a>,
        ) -> (EDHOCError, [u8; MESSAGE_3_LEN], [u8; SHA256_DIGEST_LEN]) {
            // init hacspec structs for id_cred_i and cred_i
            let id_cred_i = BytesIdCred::from_hex(self.id_cred_i);
            let mut cred_i = BytesMaxBuffer::new();
            cred_i = cred_i.update(0, &ByteSeq::from_hex(self.cred_i));
            let cred_i_len = self.cred_i.len() / 2;

            let (error, state, message_3, prk_out) =
                i_prepare_message_3(self.state, &id_cred_i, &cred_i, cred_i_len);

            self.state = state;

            // convert message_3 into native Rust array FIXME use hacspec standard library functions once available
            let mut message_native: [u8; MESSAGE_3_LEN] = [0; MESSAGE_3_LEN];
            let mut prk_out_native: [u8; SHA256_DIGEST_LEN] = [0; SHA256_DIGEST_LEN];

            assert!(message_3.len() == message_native.len());
            for i in 0..message_3.len() {
                message_native[i] = message_3[i].declassify();
            }

            for i in 0..prk_out.len() {
                prk_out_native[i] = prk_out[i].declassify();
            }

            (error, message_native, prk_out_native)
        }

        pub fn edhoc_exporter(
            self: &mut HacspecEdhocInitiator<'a>,
            label: u8,
            context: &[u8],
            length: usize,
        ) -> (EDHOCError, [u8; MAX_BUFFER_LEN]) {
            // init hacspec struct for context
            let mut context_hacspec = BytesMaxContextBuffer::new();
            context_hacspec = context_hacspec.update(0, &ByteSeq::from_public_slice(context));

            let (error, state, output) = edhoc_exporter(
                self.state,
                U8(label),
                &context_hacspec,
                context.len(),
                length,
            );
            self.state = state;

            // FIXME use hacspec standard library functions once available
            let mut output_native: [u8; MAX_BUFFER_LEN] = [0; MAX_BUFFER_LEN];
            assert!(output.len() == output_native.len());
            for i in 0..output.len() {
                output_native[i] = output[i].declassify();
            }

            (error, output_native)
        }
    }
}

#[cfg(not(feature = "hacspec"))]
mod rust {
    use super::*;
    use edhoc_consts::*;

    pub struct RustEdhocInitiator<'a> {
        state: State,       // opaque state
        i: &'a str,         // private authentication key of I
        g_r: &'a str,       // public authentication key of R
        id_cred_i: &'a str, // identifier of I's credential
        cred_i: &'a str,    // I's full credential
        id_cred_r: &'a str, // identifier of R's credential
        cred_r: &'a str,    // R's full credential
    }

    pub struct RustEdhocResponder<'a> {
        state: State,       // opaque state
        r: &'a str,         // private authentication key of R
        g_i: &'a str,       // public authentication key of I
        id_cred_i: &'a str, // identifier of I's credential
        cred_i: &'a str,    // I's full credential
        id_cred_r: &'a str, // identifier of R's credential
        cred_r: &'a str,    // R's full credential
    }

    impl<'a> RustEdhocResponder<'a> {
        pub fn new(
            state: State,
            r: &'a str,
            g_i: &'a str,
            id_cred_i: &'a str,
            cred_i: &'a str,
            id_cred_r: &'a str,
            cred_r: &'a str,
        ) -> RustEdhocResponder<'a> {
            assert!(r.len() == P256_ELEM_LEN * 2);
            assert!(g_i.len() == P256_ELEM_LEN * 2);
            assert!(id_cred_i.len() == ID_CRED_LEN * 2);
            assert!(id_cred_r.len() == ID_CRED_LEN * 2);

            RustEdhocResponder {
                state: state,
                r: r,
                g_i: g_i,
                id_cred_i: id_cred_i,
                cred_i: cred_i,
                id_cred_r: id_cred_r,
                cred_r: cred_r,
            }
        }

        pub fn process_message_1(
            self: &mut RustEdhocResponder<'a>,
            message_1: &[u8; MESSAGE_1_LEN],
        ) -> EDHOCError {
            EDHOCError::UnknownError
        }

        pub fn prepare_message_2(self: &mut RustEdhocResponder<'a>) -> [u8; MESSAGE_2_LEN] {
            [0; MESSAGE_2_LEN]
        }

        pub fn process_message_3(
            self: &mut RustEdhocResponder<'a>,
            message_3: &[u8; MESSAGE_3_LEN],
        ) -> (EDHOCError, [u8; SHA256_DIGEST_LEN]) {
            (EDHOCError::UnknownError, [0; SHA256_DIGEST_LEN])
        }

        pub fn edhoc_exporter(
            self: &mut RustEdhocResponder<'a>,
            label: u8,
            context: &[u8],
            length: usize,
        ) -> [u8; MAX_BUFFER_LEN] {
            [0; MAX_BUFFER_LEN]
        }
    }

    impl<'a> RustEdhocInitiator<'a> {
        pub fn new(
            state: State,
            i: &'a str,
            g_r: &'a str,
            id_cred_i: &'a str,
            cred_i: &'a str,
            id_cred_r: &'a str,
            cred_r: &'a str,
        ) -> RustEdhocInitiator<'a> {
            assert!(i.len() == P256_ELEM_LEN * 2);
            assert!(g_r.len() == P256_ELEM_LEN * 2);
            assert!(id_cred_i.len() == ID_CRED_LEN * 2);
            assert!(id_cred_r.len() == ID_CRED_LEN * 2);

            RustEdhocInitiator {
                state: state,
                i: i,
                g_r: g_r,
                id_cred_i: id_cred_i,
                cred_i: cred_i,
                id_cred_r: id_cred_r,
                cred_r: cred_r,
            }
        }

        pub fn prepare_message_1(self: &mut RustEdhocInitiator<'a>) -> [u8; MESSAGE_1_LEN] {
            let mut acc = NativeAccelerator {};
            let mut message_buffer: [u8; MAX_BUFFER_LEN] = [0x00; MAX_BUFFER_LEN];
            let message_1 = prepare_message_1(&mut acc, &mut self.state, &mut message_buffer);
            message_1.try_into().expect("wrong length")
        }

        pub fn process_message_2(
            self: &mut RustEdhocInitiator<'a>,
            message_2: &[u8; MESSAGE_2_LEN],
        ) -> (EDHOCError, u8) {
            let mut acc = NativeAccelerator {};
            let c_r = process_message_2(&mut acc, &mut self.state, message_2);

            (EDHOCError::Success, c_r)
        }

        pub fn prepare_message_3(
            self: &mut RustEdhocInitiator<'a>,
        ) -> ([u8; MESSAGE_3_LEN], [u8; SHA256_DIGEST_LEN]) {
            let mut acc = NativeAccelerator {};
            let mut message_buffer: [u8; MAX_BUFFER_LEN] = [0x00; MAX_BUFFER_LEN];
            let message_3 = prepare_message_3(
                &mut acc,
                &mut self.state,
                self.id_cred_i.as_bytes(),
                self.cred_i.as_bytes(),
                &mut message_buffer,
            );

            // dummy prk_out for the time being
            (message_3.try_into().unwrap(), [0; SHA256_DIGEST_LEN])
        }

        pub fn edhoc_exporter(
            self: &mut RustEdhocInitiator<'a>,
            label: u8,
            context: &[u8],
            length: usize,
        ) -> [u8; MAX_BUFFER_LEN] {
            let mut acc = NativeAccelerator {};
            let mut buffer: [u8; MAX_BUFFER_LEN] = [0x00; MAX_BUFFER_LEN];

            buffer
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hexlit::hex;

    const ID_CRED_I: &str = "a104412b";
    const ID_CRED_R: &str = "a104410a";
    const CRED_I: &str = "A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8";
    const I: &str = "fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b";
    const R: &str = "72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac";
    const G_I: &str = "ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6"; // used
    const _G_I_Y_COORD: &str = "6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8"; // not used
    const CRED_R: &str = "A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072";
    const G_R: &str = "bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0";
    const C_R_TV: [u8; 1] = hex!("27");

    const MESSAGE_1_TV: [u8; 37] =
        hex!("030258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637");

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

        let (error, message_1) = initiator.prepare_message_1();
        assert!(error == EDHOCError::Success);
        assert_eq!(message_1, MESSAGE_1_TV);
    }

    #[test]
    fn test_process_message_1() {
        let state: EdhocState = Default::default();
        let mut responder =
            EdhocResponder::new(state, R, G_I, ID_CRED_I, CRED_I, ID_CRED_R, CRED_R);

        let error = responder.process_message_1(&MESSAGE_1_TV);

        assert!(error == EDHOCError::Success);
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

        let (error, message_1) = initiator.prepare_message_1(); // to update the state
        assert!(error == EDHOCError::Success);

        let error = responder.process_message_1(&message_1);
        assert!(error == EDHOCError::Success);

        let (error, message_2, c_r) = responder.prepare_message_2();
        assert!(error == EDHOCError::Success);
        assert!(c_r != 0xff);
        let (error, _c_r) = initiator.process_message_2(&message_2);
        assert!(error == EDHOCError::Success);

        let (error, message_3, i_prk_out) = initiator.prepare_message_3();
        assert!(error == EDHOCError::Success);
        let (error, r_prk_out) = responder.process_message_3(&message_3);
        assert!(error == EDHOCError::Success);

        // check that prk_out is equal at initiator and responder side
        assert_eq!(i_prk_out, r_prk_out);

        // derive OSCORE secret and salt at both sides and compare
        let (error, i_oscore_secret) = initiator.edhoc_exporter(0u8, &[], 16); // label is 0
        assert!(error == EDHOCError::Success);
        let (error, i_oscore_salt) = initiator.edhoc_exporter(1u8, &[], 8); // label is 1
        assert!(error == EDHOCError::Success);

        let (error, r_oscore_secret) = responder.edhoc_exporter(0u8, &[], 16); // label is 0
        assert!(error == EDHOCError::Success);
        let (error, r_oscore_salt) = responder.edhoc_exporter(1u8, &[], 8); // label is 1
        assert!(error == EDHOCError::Success);

        assert_eq!(i_oscore_secret, r_oscore_secret);
        assert_eq!(i_oscore_salt, r_oscore_salt);
    }
}
