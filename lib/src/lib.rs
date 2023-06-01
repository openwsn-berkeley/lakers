#![cfg_attr(not(test), no_std)]

#[cfg(any(
    feature = "hacspec-hacspec",
    feature = "hacspec-cc2538",
    feature = "hacspec-psa",
    feature = "hacspec-cryptocell310"
))]
pub use {
    edhoc_consts::State as EdhocState, edhoc_consts::*, edhoc_crypto::*,
    hacspec::HacspecEdhocInitiator as EdhocInitiator,
    hacspec::HacspecEdhocResponder as EdhocResponder,
};

#[cfg(any(
    feature = "rust-psa",
    feature = "rust-psa-baremetal",
    feature = "rust-cryptocell310"
))]
pub use {
    edhoc_consts::State as EdhocState, edhoc_consts::*, edhoc_crypto::*,
    rust::RustEdhocInitiator as EdhocInitiator, rust::RustEdhocResponder as EdhocResponder,
};

#[cfg(any(feature = "ead-none", feature = "ead-zeroconf"))]
pub use edhoc_ead::*;

#[cfg(any(
    feature = "rust-psa",
    feature = "rust-psa-baremetal",
    feature = "rust-cryptocell310"
))]
mod edhoc;

#[cfg(any(
    feature = "rust-psa",
    feature = "rust-psa-baremetal",
    feature = "rust-cryptocell310"
))]
use edhoc::*;

#[cfg(any(
    feature = "hacspec-hacspec",
    feature = "hacspec-cc2538",
    feature = "hacspec-psa",
    feature = "hacspec-cryptocell310"
))]
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
            message_1: &EdhocMessageBuffer,
        ) -> Result<(), EDHOCError> {
            match r_process_message_1(self.state, &BufferMessage1::from_public_buffer(message_1)) {
                Ok(state) => {
                    self.state = state;
                    Ok(())
                }
                Err(error) => Err(error),
            }
        }

        pub fn prepare_message_2(
            self: &mut HacspecEdhocResponder<'a>,
        ) -> Result<(EdhocMessageBuffer, u8), EDHOCError> {
            // init hacspec structs for id_cred_r and cred_r
            let id_cred_r = BytesIdCred::from_hex(self.id_cred_r);
            let mut cred_r = BytesMaxBuffer::new();
            cred_r = cred_r.update(0, &ByteSeq::from_hex(self.cred_r));
            let cred_r_len = self.cred_r.len() / 2;

            // init hacspec structs for R's public static DH key
            let r = BytesP256ElemLen::from_hex(self.r);

            // Generate ephemeral key pair
            let (y, g_y) = edhoc_crypto::p256_generate_key_pair();

            match r_prepare_message_2(self.state, &id_cred_r, &cred_r, cred_r_len, &r, y, g_y) {
                Ok((state, message_2, c_r)) => {
                    self.state = state;
                    Ok((message_2.to_public_buffer(), c_r.declassify()))
                }
                Err(error) => Err(error),
            }
        }

        pub fn process_message_3(
            self: &mut HacspecEdhocResponder<'a>,
            message_3: &EdhocMessageBuffer,
        ) -> Result<[u8; SHA256_DIGEST_LEN], EDHOCError> {
            // init hacspec structs for id_cred_r and cred_r
            let id_cred_i = BytesIdCred::from_hex(self.id_cred_i);
            let mut cred_i = BytesMaxBuffer::new();
            cred_i = cred_i.update(0, &ByteSeq::from_hex(self.cred_i));
            let cred_i_len = self.cred_i.len() / 2;

            // init hacspec structs for R's public static DH key
            let g_i = BytesP256ElemLen::from_hex(self.g_i);

            match r_process_message_3(
                self.state,
                &BufferMessage3::from_public_buffer(&message_3),
                &id_cred_i,
                &cred_i,
                cred_i_len,
                &g_i,
            ) {
                Ok((state, prk_out)) => {
                    self.state = state;
                    Ok(prk_out.to_public_array())
                }
                Err(error) => Err(error),
            }
        }

        pub fn edhoc_exporter(
            self: &mut HacspecEdhocResponder<'a>,
            label: u8,
            context: &[u8],
            length: usize,
        ) -> Result<[u8; MAX_BUFFER_LEN], EDHOCError> {
            // init hacspec struct for context
            let mut context_hacspec = BytesMaxContextBuffer::new();
            context_hacspec = context_hacspec.update(0, &ByteSeq::from_public_slice(context));

            match edhoc_exporter(
                self.state,
                U8(label),
                &context_hacspec,
                context.len(),
                length,
            ) {
                Ok((state, output)) => {
                    self.state = state;
                    Ok(output.to_public_array())
                }
                Err(error) => Err(error),
            }
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
        ) -> Result<EdhocMessageBuffer, EDHOCError> {
            // Generate ephemeral key pair
            let (x, g_x) = edhoc_crypto::p256_generate_key_pair();

            match edhoc_hacspec::i_prepare_message_1(self.state, x, g_x) {
                Ok((state, message_1)) => {
                    self.state = state;
                    Ok(message_1.to_public_buffer())
                }
                Err(error) => Err(error),
            }
        }

        pub fn process_message_2(
            self: &mut HacspecEdhocInitiator<'a>,
            message_2: &EdhocMessageBuffer,
        ) -> Result<u8, EDHOCError> {
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
            let message_2_hacspec = BufferMessage2::from_public_buffer(&message_2);

            match edhoc_hacspec::i_process_message_2(
                self.state,
                &message_2_hacspec,
                &id_cred_r,
                &cred_r,
                cred_r_len,
                &g_r,
                &i,
            ) {
                Ok((state, c_r, _id_cred_r)) => {
                    self.state = state;
                    Ok(c_r.declassify())
                }
                Err(error) => Err(error),
            }
        }

        pub fn prepare_message_3(
            self: &mut HacspecEdhocInitiator<'a>,
        ) -> Result<(EdhocMessageBuffer, [u8; SHA256_DIGEST_LEN]), EDHOCError> {
            // init hacspec structs for id_cred_i and cred_i
            let id_cred_i = BytesIdCred::from_hex(self.id_cred_i);
            let mut cred_i = BytesMaxBuffer::new();
            cred_i = cred_i.update(0, &ByteSeq::from_hex(self.cred_i));
            let cred_i_len = self.cred_i.len() / 2;

            match i_prepare_message_3(self.state, &id_cred_i, &cred_i, cred_i_len) {
                Ok((state, message_3, prk_out)) => {
                    self.state = state;
                    Ok((message_3.to_public_buffer(), prk_out.to_public_array()))
                }
                Err(error) => Err(error),
            }
        }

        pub fn edhoc_exporter(
            self: &mut HacspecEdhocInitiator<'a>,
            label: u8,
            context: &[u8],
            length: usize,
        ) -> Result<[u8; MAX_BUFFER_LEN], EDHOCError> {
            // init hacspec struct for context
            let mut context_hacspec = BytesMaxContextBuffer::new();
            context_hacspec = context_hacspec.update(0, &ByteSeq::from_public_slice(context));

            match edhoc_exporter(
                self.state,
                U8(label),
                &context_hacspec,
                context.len(),
                length,
            ) {
                Ok((state, output)) => {
                    self.state = state;
                    Ok(output.to_public_array())
                }
                Err(error) => Err(error),
            }
        }
    }
}

#[cfg(any(
    feature = "rust-psa",
    feature = "rust-psa-baremetal",
    feature = "rust-cryptocell310"
))]
mod rust {
    use super::*;
    use edhoc_consts::*;
    use hex::FromHex;

    #[derive(Default, Copy, Clone, Debug)]
    pub struct RustEdhocInitiator<'a> {
        state: State,       // opaque state
        i: &'a str,         // private authentication key of I
        g_r: &'a str,       // public authentication key of R
        id_cred_i: &'a str, // identifier of I's credential
        cred_i: &'a str,    // I's full credential
        id_cred_r: &'a str, // identifier of R's credential
        cred_r: &'a str,    // R's full credential
    }

    #[derive(Default, Copy, Clone, Debug)]
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
            message_1: &BufferMessage1,
        ) -> Result<(), EDHOCError> {
            let state = r_process_message_1(self.state, message_1)?;
            self.state = state;

            Ok(())
        }

        pub fn prepare_message_2(
            self: &mut RustEdhocResponder<'a>,
        ) -> Result<(BufferMessage2, u8), EDHOCError> {
            let mut cred_r: BytesMaxBuffer = [0x00; MAX_BUFFER_LEN];
            hex::decode_to_slice(self.cred_r, &mut cred_r[..self.cred_r.len() / 2])
                .expect("Decoding failed");
            let (y, g_y) = edhoc_crypto::p256_generate_key_pair();

            match r_prepare_message_2(
                self.state,
                &<BytesIdCred>::from_hex(self.id_cred_r).expect("Decoding failed"),
                &cred_r,
                self.cred_r.len() / 2,
                &<BytesP256ElemLen>::from_hex(self.r).expect("Decoding failed"),
                y,
                g_y,
            ) {
                Ok((state, message_2, c_r)) => {
                    self.state = state;
                    Ok((message_2, c_r))
                }
                Err(error) => Err(error),
            }
        }

        pub fn process_message_3(
            self: &mut RustEdhocResponder<'a>,
            message_3: &BufferMessage3,
        ) -> Result<[u8; SHA256_DIGEST_LEN], EDHOCError> {
            let mut cred_i: BytesMaxBuffer = [0x00; MAX_BUFFER_LEN];
            hex::decode_to_slice(self.cred_i, &mut cred_i[..self.cred_i.len() / 2])
                .expect("Decoding failed");

            match r_process_message_3(
                self.state,
                message_3,
                &<BytesIdCred>::from_hex(self.id_cred_i).expect("Decoding failed"),
                &cred_i,
                self.cred_i.len() / 2,
                &<BytesP256ElemLen>::from_hex(self.g_i).expect("Decoding failed"),
            ) {
                Ok((state, prk_out)) => {
                    self.state = state;
                    Ok(prk_out)
                }
                Err(error) => Err(error),
            }
        }

        pub fn edhoc_exporter(
            self: &mut RustEdhocResponder<'a>,
            label: u8,
            context: &[u8],
            length: usize,
        ) -> Result<[u8; MAX_BUFFER_LEN], EDHOCError> {
            let mut context_buf: BytesMaxContextBuffer = [0x00u8; MAX_KDF_CONTEXT_LEN];
            context_buf[..context.len()].copy_from_slice(context);

            match edhoc_exporter(self.state, label, &context_buf, context.len(), length) {
                Ok((state, output)) => {
                    self.state = state;
                    Ok(output)
                }
                Err(error) => Err(error),
            }
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

        pub fn prepare_message_1(
            self: &mut RustEdhocInitiator<'a>,
        ) -> Result<BufferMessage1, EDHOCError> {
            let (x, g_x) = edhoc_crypto::p256_generate_key_pair();

            match i_prepare_message_1(self.state, x, g_x) {
                Ok((state, message_1)) => {
                    self.state = state;
                    Ok(message_1)
                }
                Err(error) => Err(error),
            }
        }

        pub fn process_message_2(
            self: &mut RustEdhocInitiator<'a>,
            message_2: &BufferMessage2,
        ) -> Result<u8, EDHOCError> {
            let mut cred_r: BytesMaxBuffer = [0x00u8; MAX_BUFFER_LEN];
            hex::decode_to_slice(self.cred_r, &mut cred_r[..self.cred_r.len() / 2])
                .expect("Decoding failed");

            match i_process_message_2(
                self.state,
                message_2,
                &<BytesIdCred>::from_hex(self.id_cred_r).expect("Decoding failed"),
                &cred_r,
                self.cred_r.len() / 2,
                &<BytesP256ElemLen>::from_hex(self.g_r).expect("Decoding failed"),
                &<BytesP256ElemLen>::from_hex(self.i).expect("Decoding failed"),
            ) {
                Ok((state, c_r, _kid)) => {
                    self.state = state;
                    Ok(c_r)
                }
                Err(error) => Err(error),
            }
        }

        pub fn prepare_message_3(
            self: &mut RustEdhocInitiator<'a>,
        ) -> Result<(BufferMessage3, [u8; SHA256_DIGEST_LEN]), EDHOCError> {
            let mut cred_i: BytesMaxBuffer = [0x00u8; MAX_BUFFER_LEN];
            hex::decode_to_slice(self.cred_i, &mut cred_i[..self.cred_i.len() / 2])
                .expect("Decoding failed");

            match i_prepare_message_3(
                self.state,
                &<BytesIdCred>::from_hex(self.id_cred_i).expect("Decoding failed"),
                &cred_i,
                self.cred_i.len() / 2,
            ) {
                Ok((state, message_3, prk_out)) => {
                    self.state = state;
                    Ok((message_3, prk_out))
                }
                Err(error) => Err(error),
            }
        }

        pub fn edhoc_exporter(
            self: &mut RustEdhocInitiator<'a>,
            label: u8,
            context: &[u8],
            length: usize,
        ) -> Result<[u8; MAX_BUFFER_LEN], EDHOCError> {
            let mut context_buf: BytesMaxContextBuffer = [0x00u8; MAX_KDF_CONTEXT_LEN];
            context_buf[..context.len()].copy_from_slice(context);

            match edhoc_exporter(self.state, label, &context_buf, context.len(), length) {
                Ok((state, output)) => {
                    self.state = state;
                    Ok(output)
                }
                Err(error) => Err(error),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use edhoc_consts::*;
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

    const MESSAGE_1_TV: &str =
        "030258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637";

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

        let message_1 = initiator.prepare_message_1();
        assert!(message_1.is_ok());
    }

    #[test]
    fn test_process_message_1() {
        let message_1_tv = EdhocMessageBuffer::from_hex(MESSAGE_1_TV);
        let state: EdhocState = Default::default();
        let mut responder =
            EdhocResponder::new(state, R, G_I, ID_CRED_I, CRED_I, ID_CRED_R, CRED_R);

        let error = responder.process_message_1(&message_1_tv);

        assert!(error.is_ok());
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

        let result = initiator.prepare_message_1(); // to update the state
        assert!(result.is_ok());

        let error = responder.process_message_1(&result.unwrap());
        assert!(error.is_ok());

        let ret = responder.prepare_message_2();
        assert!(ret.is_ok());

        let (message_2, c_r) = ret.unwrap();

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

        let message_1 = initiator.prepare_message_1().unwrap();
        assert_eq!(
            ead_initiator_state.protocol_state,
            EADInitiatorProtocolState::WaitEAD2
        );

        responder.process_message_1(&message_1).unwrap();
        assert_eq!(
            ead_responder_state.protocol_state,
            EADResponderProtocolState::ProcessedEAD1
        );

        let (message_2, _c_r) = responder.prepare_message_2().unwrap();
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
