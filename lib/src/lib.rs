#[cfg(feature = "hacspec")]
mod hacspec {
    use edhoc_hacspec::consts::*;
    use edhoc_hacspec::*;
    use hacspec_lib::*;

    pub struct HacspecEdhocInitiator<'a> {
        state: State,       // opaque state
        i: &'a str,         // private authentication key of I
        g_r: &'a str,       // public authentication key of R
        id_cred_i: &'a str, // identifier of I's credential
        cred_i: &'a str,    // I's full credential
        id_cred_r: &'a str, // identifier of R's credential
        cred_r: &'a str,    // R's full credential
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

        pub fn prepare_message_1(self: &mut HacspecEdhocInitiator<'a>, c_i: u8) -> BytesMaxBuffer {
            let (state, message_1, message_1_len) =
                edhoc_hacspec::prepare_message_1(self.state, &BytesCid([U8(c_i)]));
            self.state = state;
            message_1
        }

        pub fn process_message_2(
            self: &mut HacspecEdhocInitiator<'a>,
            message_2: &BytesMessage2,
        ) -> (EDHOCError, BytesCid) {
            // init hacspec struct for I, I's private static DH key
            let i = BytesP256ElemLen::from_hex(self.i);

            // init hacspec structs for id_cred_r and cred_r
            let id_cred_r = BytesIdCred::from_hex(self.id_cred_r);
            let mut cred_r = BytesMaxBuffer::new();
            cred_r = cred_r.update(0, &ByteSeq::from_hex(self.cred_r));
            let cred_r_len = self.cred_r.len() / 2;

            // init hacspec structs for R's public static DH key
            let g_r = BytesP256ElemLen::from_hex(self.g_r);

            let (error, state, c_r, id_cred_r) = edhoc_hacspec::process_message_2(
                self.state, message_2, &id_cred_r, &cred_r, cred_r_len, &g_r, &i,
            );

            self.state = state;
            (error, c_r)
        }

        pub fn prepare_message_3(self: &mut HacspecEdhocInitiator<'a>) -> BytesMessage3 {
            // init hacspec structs for id_cred_i and cred_i
            let id_cred_i = BytesIdCred::from_hex(self.id_cred_i);
            let mut cred_i = BytesMaxBuffer::new();
            cred_i = cred_i.update(0, &ByteSeq::from_hex(self.cred_i));
            let cred_i_len = self.cred_i.len() / 2;

            let (state, message_3) = prepare_message_3(self.state, &id_cred_i, &cred_i, cred_i_len);

            self.state = state;
            message_3
        }
    }
}

#[cfg(not(feature = "hacspec"))]
mod rust {
    use crate::*;

    pub struct RustEdhocInitiator {
        state: State,
        i: &str,
        g_r: &str,
        id_cred_i: &str,
        cred_i: &str,
        id_cred_r: &str,
        cred_r: &str,
    }

    impl RustEdhocInitiator {
        pub fn new() -> RustEdhocInitiator {}
    }
}

#[cfg(feature = "hacspec")]
pub use hacspec::HacspecEdhocInitiator as EdhocInitiator;

#[cfg(not(feature = "hacspec"))]
pub use rust::RustEdhocInitiator as EdhocInitiator;

#[cfg(test)]
mod test {
    use super::EdhocInitiator;
    use edhoc_hacspec::*;

    const ID_CRED_I: &str = "a104412b";
    const ID_CRED_R: &str = "a104410a";
    const CRED_I: &str = "A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8";
    const I: &str = "fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b";
    const _G_I_X_COORD: &str = "ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6"; // not used
    const _G_I_Y_COORD: &str = "6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8"; // not used
    const CRED_R: &str = "A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072";
    const G_R: &str = "bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0";

    #[test]
    fn test_new() {
        let state: State = Default::default();

        let initiator = EdhocInitiator::new(state, I, G_R, ID_CRED_I, CRED_I, ID_CRED_R, CRED_R);
    }
}
