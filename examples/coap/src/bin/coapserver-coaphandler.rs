use edhoc_crypto::Crypto;
use edhoc_rs::*;
use hexlit::hex;

use embedded_nal::UdpFullStack;

const _ID_CRED_I: &[u8] = &hex!("a104412b");
const _ID_CRED_R: &[u8] = &hex!("a104410a");
const CRED_I: &[u8] = &hex!("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
const _G_I: &[u8] = &hex!("ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6");
const _G_I_Y_COORD: &[u8] =
    &hex!("6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8");
const CRED_R: &[u8] = &hex!("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");
const R: &[u8] = &hex!("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");

#[derive(Default, Debug)]
struct EdhocHandler {
    connections: Vec<(u8, EdhocResponderWaitM3<'static, Crypto>)>,
}

impl EdhocHandler {
    fn take_connection_by_c_r(&mut self, c_r: u8) -> Option<EdhocResponderWaitM3<'static, Crypto>> {
        let index = self
            .connections
            .iter()
            .position(|(current_c_r, _)| current_c_r == &c_r)?;
        let last = self.connections.len() - 1;
        self.connections.swap(index, last);
        Some(self.connections.pop().unwrap().1)
    }

    fn new_c_r(&self) -> u8 {
        // FIXME: We'll need to do better, but a) that'll be more practical when we can do more
        // than u8, and b) that'll best be coordinated with a storage that not only stores EDHOC
        // contexts but also OSCORE ones.
        let result = self.connections.len();
        if result >= 24 {
            panic!("Contexts exceeded");
        }
        result as _
    }
}

enum EdhocResponse {
    // We could also store the responder in the Vec (once we're done rendering the response, we'll
    // take up a slot there anyway) if we make it an enum.
    OkSend2 {
        c_r: u8,
        responder: EdhocResponderBuildM2<'static, Crypto>,
    },
    Message3Processed,
}

impl coap_handler::Handler for EdhocHandler {
    type RequestData = EdhocResponse;
    fn extract_request_data(
        &mut self,
        request: &impl coap_message::ReadableMessage,
    ) -> Self::RequestData {
        let starts_with_true = request.payload().get(0) == Some(&0xf5);

        if starts_with_true {
            let state = EdhocState::default();

            let responder = EdhocResponder::new(
                state,
                edhoc_crypto::default_crypto(),
                &R,
                &CRED_R,
                Some(&CRED_I),
            );

            let response = responder
                .process_message_1(&request.payload()[1..].try_into().expect("wrong length"));

            if let Ok(responder) = response {
                let c_r = self.new_c_r();
                EdhocResponse::OkSend2 { c_r, responder }
            } else {
                panic!("How to respond to non-OK?")
            }
        } else {
            // potentially message 3
            let c_r_rcvd = request.payload()[0];
            let responder = self
                .take_connection_by_c_r(c_r_rcvd)
                .expect("No such C_R found");

            println!("Found state with connection identifier {:?}", c_r_rcvd);
            let result = responder
                .process_message_3(&request.payload()[1..].try_into().expect("wrong length"));

            let Ok((mut responder, prk_out)) = result else {
                println!("EDHOC processing error: {:?}", result);
                // FIXME remove state from edhoc_connections
                panic!("Handler can't just not respond");
            };

            println!("EDHOC exchange successfully completed");
            println!("PRK_out: {:02x?}", prk_out);

            let mut _oscore_secret = responder.edhoc_exporter(0u8, &[], 16); // label is 0
            println!("OSCORE secret: {:02x?}", _oscore_secret);
            let mut _oscore_salt = responder.edhoc_exporter(1u8, &[], 8); // label is 1
            println!("OSCORE salt: {:02x?}", _oscore_salt);

            // context of key update is a test vector from draft-ietf-lake-traces
            let prk_out_new = responder.edhoc_key_update(&[
                0xa0, 0x11, 0x58, 0xfd, 0xb8, 0x20, 0x89, 0x0c, 0xd6, 0xbe, 0x16, 0x96, 0x02, 0xb8,
                0xbc, 0xea,
            ]);
            println!("PRK_out after key update: {:02x?}?", prk_out_new);

            _oscore_secret = responder.edhoc_exporter(0u8, &[], 16); // label is 0
            println!("OSCORE secret after key update: {:02x?}", _oscore_secret);
            _oscore_salt = responder.edhoc_exporter(1u8, &[], 8); // label is 1
            println!("OSCORE salt after key update: {:02x?}", _oscore_salt);

            EdhocResponse::Message3Processed
        }
    }
    fn estimate_length(&mut self, _: &Self::RequestData) -> usize {
        200
    }
    fn build_response(
        &mut self,
        response: &mut impl coap_message::MutableWritableMessage,
        req: Self::RequestData,
    ) {
        response.set_code(coap_numbers::code::CHANGED.try_into().ok().unwrap());
        match req {
            EdhocResponse::OkSend2 { c_r, responder } => {
                let (responder, message_2) = responder.prepare_message_2(c_r).unwrap();
                self.connections.push((c_r, responder));
                response.set_payload(&message_2.content[..message_2.len]);
            }
            EdhocResponse::Message3Processed => (), // "send empty ack back"?
        };
    }
}

fn build_handler() -> impl coap_handler::Handler {
    use coap_handler_implementations::{HandlerBuilder, ReportingHandlerBuilder};

    let edhoc: EdhocHandler = Default::default();

    coap_handler_implementations::new_dispatcher()
        .at_with_attributes(&[".well-known", "edhoc"], &[], edhoc)
        .with_wkc()
}

fn main_on_stack<S: UdpFullStack>(stack: &mut S) {
    let mut sock = stack.socket().expect("Can't create a socket");

    let mut handler = build_handler();

    stack.bind(&mut sock, 5683).expect("Can't bind to port");

    loop {
        match embedded_nal_minimal_coapserver::poll(stack, &mut sock, &mut handler) {
            Err(embedded_nal::nb::Error::WouldBlock) => {
                // See <https://github.com/rust-embedded-community/embedded-nal/issues/47>
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            e => e.expect("UDP error during send/receive"),
        }
    }
}

fn main() {
    let mut stack = std_embedded_nal::Stack::default();
    main_on_stack(&mut stack);
}
