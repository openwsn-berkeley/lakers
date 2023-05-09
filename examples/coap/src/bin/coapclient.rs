use coap::CoAPClient;
use edhoc_rs::*;
use std::time::Duration;

const ID_CRED_I: &str = "a104412b";
const ID_CRED_R: &str = "a104410a";
const CRED_I: &str = "A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8";
const I: &str = "fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b";
const _G_I_X_COORD: &str = "ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6"; // not used
const _G_I_Y_COORD: &str = "6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8"; // not used
const CRED_R: &str = "A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072";
const G_R: &str = "bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0";

fn main() {
    let url = "coap://127.0.0.1:5683/.well-known/edhoc";
    let timeout = Duration::new(5, 0);
    println!("Client request: {}", url);

    let state: EdhocState = Default::default();
    let mut initiator =
        EdhocInitiator::new(state, &I, &G_R, &ID_CRED_I, &CRED_I, &ID_CRED_R, &CRED_R);

    // Send Message 1 over CoAP and convert the response to byte
    let mut msg_1_buf = Vec::from([0xf5u8]); // EDHOC message_1 when transported over CoAP is prepended with CBOR true
    let message_1 = initiator.prepare_message_1().unwrap();
    msg_1_buf.extend_from_slice(&message_1.content[..message_1.len]);

    let response = CoAPClient::post_with_timeout(url, msg_1_buf, timeout).unwrap();
    println!("response_vec = {:02x?}", response.message.payload);

    let c_r = initiator.process_message_2(
        &response.message.payload[..]
            .try_into()
            .expect("wrong length"),
    );

    if c_r.is_ok() {
        let mut msg_3 = Vec::from([c_r.unwrap()]);
        let (message_3, _prk_out) = initiator.prepare_message_3().unwrap();
        msg_3.extend_from_slice(&message_3.content[..message_3.len]);

        let _response = CoAPClient::post_with_timeout(url, msg_3, timeout).unwrap();
        // we don't care about the response to message_3 for now

        let _oscore_secret = initiator.edhoc_exporter(0u8, &[], 16).unwrap(); // label is 0
        let _oscore_salt = initiator.edhoc_exporter(1u8, &[], 8).unwrap(); // label is 1

        println!("EDHOC exchange successfully completed");
        println!("OSCORE secret: {:02x?}", _oscore_secret);
        println!("OSCORE salt: {:02x?}", _oscore_salt);
    } else {
        panic!("Message 2 processing error: {:#?}", c_r);
    }
}
