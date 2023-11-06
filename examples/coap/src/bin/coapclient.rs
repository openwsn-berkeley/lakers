use coap::CoAPClient;
use coap_lite::ResponseType;
use edhoc_rs::*;
use hexlit::hex;
use std::time::Duration;

const ID_CRED_I: &[u8] = &hex!("a104412b");
const ID_CRED_R: &[u8] = &hex!("a104410a");
const CRED_I: &[u8] = &hex!("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
const I: &[u8] = &hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
const _G_I_X_COORD: &[u8] =
    &hex!("ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6"); // not used
const _G_I_Y_COORD: &[u8] =
    &hex!("6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8"); // not used
const CRED_R: &[u8] = &hex!("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");
const G_R: &[u8] = &hex!("bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0");

fn main() {
    let url = "coap://127.0.0.1:5683/.well-known/edhoc";
    let timeout = Duration::new(5, 0);
    println!("Client request: {}", url);

    let state = Default::default();
    let mut initiator = EdhocInitiator::new(state, &I, &CRED_I, Some(&CRED_R));

    // Send Message 1 over CoAP and convert the response to byte
    let mut msg_1_buf = Vec::from([0xf5u8]); // EDHOC message_1 when transported over CoAP is prepended with CBOR true
    let c_i = generate_connection_identifier_cbor();
    let (initiator, message_1) = initiator.prepare_message_1(c_i).unwrap();
    msg_1_buf.extend_from_slice(&message_1.content[..message_1.len]);
    println!("message_1 len = {}", msg_1_buf.len());

    let response = CoAPClient::post_with_timeout(url, msg_1_buf, timeout).unwrap();
    if response.get_status() != &ResponseType::Changed {
        panic!("Message 1 response error: {:?}", response.get_status());
    }
    println!("response_vec = {:02x?}", response.message.payload);
    println!("message_2 len = {}", response.message.payload.len());

    let m2result = initiator.process_message_2(
        &response.message.payload[..]
            .try_into()
            .expect("wrong length"),
    );

    if let Ok((initiator, c_r)) = m2result {
        let mut msg_3 = Vec::from([c_r]);
        let (mut initiator, message_3, prk_out) = initiator.prepare_message_3().unwrap();
        msg_3.extend_from_slice(&message_3.content[..message_3.len]);
        println!("message_3 len = {}", msg_3.len());

        let _response = CoAPClient::post_with_timeout(url, msg_3, timeout).unwrap();
        // we don't care about the response to message_3 for now

        println!("EDHOC exchange successfully completed");
        println!("PRK_out: {:02x?}", prk_out);

        let mut _oscore_secret = initiator.edhoc_exporter(0u8, &[], 16); // label is 0
        let mut _oscore_salt = initiator.edhoc_exporter(1u8, &[], 8); // label is 1

        println!("OSCORE secret: {:02x?}", _oscore_secret);
        println!("OSCORE salt: {:02x?}", _oscore_salt);

        // context of key update is a test vector from draft-ietf-lake-traces
        let prk_out_new = initiator.edhoc_key_update(&[
            0xa0, 0x11, 0x58, 0xfd, 0xb8, 0x20, 0x89, 0x0c, 0xd6, 0xbe, 0x16, 0x96, 0x02, 0xb8,
            0xbc, 0xea,
        ]);

        println!("PRK_out after key update: {:02x?}?", prk_out_new);

        // compute OSCORE secret and salt after key update
        _oscore_secret = initiator.edhoc_exporter(0u8, &[], 16); // label is 0
        _oscore_salt = initiator.edhoc_exporter(1u8, &[], 8); // label is 1

        println!("OSCORE secret after key update: {:02x?}", _oscore_secret);
        println!("OSCORE salt after key update: {:02x?}", _oscore_salt);
    } else {
        panic!("Message 2 processing error: {:#?}", m2result);
    }
}
