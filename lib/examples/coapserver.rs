use coap_lite::{CoapRequest, Packet, RequestType};
use std::net::{UdpSocket};
use edhoc_rs::*;

const ID_CRED_I: &str = "a1044103";
const ID_CRED_R: &str = "a104410a";
const CRED_I: &str = "A2026008A101A501020241032001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8";
const G_I: &str = "ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6"; // not used
const _G_I_Y_COORD: &str = "6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8"; // not used
const CRED_R: &str = "A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072";
const R: &str = "72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac";
const G_R: &str = "bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0";

fn main() {
    let mut buf = [0; 100];
    let socket = UdpSocket::bind("31.133.130.112:5683").unwrap();
    let state: EdhocState = Default::default();
    let mut responder = EdhocResponder::new(state, &R, &G_I, &ID_CRED_I, &CRED_I, &ID_CRED_R, &CRED_R);

    let (size, src) = socket.recv_from(&mut buf).expect("Didn't receive data");
    let packet = Packet::from_bytes(&buf[..size]).unwrap();
    let request = CoapRequest::from_packet(packet, src);

    let method = request.get_method().clone();
    let path = request.get_path();

    if path == ".well-known/edhoc" {
        println!("received message 1 from {}", src);
        // This is an EDHOC message
        let error = responder.process_message_1(&request.message.payload[1..].try_into().expect("wrong length"));
        if error == EdhocError::Success {
            let (_error, message_2) = responder.prepare_message_2();
            let mut response = request.response.unwrap();
            response.message.payload = message_2.to_vec();
            let packet = response.message.to_bytes().unwrap();
            socket.send_to(&packet[..], &src).expect("Could not send the data");

            // wait for message 3
            let (size, src) = socket.recv_from(&mut buf).expect("Didn't receive data");
            let packet = Packet::from_bytes(&buf[..size]).unwrap();
            let request = CoapRequest::from_packet(packet, src);

            let method = request.get_method().clone();
            let path = request.get_path();
            assert!(method == RequestType::Post);
            assert!(path == ".well-known/edhoc");

            println!("message_3 len: {:?}", request.message.payload.len());
            let (error, _prk_out) = responder.process_message_3(&request.message.payload[1..].try_into().expect("wrong length"));
            assert!(error == EdhocError::Success);

            let mut response = request.response.unwrap();
            response.message.payload =  b"".to_vec();
            let packet = response.message.to_bytes().unwrap();
            socket.send_to(&packet[..], &src).expect("Could not send the data");

            let (_error, _oscore_secret) = responder.edhoc_exporter(0u8, &[], 16); // label is 0
            println!("oscore_secret: {:02x?}", _oscore_secret);
            let (_error, _oscore_salt) = responder.edhoc_exporter(1u8, &[], 8); // label is 1
            println!("oscore_salt: {:02x?}", _oscore_salt);
        }
    }
}
