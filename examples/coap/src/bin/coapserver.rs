use coap_lite::{CoapRequest, Packet, ResponseType};
use edhoc_rs::*;
use std::net::UdpSocket;

const ID_CRED_I: &str = "a104412b";
const ID_CRED_R: &str = "a104410a";
const CRED_I: &str = "A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8";
const G_I: &str = "ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6"; // not used
const _G_I_Y_COORD: &str = "6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8"; // not used
const CRED_R: &str = "A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072";
const R: &str = "72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac";

fn main() {
    let mut buf = [0; 100];
    let socket = UdpSocket::bind("127.0.0.1:5683").unwrap();

    let mut edhoc_connections = Vec::new();

    println!("Waiting for CoAP messages...");
    loop {
        let (size, src) = socket.recv_from(&mut buf).expect("Didn't receive data");
        let packet = Packet::from_bytes(&buf[..size]).unwrap();
        let request = CoapRequest::from_packet(packet, src);

        let path = request.get_path();
        let mut response = request.response.unwrap();

        if path == ".well-known/edhoc" {
            println!("Received message from {}", src);
            // This is an EDHOC message
            if request.message.payload[0] == 0xf5 {
                let state = EdhocState::default();
                let mut responder =
                    EdhocResponder::new(state, &R, &G_I, &ID_CRED_I, &CRED_I, &ID_CRED_R, &CRED_R);

                let error = responder.process_message_1(
                    &request.message.payload[1..]
                        .try_into()
                        .expect("wrong length"),
                );

                if error.is_ok() {
                    let (message_2, c_r) = responder.prepare_message_2().unwrap();
                    response.message.payload = Vec::from(&message_2.content[..message_2.len]);
                    // save edhoc connection
                    edhoc_connections.push((c_r, responder));
                }
            } else {
                // potentially message 3
                println!("Received message 3");
                let c_r_rcvd = request.message.payload[0];
                let (index, mut responder, ec) = lookup_state(c_r_rcvd, edhoc_connections).unwrap();
                edhoc_connections = ec;

                println!("Found state with connection identifier {:?}", c_r_rcvd);
                let prk_out = responder.process_message_3(
                    &request.message.payload[1..]
                        .try_into()
                        .expect("wrong length"),
                );

                if prk_out.is_err() {
                    println!("EDHOC processing error: {:?}", prk_out);
                    // FIXME remove state from edhoc_connections
                    continue;
                }

                // update edhoc connection
                edhoc_connections[index] = (c_r_rcvd, responder);

                // send empty ack back
                response.message.payload = b"".to_vec();

                println!("EDHOC exchange successfully completed");
                let _oscore_secret = responder.edhoc_exporter(0u8, &[], 16).unwrap(); // label is 0
                println!("oscore_secret: {:02x?}", _oscore_secret);
                let _oscore_salt = responder.edhoc_exporter(1u8, &[], 8).unwrap(); // label is 1
                println!("oscore_salt: {:02x?}", _oscore_salt);
            }
            response.set_status(ResponseType::Changed);
        } else {
            println!("Received message at unknown resource");
            response.message.payload = b"Resource not found".to_vec();
            response.set_status(ResponseType::BadRequest);
        }
        let packet = response.message.to_bytes().unwrap();
        socket
            .send_to(&packet[..], &src)
            .expect("Could not send the data");
    }
}

fn lookup_state<'a>(
    c_r_rcvd: u8,
    edhoc_protocol_states: Vec<(u8, EdhocResponder<'a>)>,
) -> Result<(usize, EdhocResponder<'a>, Vec<(u8, EdhocResponder)>), EDHOCError> {
    for (i, element) in edhoc_protocol_states.iter().enumerate() {
        let (c_r, responder) = element;
        if *c_r == c_r_rcvd {
            return Ok((i, *responder, edhoc_protocol_states));
        }
    }
    return Err(EDHOCError::WrongState);
}
