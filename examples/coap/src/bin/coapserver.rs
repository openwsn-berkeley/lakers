use coap_lite::{CoapRequest, Packet, ResponseType};
use edhoc_rs::*;
use hexlit::hex;
use std::net::UdpSocket;

const _ID_CRED_I: &[u8] = &hex!("a104412b");
const ID_CRED_R: &[u8] = &hex!("a104410a");
const CRED_I: &[u8] = &hex!("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
const _G_I: &[u8] = &hex!("ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6");
const _G_I_Y_COORD: &[u8] =
    &hex!("6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8");
const CRED_R: &[u8] = &hex!("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");
const R: &[u8] = &hex!("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");

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
                let responder = EdhocResponder::new(
                    lakers_crypto::default_crypto(),
                    &R,
                    &CRED_R,
                    Some(&CRED_I),
                );

                let result = responder.process_message_1(
                    &request.message.payload[1..]
                        .try_into()
                        .expect("wrong length"),
                );

                if let Ok((responder, _ead_1)) = result {
                    let c_r =
                        generate_connection_identifier_cbor(&mut lakers_crypto::default_crypto());
                    let kid = IdCred::CompactKid(ID_CRED_R[3]);
                    let (responder, message_2) =
                        responder.prepare_message_2(&kid, Some(c_r), &None).unwrap();
                    response.message.payload = Vec::from(message_2.as_slice());
                    // save edhoc connection
                    edhoc_connections.push((c_r, responder));
                }
            } else {
                // potentially message 3
                println!("Received message 3");
                let c_r_rcvd = request.message.payload[0];
                // FIXME let's better not *panic here
                let responder = take_state(c_r_rcvd, &mut edhoc_connections).unwrap();

                println!("Found state with connection identifier {:?}", c_r_rcvd);
                let message_3 =
                    EdhocMessageBuffer::new_from_slice(&request.message.payload[1..]).unwrap();
                let Ok((responder, id_cred_i, _ead_3)) = responder.process_message_3a(&message_3)
                else {
                    println!("EDHOC processing error: {:?}", message_3);
                    // We don't get another chance, it's popped and can't be used any further
                    // anyway legally
                    continue;
                };
                let (valid_cred_i, _g_i) =
                    credential_check_or_fetch(Some(CRED_I.try_into().unwrap()), id_cred_i).unwrap();
                let Ok((mut responder, prk_out)) =
                    responder.process_message_3b(valid_cred_i.as_slice())
                else {
                    println!("EDHOC processing error: {:?}", valid_cred_i);
                    continue;
                };

                // send empty ack back
                response.message.payload = b"".to_vec();

                println!("EDHOC exchange successfully completed");
                println!("PRK_out: {:02x?}", prk_out);

                let mut _oscore_secret = responder.edhoc_exporter(0u8, &[], 16); // label is 0
                println!("OSCORE secret: {:02x?}", _oscore_secret);
                let mut _oscore_salt = responder.edhoc_exporter(1u8, &[], 8); // label is 1
                println!("OSCORE salt: {:02x?}", _oscore_salt);

                // context of key update is a test vector from draft-ietf-lake-traces
                let prk_out_new = responder.edhoc_key_update(&[
                    0xa0, 0x11, 0x58, 0xfd, 0xb8, 0x20, 0x89, 0x0c, 0xd6, 0xbe, 0x16, 0x96, 0x02,
                    0xb8, 0xbc, 0xea,
                ]);
                println!("PRK_out after key update: {:02x?}?", prk_out_new);

                _oscore_secret = responder.edhoc_exporter(0u8, &[], 16); // label is 0
                println!("OSCORE secret after key update: {:02x?}", _oscore_secret);
                _oscore_salt = responder.edhoc_exporter(1u8, &[], 8); // label is 1
                println!("OSCORE salt after key update: {:02x?}", _oscore_salt);
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

fn take_state<R>(
    c_r_rcvd: u8,
    edhoc_protocol_states: &mut Vec<(u8, R)>,
) -> Result<R, &'static str> {
    for (i, element) in edhoc_protocol_states.iter().enumerate() {
        let (c_r, _responder) = element;
        if *c_r == c_r_rcvd {
            let max_index = edhoc_protocol_states.len() - 1;
            edhoc_protocol_states.swap(i, max_index);
            let Some((_c_r, responder)) = edhoc_protocol_states.pop() else {
                unreachable!();
            };
            return Ok(responder);
        }
    }
    return Err("No stored state available for that C_R");
}
