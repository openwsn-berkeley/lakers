use hexlit::hex;
use lakers::*;
use lakers_crypto::Crypto;
use lakers_ead::ZeroTouchDevice;

use embedded_nal_async::UdpStack;

const ID_CRED_I: &[u8] = &hex!("a104412b");
const _ID_CRED_R: &[u8] = &hex!("a104410a");
const CRED_I: &[u8] = &hex!("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
const I: &[u8] = &hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
const _G_I_X_COORD: &[u8] =
    &hex!("ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6");
const _G_I_Y_COORD: &[u8] =
    &hex!("6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8");
const CRED_R: &[u8] = &hex!("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");
const _G_R: &[u8] = &hex!("bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0");

async fn run_client_operations<const N: usize>(
    client: embedded_nal_coap::CoAPRuntimeClient<'_, N>,
) -> Result<(), EDHOCError> {
    let demoserver = "[::1]:5683".parse().unwrap();
    let path = "/.well-known/edhoc";

    use coap_request::Stack;

    println!("Client request: to {:?}, path {}", demoserver, path);

    let cred_i = CredentialRPK::new(CRED_I.try_into().unwrap()).unwrap();
    let cred_r = CredentialRPK::new(CRED_R.try_into().unwrap()).unwrap();

    let initiator = EdhocInitiator::new(lakers_crypto::default_crypto());

    // Send Message 1 over CoAP and convert the response to byte
    let mut msg_1_buf = Vec::from([0xf5u8]); // EDHOC message_1 when transported over CoAP is prepended with CBOR true
    let c_i = generate_connection_identifier_cbor(&mut lakers_crypto::default_crypto());
    let ead_1 = None;
    let (initiator, message_1) = initiator.prepare_message_1(Some(c_i), &ead_1)?;
    msg_1_buf.extend_from_slice(message_1.as_slice());
    println!("message_1 len = {}", msg_1_buf.len());

    let mut message_2 = None;

    client
        .to(demoserver)
        .request(
            coap_request_implementations::Code::post()
                .with_path(path)
                .with_request_payload_slice(&msg_1_buf)
                .processing_response_payload_through(|response| {
                    println!("response = {:02x?}", response);
                    message_2 = Some(EdhocMessageBuffer::new_from_slice(response));
                }),
        )
        .await
        .expect("Message 1 request failed")
        .expect("Message 1 response was not successful");

    let message_2 = message_2.expect("Successful processsing on the client, but no response seen?");
    let message_2 = message_2.expect("Failed to create an EdhocMessageBuffer from the response");

    let (initiator, c_r, id_cred_r, _ead_2) = initiator.parse_message_2(&message_2)?;
    let valid_cred_r = credential_check_or_fetch(Some(cred_r), id_cred_r).unwrap();
    let initiator = initiator.verify_message_2(&I, cred_i, valid_cred_r)?;

    let mut msg_3 = Vec::from([c_r]);
    let (mut initiator, message_3, prk_out) =
        initiator.prepare_message_3(CredentialTransfer::ByReference, &None)?;
    msg_3.extend_from_slice(message_3.as_slice());
    println!("message_3 len = {}", msg_3.len());

    client
        .to(demoserver)
        .request(
            coap_request_implementations::Code::post()
                .with_path(path)
                .with_request_payload_slice(&msg_3),
        )
        .await
        .expect("Message 3 request failed")
        .expect("Message 3 response was not successful");

    // we don't care about the response to message_3 for now

    println!("EDHOC exchange successfully completed");
    println!("PRK_out: {:02x?}", prk_out);

    let mut oscore_secret = initiator.edhoc_exporter(0u8, &[], 16); // label is 0
    let mut oscore_salt = initiator.edhoc_exporter(1u8, &[], 8); // label is 1

    println!("OSCORE secret: {:02x?}", oscore_secret);
    println!("OSCORE salt: {:02x?}", oscore_salt);

    // context of key update is a test vector from draft-ietf-lake-traces
    let prk_out_new = initiator.edhoc_key_update(&[
        0xa0, 0x11, 0x58, 0xfd, 0xb8, 0x20, 0x89, 0x0c, 0xd6, 0xbe, 0x16, 0x96, 0x02, 0xb8, 0xbc,
        0xea,
    ]);

    println!("PRK_out after key update: {:02x?}?", prk_out_new);

    // compute OSCORE secret and salt after key update
    oscore_secret = initiator.edhoc_exporter(0u8, &[], 16); // label is 0
    oscore_salt = initiator.edhoc_exporter(1u8, &[], 8); // label is 1

    println!("OSCORE secret after key update: {:02x?}", oscore_secret);
    println!("OSCORE salt after key update: {:02x?}", oscore_salt);

    Ok(())
}

async fn main_on_stack<S: UdpStack>(stack: &mut S) {
    // FIXME this needs coordination btwn embedded-nal-async and -coap
    //     let (_localaddr, mut sock) = stack
    //         .bind_single(embedded_nal_async::SocketAddr::new(
    //             "::".parse().unwrap(),
    //             0,
    //         ))
    //         .await
    //         .expect("Can't create a socket");
    let mut sock = stack
        .bind_multiple(embedded_nal_async::SocketAddr::new(
            "::".parse().unwrap(),
            1234,
        ))
        .await
        .expect("Can't create a socket");

    // Shortest way to 4.04 all requests
    let mut handler = coap_handler_implementations::new_dispatcher();

    let coap = embedded_nal_coap::CoAPShared::<1>::new();
    let (client, server) = coap.split();

    use rand::SeedableRng;

    match embassy_futures::select::select(
        server.run(
            &mut sock,
            &mut handler,
            &mut rand::rngs::StdRng::from_entropy(),
        ),
        run_client_operations(client),
    )
    .await
    {
        embassy_futures::select::Either::First(r) => {
            panic!("CoAP task terminated unexpectedly: {:?}", r)
        }
        embassy_futures::select::Either::Second(result) => {
            result.expect("Client operation was not successful")
        }
    }
}

#[async_std::main]
async fn main() {
    let mut stack = std_embedded_nal_async::Stack::default();

    main_on_stack(&mut stack).await
}
