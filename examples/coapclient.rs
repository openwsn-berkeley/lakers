use coap::CoAPClient;
use hacspec_edhoc::consts::*;
use hacspec_edhoc::*;
use hacspec_lib::*;
const ID_CRED_I: &str = "a104412b";
const ID_CRED_R: u8 = 0x0au8;
const CRED_I: &str = "A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8";

fn main() {
    let url = "coap://92.34.13.218:5690/.well-known/edhoc";
    println!("Client request: {}", url);

    let state: State = Default::default();
    let id_cred_i = BytesIdCred::from_hex(ID_CRED_I);
    let mut cred_i = BytesMaxBuffer::new();
    cred_i = cred_i.update(0, &ByteSeq::from_hex(CRED_I));

    let (state, message_1, message_1_len) = prepare_message_1(state);
    // Send Message 1 over CoAP and convert the response to byte
    let mut message_1_vec = Vec::new();
    message_1_vec.push(0xf5 as u8);
    for i in 0..message_1_len {
        message_1_vec.push(message_1[i].declassify());
    }

    let response = CoAPClient::post(url, message_1_vec).unwrap();
    println!("response_vec = {:02x?}", response.message.payload);

    // convert response to hacspec array
    let mut message_2 = BytesMessage2::new();
    message_2 = message_2.update(0, &ByteSeq::from_public_slice(&response.message.payload));
    let message_2_len = response.message.payload.len();

    let (state, verified, c_r, id_cred_r) = process_message_2(state, &message_2);

    // Check that we are talking with the expected peer
    assert_eq!(ID_CRED_R, id_cred_r.declassify());

    let c_r = c_r[0 as usize].declassify();

    if verified {
        let (state, message_3) = prepare_message_3(state, &id_cred_i, &cred_i);

        // Send Message 3 over CoAP
        let mut message_3_vec = Vec::new();
        message_3_vec.push(c_r);
        for i in 0..MESSAGE_3_LEN {
            message_3_vec.push(message_3[i].declassify());
        }

        let _response = CoAPClient::post(url, message_3_vec).unwrap();
        // we don't care about the response to message_3 for now

        let (state, oscore_secret) =
            edhoc_exporter(state, U8(0), &BytesMaxContextBuffer::new(), 0, 16);
        let (state, oscore_salt) =
            edhoc_exporter(state, U8(1), &BytesMaxContextBuffer::new(), 0, 16);
    } else {
        panic!("Message 2 not verified.");
    }
}
