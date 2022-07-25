use coap::CoAPClient;
use hacspec_edhoc::consts::*;
use hacspec_edhoc::*;
use hacspec_lib::*;

const ID_CRED_I: &str = "a104412b";
const ID_CRED_R: &str = "a104410a";
const CRED_I: &str = "A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8";
const I: &str = "fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b";
const _G_I_X_COORD: &str = "ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6"; // not used
const _G_I_Y_COORD: &str = "6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8"; // not used
const CRED_R: &str = "A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072";
const G_R: &str = "bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0";
const C_I: BytesCid = BytesCid(secret_bytes!([0x0eu8]));

fn main() {
    let url = "coap://92.34.13.218:5690/.well-known/edhoc";
    println!("Client request: {}", url);

    let state: State = Default::default();

    // init hacspec structs for id_cred_i and cred_i
    let id_cred_i = BytesIdCred::from_hex(ID_CRED_I);
    let mut cred_i = BytesMaxBuffer::new();
    cred_i = cred_i.update(0, &ByteSeq::from_hex(CRED_I));
    let cred_i_len = CRED_I.len() / 2;

    // init hacspec struct for I, I's private static DH key
    let i = BytesP256ElemLen::from_hex(I);

    // init hacspec structs for id_cred_r and cred_r
    let id_cred_r = BytesIdCred::from_hex(ID_CRED_R);
    let mut cred_r = BytesMaxBuffer::new();
    cred_r = cred_r.update(0, &ByteSeq::from_hex(CRED_R));
    let cred_r_len = CRED_R.len() / 2;

    // init hacspec structs for R's public static DH key
    let g_r = BytesP256ElemLen::from_hex(G_R);

    let (state, message_1, message_1_len) = prepare_message_1(state, &C_I);
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

    let (error, state, c_r, id_cred_r) =
        process_message_2(state, &message_2, &id_cred_r, &cred_r, cred_r_len, &g_r, &i);

    if error == EDHOCError::Success {
        let c_r = c_r[0 as usize].declassify();
        let (state, message_3) = prepare_message_3(state, &id_cred_i, &cred_i, cred_i_len);

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
            edhoc_exporter(state, U8(1), &BytesMaxContextBuffer::new(), 0, 8);
    } else {
        panic!("Message 2 processing error: {:#?}", error);
    }
}
