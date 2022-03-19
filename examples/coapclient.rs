use coap::CoAPClient;
use edhoc::*;
use hex_literal::hex;
const X: [u8; 32] = hex!("368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525");
const G_X: [u8; 32] = hex!("8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6");
const C_I: i8 = -24;
const ID_CRED_R: [u8; 3] = hex!("A10405");
const CRED_R : [u8; 83] = hex!("A2026008A101A50102020520012158206F9702A66602D78F5E81BAC1E0AF01F8B52810C502E87EBB7C926C07426FD02F225820C8D33274C71C9B3EE57D842BBF2238B8283CB410ECA216FB72A78EA7A870F800");
const G_R: [u8; P256_ELEM_LEN] =
    hex!("6f9702a66602d78f5e81bac1e0af01f8b52810c502e87ebb7c926c07426fd02f");

const ID_CRED_I: [u8; 3] = hex!("a1042b");
const CRED_I: [u8; 106] = hex!("a2027734322d35302d33312d46462d45462d33372d33322d333908a101a50102022b2001215820ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb62258206e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8");
const I: [u8; P256_ELEM_LEN] =
    hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");

fn main() {
    let url = "coap://31.133.128.122:5683/.well-known/edhoc";
    println!("Client request: {}", url);

    let mut message_buffer: [u8; MAX_BUFFER_LEN] = [0x00; MAX_BUFFER_LEN];
    let mut digest_message_1: [u8; SHA256_DIGEST_LEN] = [0x00; SHA256_DIGEST_LEN];

    let message_1_len = encode_message_1(
        EDHOC_METHOD,
        &EDHOC_SUPPORTED_SUITES,
        G_X,
        C_I,
        &mut message_buffer,
    );
    crypto::sha256_digest(&message_buffer[0..message_1_len], &mut digest_message_1);

    // Send Message 1 over CoAP and convert the response to byte
    let mut data = message_buffer[0..message_1_len].to_vec();
    data.insert(0, 0xf5 as u8);

    let response = CoAPClient::post(url, data).unwrap();
    println!("response_vec = {:02x?}", response.message.payload);
    // convert response to byte array
    for i in 0..response.message.payload.len() {
        message_buffer[i] = response.message.payload[i] as u8;
    }
    let message_2_len = response.message.payload.len();

    // proceed with processing of message_2
    let mut g_y: [u8; P256_ELEM_LEN] = [0x00; P256_ELEM_LEN];
    let mut ciphertext_2: [u8; CIPHERTEXT_2_LEN] = [0x00; CIPHERTEXT_2_LEN];
    let mut c_r: u8 = 0x00;
    parse_message_2(
        &message_buffer[0..message_2_len],
        &mut g_y,
        &mut ciphertext_2,
        &mut c_r,
    );

    // compute prk_2e
    let mut prk_2e: [u8; P256_ELEM_LEN] = [0x00; P256_ELEM_LEN];
    let mut plaintext_2: [u8; PLAINTEXT_2_LEN] = [0x00; PLAINTEXT_2_LEN];
    compute_prk_2e(X, g_y, &mut prk_2e);
    decrypt_ciphertext_2(
        prk_2e,
        g_y,
        &[c_r as i8],
        ciphertext_2,
        digest_message_1,
        &mut plaintext_2,
    );

    // decode plaintext_2
    let mut id_cred_r: u8 = 0x00;
    let mut mac_2: [u8; MAC_LENGTH_2] = [0x00; MAC_LENGTH_2];
    let mut ead_2: [u8; 0] = [];
    decode_plaintext_2(&plaintext_2, &mut id_cred_r, &mut mac_2, &mut ead_2);

    if id_cred_r != ID_CRED_R[2] {
        panic!("Unknown authentication peer!");
    }

    // verify mac_2
    let mut prk_3e2m: [u8; P256_ELEM_LEN] = [0x00; P256_ELEM_LEN];
    compute_prk_3e2m(prk_2e, X, G_R, &mut prk_3e2m);
    let mut th_2: [u8; SHA256_DIGEST_LEN] = [0x00; SHA256_DIGEST_LEN];
    compute_th_2(digest_message_1, g_y, &[c_r as i8], &mut th_2);
    compute_and_verify_mac_2(prk_3e2m, &ID_CRED_R, &CRED_R, th_2, mac_2);

    // message 3 processing
    let mut th_3: [u8; SHA256_DIGEST_LEN] = [0x00; SHA256_DIGEST_LEN];
    compute_th_3_th_4(th_2, &ciphertext_2, &mut th_3);

    let mut prk_4x3m: [u8; P256_ELEM_LEN] = [0x00; P256_ELEM_LEN];
    compute_prk_4x3m(prk_3e2m, I, g_y, &mut prk_4x3m);
    let mut mac_3: [u8; MAC_LENGTH_3] = [0x00; MAC_LENGTH_3];
    compute_mac_3(prk_4x3m, th_3, &ID_CRED_I, &CRED_I, &mut mac_3);

    let mut ciphertext_3: [u8; CIPHERTEXT_3_LEN] = [0x00; CIPHERTEXT_3_LEN];
    compute_ciphertext_3(prk_3e2m, th_3, &ID_CRED_I, mac_3, &mut ciphertext_3);

    let message_3_len = encode_message_3(ciphertext_3, &mut message_buffer);

    let mut th_4: [u8; SHA256_DIGEST_LEN] = [0x00; SHA256_DIGEST_LEN];
    compute_th_3_th_4(th_3, &ciphertext_3, &mut th_4);
    // export th_4 and prk_4x3m
    println!("th_4 = {:02x?}", th_4);
    println!("prk_4x3m = {:02x?}", prk_4x3m);

    // FIXME code duplication senidng message 3 over coap
    // Send Message 1 over CoAP and convert the response to byte
    let mut data = message_buffer[0..message_3_len].to_vec();
    data.insert(0, c_r);

    let response = CoAPClient::post(url, data).unwrap();
    println!("response_vec = {:02x?}", response.message.payload);
    // convert response to byte array
    for i in 0..response.message.payload.len() {
        message_buffer[i] = response.message.payload[i] as u8;
    }
    let message_4_len = response.message.payload.len();
    println!(
        "Received message_4: {:02x?}",
        &message_buffer[0..message_4_len]
    );

}
