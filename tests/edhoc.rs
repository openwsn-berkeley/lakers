use hacspec_edhoc::consts::*;
use hacspec_edhoc::*;
use hacspec_lib::*;

array!(BytesMessage1Tv, 37, U8);
// test vectors (TV)

const METHOD_TV: u8 = 0x03;
// manually modified test vector to include a single supported cipher suite
const SUITES_I_TV: &str = "02";
const G_X_TV: &str = "8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6";
const C_I_TV: &str = "37";
const C_R_TV: &str = "27";
// manually modified test vector to include a single supported cipher suite
const MESSAGE_1_TV: &str =
    "030258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637";
const MESSAGE_2_TV: &str =
    "582a419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d549cef36e229fff1e584927";
const G_Y_TV: &str = "419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5";
const CIPHERTEXT_2_TV: &str = "49cef36e229fff1e5849";
const H_MESSAGE_1_TV: &str = "ca02cabda5a8902749b42f711050bb4dbd52153e87527594b39f50cdf019888c";
const TH_2_TV: &str = "9b99cfd7afdcbcc9950a6373507f2a81013319625697e4f9bf7a448fc8e633ca";
const TH_3_TV: &str = "426f8f65c17f6210392e9a16d51fe07160a25ac6fda440cfb13ec196231f3624";
const CIPHERTEXT_3_TV: &str = "885c63fd0b17f2c3f8f10bc8bf3f470ec8a1";
const TH_4_TV: &str = "ba682e7165e9d484bd2ebb031c09da1ea5b82eb332439c4c7ec73c2c239e3450";
const PRK_2E_TV: &str = "fd9eef627487e40390cae922512db5a647c08dc90deb22b72ece6f156ff1c396";
const KEYSTREAM_2_TV: &str = "7b86c04af73b50d31b6f";
const PRK_3E2M_TV: &str = "af4b5918682adf4c96fd7305b69f8fb78efc9a230dd21f4c61be7d3c109446b3";
const CONTEXT_INFO_MAC_2_TV : &str = "A10432A2026B6578616D706C652E65647508A101A5010202322001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072";
const MAC_2_TV: &str = "3324d5a4afcd4326";
const ID_CRED_I_TV: &str = "a1042b";
const MAC_3_TV: &str = "4cd53d74f0a6ed8b";
const MESSAGE_3_TV: &str = "52885c63fd0b17f2c3f8f10bc8bf3f470ec8a1";
const PRK_4X3M_TV: &str = "4a40f2aca7e1d9dbaf2b276bce75f0ce6d513f75a95af8905f2a14f2493b2477";
const CRED_I_TV : &str = "a2027734322d35302d33312d46462d45462d33372d33322d333908a101a50102022b2001215820ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb62258206e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8";
const ID_CRED_R_TV: &str = "a10432";
const CRED_R_TV : &str = "a2026b6578616d706c652e65647508a101a5010202322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072";
const PLAINTEXT_2_TV: &str = "32483324d5a4afcd4326";
const I_TV: &str = "fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b";
const X_TV: &str = "368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525";
const G_R_TV: &str = "bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0";

#[test]
fn test_encode_message_1() {
    let method_tv = U8(METHOD_TV);
    let suites_i_tv = BytesSupportedSuites::from_hex(SUITES_I_TV);
    let g_x_tv = BytesP256ElemLen::from_hex(G_X_TV);
    let c_i_tv = BytesCid::from_hex(C_I_TV);
    let message_1_tv = BytesMessage1Tv::from_hex(MESSAGE_1_TV);

    let (message_1, message_1_len) = encode_message_1(method_tv, &suites_i_tv, &g_x_tv, &c_i_tv);

    assert_eq!(message_1_len, message_1_tv.len());
    for i in 0..message_1_tv.len() {
        assert_eq!(message_1[i].declassify(), message_1_tv[i].declassify());
    }
}

#[test]
fn test_parse_message_2() {
    let message_2_tv = BytesMessage2::from_hex(MESSAGE_2_TV);
    let g_y_tv = BytesP256ElemLen::from_hex(G_Y_TV);
    let ciphertext_2_tv = BytesCiphertext2::from_hex(CIPHERTEXT_2_TV);

    let (g_y, ciphertext_2, _c_r) = parse_message_2(&message_2_tv);

    assert_bytes_eq!(g_y, g_y_tv);
    assert_bytes_eq!(ciphertext_2, ciphertext_2_tv);
}

#[test]
fn test_compute_th_2() {
    let h_message_1_tv = BytesHashLen::from_hex(H_MESSAGE_1_TV);
    let g_y_tv = BytesP256ElemLen::from_hex(G_Y_TV);
    let c_r_tv = BytesCid::from_hex(C_R_TV);
    let th_2_tv = BytesHashLen::from_hex(TH_2_TV);

    let th_2 = compute_th_2(&h_message_1_tv, &g_y_tv, &c_r_tv);
    assert_bytes_eq!(th_2, th_2_tv);
}

#[test]
fn test_compute_th_3_th_4() {
    let th_2_tv = BytesHashLen::from_hex(TH_2_TV);
    let th_3_tv = BytesHashLen::from_hex(TH_3_TV);
    let mut ciphertext_2_tv = BytesMaxBuffer::new();
    ciphertext_2_tv = ciphertext_2_tv.update(0, &BytesCiphertext2::from_hex(CIPHERTEXT_2_TV));
    let mut ciphertext_3_tv = BytesMaxBuffer::new();
    ciphertext_3_tv = ciphertext_3_tv.update(0, &BytesCiphertext3::from_hex(CIPHERTEXT_3_TV));
    let th_4_tv = BytesHashLen::from_hex(TH_4_TV);

    let th_3 = compute_th_3_th_4(&th_2_tv, &ciphertext_2_tv, CIPHERTEXT_2_LEN);
    assert_bytes_eq!(th_3, th_3_tv);

    let th_4 = compute_th_3_th_4(&th_3_tv, &ciphertext_3_tv, CIPHERTEXT_3_LEN);
    assert_bytes_eq!(th_4, th_4_tv);
}

#[test]
fn test_edhoc_kdf() {
    let th_2_tv = BytesHashLen::from_hex(TH_2_TV);
    let prk_2e_tv = BytesP256ElemLen::from_hex(PRK_2E_TV);
    let keystream_2_tv = BytesPlaintext2::from_hex(KEYSTREAM_2_TV);
    let mut label_tv = BytesMaxLabelBuffer::new();
    label_tv = label_tv.update(0, &ByteSeq::from_public_slice("KEYSTREAM_2".as_bytes()));
    const LEN_TV: usize = 10;
    let context = BytesMaxContextBuffer::new();

    let output = edhoc_kdf(&prk_2e_tv, &th_2_tv, &label_tv, 11, &context, 0, LEN_TV);
    for i in 0..keystream_2_tv.len() {
        assert_eq!(keystream_2_tv[i].declassify(), output[i].declassify());
    }

    let prk_3e2m_tv = BytesP256ElemLen::from_hex(PRK_3E2M_TV);
    let mut label_mac_2_tv = BytesMaxLabelBuffer::new();
    label_mac_2_tv = label_mac_2_tv.update(0, &ByteSeq::from_public_slice("MAC_2".as_bytes()));
    let mut context_info_mac_2 = BytesMaxContextBuffer::new();
    context_info_mac_2 = context_info_mac_2.update(0, &ByteSeq::from_hex(CONTEXT_INFO_MAC_2_TV));
    let mac_2_tv = BytesMac2::from_hex(MAC_2_TV);

    let output_2 = edhoc_kdf(
        &prk_3e2m_tv,
        &th_2_tv,
        &label_mac_2_tv,
        5, // length of "MAC_2"
        &context_info_mac_2,
        CONTEXT_INFO_MAC_2_TV.len() / 2, // divide by two to get num of bytes from hex string
        MAC_LENGTH_2,
    );

    for i in 0..MAC_2_TV.len() / 2 {
        assert_eq!(mac_2_tv[i].declassify(), output_2[i].declassify());
    }
}

#[test]
fn test_compute_bstr_ciphertext_3() {
    let prk_3e2m_tv = BytesP256ElemLen::from_hex(PRK_3E2M_TV);
    let th_3_tv = BytesHashLen::from_hex(TH_3_TV);
    let id_cred_i_tv = BytesIdCred::from_hex(ID_CRED_I_TV);
    let mac_3_tv = BytesMac3::from_hex(MAC_3_TV);
    let message_3_tv = BytesMessage3::from_hex(MESSAGE_3_TV);

    let bstr_ciphertext_3 =
        compute_bstr_ciphertext_3(&prk_3e2m_tv, &th_3_tv, &id_cred_i_tv, &mac_3_tv);
    assert_bytes_eq!(bstr_ciphertext_3, message_3_tv);
}

#[test]
fn test_compute_mac_3() {
    let prk_4x3m_tv = BytesP256ElemLen::from_hex(PRK_4X3M_TV);
    let th_3_tv = BytesHashLen::from_hex(TH_3_TV);
    let id_cred_i_tv = BytesIdCred::from_hex(ID_CRED_I_TV);
    let mut cred_i_tv = BytesMaxBuffer::new();
    cred_i_tv = cred_i_tv.update(0, &ByteSeq::from_hex(CRED_I_TV));
    let mac_3_tv = BytesMac3::from_hex(MAC_3_TV);

    let mac_3 = compute_mac_3(
        &prk_4x3m_tv,
        &th_3_tv,
        &id_cred_i_tv,
        &cred_i_tv,
        CRED_I_TV.len() / 2, // divide by two to get num of bytes from hex string
    );
    assert_bytes_eq!(mac_3, mac_3_tv);
}

#[test]
fn test_compute_and_verify_mac_2() {
    let prk_3e2m_tv = BytesP256ElemLen::from_hex(PRK_3E2M_TV);
    let id_cred_r_tv = BytesIdCred::from_hex(ID_CRED_R_TV);
    let mut cred_r_tv = BytesMaxBuffer::new();
    cred_r_tv = cred_r_tv.update(0, &ByteSeq::from_hex(CRED_R_TV));
    let th_2_tv = BytesHashLen::from_hex(TH_2_TV);
    let mac_2_tv = BytesMac2::from_hex(MAC_2_TV);

    assert!(compute_and_verify_mac_2(
        &prk_3e2m_tv,
        &id_cred_r_tv,
        &cred_r_tv,
        CRED_R_TV.len() / 2,
        &th_2_tv,
        &mac_2_tv
    ));
}

#[test]
fn test_decode_plaintext_2() {
    let plaintext_2_tv = BytesPlaintext2::from_hex(PLAINTEXT_2_TV);
    let id_cred_r_tv = BytesIdCred::from_hex(ID_CRED_R_TV);
    let mac_2_tv = BytesMac2::from_hex(MAC_2_TV);
    let ead_2_tv = BytesEad2::new();

    let (id_cred_r, mac_2, ead_2) = decode_plaintext_2(&plaintext_2_tv);
    assert_eq!(U8::declassify(id_cred_r), U8::declassify(id_cred_r_tv[2]));
    assert_bytes_eq!(mac_2, mac_2_tv);
    assert_bytes_eq!(ead_2, ead_2_tv);
}

#[test]
fn test_decrypt_ciphertext_2() {
    let prk_2e_tv = BytesP256ElemLen::from_hex(PRK_2E_TV);
    let g_y_tv = BytesP256ElemLen::from_hex(G_Y_TV);
    let c_r_tv = BytesCid::from_hex(C_R_TV);
    let ciphertext_2_tv = BytesCiphertext2::from_hex(CIPHERTEXT_2_TV);
    let h_message_1_tv = BytesHashLen::from_hex(H_MESSAGE_1_TV);
    let plaintext_2_tv = BytesPlaintext2::from_hex(PLAINTEXT_2_TV);

    let plaintext_2 = decrypt_ciphertext_2(
        &prk_2e_tv,
        &g_y_tv,
        &c_r_tv,
        &ciphertext_2_tv,
        &h_message_1_tv,
    );
    assert_bytes_eq!(plaintext_2_tv, plaintext_2);
}

#[test]
fn test_compute_prk_4x3m() {
    let prk_3e2m_tv = BytesP256ElemLen::from_hex(PRK_3E2M_TV);
    let i_tv = BytesP256ElemLen::from_hex(I_TV);
    let g_y_tv = BytesP256ElemLen::from_hex(G_Y_TV);
    let prk_4x3m_tv = BytesP256ElemLen::from_hex(PRK_4X3M_TV);

    let prk_4x3m = compute_prk_4x3m(&prk_3e2m_tv, &i_tv, &g_y_tv);
    assert_bytes_eq!(prk_4x3m, prk_4x3m_tv);
}

#[test]
fn test_compute_prk_3e2m() {
    let prk_2e_tv = BytesP256ElemLen::from_hex(PRK_2E_TV);
    let x_tv = BytesP256ElemLen::from_hex(X_TV);
    let g_r_tv = BytesP256ElemLen::from_hex(G_R_TV);
    let prk_3e2m_tv = BytesP256ElemLen::from_hex(PRK_3E2M_TV);

    let prk_3e2m = compute_prk_3e2m(&prk_2e_tv, &x_tv, &g_r_tv);
    assert_bytes_eq!(prk_3e2m, prk_3e2m_tv);
}

#[test]
fn test_compute_prk_2e() {
    let x_tv = BytesP256ElemLen::from_hex(X_TV);
    let g_y_tv = BytesP256ElemLen::from_hex(G_Y_TV);
    let prk_2e_tv = BytesP256ElemLen::from_hex(PRK_2E_TV);

    let prk_2e = compute_prk_2e(&x_tv, &g_y_tv);
    assert_bytes_eq!(prk_2e, prk_2e_tv);
}
