use hacspec_edhoc::consts::*;
use hacspec_edhoc::*;
use hacspec_lib::*;

use hexlit::hex;

array!(BytesMessage1Tv, 39, U8);
// test vectors (TV)
const X_TV: [u8; P256_ELEM_LEN] =
    hex!("368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525");
const G_XY_TV: [u8; P256_ELEM_LEN] =
    hex!("2f0cb7e860ba538fbf5c8bded009f6259b4b628fe1eb7dbe9378e5ecf7a824ba");

const G_R_TV: [u8; P256_ELEM_LEN] =
    hex!("bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0");
const ID_CRED_R_TV: [u8; 3] = hex!("a10432");
const CRED_R_TV : [u8; 94] = hex!("a2026b6578616d706c652e65647508a101a5010202322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
const PLAINTEXT_2_TV: [u8; PLAINTEXT_2_LEN] = hex!("32483324d5a4afcd4326");
const I_TV: [u8; P256_ELEM_LEN] =
    hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
const EAD_2_TV: [u8; 0] = hex!("");

#[test]
fn test_encode_message_1() {
    let METHOD_TV = U8(0x03);
    let SUITES_I_TV = BytesSupportedSuites::from_hex("0602");
    let G_X_TV = BytesP256ElemLen::from_hex(
        "8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6",
    );
    let C_I_TV: i8 = -24i8;
    let MESSAGE_1_TV = BytesMessage1Tv::from_hex(
        "0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637",
    );

    let message_1 = BytesMaxBuffer::new();

    let (message_1, message_1_len) =
        encode_message_1(METHOD_TV, &SUITES_I_TV, &G_X_TV, C_I_TV, message_1);
    assert_eq!(message_1_len, MESSAGE_1_TV.len());
    for i in 0..MESSAGE_1_TV.len() {
        assert_eq!(message_1[i].declassify(), MESSAGE_1_TV[i].declassify());
    }
}

#[test]
fn test_parse_message_2() {
    let MESSAGE_2_TV = BytesMessage2::from_hex("582a419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d549cef36e229fff1e584927");
    let G_Y_TV = BytesP256ElemLen::from_hex(
        "419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5",
    );
    let CIPHERTEXT_2_TV = BytesCiphertext2::from_hex("49cef36e229fff1e5849");
    let g_y = BytesP256ElemLen::new();
    let ciphertext_2 = BytesCiphertext2::new();
    let c_r = U8(0xff);

    let (g_y, ciphertext_2, c_r) = parse_message_2(&MESSAGE_2_TV, g_y, ciphertext_2, c_r);

    assert_bytes_eq!(g_y, G_Y_TV);
    assert_bytes_eq!(ciphertext_2, CIPHERTEXT_2_TV);
}

#[test]
fn test_compute_th_2() {
    let H_MESSAGE_1_TV =
        BytesHashLen::from_hex("ca02cabda5a8902749b42f711050bb4dbd52153e87527594b39f50cdf019888c");
    let G_Y_TV = BytesP256ElemLen::from_hex(
        "419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5",
    );
    let C_R_TV = BytesCidR::from_hex("27");

    let TH_2_TV =
        BytesHashLen::from_hex("9b99cfd7afdcbcc9950a6373507f2a81013319625697e4f9bf7a448fc8e633ca");

    let th_2 = BytesHashLen::new();
    let th_2 = compute_th_2(&H_MESSAGE_1_TV, &G_Y_TV, &C_R_TV, th_2);
    assert_bytes_eq!(th_2, TH_2_TV);
}

#[test]
fn test_compute_th_3_th_4() {
    let TH_2_TV =
        BytesHashLen::from_hex("9b99cfd7afdcbcc9950a6373507f2a81013319625697e4f9bf7a448fc8e633ca");

    let TH_3_TV =
        BytesHashLen::from_hex("426f8f65c17f6210392e9a16d51fe07160a25ac6fda440cfb13ec196231f3624");
    let mut CIPHERTEXT_2_TV = BytesMaxBuffer::new();
    CIPHERTEXT_2_TV =
        CIPHERTEXT_2_TV.update(0, &BytesCiphertext2::from_hex("49cef36e229fff1e5849"));
    let mut CIPHERTEXT_3_TV = BytesMaxBuffer::new();
    CIPHERTEXT_3_TV = CIPHERTEXT_3_TV.update(
        0,
        &BytesCiphertext3::from_hex("885c63fd0b17f2c3f8f10bc8bf3f470ec8a1"),
    );
    let TH_4_TV =
        BytesHashLen::from_hex("ba682e7165e9d484bd2ebb031c09da1ea5b82eb332439c4c7ec73c2c239e3450");
    let th_3 = BytesHashLen::new();
    let th_3 = compute_th_3_th_4(&TH_2_TV, &CIPHERTEXT_2_TV, CIPHERTEXT_2_LEN, th_3);
    assert_bytes_eq!(th_3, TH_3_TV);

    let th_4 = BytesHashLen::new();
    let th_4 = compute_th_3_th_4(&TH_3_TV, &CIPHERTEXT_3_TV, CIPHERTEXT_3_LEN, th_4);
    assert_bytes_eq!(th_4, TH_4_TV);
}

#[test]
fn test_edhoc_kdf() {
    let TH_2_TV =
        BytesHashLen::from_hex("9b99cfd7afdcbcc9950a6373507f2a81013319625697e4f9bf7a448fc8e633ca");

    let PRK_2E_TV = BytesP256ElemLen::from_hex(
        "fd9eef627487e40390cae922512db5a647c08dc90deb22b72ece6f156ff1c396",
    );

    let KEYSTREAM_2_TV = BytesPlaintext2::from_hex("7b86c04af73b50d31b6f");

    let mut LABEL_TV = BytesMaxLabelBuffer::new();
    LABEL_TV = LABEL_TV.update(0, &ByteSeq::from_public_slice("KEYSTREAM_2".as_bytes()));

    const LEN_TV: usize = 10;

    let CONTEXT = BytesMaxContextBuffer::new();

    let mut output = BytesMaxBuffer::new();
    output = edhoc_kdf(
        &PRK_2E_TV, &TH_2_TV, &LABEL_TV, 11, &CONTEXT, 0, LEN_TV, output,
    );

    for i in 0..KEYSTREAM_2_TV.len() {
        assert_eq!(KEYSTREAM_2_TV[i].declassify(), output[i].declassify());
    }

    let PRK_3E2M_TV = BytesP256ElemLen::from_hex(
        "af4b5918682adf4c96fd7305b69f8fb78efc9a230dd21f4c61be7d3c109446b3",
    );

    let mut LABEL_MAC_2_TV = BytesMaxLabelBuffer::new();
    LABEL_MAC_2_TV = LABEL_MAC_2_TV.update(0, &ByteSeq::from_public_slice("MAC_2".as_bytes()));
    let LABEL_MAC_2_TV_LEN = 5;

    let mut CONTEXT_INFO_MAC_2 = BytesMaxContextBuffer::new();
    CONTEXT_INFO_MAC_2 = CONTEXT_INFO_MAC_2.update(0, &ByteSeq::from_hex("A10432A2026B6578616D706C652E65647508A101A5010202322001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072"));
    let CONTEXT_INFO_MAC_2_LEN = 97;

    let MAC_2_TV = BytesMac2::from_hex("3324d5a4afcd4326");

    let mut output_2 = BytesMaxBuffer::new();

    output_2 = edhoc_kdf(
        &PRK_3E2M_TV,
        &TH_2_TV,
        &LABEL_MAC_2_TV,
        LABEL_MAC_2_TV_LEN,
        &CONTEXT_INFO_MAC_2,
        CONTEXT_INFO_MAC_2_LEN,
        MAC_LENGTH_2,
        output_2,
    );

    for i in 0..MAC_2_TV.len() {
        assert_eq!(MAC_2_TV[i].declassify(), output_2[i].declassify());
    }
}

#[test]
fn test_compute_bstr_ciphertext_3() {
    let PRK_3E2M_TV = BytesP256ElemLen::from_hex(
        "af4b5918682adf4c96fd7305b69f8fb78efc9a230dd21f4c61be7d3c109446b3",
    );
    let TH_3_TV =
        BytesHashLen::from_hex("426f8f65c17f6210392e9a16d51fe07160a25ac6fda440cfb13ec196231f3624");
    let ID_CRED_I_TV = BytesIdCred::from_hex("a1042b");

    let MAC_3_TV = BytesMac3::from_hex("4cd53d74f0a6ed8b");

    let MESSAGE_3_TV = BytesMessage3::from_hex("52885c63fd0b17f2c3f8f10bc8bf3f470ec8a1");
    let mut bstr_ciphertext_3 = BytesMessage3::new();

    bstr_ciphertext_3 = compute_bstr_ciphertext_3(
        &PRK_3E2M_TV,
        &TH_3_TV,
        &ID_CRED_I_TV,
        &MAC_3_TV,
        bstr_ciphertext_3,
    );

    assert_bytes_eq!(bstr_ciphertext_3, MESSAGE_3_TV);
}

#[test]
fn test_compute_mac_3() {
    let mut mac_3 = BytesMac3::new();

    let PRK_4X3M_TV = BytesP256ElemLen::from_hex(
        "4a40f2aca7e1d9dbaf2b276bce75f0ce6d513f75a95af8905f2a14f2493b2477",
    );
    let TH_3_TV =
        BytesHashLen::from_hex("426f8f65c17f6210392e9a16d51fe07160a25ac6fda440cfb13ec196231f3624");
    let ID_CRED_I_TV = BytesIdCred::from_hex("a1042b");
    let mut CRED_I_TV = BytesMaxBuffer::new();
    CRED_I_TV = CRED_I_TV.update(0, &ByteSeq::from_hex("a2027734322d35302d33312d46462d45462d33372d33322d333908a101a50102022b2001215820ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb62258206e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8"));

    let MAC_3_TV = BytesMac3::from_hex("4cd53d74f0a6ed8b");

    mac_3 = compute_mac_3(
        &PRK_4X3M_TV,
        &TH_3_TV,
        &ID_CRED_I_TV,
        &CRED_I_TV,
        106,
        mac_3,
    );
    assert_bytes_eq!(mac_3, MAC_3_TV);
}
