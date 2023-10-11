#![no_std]

use edhoc_consts::*;
use edhoc_crypto::*;

// initiator side
#[derive(Default, PartialEq, Copy, Clone, Debug)]
pub enum EADInitiatorProtocolState {
    #[default]
    NonInitialized,
    Start,
    WaitEAD2,
    Completed, // TODO[ead]: check if it is really ok to consider Completed after processing EAD_2
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub struct EADInitiatorState {
    pub protocol_state: EADInitiatorProtocolState,
    pub(crate) id_u: EdhocMessageBuffer, // identifier of the device (U), equivalent to ID_CRED_I in EDHOC
    pub(crate) g_w: BytesP256ElemLen,    // public key of the enrollment server (W)
    pub(crate) loc_w: EdhocMessageBuffer, // address of the enrollment server (W)
}

impl EADInitiatorState {
    pub fn new(id_u: EdhocMessageBuffer, g_w: BytesP256ElemLen, loc_w: EdhocMessageBuffer) -> Self {
        EADInitiatorState {
            protocol_state: EADInitiatorProtocolState::Start,
            id_u,
            g_w,
            loc_w,
        }
    }
}

// shared mutable global state for EAD
// NOTE: this is not thread-safe
static mut EAD_INITIATOR_GLOBAL_STATE: EADInitiatorState = EADInitiatorState {
    protocol_state: EADInitiatorProtocolState::Start,
    // FIXME: lots of wasted bytes in id_u and loc_w.
    // they could both be &[u8], but that would require a <'a> lifetime which clashes with the static lifetime of the global state
    id_u: EdhocMessageBuffer {
        content: [0u8; MAX_MESSAGE_SIZE_LEN],
        len: 0,
    },
    g_w: [0u8; P256_ELEM_LEN],
    loc_w: EdhocMessageBuffer {
        content: [0u8; MAX_MESSAGE_SIZE_LEN],
        len: 0,
    },
};
pub fn ead_initiator_get_global_state() -> &'static EADInitiatorState {
    unsafe { &EAD_INITIATOR_GLOBAL_STATE }
}
pub fn ead_initiator_get_global_state_own() -> EADInitiatorState {
    unsafe { EAD_INITIATOR_GLOBAL_STATE }
}
pub fn ead_initiator_set_global_state(new_state: EADInitiatorState) {
    unsafe {
        EAD_INITIATOR_GLOBAL_STATE = new_state;
    }
}

pub fn i_prepare_ead_1(x: &BytesP256ElemLen, ss: u8) -> Option<EADItem> {
    let state = ead_initiator_get_global_state();
    if state.protocol_state != EADInitiatorProtocolState::Start {
        return None;
    }

    let enc_id = build_enc_id(x, &state.id_u, &state.g_w, ss);
    let value = Some(encode_ead_1(&state.loc_w, &enc_id));

    let ead_1 = EADItem {
        label: EAD_ZEROCONF_LABEL,
        is_critical: true,
        value,
    };

    ead_initiator_set_global_state(EADInitiatorState {
        protocol_state: EADInitiatorProtocolState::WaitEAD2,
        ..ead_initiator_get_global_state_own()
    });

    Some(ead_1)
}

pub fn i_process_ead_2(_ead_2: EADItem) -> Result<(), ()> {
    // TODO: verify the label
    // TODO: verify the voucher

    ead_initiator_set_global_state(EADInitiatorState {
        protocol_state: EADInitiatorProtocolState::Completed,
        ..ead_initiator_get_global_state_own()
    });

    Ok(())
}

pub fn i_prepare_ead_3() -> Option<EADItem> {
    Some(EADItem::new())
}

fn build_enc_id(
    x: &BytesP256ElemLen, // ephemeral key of U
    id_u: &EdhocMessageBuffer,
    g_w: &BytesP256ElemLen,
    ss: u8,
) -> EdhocMessageBuffer {
    // PRK = EDHOC-Extract(salt, IKM)
    // NOTE: salt should be h'' (the zero-length byte string), but crypto backends are hardcoded to salts of size SHA256_DIGEST_LEN (32).
    //       using a larger but all-zeroes salt seems to generate the same result though.
    let salt: BytesHashLen = [0u8; SHA256_DIGEST_LEN];
    let g_xw = p256_ecdh(x, g_w);
    let prk = hkdf_extract(&salt, &g_xw);

    let (k_1, iv_1) = compute_k_1_iv_1(&prk);

    // plaintext = (ID_U: bstr)
    let mut plaintext = EdhocMessageBuffer::new();
    plaintext.content[0] = CBOR_MAJOR_BYTE_STRING + id_u.len as u8;
    plaintext.content[1..1 + id_u.len].copy_from_slice(&id_u.content[..id_u.len]);
    plaintext.len = 1 + id_u.len;

    // external_aad = (SS: int)
    let enc_structure = encode_enc_structure(ss);

    // ENC_ID = 'ciphertext' of COSE_Encrypt0
    aes_ccm_encrypt_tag_8(&k_1, &iv_1, &enc_structure[..], &plaintext)
}

fn compute_k_1_iv_1(prk: &BytesHashLen) -> (BytesCcmKeyLen, BytesCcmIvLen) {
    // K_1 = EDHOC-Expand(PRK, info = (0, h'', AES_CCM_KEY_LEN), length)
    let mut k_1: BytesCcmKeyLen = [0x00; AES_CCM_KEY_LEN];
    let k_1_buf = edhoc_kdf(prk, 0, &[0x00; MAX_KDF_CONTEXT_LEN], 0, AES_CCM_KEY_LEN);
    k_1[..].copy_from_slice(&k_1_buf[..AES_CCM_KEY_LEN]);

    // IV_1 = EDHOC-Expand(PRK, info = (1, h'', AES_CCM_KEY_LEN), length)
    let mut iv_1: BytesCcmIvLen = [0x00; AES_CCM_IV_LEN];
    // NOTE (FIXME?): here we actually generate AES_CCM_KEY_LEN bytes, but then we only use AES_CCM_IV_LEN of them (next line)
    let iv_1_buf = edhoc_kdf(prk, 1, &[0x00; MAX_KDF_CONTEXT_LEN], 0, AES_CCM_KEY_LEN);
    iv_1[..].copy_from_slice(&iv_1_buf[..AES_CCM_IV_LEN]);

    (k_1, iv_1)
}

const EAD_ENC_STRUCTURE_LEN: usize = 2 + 8 + 3;
fn encode_enc_structure(ss: u8) -> [u8; EAD_ENC_STRUCTURE_LEN] {
    let mut encrypt0: Bytes8 = [0x00; 8];
    encrypt0[0] = 0x45u8; // 'E'
    encrypt0[1] = 0x6eu8; // 'n'
    encrypt0[2] = 0x63u8; // 'c'
    encrypt0[3] = 0x72u8; // 'r'
    encrypt0[4] = 0x79u8; // 'y'
    encrypt0[5] = 0x70u8; // 'p'
    encrypt0[6] = 0x74u8; // 't'
    encrypt0[7] = 0x30u8; // '0'

    let mut enc_structure: [u8; EAD_ENC_STRUCTURE_LEN] = [0x00; EAD_ENC_STRUCTURE_LEN];

    // encode Enc_structure from rfc9052 Section 5.3
    enc_structure[0] = CBOR_MAJOR_ARRAY | 3 as u8; // 3 is the fixed number of elements in the array
    enc_structure[1] = CBOR_MAJOR_TEXT_STRING | encrypt0.len() as u8;
    enc_structure[2..2 + encrypt0.len()].copy_from_slice(&encrypt0[..]);
    enc_structure[encrypt0.len() + 2] = CBOR_MAJOR_BYTE_STRING | 0x00 as u8; // 0 for zero-length byte string (empty Header)
    enc_structure[encrypt0.len() + 3] = CBOR_MAJOR_BYTE_STRING | 0x01 as u8; // 1 for the `ss` value
    enc_structure[encrypt0.len() + 4] = ss;

    enc_structure
}

// NOTE: can we import this from the edhoc-rs main crate?
fn edhoc_kdf(
    prk: &BytesHashLen,
    label: u8,
    context: &BytesMaxContextBuffer,
    context_len: usize,
    length: usize,
) -> BytesMaxBuffer {
    let mut info: BytesMaxInfoBuffer = [0x00; MAX_INFO_LEN];

    // construct info with inline cbor encoding
    info[0] = label;
    let mut info_len = if context_len < 24 {
        info[1] = context_len as u8 | CBOR_MAJOR_BYTE_STRING;
        info[2..2 + context_len].copy_from_slice(&context[..context_len]);
        2 + context_len
    } else {
        info[1] = CBOR_BYTE_STRING;
        info[2] = context_len as u8;
        info[3..3 + context_len].copy_from_slice(&context[..context_len]);
        3 + context_len
    };

    info_len = if length < 24 {
        info[info_len] = length as u8;
        info_len + 1
    } else {
        info[info_len] = CBOR_UINT_1BYTE;
        info[info_len + 1] = length as u8;
        info_len + 2
    };

    let output = hkdf_expand(prk, &info, info_len, length);

    output
}

fn encode_ead_1(loc_w: &EdhocMessageBuffer, enc_id: &EdhocMessageBuffer) -> EdhocMessageBuffer {
    let mut output = EdhocMessageBuffer::new();

    output.content[0] = CBOR_BYTE_STRING;
    // put length at output.content[1] after other sizes are known

    output.content[2] = CBOR_TEXT_STRING;
    output.content[3] = loc_w.len as u8;
    output.content[4..4 + loc_w.len].copy_from_slice(&loc_w.content[..loc_w.len]);

    output.content[4 + loc_w.len] = CBOR_MAJOR_BYTE_STRING + enc_id.len as u8;
    output.content[5 + loc_w.len..5 + loc_w.len + enc_id.len]
        .copy_from_slice(&enc_id.content[..enc_id.len]);

    output.len = 5 + loc_w.len + enc_id.len;
    output.content[1] = (output.len - 2) as u8;

    output
}

#[cfg(test)]
mod test_initiator {
    use super::*;
    use edhoc_consts::*;
    use hexlit::hex;

    // U
    const X_TV: BytesP256ElemLen =
        hex!("A0C71BDBA570FFD270D90BDF416C142921F214406271FCF55B8567F079B50DA0");
    const ID_U_TV: &[u8] = &hex!("a104412b");

    // V
    // TODO...

    // W
    const G_W_TV: &[u8] = &hex!("FFA4F102134029B3B156890B88C9D9619501196574174DCB68A07DB0588E4D41");
    const LOC_W_TV: &[u8] = &hex!("636F61703A2F2F656E726F6C6C6D656E742E736572766572"); // coap://enrollment.server

    const ENC_ID_TV: &[u8] = &hex!("71fb72788b180ebe332697d711");
    const PRK_TV: &[u8] = &hex!("04da32d221db25db701667f9d3903374a45a9b04f25d1cb481b099a480cece04");
    const K_1_TV: &[u8] = &hex!("95a90f115d8fc5252849a25ba5225575");
    const IV_1_TV: &[u8] = &hex!("083cb9a00da66af4f56877fcda");

    const EAD1_VALUE_TV: &[u8] = &hex!(
        "58287818636f61703a2f2f656e726f6c6c6d656e742e7365727665724d71fb72788b180ebe332697d711"
    );

    const SS_TV: u8 = 2;

    #[test]
    fn test_compute_keys() {
        let k_1_tv: BytesCcmKeyLen = K_1_TV.try_into().unwrap();
        let iv_1_tv: BytesCcmIvLen = IV_1_TV.try_into().unwrap();
        let prk_tv: BytesHashLen = PRK_TV.try_into().unwrap();

        let prk = hkdf_extract(
            &[0u8; SHA256_DIGEST_LEN],
            &p256_ecdh(&X_TV.try_into().unwrap(), &G_W_TV.try_into().unwrap()),
        );
        assert_eq!(prk, prk_tv);

        let (k_1, iv_1) = compute_k_1_iv_1(&prk);
        assert_eq!(k_1, k_1_tv);
        assert_eq!(iv_1, iv_1_tv);
    }

    #[test]
    fn test_build_enc_id() {
        let enc_id_tv: EdhocMessageBuffer = ENC_ID_TV.try_into().unwrap();

        let enc_id = build_enc_id(
            &X_TV.try_into().unwrap(),
            &ID_U_TV.try_into().unwrap(),
            &G_W_TV.try_into().unwrap(),
            SS_TV,
        );
        assert_eq!(enc_id.content, enc_id_tv.content);
    }

    #[test]
    fn test_prepare_ead_1() {
        let ead_1_value_tv: EdhocMessageBuffer = EAD1_VALUE_TV.try_into().unwrap();

        ead_initiator_set_global_state(EADInitiatorState::new(
            ID_U_TV.try_into().unwrap(),
            G_W_TV.try_into().unwrap(),
            LOC_W_TV.try_into().unwrap(),
        ));

        let ead_1 = i_prepare_ead_1(&X_TV.try_into().unwrap(), SS_TV).unwrap();
        assert_eq!(
            ead_initiator_get_global_state().protocol_state,
            EADInitiatorProtocolState::WaitEAD2
        );
        assert_eq!(ead_1.label, EAD_ZEROCONF_LABEL);
        assert_eq!(ead_1.is_critical, true);
        assert_eq!(ead_1.value.unwrap().content, ead_1_value_tv.content);
    }
}

// responder side
#[derive(Default, PartialEq, Copy, Clone, Debug)]
pub enum EADResponderProtocolState {
    #[default]
    Start,
    ProcessedEAD1,
    WaitEAD3,
    Completed,
}

pub struct EADResponderState {
    pub protocol_state: EADResponderProtocolState,
}

impl EADResponderState {
    pub fn new() -> Self {
        EADResponderState {
            protocol_state: EADResponderProtocolState::Start,
        }
    }
}

// shared mutable global state for EAD
// NOTE: this is not thread-safe
static mut EAD_RESPONDER_GLOBAL_STATE: EADResponderState = EADResponderState {
    protocol_state: EADResponderProtocolState::Start,
};
pub fn ead_responder_get_global_state() -> &'static EADResponderState {
    unsafe { &EAD_RESPONDER_GLOBAL_STATE }
}
pub fn ead_responder_set_global_state(new_state: EADResponderState) {
    unsafe {
        EAD_RESPONDER_GLOBAL_STATE = new_state;
    }
}

pub fn r_process_ead_1(_ead_1: EADItem) -> Result<(), ()> {
    // TODO: parse and verify the label
    // TODO: trigger the voucher request to W

    ead_responder_set_global_state(EADResponderState {
        protocol_state: EADResponderProtocolState::ProcessedEAD1,
    });

    Ok(())
}

pub fn r_prepare_ead_2() -> Option<EADItem> {
    let mut ead_2 = EADItem::new();

    // add the label to the buffer (non-critical)
    ead_2.label = EAD_ZEROCONF_LABEL;
    ead_2.is_critical = true;

    // TODO: append Voucher (H(message_1), CRED_V) to the buffer

    // NOTE: see the note in lib.rs::test_ead
    // state.protocol_state = EADResponderProtocolState::WaitMessage3;
    ead_responder_set_global_state(EADResponderState {
        protocol_state: EADResponderProtocolState::Completed,
    });

    Some(ead_2)
}

pub fn r_process_ead_3(_ead_3: EADItem) -> Result<(), ()> {
    // TODO: maybe retrive CRED_U from a Credential Database

    // state.protocol_state = EADResponderProtocolState::Completed;

    Ok(())
}
