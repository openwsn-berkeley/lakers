#![no_std]

use edhoc_consts::*;
use edhoc_crypto::*;

// ---- initiator side (device)

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
    pub(crate) prk: BytesHashLen,
    pub(crate) voucher: BytesHashLen,
}

impl EADInitiatorState {
    pub fn new(id_u: EdhocMessageBuffer, g_w: BytesP256ElemLen, loc_w: EdhocMessageBuffer) -> Self {
        EADInitiatorState {
            protocol_state: EADInitiatorProtocolState::Start,
            id_u,
            g_w,
            loc_w,
            prk: [0u8; SHA256_DIGEST_LEN],
            voucher: [0u8; SHA256_DIGEST_LEN],
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
    prk: [0u8; SHA256_DIGEST_LEN],
    voucher: [0u8; SHA256_DIGEST_LEN],
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

    // PRK = EDHOC-Extract(salt, IKM)
    let prk = compute_prk(x, &state.g_w);

    let enc_id = build_enc_id(&prk, &state.id_u, ss);
    let value = Some(encode_ead_1(&state.loc_w, &enc_id));

    let ead_1 = EADItem {
        label: EAD_ZEROCONF_LABEL,
        is_critical: true,
        value,
    };

    ead_initiator_set_global_state(EADInitiatorState {
        protocol_state: EADInitiatorProtocolState::WaitEAD2,
        prk,
        ..ead_initiator_get_global_state_own()
    });

    Some(ead_1)
}

pub fn i_process_ead_2(
    ead_2: EADItem,
    cred_v: &EdhocMessageBuffer,
    h_message_1: &BytesHashLen,
) -> Result<(), ()> {
    let state = ead_initiator_get_global_state();

    let voucher = verify_voucher(&ead_2.value.unwrap(), h_message_1, cred_v, &state.prk)?;

    ead_initiator_set_global_state(EADInitiatorState {
        protocol_state: EADInitiatorProtocolState::Completed,
        voucher,
        ..ead_initiator_get_global_state_own()
    });

    Ok(())
}

pub fn i_prepare_ead_3() -> Option<EADItem> {
    Some(EADItem::new())
}

fn parse_ead_2_value(ead_2_value: &Option<EdhocMessageBuffer>) -> Result<BytesHashLen, ()> {
    let value = ead_2_value.unwrap();
    let voucher: BytesHashLen = value.content[2..2 + SHA256_DIGEST_LEN].try_into().unwrap();

    let enc_id: EdhocMessageBuffer = EdhocMessageBuffer::new();

    Ok(voucher)
}

fn verify_voucher(
    received_voucher: &EdhocMessageBuffer,
    h_message_1: &BytesHashLen,
    cred_v: &EdhocMessageBuffer,
    prk: &BytesHashLen,
) -> Result<BytesHashLen, ()> {
    let computed_voucher = prepare_voucher(h_message_1, cred_v, prk);
    if received_voucher.content == computed_voucher.content {
        let mut voucher_mac: BytesHashLen = Default::default();
        voucher_mac[..SHA256_DIGEST_LEN]
            .copy_from_slice(&computed_voucher.content[2..2 + SHA256_DIGEST_LEN]);
        return Ok(voucher_mac);
    } else {
        return Err(());
    }
}

fn build_enc_id(
    prk: &BytesHashLen, // ephemeral key of U
    id_u: &EdhocMessageBuffer,
    ss: u8,
) -> EdhocMessageBuffer {
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

fn compute_prk(a: &BytesP256ElemLen, g_b: &BytesP256ElemLen) -> BytesHashLen {
    // NOTE: salt should be h'' (the zero-length byte string), but crypto backends are hardcoded to salts of size SHA256_DIGEST_LEN (32).
    //       using a larger but all-zeroes salt seems to generate the same result though.
    let salt: BytesHashLen = [0u8; SHA256_DIGEST_LEN];
    let g_ab = p256_ecdh(a, g_b);
    hkdf_extract(&salt, &g_ab)
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

// ---- responder side (authenticator)

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

pub fn r_process_ead_1(ead_1: &EADItem, message_1: &BufferMessage1) -> Result<(), ()> {
    let opaque_state: Option<EdhocMessageBuffer> = None; // TODO: receive as parameter

    if ead_1.label != EAD_ZEROCONF_LABEL {
        return Err(());
    }
    let (_loc_w, _enc_id) = parse_ead_1_value(&ead_1.value)?;
    let voucher_request = encode_voucher_request(message_1, &opaque_state);

    // TODO: implement send_voucher_request(&loc_w, &voucher_request);

    ead_responder_set_global_state(EADResponderState {
        protocol_state: EADResponderProtocolState::ProcessedEAD1,
    });

    Ok(())
}

pub fn r_prepare_ead_2(voucher_response: &EdhocMessageBuffer) -> Option<EADItem> {
    let mut ead_2 = EADItem::new();

    // FIXME: we probably don't want to parse the voucher response here, but rather receive only the 'voucher' already parsed
    let (_message_1, voucher, _opaque_state) = parse_voucher_response(voucher_response).unwrap();

    ead_2.label = EAD_ZEROCONF_LABEL;
    ead_2.is_critical = true;
    ead_2.value = Some(voucher);

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

fn parse_voucher_response(
    voucher_response: &EdhocMessageBuffer,
) -> Result<
    (
        EdhocMessageBuffer,
        EdhocMessageBuffer,
        Option<EdhocMessageBuffer>,
    ),
    (),
> {
    let mut message_1 = EdhocMessageBuffer::new();
    let mut voucher = EdhocMessageBuffer::new();

    let array_size = voucher_response.content[0] - CBOR_MAJOR_ARRAY;

    if !(array_size == 2 || array_size == 3) || voucher_response.content[1] != CBOR_BYTE_STRING {
        return Err(());
    }

    message_1.len = voucher_response.content[2] as usize;
    message_1.content[..message_1.len]
        .copy_from_slice(&voucher_response.content[3..3 + message_1.len]);

    if voucher_response.content[3 + message_1.len] != CBOR_BYTE_STRING {
        return Err(());
    }
    voucher.len = voucher_response.content[4 + message_1.len] as usize;
    voucher.content[..voucher.len].copy_from_slice(
        &voucher_response.content[5 + message_1.len..5 + message_1.len + voucher.len],
    );

    if array_size == 3 {
        if voucher_response.content[5 + message_1.len + voucher.len] != CBOR_BYTE_STRING {
            return Err(());
        }
        let mut opaque_state = EdhocMessageBuffer::new();
        opaque_state.len = voucher_response.content[6 + message_1.len + voucher.len] as usize;
        opaque_state.content[..opaque_state.len].copy_from_slice(
            &voucher_response.content[7 + message_1.len + voucher.len
                ..7 + message_1.len + voucher.len + opaque_state.len],
        );
        return Ok((message_1, voucher, Some(opaque_state)));
    } else {
        return Ok((message_1, voucher, None));
    }
}

fn parse_ead_1_value(
    ead_1_value: &Option<EdhocMessageBuffer>,
) -> Result<(EdhocMessageBuffer, EdhocMessageBuffer), ()> {
    let value = ead_1_value.unwrap();
    let loc_w: EdhocMessageBuffer = value.content[4..4 + value.content[3] as usize]
        .try_into()
        .unwrap();

    let enc_id: EdhocMessageBuffer = EdhocMessageBuffer::new();

    Ok((loc_w, enc_id))
}

pub fn encode_voucher_request(
    message_1: &EdhocMessageBuffer,
    opaque_state: &Option<EdhocMessageBuffer>,
) -> EdhocMessageBuffer {
    let mut output = EdhocMessageBuffer::new();

    output.content[1] = CBOR_BYTE_STRING;
    output.content[2] = message_1.len as u8;
    output.content[3..3 + message_1.len].copy_from_slice(&message_1.content[..message_1.len]);

    if let Some(opaque_state) = opaque_state {
        output.content[0] = CBOR_MAJOR_ARRAY | 2;

        output.content[3 + message_1.len] = CBOR_BYTE_STRING;
        output.content[4 + message_1.len] = opaque_state.len as u8;
        output.content[5 + message_1.len..5 + message_1.len + opaque_state.len]
            .copy_from_slice(&opaque_state.content[..opaque_state.len]);

        output.len = 5 + message_1.len + opaque_state.len;
    } else {
        output.content[0] = CBOR_MAJOR_ARRAY | 1;
        output.len = 3 + message_1.len;
    }

    output
}

// ---- enrollment server side

fn handle_voucher_request(
    vreq: &EdhocMessageBuffer,
    cred_v: &EdhocMessageBuffer,
    w: &BytesP256ElemLen,   // TODO: have w be in the state of W
    g_x: &BytesP256ElemLen, // TODO: get g_x from message_1
) -> Result<EdhocMessageBuffer, ()> {
    let (message_1, opaque_state) = parse_voucher_request(vreq)?;

    // compute hash
    let mut message_1_buf: BytesMaxBuffer = [0x00; MAX_BUFFER_LEN];
    message_1_buf[..message_1.len].copy_from_slice(&message_1.content[..message_1.len]);
    let h_message_1 = sha256_digest(&message_1_buf, message_1.len);

    let prk = compute_prk(&w, &g_x);

    let voucher = prepare_voucher(&h_message_1, cred_v, &prk);
    let voucher_response = encode_voucher_response(&message_1, &voucher, &opaque_state);
    Ok(voucher_response)
}

fn prepare_voucher(
    h_message_1: &BytesHashLen,
    cred_v: &EdhocMessageBuffer,
    prk: &BytesP256ElemLen,
) -> EdhocMessageBuffer {
    let voucher_input = encode_voucher_input(&h_message_1, &cred_v);
    let voucher_mac = compute_voucher_mac(&prk, &voucher_input);
    encode_voucher(&voucher_mac)
}

fn parse_voucher_request(
    vreq: &EdhocMessageBuffer,
) -> Result<(EdhocMessageBuffer, Option<EdhocMessageBuffer>), ()> {
    let mut message_1: EdhocMessageBuffer = EdhocMessageBuffer::new();

    let array_size = vreq.content[0] - CBOR_MAJOR_ARRAY;

    if (array_size != 1 && array_size != 2) || vreq.content[1] != CBOR_BYTE_STRING {
        return Err(());
    }

    message_1.len = vreq.content[2] as usize;
    message_1.content[..message_1.len].copy_from_slice(&vreq.content[3..3 + message_1.len]);

    if array_size == 2 {
        if vreq.content[3 + message_1.len] != CBOR_BYTE_STRING {
            return Err(());
        }
        let mut opaque_state: EdhocMessageBuffer = EdhocMessageBuffer::new();
        opaque_state.len = vreq.content[4 + message_1.len] as usize;
        opaque_state.content[..opaque_state.len].copy_from_slice(
            &vreq.content[5 + message_1.len..5 + message_1.len + opaque_state.len],
        );

        Ok((message_1, Some(opaque_state)))
    } else {
        Ok((message_1, None))
    }
}

fn encode_voucher_input(
    h_message_1: &BytesHashLen,
    cred_v: &EdhocMessageBuffer,
) -> EdhocMessageBuffer {
    let mut voucher_input = EdhocMessageBuffer::new();

    voucher_input.content[0] = CBOR_BYTE_STRING;
    voucher_input.content[1] = SHA256_DIGEST_LEN as u8;
    voucher_input.content[2..2 + SHA256_DIGEST_LEN]
        .copy_from_slice(&h_message_1[..SHA256_DIGEST_LEN]);

    voucher_input.content[2 + SHA256_DIGEST_LEN] = CBOR_BYTE_STRING;
    voucher_input.content[3 + SHA256_DIGEST_LEN] = cred_v.len as u8;
    voucher_input.content[4 + SHA256_DIGEST_LEN..4 + SHA256_DIGEST_LEN + cred_v.len]
        .copy_from_slice(&cred_v.content[..cred_v.len]);

    voucher_input.len = 4 + SHA256_DIGEST_LEN + cred_v.len;

    voucher_input
}

fn compute_voucher_mac(prk: &BytesHashLen, voucher_input: &EdhocMessageBuffer) -> BytesHashLen {
    let mut voucher_mac: BytesHashLen = [0x00; SHA256_DIGEST_LEN];

    let mut context = [0x00; MAX_KDF_CONTEXT_LEN];
    context[..voucher_input.len].copy_from_slice(&voucher_input.content[..voucher_input.len]);

    let voucher_mac_buf = edhoc_kdf(prk, 2, &context, voucher_input.len, SHA256_DIGEST_LEN);
    voucher_mac[..SHA256_DIGEST_LEN].copy_from_slice(&voucher_mac_buf[..SHA256_DIGEST_LEN]);

    voucher_mac
}

fn encode_voucher(voucher_mac: &BytesHashLen) -> EdhocMessageBuffer {
    let mut voucher = EdhocMessageBuffer::new();
    voucher.content[0] = CBOR_BYTE_STRING;
    voucher.content[1] = SHA256_DIGEST_LEN as u8;
    voucher.content[2..2 + SHA256_DIGEST_LEN].copy_from_slice(&voucher_mac[..SHA256_DIGEST_LEN]);
    voucher.len = 2 + SHA256_DIGEST_LEN;

    voucher
}

fn encode_voucher_response(
    message_1: &EdhocMessageBuffer,
    voucher: &EdhocMessageBuffer,
    opaque_state: &Option<EdhocMessageBuffer>,
) -> EdhocMessageBuffer {
    let mut output = EdhocMessageBuffer::new();

    output.content[1] = CBOR_BYTE_STRING;
    output.content[2] = message_1.len as u8;
    output.content[3..3 + message_1.len].copy_from_slice(&message_1.content[..message_1.len]);

    output.content[3 + message_1.len] = CBOR_BYTE_STRING;
    output.content[4 + message_1.len] = voucher.len as u8;
    output.content[5 + message_1.len..5 + message_1.len + voucher.len]
        .copy_from_slice(&voucher.content[..voucher.len]);

    if let Some(opaque_state) = opaque_state {
        output.content[0] = CBOR_MAJOR_ARRAY | 3;

        output.content[5 + message_1.len + voucher.len] = CBOR_BYTE_STRING;
        output.content[6 + message_1.len + voucher.len] = opaque_state.len as u8;
        output.content
            [7 + message_1.len + voucher.len..7 + message_1.len + voucher.len + opaque_state.len]
            .copy_from_slice(&opaque_state.content[..opaque_state.len]);

        output.len = 7 + message_1.len + voucher.len + opaque_state.len;
    } else {
        output.content[0] = CBOR_MAJOR_ARRAY | 2;
        output.len = 5 + message_1.len + voucher.len;
    }

    output
}

#[cfg(test)]
mod test_vectors {
    use edhoc_consts::*;
    use hexlit::hex;

    // inputs
    // U
    pub const ID_U_TV: &[u8] = &hex!("a104412b");
    pub const X_TV: BytesP256ElemLen =
        hex!("368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525");
    pub const G_X_TV: &[u8] =
        &hex!("8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6");

    // V
    pub const CRED_V_TV: &[u8] = &hex!("a2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");

    // W
    pub const W_TV: &[u8] =
        &hex!("4E5E15AB35008C15B89E91F9F329164D4AACD53D9923672CE0019F9ACD98573F");
    pub const G_W_TV: &[u8] =
        &hex!("FFA4F102134029B3B156890B88C9D9619501196574174DCB68A07DB0588E4D41");
    pub const LOC_W_TV: &[u8] = &hex!("636F61703A2F2F656E726F6C6C6D656E742E736572766572"); // coap://enrollment.server

    // computed artifacts
    // EAD_1
    pub const SS_TV: u8 = 2;
    pub const ENC_ID_TV: &[u8] = &hex!("9a3155137f2be07ee91c51ec23");
    pub const PRK_TV: &[u8] =
        &hex!("d40f1601b577dbe7827bb3a20e0d16f7231c3a25225c1ed733f9094050d59666");
    pub const K_1_TV: &[u8] = &hex!("6f2a9112801a5011aa33576b5c7862ad");
    pub const IV_1_TV: &[u8] = &hex!("cd6676432b510ed2b7a7f7d5a7");
    pub const EAD1_VALUE_TV: &[u8] = &hex!(
        "58287818636f61703a2f2f656e726f6c6c6d656e742e7365727665724d9a3155137f2be07ee91c51ec23"
    );
    pub const MESSAGE_1_WITH_EAD_TV: &[u8] = &hex!("0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6370158287818636f61703a2f2f656e726f6c6c6d656e742e7365727665724d9a3155137f2be07ee91c51ec23");

    // VREQ
    pub const VOUCHER_REQUEST_TV: &[u8] = &hex!("8158520382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6370158287818636f61703a2f2f656e726f6c6c6d656e742e7365727665724d9a3155137f2be07ee91c51ec23");

    // VRES
    pub const VOUCHER_RESPONSE_TV: &[u8] = &hex!("8258520382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6370158287818636f61703a2f2f656e726f6c6c6d656e742e7365727665724d9a3155137f2be07ee91c51ec2358225820d99c86cf666f614d82cc3cfd0fb53cfa393f463f42ece49e38b056808ad5dfc9");
    pub const H_MESSAGE_1_TV: &[u8] =
        &hex!("c37b6590c1feefaf5a5b64f68db9bc5aa005283c53dfc5760d920399bbd8e6fb");
    pub const VOUCHER_INPUT_TV: &[u8] = &hex!("5820c37b6590c1feefaf5a5b64f68db9bc5aa005283c53dfc5760d920399bbd8e6fb585fa2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
    pub const VOUCHER_MAC_TV: &[u8] =
        &hex!("d99c86cf666f614d82cc3cfd0fb53cfa393f463f42ece49e38b056808ad5dfc9");
    pub const VOUCHER_TV: &[u8] =
        &hex!("5820d99c86cf666f614d82cc3cfd0fb53cfa393f463f42ece49e38b056808ad5dfc9");

    // EAD_2
    pub const EAD2_VALUE_TV: &[u8] =
        &hex!("5820d99c86cf666f614d82cc3cfd0fb53cfa393f463f42ece49e38b056808ad5dfc9");

    // ---- Traces for stateless operation (prefixed with SLO)
    // VREQ
    pub const OPAQUE_STATE_TV: &[u8] =
        &hex!("827819666538303a3a623833343a643630623a373936663a38646530198bed");
    pub const SLO_VOUCHER_REQUEST_TV: &[u8] = &hex!("8258520382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6370158287818636f61703a2f2f656e726f6c6c6d656e742e7365727665724d9a3155137f2be07ee91c51ec23581f827819666538303a3a623833343a643630623a373936663a38646530198bed");

    // VRES
    pub const SLO_VOUCHER_RESPONSE_TV: &[u8] = &hex!("8358520382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6370158287818636f61703a2f2f656e726f6c6c6d656e742e7365727665724d9a3155137f2be07ee91c51ec2358225820d99c86cf666f614d82cc3cfd0fb53cfa393f463f42ece49e38b056808ad5dfc9581f827819666538303a3a623833343a643630623a373936663a38646530198bed");
}

#[cfg(test)]
mod test_initiator {
    use super::*;
    use edhoc_consts::*;
    use test_vectors::*;

    #[test]
    fn test_compute_keys() {
        let k_1_tv: BytesCcmKeyLen = K_1_TV.try_into().unwrap();
        let iv_1_tv: BytesCcmIvLen = IV_1_TV.try_into().unwrap();
        let prk_tv: BytesHashLen = PRK_TV.try_into().unwrap();

        let prk_xw = compute_prk(&X_TV.try_into().unwrap(), &G_W_TV.try_into().unwrap());
        let prk_wx = compute_prk(&W_TV.try_into().unwrap(), &G_X_TV.try_into().unwrap());
        assert_eq!(prk_xw, prk_tv);
        assert_eq!(prk_xw, prk_wx);

        let (k_1, iv_1) = compute_k_1_iv_1(&prk_xw);
        assert_eq!(k_1, k_1_tv);
        assert_eq!(iv_1, iv_1_tv);
    }

    #[test]
    fn test_build_enc_id() {
        let enc_id_tv: EdhocMessageBuffer = ENC_ID_TV.try_into().unwrap();
        let prk_tv: BytesHashLen = PRK_TV.try_into().unwrap();

        let enc_id = build_enc_id(
            &PRK_TV.try_into().unwrap(),
            &ID_U_TV.try_into().unwrap(),
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

    // stateful operation tests

    // stateless operation tests
    #[test]
    fn test_verify_voucher() {
        let voucher_tv = VOUCHER_TV.try_into().unwrap();
        let h_message_1_tv = H_MESSAGE_1_TV.try_into().unwrap();
        let cred_v_tv = CRED_V_TV.try_into().unwrap();
        let prk_tv = PRK_TV.try_into().unwrap();
        let voucher_mac_tv: BytesHashLen = VOUCHER_MAC_TV.try_into().unwrap();

        let res = verify_voucher(&voucher_tv, &h_message_1_tv, &cred_v_tv, &prk_tv);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), voucher_mac_tv);
    }

    #[test]
    fn test_process_ead_2() {
        let ead_2_value_tv: EdhocMessageBuffer = EAD2_VALUE_TV.try_into().unwrap();
        let cred_v_tv = CRED_V_TV.try_into().unwrap();
        let h_message_1_tv = H_MESSAGE_1_TV.try_into().unwrap();

        let ead_2_tv = EADItem {
            label: EAD_ZEROCONF_LABEL,
            is_critical: true,
            value: Some(ead_2_value_tv),
        };

        let mut state = EADInitiatorState::new(
            ID_U_TV.try_into().unwrap(),
            G_W_TV.try_into().unwrap(),
            LOC_W_TV.try_into().unwrap(),
        );
        state.prk = PRK_TV.try_into().unwrap();
        ead_initiator_set_global_state(state);

        let res = i_process_ead_2(ead_2_tv, &cred_v_tv, &h_message_1_tv);
        assert!(res.is_ok());
        assert_eq!(
            ead_initiator_get_global_state().protocol_state,
            EADInitiatorProtocolState::Completed
        );
    }
}

#[cfg(test)]
mod test_responder {
    use super::*;
    use edhoc_consts::*;
    use test_vectors::*;

    #[test]
    fn test_parse_ead_1_value() {
        let ead_1_value_tv: EdhocMessageBuffer = EAD1_VALUE_TV.try_into().unwrap();
        let loc_w_tv: EdhocMessageBuffer = LOC_W_TV.try_into().unwrap();

        let res = parse_ead_1_value(&Some(ead_1_value_tv));
        assert!(res.is_ok());
        let (loc_w, enc_id) = res.unwrap();
        assert_eq!(loc_w.content, loc_w_tv.content);
    }

    #[test]
    fn test_encode_voucher_request() {
        let message_1_tv: EdhocMessageBuffer = MESSAGE_1_WITH_EAD_TV.try_into().unwrap();
        let voucher_request_tv: EdhocMessageBuffer = VOUCHER_REQUEST_TV.try_into().unwrap();

        let voucher_request = encode_voucher_request(&message_1_tv, &None);
        assert_eq!(voucher_request.content, voucher_request_tv.content);
    }

    #[test]
    fn test_process_ead_1() {
        let ead_1_value_tv: EdhocMessageBuffer = EAD1_VALUE_TV.try_into().unwrap();
        let message_1_tv: EdhocMessageBuffer = MESSAGE_1_WITH_EAD_TV.try_into().unwrap();

        let ead_1 = EADItem {
            label: EAD_ZEROCONF_LABEL,
            is_critical: true,
            value: Some(ead_1_value_tv),
        };

        ead_responder_set_global_state(EADResponderState::new());

        let res = r_process_ead_1(&ead_1, &message_1_tv);
        assert!(res.is_ok());
        assert_eq!(
            ead_responder_get_global_state().protocol_state,
            EADResponderProtocolState::ProcessedEAD1
        );
    }

    #[test]
    fn test_parse_voucher_response() {
        let voucher_response_tv: EdhocMessageBuffer = VOUCHER_RESPONSE_TV.try_into().unwrap();
        let message_1_tv: EdhocMessageBuffer = MESSAGE_1_WITH_EAD_TV.try_into().unwrap();
        let voucher_tv: EdhocMessageBuffer = VOUCHER_TV.try_into().unwrap();

        let res = parse_voucher_response(&voucher_response_tv);
        assert!(res.is_ok());
        let (message_1, voucher, opaque_state) = res.unwrap();
        assert_eq!(message_1.content, message_1_tv.content);
        assert_eq!(voucher.content, voucher_tv.content);
        assert!(opaque_state.is_none());
    }

    #[test]
    fn test_r_prepare_ead_2() {
        let voucher_response_tv: EdhocMessageBuffer = VOUCHER_RESPONSE_TV.try_into().unwrap();
        let ead_2_value_tv: EdhocMessageBuffer = EAD2_VALUE_TV.try_into().unwrap();

        ead_responder_set_global_state(EADResponderState::new());

        let ead_2 = r_prepare_ead_2(&voucher_response_tv).unwrap();
        assert_eq!(
            ead_responder_get_global_state().protocol_state,
            EADResponderProtocolState::Completed
        );
        assert_eq!(ead_2.label, EAD_ZEROCONF_LABEL);
        assert_eq!(ead_2.is_critical, true);
        assert_eq!(ead_2.value.unwrap().content, ead_2_value_tv.content);
    }

    // tests for the statelss operation mode
    #[test]
    fn slo_test_encode_voucher_request() {
        let message_1_tv: EdhocMessageBuffer = MESSAGE_1_WITH_EAD_TV.try_into().unwrap();
        let opaque_state_tv: EdhocMessageBuffer = OPAQUE_STATE_TV.try_into().unwrap();
        let voucher_request_tv: EdhocMessageBuffer = SLO_VOUCHER_REQUEST_TV.try_into().unwrap();

        let voucher_request = encode_voucher_request(&message_1_tv, &Some(opaque_state_tv));
        assert_eq!(voucher_request.content, voucher_request_tv.content);
    }

    #[test]
    fn slo_test_parse_voucher_response() {
        let voucher_response_tv: EdhocMessageBuffer = SLO_VOUCHER_RESPONSE_TV.try_into().unwrap();
        let message_1_tv: EdhocMessageBuffer = MESSAGE_1_WITH_EAD_TV.try_into().unwrap();
        let voucher_tv: EdhocMessageBuffer = VOUCHER_TV.try_into().unwrap();
        let opaque_state_tv: EdhocMessageBuffer = OPAQUE_STATE_TV.try_into().unwrap();

        let res = parse_voucher_response(&voucher_response_tv);
        assert!(res.is_ok());
        let (message_1, voucher, opaque_state) = res.unwrap();
        assert_eq!(message_1.content, message_1_tv.content);
        assert_eq!(voucher.content, voucher_tv.content);
        assert_eq!(opaque_state.unwrap().content, opaque_state_tv.content);
    }
}

#[cfg(test)]
mod test_enrollment_server {
    use super::*;
    use edhoc_consts::*;
    use test_vectors::*;

    #[test]
    fn test_encode_voucher_input() {
        let h_message_1_tv: BytesHashLen = H_MESSAGE_1_TV.try_into().unwrap();
        let cred_v_tv: EdhocMessageBuffer = CRED_V_TV.try_into().unwrap();
        let voucher_input_tv: EdhocMessageBuffer = VOUCHER_INPUT_TV.try_into().unwrap();

        let voucher_input = encode_voucher_input(&h_message_1_tv, &cred_v_tv);
        assert_eq!(voucher_input.content, voucher_input_tv.content);
    }

    #[test]
    fn test_compute_voucher_mac() {
        let prk_tv: BytesHashLen = PRK_TV.try_into().unwrap();
        let voucher_input_tv: EdhocMessageBuffer = VOUCHER_INPUT_TV.try_into().unwrap();
        let voucher_mac_tv: BytesHashLen = VOUCHER_MAC_TV.try_into().unwrap();

        let voucher_mac = compute_voucher_mac(&prk_tv, &voucher_input_tv);
        assert_eq!(voucher_mac, voucher_mac_tv);
    }

    #[test]
    fn test_encode_voucher() {
        let h_message_1: BytesHashLen = H_MESSAGE_1_TV.try_into().unwrap();
        let cred_v: EdhocMessageBuffer = CRED_V_TV.try_into().unwrap();
        let prk: BytesHashLen = PRK_TV.try_into().unwrap();
        let voucher_tv: EdhocMessageBuffer = VOUCHER_TV.try_into().unwrap();

        let voucher = prepare_voucher(&h_message_1, &cred_v, &prk);
        assert_eq!(voucher.content, voucher_tv.content);
    }

    #[test]
    fn test_encode_voucher_response() {
        let message_1_tv: EdhocMessageBuffer = MESSAGE_1_WITH_EAD_TV.try_into().unwrap();
        let voucher_tv: EdhocMessageBuffer = VOUCHER_TV.try_into().unwrap();
        let opaque_state_tv: EdhocMessageBuffer = OPAQUE_STATE_TV.try_into().unwrap();
        let voucher_response_tv: EdhocMessageBuffer = SLO_VOUCHER_RESPONSE_TV.try_into().unwrap();

        let voucher_response =
            encode_voucher_response(&message_1_tv, &voucher_tv, &Some(opaque_state_tv));
        assert_eq!(voucher_response.content, voucher_response_tv.content);
    }

    #[test]
    fn test_parse_voucher_request() {
        let voucher_request_tv: EdhocMessageBuffer = VOUCHER_REQUEST_TV.try_into().unwrap();
        let message_1_tv: EdhocMessageBuffer = MESSAGE_1_WITH_EAD_TV.try_into().unwrap();

        let voucher_request = parse_voucher_request(&voucher_request_tv);
        assert!(voucher_request.is_ok());
        let (message_1, opaque_state) = voucher_request.unwrap();
        assert_eq!(message_1.content, message_1_tv.content);
        assert!(opaque_state.is_none());
    }

    #[test]
    fn test_handle_voucher_request() {
        let voucher_request_tv: EdhocMessageBuffer = VOUCHER_REQUEST_TV.try_into().unwrap();
        let cred_v_tv: EdhocMessageBuffer = CRED_V_TV.try_into().unwrap();
        let w_tv: BytesP256ElemLen = W_TV.try_into().unwrap();
        let g_x_tv: BytesP256ElemLen = G_X_TV.try_into().unwrap();
        let voucher_response_tv: EdhocMessageBuffer = VOUCHER_RESPONSE_TV.try_into().unwrap();

        let res = handle_voucher_request(&voucher_request_tv, &cred_v_tv, &w_tv, &g_x_tv);
        assert!(res.is_ok());
        let voucher_response = res.unwrap();
        assert_eq!(voucher_response.content, voucher_response_tv.content);
    }

    // tests for the statelss operation mode
    #[test]
    fn slo_test_parse_voucher_request() {
        let voucher_request_tv: EdhocMessageBuffer = SLO_VOUCHER_REQUEST_TV.try_into().unwrap();
        let message_1_tv: EdhocMessageBuffer = MESSAGE_1_WITH_EAD_TV.try_into().unwrap();
        let opaque_state_tv: EdhocMessageBuffer = OPAQUE_STATE_TV.try_into().unwrap();

        let voucher_request = parse_voucher_request(&voucher_request_tv);
        assert!(voucher_request.is_ok());
        let (message_1, opaque_state) = voucher_request.unwrap();
        assert_eq!(message_1.content, message_1_tv.content);
        assert_eq!(opaque_state.unwrap().content, opaque_state_tv.content);
    }

    #[test]
    fn slo_test_handle_voucher_request() {
        let voucher_request_tv: EdhocMessageBuffer = SLO_VOUCHER_REQUEST_TV.try_into().unwrap();
        let cred_v_tv: EdhocMessageBuffer = CRED_V_TV.try_into().unwrap();
        let w_tv: BytesP256ElemLen = W_TV.try_into().unwrap();
        let g_x_tv: BytesP256ElemLen = G_X_TV.try_into().unwrap();
        let voucher_response_tv: EdhocMessageBuffer = SLO_VOUCHER_RESPONSE_TV.try_into().unwrap();

        let res = handle_voucher_request(&voucher_request_tv, &cred_v_tv, &w_tv, &g_x_tv);
        assert!(res.is_ok());
        let voucher_response = res.unwrap();
        assert_eq!(voucher_response.content, voucher_response_tv.content);
    }
}
