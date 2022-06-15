use hacspec_lib::*;
pub mod consts;

use consts::*;

pub fn encode_message_1(
    method: u8,
    suites: &[u8],
    g_x: [u8; P256_ELEM_LEN],
    c_i: i8,
    output: &mut [u8],
) -> usize {
    output[0] = method; // CBOR unsigned int less than 24 is encoded verbatim

    let index: usize;

    if suites.len() == 1 {
        output[1] = suites[0];
        index = 2;
    } else {
        output[1] = 0x80 | suites.len() as u8;
        output[2..(suites.len() + 2)].copy_from_slice(&suites[..(suites.len() + 2 - 2)]);
        index = suites.len() + 2;
    }
    output[index] = CBOR_BYTE_STRING; // CBOR byte string magic number
    output[index + 1] = P256_ELEM_LEN as u8; // length of the byte string
    for i in index + 2..index + 2 + P256_ELEM_LEN {
        // copy byte string
        output[i] = g_x[i - index - 2];
    }
    if c_i >= 0 {
        output[index + 2 + P256_ELEM_LEN] = c_i as u8; // CBOR uint less than 24 is encoded verbatim
    } else {
        output[index + 2 + P256_ELEM_LEN] = 0x20 | (-1 + -c_i) as u8;
    }
    (index + 3 + P256_ELEM_LEN) as usize
}
