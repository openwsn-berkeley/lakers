const MESSAGE_1_LEN: usize = 37;
const MESSAGE_2_LEN: usize = 45;

const PRIVATE_KEY_LEN: usize = 32;
const PUBLIC_KEY_LEN: usize = PRIVATE_KEY_LEN;

// ciphertext is message_len -1 for c_r, -2 for cbor magic numbers
const CIPHERTEXT_2_LEN: usize = MESSAGE_2_LEN - PUBLIC_KEY_LEN - 1 - 2;
const PLAINTEXT_2_LEN: usize = CIPHERTEXT_2_LEN;

// maximum supported length of connection identifier for R
const MAX_C_R_LEN: usize = 0;

pub fn encode_message_1 <'a> ( method: u8,
								suites : u8,
								g_x : [u8; PUBLIC_KEY_LEN],
								c_i : u8,
								buf: &'a mut [u8; MESSAGE_1_LEN]) {
	assert!(MESSAGE_1_LEN > 1 + 1 + PUBLIC_KEY_LEN + 1); // length check
	assert!(method < 24 && suites < 24 && c_i < 24); // CBOR encoding checks

	buf[0] = method; 	// CBOR unsigned int less than 24 is encoded verbatim
	buf[1] = suites; 	// CBOR unsigned int less than 24 is encoded verbatim
	buf[2] = 0x58;		// CBOR byte string magic number
	buf[3] = PUBLIC_KEY_LEN as u8; // length of the byte string
	for i in 0..PUBLIC_KEY_LEN { // copy byte string
		buf[4+i] = g_x[i];
	}
	buf[4+PUBLIC_KEY_LEN] = c_i;	// CBOR uint less than 24 is encoded verbatim
}

pub fn parse_message_2 <'a> ( rcvd_message_2: &'a [u8; MESSAGE_2_LEN],
							   g_y_buf: &'a mut [u8; PUBLIC_KEY_LEN],
							   ciphertext_2_buf: &'a mut [u8; CIPHERTEXT_2_LEN],
							   c_r: &'a mut u8 ) {
		assert!(rcvd_message_2.len() == MESSAGE_2_LEN);

		*c_r = rcvd_message_2[MESSAGE_2_LEN-1];

		for i in 0 .. PUBLIC_KEY_LEN {
			g_y_buf[i] = rcvd_message_2[i+2];
		}

	for i in 0 .. CIPHERTEXT_2_LEN {
			ciphertext_2_buf[i] = rcvd_message_2[i + 2 + PUBLIC_KEY_LEN];
		}
}

pub fn decrypt_ciphertext_2 <'a> (x: [u8; PRIVATE_KEY_LEN],
									g_x: [u8; PUBLIC_KEY_LEN],
									g_y: [u8; PUBLIC_KEY_LEN],
									g_r: [u8; PUBLIC_KEY_LEN],
									c_r: [u8; MAX_C_R_LEN],
									plaintext_2: &'a mut [u8; PLAINTEXT_2_LEN]){

}

fn main() {
	println!{"Hello, world!"};
}

#[cfg(test)]
mod tests {
	use super::*;

	// test vectors (TV)
	const METHOD_TV: u8 = 3;
	const SUITES_TV: u8 = 0;
	const C_I_TV: u8 = 12;
	const C_R_TV: [u8; 0] = [];
	const MESSAGE_1_TV : [u8; MESSAGE_1_LEN] =
						[ 0x03, 0x00, 0x58, 0x20, 0x3a, 0xa9, 0xeb, 0x32,
						  0x01, 0xb3, 0x36, 0x7b, 0x8c, 0x8b, 0xe3, 0x8d,
						  0x91, 0xe5, 0x7a, 0x2b, 0x43, 0x3e, 0x67, 0x88,
						  0x8c, 0x86, 0xd2, 0xac, 0x00, 0x6a, 0x52, 0x08,
						  0x42, 0xed, 0x50, 0x37, 0x0c ];

	const MESSAGE_2_TV :[u8; MESSAGE_2_LEN] =
						[ 0x58, 0x2a, 0x25, 0x54, 0x91, 0xb0, 0x5a, 0x39,
						  0x89, 0xff, 0x2d, 0x3f, 0xfe, 0xa6, 0x20, 0x98,
						  0xaa, 0xb5, 0x7c, 0x16, 0x0f, 0x29, 0x4e, 0xd9,
						  0x48, 0x01, 0x8b, 0x41, 0x90, 0xf7, 0xd1, 0x61,
						  0x82, 0x4e, 0x0f, 0xf0, 0x4c, 0x29, 0x4f, 0x4a,
						  0xc6, 0x02, 0xcf, 0x78, 0x40 ];

	const PLAINTEXT_2_TV : [u8; PLAINTEXT_2_LEN] =
						[ 0x05, 0x48, 0x8e, 0x27, 0xcb, 0xd4, 0x94, 0xf7,
						  0x52, 0x83 ];

	const CIPHERTEXT_2_TV : [u8; CIPHERTEXT_2_LEN] =
						[ 0x0f, 0xf0, 0x4c, 0x29, 0x4f, 0x4a, 0xc6, 0x02,
						  0xcf, 0x78 ];

	const X_TV: [u8; PRIVATE_KEY_LEN] =
						[ 0xb3, 0x11, 0x19, 0x98, 0xcb, 0x3f, 0x66, 0x86,
						  0x63, 0xed, 0x42, 0x51, 0xc7, 0x8b, 0xe6, 0xe9,
						  0x5a, 0x4d, 0xa1, 0x27, 0xe4, 0xf6, 0xfe, 0xe2,
						  0x75, 0xe8, 0x55, 0xd8, 0xd9, 0xdf, 0xd8, 0xed ];

	const G_X_TV: [u8; PUBLIC_KEY_LEN] =
						[ 0x3a, 0xa9, 0xeb, 0x32, 0x01, 0xb3, 0x36, 0x7b,
						  0x8c, 0x8b, 0xe3, 0x8d, 0x91, 0xe5, 0x7a, 0x2b,
						  0x43, 0x3e, 0x67, 0x88, 0x8c, 0x86, 0xd2, 0xac,
						  0x00, 0x6a, 0x52, 0x08, 0x42, 0xed, 0x50, 0x37 ];

	const G_Y_TV : [u8; PUBLIC_KEY_LEN] =
						[ 0x25, 0x54, 0x91, 0xb0, 0x5a, 0x39, 0x89, 0xff,
						  0x2d, 0x3f, 0xfe, 0xa6, 0x20, 0x98, 0xaa, 0xb5,
						  0x7c, 0x16, 0x0f, 0x29, 0x4e, 0xd9, 0x48, 0x01,
						  0x8b, 0x41, 0x90, 0xf7, 0xd1, 0x61, 0x82, 0x4e ];

	const G_R_TV : [u8; PUBLIC_KEY_LEN] =
						[ 0xe6, 0x6f, 0x35, 0x59, 0x90, 0x22, 0x3c, 0x3f,
						  0x6c, 0xaf, 0xf8, 0x62, 0xe4, 0x07, 0xed, 0xd1,
						  0x17, 0x4d, 0x07, 0x01, 0xa0, 0x9e, 0xcd, 0x6a,
						  0x15, 0xce, 0xe2, 0xc6, 0xce, 0x21, 0xaa, 0x50 ];

	#[test]
	fn test_encode_message_1() {
		let mut message_1_buf = [0xff as u8; MESSAGE_1_LEN];
		encode_message_1(METHOD_TV,
							SUITES_TV,
							G_X_TV,
							C_I_TV,
							&mut message_1_buf);
		assert!(MESSAGE_1_TV == message_1_buf);
	}

	#[test]
	fn test_parse_message_2() {
		let mut g_y_buf = [0x00 as u8; PUBLIC_KEY_LEN];
		let mut ciphertext_2_buf = [0x00 as u8; CIPHERTEXT_2_LEN];
		let mut c_r = 0xff as u8;
		parse_message_2(&MESSAGE_2_TV,
						&mut g_y_buf,
						&mut ciphertext_2_buf,
						&mut c_r);

		assert!(G_Y_TV == g_y_buf);
		assert!(CIPHERTEXT_2_TV == ciphertext_2_buf);
	}

	#[test]
	fn test_decrypt_ciphertext_2() {

	let mut plaintext_2_buf = [0x00 as u8; PLAINTEXT_2_LEN];
	decrypt_ciphertext_2(X_TV,
							G_X_TV,
							G_Y_TV,
							G_R_TV,
							C_R_TV,
							&mut plaintext_2_buf);

	assert!(PLAINTEXT_2_TV == plaintext_2_buf);

	}
}

