const MESSAGE_1_LEN: usize = 37;
const MESSAGE_2_LEN: usize = 45;

const EPHEMERAL_KEY_LEN: usize = 32;

// ciphertext is message_len -1 for c_r, -2 for cbor magic numbers
const CIPHERTEXT_2_LEN: usize = MESSAGE_2_LEN - EPHEMERAL_KEY_LEN - 1 - 2;

pub fn encode_message_1 <'a> ( buf: &'a mut [u8; MESSAGE_1_LEN],
								method: u8,
								suites : u8,
								g_x : [u8; EPHEMERAL_KEY_LEN],
								c_i : u8 )
								-> usize {
	assert!(MESSAGE_1_LEN > 1 + 1 + EPHEMERAL_KEY_LEN + 1); // length check
	assert!(method < 24 && suites < 24 && c_i < 24); // CBOR encoding checks

	buf[0] = method; 	// CBOR unsigned int less than 24 is encoded verbatim
	buf[1] = suites; 	// CBOR unsigned int less than 24 is encoded verbatim
	buf[2] = 0x58;		// CBOR byte string magic number
	buf[3] = EPHEMERAL_KEY_LEN as u8; // length of the byte string
	for i in 0..EPHEMERAL_KEY_LEN { // copy byte string
		buf[4+i] = g_x[i];
	}
	buf[4+EPHEMERAL_KEY_LEN] = c_i;	// CBOR uint less than 24 is encoded verbatim
	MESSAGE_1_LEN
}

pub fn parse_message_2 <'a> ( rcvd_message_2: &'a [u8; MESSAGE_2_LEN],
							   g_y_buf: &'a mut [u8; EPHEMERAL_KEY_LEN],
							   ciphertext_2_buf: &'a mut [u8; CIPHERTEXT_2_LEN],
							   c_r: &'a mut u8 )
							   -> Result<u8, i8> {
		assert!(rcvd_message_2.len() == MESSAGE_2_LEN);

		*c_r = rcvd_message_2[MESSAGE_2_LEN-1];

		for i in 0 .. EPHEMERAL_KEY_LEN {
			g_y_buf[i] = rcvd_message_2[i+2];
		}

	for i in 0 .. CIPHERTEXT_2_LEN {
			ciphertext_2_buf[i] = rcvd_message_2[i + 2 + EPHEMERAL_KEY_LEN];
		}

		Ok(0)
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
	const CONNECTION_ID_TV: u8 = 12;
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

	const CIPHERTEXT_2_TV : [u8; CIPHERTEXT_2_LEN] =
						[ 0x0f, 0xf0, 0x4c, 0x29, 0x4f, 0x4a, 0xc6, 0x02,
						  0xcf, 0x78 ];

	const G_X_TV: [u8; EPHEMERAL_KEY_LEN] =
						[ 0x3a, 0xa9, 0xeb, 0x32, 0x01, 0xb3, 0x36, 0x7b,
						  0x8c, 0x8b, 0xe3, 0x8d, 0x91, 0xe5, 0x7a, 0x2b,
						  0x43, 0x3e, 0x67, 0x88, 0x8c, 0x86, 0xd2, 0xac,
						  0x00, 0x6a, 0x52, 0x08, 0x42, 0xed, 0x50, 0x37 ];

	const G_Y_TV : [u8; EPHEMERAL_KEY_LEN] =
						[ 0x25, 0x54, 0x91, 0xb0, 0x5a, 0x39, 0x89, 0xff,
						  0x2d, 0x3f, 0xfe, 0xa6, 0x20, 0x98, 0xaa, 0xb5,
						  0x7c, 0x16, 0x0f, 0x29, 0x4e, 0xd9, 0x48, 0x01,
						  0x8b, 0x41, 0x90, 0xf7, 0xd1, 0x61, 0x82, 0x4e ];

	#[test]
	fn test_encode_message_1() {
		let mut message_1_buf = [0xff as u8; MESSAGE_1_LEN];
		let _ret = encode_message_1(&mut message_1_buf,
									METHOD_TV,
									SUITES_TV,
									G_X_TV,
									CONNECTION_ID_TV);
		assert!(MESSAGE_1_TV == message_1_buf);
	}

	#[test]
	fn test_parse_message_2() {
		let mut g_y_buf = [0x00 as u8; EPHEMERAL_KEY_LEN];
		let mut ciphertext_2_buf = [0x00 as u8; CIPHERTEXT_2_LEN];
		let mut c_r = 0xff as u8;
		let _res = parse_message_2(&MESSAGE_2_TV, &mut g_y_buf, &mut ciphertext_2_buf, &mut c_r);

		assert!(G_Y_TV == g_y_buf);
		assert!(CIPHERTEXT_2_TV == ciphertext_2_buf);
	}

	#[test]
	fn test_decrypt_message_2() {

	}
}
