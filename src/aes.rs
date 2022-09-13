// Pure Rust port of https://github.com/kokke/tiny-AES-c

pub trait AesContext {
    fn pgp_aes_encrypt(&self, inp: &[u8; 16], out: &mut [u8; 16]);

    fn aes_set_key(&mut self, key: &[u8; 16]);
}

pub struct DefaultAesContext {
    pub round_key: [u8; 176],
}

impl DefaultAesContext {
    pub fn new() -> Self {
        Self {
            round_key: [0; 176],
        }
    }
}

impl AesContext for DefaultAesContext {
    fn pgp_aes_encrypt(&self, inp: &[u8; 16], out: &mut [u8; 16]) {
        out.copy_from_slice(inp);
        aes_ecb_encrypt(&self.round_key, out)
    }

    fn aes_set_key(&mut self, key: &[u8; 16]) {
        key_expansion(&mut self.round_key, key);
    }
}

const COLUMN_COUNT: usize = 4;
const WORD_COUNT: usize = 4;
const ROUND_COUNT: usize = 10;

const SBOX: [u8; 256] = [
    // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

// The round constant word array, Rcon[i], contains the values given by
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
const RCON: [u8; 11] = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

fn aes_ecb_encrypt(round_key: &[u8; 176], inout: &mut [u8; 16]) {
    // Add the First round key to the state before starting the rounds.
    add_round_key(0, inout, round_key);

    // There will be ROUND_COUNT rounds.
    // The first ROUND_COUNT-1 rounds are identical.
    // These ROUND_COUNT-1 rounds are executed in the loop below.
    for round in 1..ROUND_COUNT {
        substitute_bytes(inout);
        shift_rows(inout);
        mix_columns(inout);
        add_round_key(round, inout, round_key)
    }

    // The last round is given below.
    // The MixColumns function is not here in the last round.
    substitute_bytes(inout);
    shift_rows(inout);
    add_round_key(ROUND_COUNT, inout, round_key);
}

// This function produces ColumnCount(RoundCount+1) round keys. The round keys are used in each round to decrypt the states.
fn key_expansion(round_key: &mut [u8; 176], key: &[u8; 16]) {
    let mut j;
    let mut k;
    let mut m;
    let temp: &mut [u8; 4] = &mut [0; 4]; // Used for the column/row operations

    // The first round key is the key itself.
    for i in 0..WORD_COUNT {
        round_key[(i * 4) + 0] = key[(i * 4) + 0];
        round_key[(i * 4) + 1] = key[(i * 4) + 1];
        round_key[(i * 4) + 2] = key[(i * 4) + 2];
        round_key[(i * 4) + 3] = key[(i * 4) + 3];
    }

    // All other round keys are found from the previous round keys.
    for i in WORD_COUNT..(COLUMN_COUNT * (ROUND_COUNT + 1)) {
        {
            k = (i - 1) * 4;
            temp[0] = round_key[k + 0];
            temp[1] = round_key[k + 1];
            temp[2] = round_key[k + 2];
            temp[3] = round_key[k + 3];
        }

        if i % WORD_COUNT == 0 {
            // This function shifts the 4 bytes in a word to the left once.
            // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

            // RotWord()
            {
                m = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = m;
            }

            // SubWord() is a function that takes a four-byte input word and
            // applies the S-box to each of the four bytes to produce an output word.

            // SubWord()
            {
                temp[0] = SBOX[temp[0] as usize];
                temp[1] = SBOX[temp[1] as usize];
                temp[2] = SBOX[temp[2] as usize];
                temp[3] = SBOX[temp[3] as usize];
            }

            temp[0] = temp[0] ^ RCON[i / WORD_COUNT];
        }

        j = i * 4;
        k = (i - WORD_COUNT) * 4;
        round_key[j + 0] = round_key[k + 0] ^ temp[0];
        round_key[j + 1] = round_key[k + 1] ^ temp[1];
        round_key[j + 2] = round_key[k + 2] ^ temp[2];
        round_key[j + 3] = round_key[k + 3] ^ temp[3];
    }
}

fn add_round_key(round: usize, state: &mut [u8; 16], round_key: &[u8; 176]) {
    for i in 0..4 {
        for j in 0..4 {
            state[(4 * i) + j] ^= round_key[(round * COLUMN_COUNT * 4) + (i * COLUMN_COUNT) + j];
        }
    }
}

// MixColumns function mixes the columns of the state matrix
fn mix_columns(state: &mut [u8; 16]) {
    let mut time;
    let mut temp;
    for i in 0..4 {
        let j = 4 * i;
        let t = state[j + 0];
        temp = state[j + 0] ^ state[j + 1] ^ state[j + 2] ^ state[j + 3];
        time = state[j + 0] ^ state[j + 1];
        time = xtime(time);
        state[j + 0] ^= time ^ temp;
        time = state[j + 1] ^ state[j + 2];
        time = xtime(time);
        state[j + 1] ^= time ^ temp;
        time = state[j + 2] ^ state[j + 3];
        time = xtime(time);
        state[j + 2] ^= time ^ temp;
        time = state[j + 3] ^ t;
        time = xtime(time);
        state[j + 3] ^= time ^ temp;
    }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
fn shift_rows(state: &mut [u8; 16]) {
    // Rotate first row 1 columns to left
    let temp = state[(4 * 0) + 1];
    state[(4 * 0) + 1] = state[(4 * 1) + 1];
    state[(4 * 1) + 1] = state[(4 * 2) + 1];
    state[(4 * 2) + 1] = state[(4 * 3) + 1];
    state[(4 * 3) + 1] = temp;

    // Rotate second row 2 columns to left
    let temp = state[(4 * 0) + 2];
    state[(4 * 0) + 2] = state[(4 * 2) + 2];
    state[(4 * 2) + 2] = temp;

    let temp = state[(4 * 1) + 2];
    state[(4 * 1) + 2] = state[(4 * 3) + 2];
    state[(4 * 3) + 2] = temp;

    // Rotate third row 3 columns to left
    let temp = state[(4 * 0) + 3];
    state[(4 * 0) + 3] = state[(4 * 3) + 3];
    state[(4 * 3) + 3] = state[(4 * 2) + 3];
    state[(4 * 2) + 3] = state[(4 * 1) + 3];
    state[(4 * 1) + 3] = temp;
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
fn substitute_bytes(state: &mut [u8; 16]) {
    for i in 0..4 {
        for j in 0..4 {
            state[(4 * j) + i] = SBOX[state[(4 * j) + i] as usize];
        }
    }
}

fn xtime(x: u8) -> u8 {
    (x << 1) ^ (((x >> 7) & 1) * 0x1b)
}

// Tests from National Institute of Standards and Technology Special Publication 800-38A 2001 ED
// F.1. ECB Example Vectors
#[test]
pub fn test_ecb_encrypt_1() {
    let plaintext: [u8; 16] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a,
    ];
    let expected: [u8; 16] = [
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef,
        0x97,
    ];
    let key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];

    let mut round_key = [0; 176];
    let mut actual: [u8; 16] = [0; 16];
    actual.copy_from_slice(&plaintext);

    key_expansion(&mut round_key, &key);
    aes_ecb_encrypt(&round_key, &mut actual);
    assert_eq!(expected, actual);
}

#[test]
pub fn test_ecb_encrypt_2() {
    let plaintext: [u8; 16] = [
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e,
        0x51,
    ];
    let expected: [u8; 16] = [
        0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba,
        0xaf,
    ];
    let key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];

    let mut round_key = [0; 176];
    let mut actual: [u8; 16] = [0; 16];
    actual.copy_from_slice(&plaintext);

    key_expansion(&mut round_key, &key);
    aes_ecb_encrypt(&round_key, &mut actual);
    assert_eq!(expected, actual);
}

#[test]
pub fn test_ecb_encrypt_3() {
    let plaintext: [u8; 16] = [
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52,
        0xef,
    ];
    let expected: [u8; 16] = [
        0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06,
        0x88,
    ];
    let key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];

    let mut round_key = [0; 176];
    let mut actual: [u8; 16] = [0; 16];
    actual.copy_from_slice(&plaintext);

    key_expansion(&mut round_key, &key);
    aes_ecb_encrypt(&round_key, &mut actual);
    assert_eq!(expected, actual);
}

#[test]
pub fn test_ecb_encrypt_4() {
    let plaintext: [u8; 16] = [
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37,
        0x10,
    ];
    let expected: [u8; 16] = [
        0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d,
        0xd4,
    ];
    let key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];

    let mut round_key = [0; 176];
    let mut actual: [u8; 16] = [0; 16];
    actual.copy_from_slice(&plaintext);

    key_expansion(&mut round_key, &key);
    aes_ecb_encrypt(&round_key, &mut actual);
    assert_eq!(expected, actual);
}
