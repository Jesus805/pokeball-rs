pub(crate) mod cert;

use cert::generate_nonce;

#[cfg(feature = "default_aes")]
use cert::{
    decrypt_next_default as decrypt_next, generate_chal_0_default as generate_chal_0,
    generate_next_chal_default as generate_next_chal,
    generate_reconnect_response_default as generate_reconnect_response,
};

#[cfg(not(feature = "default_aes"))]
use cert::{decrypt_next, generate_chal_0, generate_next_chal, generate_reconnect_response};

#[repr(C, packed)]
pub struct ChallengeData {
    pub state: [u8; 4],
    pub nonce: [u8; 16],
    pub encrypted_main_challenge: [u8; 80],
    pub encrypted_hash: [u8; 16],
    pub bt_addr: [u8; 6],
    pub blob: [u8; 256],
}

#[repr(C, packed)]
pub(crate) struct MainChallengeData {
    pub bt_addr: [u8; 6],
    pub key: [u8; 16],
    pub nonce: [u8; 16],
    pub encrypted_challenge: [u8; 16],
    pub encrypted_hash: [u8; 16],
    pub flash_data: [u8; 10],
}

impl MainChallengeData {
    pub fn new(rev_bt_addr: [u8; 6], key: &[u8; 16], nonce: &[u8; 16]) -> Self {
        Self {
            bt_addr: rev_bt_addr,
            key: key.clone(),
            nonce: nonce.clone(),
            encrypted_challenge: [0; 16],
            encrypted_hash: [0; 16],
            flash_data: [0; 10],
        }
    }
}

#[repr(C, packed)]
pub struct NextChallenge {
    pub state: [u8; 4],
    pub nonce: [u8; 16],
    pub encrypted_challenge: [u8; 16],
    pub encrypted_hash: [u8; 16],
}

#[test]
fn test_challenge_sizes() {
    assert_eq!(core::mem::size_of::<MainChallengeData>(), 80);
    assert_eq!(core::mem::size_of::<ChallengeData>(), 378);
    assert_eq!(core::mem::size_of::<NextChallenge>(), 52);
}
