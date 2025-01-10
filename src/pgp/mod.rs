mod pgp;

use crate::cert::MainChallengeData;
pub use self::pgp::{

};

pub struct LedPattern {
    pub duration: u8,
    pub red: u8,
    pub green: u8,
    pub blue: u8,
}

impl LedPattern {
    pub(crate) fn new(duration: u8, red: u8, green: u8, blue: u8) -> Self {
        Self {
            duration,
            red,
            green,
            blue
        }
    }
}