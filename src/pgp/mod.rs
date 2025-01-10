mod pgp;

pub use self::pgp::{decode_led_pattern, decode_led_priority};

pub enum LedResult {
    Unknown,
    PokemonEncounter,
    NewPokemonEncounter,
    PokemonCaught,
    PokemonFled(u8), // Number of ball shakes
    PokestopEncounter,
    PokestopSpun(u8), // Number of items
}

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
            blue,
        }
    }
}
