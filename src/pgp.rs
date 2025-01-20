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

/*
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
*/

pub fn decode_led_priority(buffer: &[u8]) -> u8 {
    (buffer[3] >> 5) & 0x07
}

pub fn decode_led_pattern(_buffer: &[u8], _led_pattern_count: u8) -> LedResult {
    // TODO
    /*
    let led_pattern_count = buffer[3] & 0x1f;

    let pattern: [LedPattern; led_pattern_count];
    for i in 0..led_pattern_count as usize {
        let p = 4 + 3 * i;
        pattern[i].duration = buffer[p];
        pattern[i].red = buffer[p + 1] & 0x0f;
        pattern[i].green = (buffer[p + 1] >> 4) & 0x0f;
        pattern[i].blue = buffer[p + 2] & 0x0f;
    }
    */
    LedResult::Unknown
}
