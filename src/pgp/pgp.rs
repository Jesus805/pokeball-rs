use crate::pgp::LedResult;

pub fn decode_led_priority(buffer: &[u8]) -> u8 {
    (buffer[3] >> 5) & 0x07
}

pub fn decode_led_pattern(buffer: &[u8], led_pattern_count: u8) -> LedResult {
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
