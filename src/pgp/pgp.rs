use crate::pgp::LedPattern;

fn decode_number_of_led_patterns(buffer: &[u8]) -> u8 {
    buffer[3] & 0x1f
}

fn decode_led_priority(buffer: &[u8]) -> u8 {
    (buffer[3] >> 5) & 0x07
}

fn decode_led_notify(buffer: &[u8], number_of_patterns: u8, patterns: &mut [LedPattern]) {
    for i in 0..number_of_patterns as usize {
        let p = 4 + 3 * i;
        patterns[i].duration = buffer[p];
        patterns[i].red = buffer[p + 1] & 0x0f;
        patterns[i].green = (buffer[p + 1] >> 4) & 0x0f;
        patterns[i].blue = buffer[p + 2] & 0x0f;
    }
}