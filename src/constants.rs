pub static DEVICE_NAME: &str = "Pokemon GO Plus";

pub const CERTIFICATION_SERVICE_BYTES: [u8; 16] = [
    0xbb, 0xe8, 0x77, 0x09, 0x5b, 0x89, 0x44, 0x33, 0xab, 0x7f, 0x8b, 0x8e, 0xef, 0xd, 0x8e, 0x37,
];
pub const CENTRAL_TO_SFIDA_CHAR_BYTES: [u8; 16] = [
    0xbb, 0xe8, 0x77, 0x09, 0x5b, 0x89, 0x44, 0x33, 0xab, 0x7f, 0x8b, 0x8e, 0xef, 0xd, 0x8e, 0x38,
];
pub const SFIDA_COMMANDS_CHAR_BYTES: [u8; 16] = [
    0xbb, 0xe8, 0x77, 0x09, 0x5b, 0x89, 0x44, 0x33, 0xab, 0x7f, 0x8b, 0x8e, 0xef, 0xd, 0x8e, 0x39,
];
pub const SFIDA_TO_CENTRAL_CHAR_BYTES: [u8; 16] = [
    0xbb, 0xe8, 0x77, 0x09, 0x5b, 0x89, 0x44, 0x33, 0xab, 0x7f, 0x8b, 0x8e, 0xef, 0xd, 0x8e, 0x3a,
];

pub const PGP_SERVICE_BYTES: [u8; 16] = [
    0x21, 0xc5, 0x04, 0x62, 0x67, 0xcb, 0x63, 0xa3, 0x5c, 0x4c, 0x82, 0xb5, 0xb9, 0x93, 0x9a, 0xeb,
];
pub const LED_CHAR_BYTES: [u8; 16] = [
    0x21, 0xc5, 0x04, 0x62, 0x67, 0xcb, 0x63, 0xa3, 0x5c, 0x4c, 0x82, 0xb5, 0xb9, 0x93, 0x9a, 0xec,
];
pub const BUTTON_CHAR_BYTES: [u8; 16] = [
    0x21, 0xc5, 0x04, 0x62, 0x67, 0xcb, 0x63, 0xa3, 0x5c, 0x4c, 0x82, 0xb5, 0xb9, 0x93, 0x9a, 0xed,
];
pub const UNKNOWN_CHAR_BYTES: [u8; 16] = [
    0x21, 0xc5, 0x04, 0x62, 0x67, 0xcb, 0x63, 0xa3, 0x5c, 0x4c, 0x82, 0xb5, 0xb9, 0x93, 0x9a, 0xee,
];
pub const UPDATE_REQUEST_CHAR_BYTES: [u8; 16] = [
    0x21, 0xc5, 0x04, 0x62, 0x67, 0xcb, 0x63, 0xa3, 0x5c, 0x4c, 0x82, 0xb5, 0xb9, 0x93, 0x9a, 0xef,
];
pub const FIRMWARE_VERSION_CHAR_BYTES: [u8; 16] = [
    0x21, 0xc5, 0x04, 0x62, 0x67, 0xcb, 0x63, 0xa3, 0x5c, 0x4c, 0x82, 0xb5, 0xb9, 0x93, 0x9a, 0xf0,
];
