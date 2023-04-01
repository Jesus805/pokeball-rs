use uuid::Uuid;

pub const CERTIFICATION_SERVICE_UUID: Uuid =
    Uuid::from_bytes(crate::constants::CERTIFICATION_SERVICE_BYTES);
pub const CENTRAL_TO_SFIDA_CHAR_UUID: Uuid =
    Uuid::from_bytes(crate::constants::CENTRAL_TO_SFIDA_CHAR_BYTES);
pub const SFIDA_COMMANDS_CHAR_UUID: Uuid =
    Uuid::from_bytes(crate::constants::SFIDA_COMMANDS_CHAR_BYTES);
pub const SFIDA_TO_CENTRAL_CHAR_UUID: Uuid =
    Uuid::from_bytes(crate::constants::SFIDA_TO_CENTRAL_CHAR_BYTES);

pub const PGP_SERVICE_UUID: Uuid = Uuid::from_bytes(crate::constants::PGP_SERVICE_BYTES);
pub const LED_CHAR_UUID: Uuid = Uuid::from_bytes(crate::constants::LED_CHAR_BYTES);
pub const BUTTON_CHAR_UUID: Uuid = Uuid::from_bytes(crate::constants::BUTTON_CHAR_BYTES);
pub const UNKNOWN_CHAR_UUID: Uuid = Uuid::from_bytes(crate::UNKNOWN_CHAR_BYTES);
pub const UPDATE_REQUEST_CHAR_UUID: Uuid =
    Uuid::from_bytes(crate::constants::UPDATE_REQUEST_CHAR_BYTES);
pub const FIRMWARE_VERSION_CHAR_UUID: Uuid =
    Uuid::from_bytes(crate::constants::FIRMWARE_VERSION_CHAR_BYTES);
