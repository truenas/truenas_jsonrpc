//! The crate error type.

/// Something went wrong opening or using the keyring.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The keyring config was missing required fields or otherwise malformed (a schema error).
    #[error("invalid keyring config: {0}")]
    Config(String),
    /// A key or sub-keyring name was invalid (e.g. it contained an interior NUL byte).
    #[error("invalid name: {0}")]
    InvalidName(String),
    /// A keyring syscall (`add_key` / `keyctl`) failed.
    #[error("keyring syscall: {0}")]
    Io(#[from] std::io::Error),
    /// A stored record failed to serialize or deserialize.
    #[error("record (de)serialization: {0}")]
    Record(#[source] serde_json::Error),
}
