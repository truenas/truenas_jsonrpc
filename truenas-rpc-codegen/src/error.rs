//! The codegen error type (hand-rolled `Display`/`Error` — no `thiserror` dependency).

use std::fmt;

/// An error parsing, validating, or generating from a json-idl spec.
#[derive(Debug)]
pub struct CodegenError {
    origin: Option<String>,
    message: String,
}

impl CodegenError {
    /// A general error with no source location.
    pub fn new(message: impl Into<String>) -> Self {
        Self { origin: None, message: message.into() }
    }

    /// An error attributed to a source spec / file.
    pub fn at(origin: impl Into<String>, message: impl Into<String>) -> Self {
        Self { origin: Some(origin.into()), message: message.into() }
    }

    /// The error message (without the origin prefix).
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for CodegenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.origin {
            Some(o) => write!(f, "{o}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for CodegenError {}

impl From<std::io::Error> for CodegenError {
    fn from(e: std::io::Error) -> Self {
        CodegenError::new(format!("io error: {e}"))
    }
}

/// Result alias for codegen operations.
pub type Result<T> = std::result::Result<T, CodegenError>;
