//! `Secret<T>` — a wrapper marking a field as sensitive.

use std::fmt;
use std::ops::Deref;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A value that must not appear in logs or audit output.
///
/// `Secret<T>` is **wire-transparent**: it serializes and deserializes exactly as the
/// inner `T` on both the JSON and XDR wires (it adds no framing — the XDR codec passes
/// single-field newtypes straight through, and JSON does the same). Only its [`fmt::Debug`]
/// is redacted, so a secret can't leak into a `{:?}` log line. Audit redaction of the
/// request-params / response view is performed separately by the dispatch core from a
/// method's `secret_fields` list; generated code both wraps secret fields in `Secret<T>`
/// and registers their names there.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Secret<T>(pub T);

impl<T> Secret<T> {
    /// Consume the wrapper, returning the inner value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(********)")
    }
}

impl<T> Deref for Secret<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Secret(value)
    }
}

impl<T: Serialize> Serialize for Secret<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer) // transparent on the wire
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Secret<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Secret(T::deserialize(deserializer)?))
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn transparent_wire_and_redacted_debug() {
        let s = Secret::from("pw".to_string());
        assert_eq!(&*s, "pw"); // Deref
        assert_eq!(s.clone().into_inner(), "pw"); // Clone + into_inner
        assert_eq!(format!("{s:?}"), "Secret(********)"); // Debug is redacted
                                                          // Wire-transparent through serde_json (the JSON wire): no wrapper object.
        assert_eq!(serde_json::to_string(&s).unwrap(), "\"pw\"");
        let d: Secret<String> = serde_json::from_str("\"pw\"").unwrap();
        assert_eq!(s, d); // PartialEq / Eq
        assert_eq!(Secret::<u32>::default().0, 0); // Default
    }
}
