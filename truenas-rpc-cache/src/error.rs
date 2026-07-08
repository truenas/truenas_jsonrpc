//! [`CacheError`] — the error type for cache operations.

/// An error from a cache operation.
///
/// A pure in-memory cache is effectively infallible (its ops return `Ok`); these variants are
/// produced by the persistent LMDB backend (value (de)serialization, an LMDB error, or a full map).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CacheError {
    /// A value failed to serialize (on `put`) or deserialize (on `get` — e.g. the stored bytes don't
    /// match the requested type). Produced by the persistent backend's value codec.
    #[error("cache value serialize/deserialize: {0}")]
    Codec(String),

    /// The LMDB backend returned an error (the message is `mdb_strerror`).
    #[error("lmdb: {0}")]
    Lmdb(String),

    /// The LMDB map is full — the environment's `map_size` needs to be larger.
    #[error("lmdb map full — increase the environment map_size")]
    MapFull,
}
