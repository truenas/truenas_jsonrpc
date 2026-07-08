//! Decode strictness.
//!
//! XDR's two reference implementations disagree on decode leniency: FreeBSD `sys/xdr`
//! (and the `xdrlib3` codec the committed conformance vectors are generated with) ignore
//! the trailing pad bytes of opaque/string fields and accept embedded NULs, whereas ZFS
//! `spl-xdr` rejects both (its documented decode rules 4 and 5). Encoding is identical
//! either way (canonical pad is always zero); only decode differs, so strictness is a
//! decode-time mode.

/// How strict the decoder is about reserved/padding bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Strictness {
    /// FreeBSD `sys/xdr` / `xdrlib3` behavior: ignore opaque/string pad bytes and accept
    /// embedded NULs. This is the default, so the committed golden vectors decode.
    #[default]
    Lenient,
    /// ZFS `spl-xdr` behavior: a non-zero pad byte ([`crate::XdrError::NonZeroPadding`])
    /// or an embedded NUL in a string ([`crate::XdrError::EmbeddedNul`]) is an error.
    Strict,
}
