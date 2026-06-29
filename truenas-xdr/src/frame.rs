//! The TXDR binary-wire frame. A frame is `magic · XDR<envelope> · payload`:
//!
//! ```text
//! Request: magic · XDR<(version, proc_id, id:opaque[16]?)>          · params:XDR<Accepts>
//! Reply:   magic · XDR<(version, id:opaque[16]?, status)>           · status 0 → result:XDR
//!                                                                      status 1 → XDR<(code, detail<>)>
//! ```
//!
//! The magic is the pre-decode discriminator (a JSON envelope always begins with `{` =
//! `0x7B`, so a non-`{` first word is unambiguously an XDR frame). The envelopes are
//! encoded as tuples through the same [`crate::to_bytes`]/[`crate::from_bytes`] codec used
//! for params/results, so the frame needs no separate serde-derive.

use crate::{from_bytes, from_bytes_with, to_bytes, FixedOpaque, Strictness, VarOpaque, XdrError};

/// Frame magic, `"TXDR"` as a big-endian `u32`.
pub const MAGIC: u32 = 0x5458_4452;
/// The frame protocol version.
pub const VERSION: u32 = 1;
/// Proc-ids `0..=RESERVED_PROC_MAX` are reserved for protocol control messages (the `$/`
/// namespace over the binary wire); application methods must use a proc-id above this.
pub const RESERVED_PROC_MAX: u32 = 1000;
/// Reply status: success (the result follows).
pub const STATUS_OK: u32 = 0;
/// Reply status: error (a `(code, detail)` payload follows).
pub const STATUS_ERR: u32 = 1;

// The envelopes as tuples (encoded field-by-field, no framing — exactly the XDR struct layout).
type RequestEnvelope = (u32, u32, u32, Option<FixedOpaque<16>>); // magic, version, proc_id, id
type ReplyEnvelope = (u32, u32, Option<FixedOpaque<16>>, u32); // magic, version, id, status

/// True iff `wire` begins with the TXDR [`MAGIC`] (a cheap whole-message prefix check).
pub fn is_xdr(wire: &[u8]) -> bool {
    wire.len() >= 4 && u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]) == MAGIC
}

/// A parsed request frame. `params` borrows the tail of the input wire.
#[derive(Debug, PartialEq, Eq)]
pub struct Request<'a> {
    /// The frame version (always [`VERSION`] for a frame this build accepts).
    pub version: u32,
    /// The method's binary proc-id.
    pub proc_id: u32,
    /// The 16 raw id bytes, or `None` for a notification.
    pub rid: Option<[u8; 16]>,
    /// The XDR-encoded params (the remainder of the frame).
    pub params: &'a [u8],
}

/// A parsed reply frame. `body` borrows the tail (the result for [`STATUS_OK`], or the
/// `(code, detail)` error payload for [`STATUS_ERR`]).
#[derive(Debug, PartialEq, Eq)]
pub struct Reply<'a> {
    /// The frame version.
    pub version: u32,
    /// The 16 raw id bytes echoed from the request, or `None`.
    pub rid: Option<[u8; 16]>,
    /// [`STATUS_OK`] or [`STATUS_ERR`].
    pub status: u32,
    /// The result bytes (ok) or the error payload bytes (err).
    pub body: &'a [u8],
}

/// Build a request frame: magic + envelope + the already-XDR-encoded `params`.
pub fn build_request(
    proc_id: u32,
    rid: Option<[u8; 16]>,
    params: &[u8],
) -> Result<Vec<u8>, XdrError> {
    let env: RequestEnvelope = (MAGIC, VERSION, proc_id, rid.map(FixedOpaque));
    let mut out = to_bytes(&env)?;
    out.extend_from_slice(params);
    Ok(out)
}

/// Parse a request frame. Assumes [`is_xdr`] has already selected the XDR path; still
/// validates the magic + version defensively.
pub fn parse_request(wire: &[u8]) -> Result<Request<'_>, XdrError> {
    let ((magic, version, proc_id, id), rest) =
        from_bytes_with::<RequestEnvelope>(wire, Strictness::Lenient)?;
    check_header(magic, version)?;
    Ok(Request { version, proc_id, rid: id.map(|f| f.0), params: rest })
}

/// Build a success reply frame: magic + envelope (status 0) + the encoded `result`.
pub fn build_reply_ok(rid: Option<[u8; 16]>, result: &[u8]) -> Result<Vec<u8>, XdrError> {
    let env: ReplyEnvelope = (MAGIC, VERSION, rid.map(FixedOpaque), STATUS_OK);
    let mut out = to_bytes(&env)?;
    out.extend_from_slice(result);
    Ok(out)
}

/// Build an error reply frame: magic + envelope (status 1) + `(code, detail)`. `detail_json`
/// is the JSON `{code,message[,data]}` object (the same `error` member the JSON wire carries).
pub fn build_reply_err(
    rid: Option<[u8; 16]>,
    code: i32,
    detail_json: &[u8],
) -> Result<Vec<u8>, XdrError> {
    let env: ReplyEnvelope = (MAGIC, VERSION, rid.map(FixedOpaque), STATUS_ERR);
    let mut out = to_bytes(&env)?;
    let payload = to_bytes(&(code, VarOpaque(detail_json.to_vec())))?;
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Parse a reply frame into its envelope + the trailing result/error body.
pub fn parse_reply(wire: &[u8]) -> Result<Reply<'_>, XdrError> {
    let ((magic, version, id, status), rest) =
        from_bytes_with::<ReplyEnvelope>(wire, Strictness::Lenient)?;
    check_header(magic, version)?;
    Ok(Reply { version, rid: id.map(|f| f.0), status, body: rest })
}

/// Decode a [`STATUS_ERR`] reply body into `(code, detail_json_bytes)`.
pub fn parse_error_payload(body: &[u8]) -> Result<(i32, Vec<u8>), XdrError> {
    let (code, detail): (i32, VarOpaque) = from_bytes(body)?;
    Ok((code, detail.0))
}

fn check_header(magic: u32, version: u32) -> Result<(), XdrError> {
    if magic != MAGIC {
        return Err(XdrError::Message("not a TXDR frame (bad magic)".to_string()));
    }
    if version != VERSION {
        return Err(XdrError::Message(format!("unsupported TXDR frame version {version}")));
    }
    Ok(())
}
