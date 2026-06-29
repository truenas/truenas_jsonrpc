//! The raw GSSAPI C ABI (RFC 2744) — the ~6 `gss_*` functions + `#[repr(C)]` types the acceptor
//! handshake needs, plus thin wrappers that own the `unsafe` calls and GSS buffer/name lifetimes.
//! All `unsafe` in the crate lives here (and the one `Send` impl in `lib.rs`), each call site
//! documented with a `// SAFETY:` note — the audited-block policy the keyring/nss/audit crates use.

#![allow(non_camel_case_types)]

use std::os::raw::{c_int, c_void};
use std::ptr;

/// GSSAPI status type (`OM_uint32`).
pub(crate) type OM_uint32 = u32;

/// `gss_buffer_desc` — a token / name buffer. NOTE: `length` is C `size_t` (`usize`), **not** `u32`.
#[repr(C)]
pub(crate) struct gss_buffer_desc {
    pub length: usize,
    pub value: *mut c_void,
}
pub(crate) type gss_buffer_t = *mut gss_buffer_desc;

// Opaque GSS handles — used only behind pointers.
#[repr(C)]
pub(crate) struct gss_name_struct {
    _unused: [u8; 0],
}
pub(crate) type gss_name_t = *mut gss_name_struct;
#[repr(C)]
pub(crate) struct gss_ctx_id_struct {
    _unused: [u8; 0],
}
pub(crate) type gss_ctx_id_t = *mut gss_ctx_id_struct;
#[repr(C)]
pub(crate) struct gss_cred_id_struct {
    _unused: [u8; 0],
}
pub(crate) type gss_cred_id_t = *mut gss_cred_id_struct;
#[repr(C)]
pub(crate) struct gss_OID_desc {
    _unused: [u8; 0],
}
pub(crate) type gss_OID = *mut gss_OID_desc;

/// `gss_channel_bindings_struct` — only `application_data` is ever set (the TLS binding token).
#[repr(C)]
pub(crate) struct gss_channel_bindings_struct {
    pub initiator_addrtype: OM_uint32,
    pub initiator_address: gss_buffer_desc,
    pub acceptor_addrtype: OM_uint32,
    pub acceptor_address: gss_buffer_desc,
    pub application_data: gss_buffer_desc,
}
pub(crate) type gss_channel_bindings_t = *mut gss_channel_bindings_struct;

/// `GSS_S_CONTINUE_NEEDED` — set in the major status when another round is needed.
pub(crate) const GSS_S_CONTINUE_NEEDED: OM_uint32 = 1;

/// The `GSS_ERROR` macro: non-zero iff any calling- or routine-error bits are set (offsets 24/16,
/// each an 8-bit field — MIT/RFC 2744).
pub(crate) fn gss_error(x: OM_uint32) -> OM_uint32 {
    x & ((0xff << 24) | (0xff << 16))
}

fn empty_buffer() -> gss_buffer_desc {
    gss_buffer_desc { length: 0, value: ptr::null_mut() }
}

#[allow(unsafe_code)]
extern "C" {
    fn gss_accept_sec_context(
        minor_status: *mut OM_uint32,
        context_handle: *mut gss_ctx_id_t,
        acceptor_cred_handle: gss_cred_id_t,
        input_token: gss_buffer_t,
        input_chan_bindings: gss_channel_bindings_t,
        src_name: *mut gss_name_t,
        mech_type: *mut gss_OID,
        output_token: gss_buffer_t,
        ret_flags: *mut OM_uint32,
        time_rec: *mut OM_uint32,
        delegated_cred_handle: *mut gss_cred_id_t,
    ) -> OM_uint32;

    fn gss_inquire_context(
        minor_status: *mut OM_uint32,
        context_handle: gss_ctx_id_t,
        src_name: *mut gss_name_t,
        targ_name: *mut gss_name_t,
        lifetime_rec: *mut OM_uint32,
        mech_type: *mut gss_OID,
        ctx_flags: *mut OM_uint32,
        locally_initiated: *mut c_int,
        open: *mut c_int,
    ) -> OM_uint32;

    fn gss_display_name(
        minor_status: *mut OM_uint32,
        input_name: gss_name_t,
        output_name_buffer: gss_buffer_t,
        output_name_type: *mut gss_OID,
    ) -> OM_uint32;

    fn gss_release_buffer(minor_status: *mut OM_uint32, buffer: gss_buffer_t) -> OM_uint32;
    fn gss_release_name(minor_status: *mut OM_uint32, name: *mut gss_name_t) -> OM_uint32;
    fn gss_delete_sec_context(
        minor_status: *mut OM_uint32,
        context_handle: *mut gss_ctx_id_t,
        output_token: gss_buffer_t,
    ) -> OM_uint32;
}

/// The result of one acceptor step: the GSS status pair and the server's reply token (copied out of
/// the GSS-allocated buffer, which is released here).
pub(crate) struct StepOut {
    pub major: OM_uint32,
    pub minor: OM_uint32,
    pub token: Vec<u8>,
}

/// Copy a GSS-allocated output buffer into an owned `Vec` and release it.
fn copy_and_release(buf: &mut gss_buffer_desc) -> Vec<u8> {
    if buf.value.is_null() || buf.length == 0 {
        return Vec::new();
    }
    // SAFETY: on a successful GSS call `buf.value` points at `buf.length` bytes the library
    // allocated; read them once into an owned Vec.
    #[allow(unsafe_code)]
    let bytes = unsafe { std::slice::from_raw_parts(buf.value.cast::<u8>(), buf.length).to_vec() };
    let mut minor: OM_uint32 = 0;
    // SAFETY: release the GSS-allocated buffer (frees `buf.value`, zeroes the descriptor).
    #[allow(unsafe_code)]
    unsafe {
        gss_release_buffer(&mut minor, buf);
    }
    bytes
}

/// One `gss_accept_sec_context` step over the default host keytab (`GSS_C_NO_CREDENTIAL`), with an
/// optional channel-binding `application_data`. `ctx` is created on the first call and updated
/// in place; the unused src_name/mech/time/deleg out-params are NULL.
pub(crate) fn accept_step(
    ctx: &mut gss_ctx_id_t,
    input: &[u8],
    channel_binding: Option<&[u8]>,
) -> StepOut {
    let mut minor: OM_uint32 = 0;
    let mut in_buf =
        gss_buffer_desc { length: input.len(), value: input.as_ptr() as *mut c_void };
    let mut out_buf = empty_buffer();
    let mut ret_flags: OM_uint32 = 0;
    let mut cb = gss_channel_bindings_struct {
        initiator_addrtype: 0,
        initiator_address: empty_buffer(),
        acceptor_addrtype: 0,
        acceptor_address: empty_buffer(),
        application_data: empty_buffer(),
    };
    let cb_ptr: gss_channel_bindings_t = match channel_binding {
        Some(data) => {
            cb.application_data =
                gss_buffer_desc { length: data.len(), value: data.as_ptr() as *mut c_void };
            &mut cb
        }
        None => ptr::null_mut(),
    };

    // SAFETY: `gss_accept_sec_context` reads `in_buf` (valid for `input.len()`) and `cb` (when
    // non-null, its `application_data` is valid for `data.len()`), reads/updates `*ctx`, and writes
    // `minor`/`out_buf`/`ret_flags` — all valid locals. We pass `GSS_C_NO_CREDENTIAL` (null) for the
    // acceptor cred and NULL for the src_name/mech/time/deleg out-params we don't consume.
    #[allow(unsafe_code)]
    let major = unsafe {
        gss_accept_sec_context(
            &mut minor,
            ctx,
            ptr::null_mut(),
            &mut in_buf,
            cb_ptr,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut out_buf,
            &mut ret_flags,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    let token = copy_and_release(&mut out_buf);
    StepOut { major, minor, token }
}

/// The established context's initiator principal as text (`gss_inquire_context` → `gss_display_name`).
pub(crate) fn source_name(ctx: gss_ctx_id_t) -> Result<String, (OM_uint32, OM_uint32)> {
    let mut minor: OM_uint32 = 0;
    let mut name: gss_name_t = ptr::null_mut();
    // SAFETY: `gss_inquire_context` writes the initiator handle into `name`; all other out-params
    // are NULL (not requested).
    #[allow(unsafe_code)]
    let major = unsafe {
        gss_inquire_context(
            &mut minor,
            ctx,
            &mut name,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if gss_error(major) != 0 {
        return Err((major, minor));
    }

    let mut out_buf = empty_buffer();
    // SAFETY: `gss_display_name` reads the `name` handle and writes the text into `out_buf`.
    #[allow(unsafe_code)]
    let major = unsafe { gss_display_name(&mut minor, name, &mut out_buf, ptr::null_mut()) };
    let text = copy_and_release(&mut out_buf);
    // SAFETY: release the name handle `gss_inquire_context` produced.
    #[allow(unsafe_code)]
    unsafe {
        gss_release_name(&mut minor, &mut name);
    }
    if gss_error(major) != 0 {
        return Err((major, minor));
    }
    Ok(String::from_utf8_lossy(&text).into_owned())
}

/// Free a security context (`gss_delete_sec_context`); no-op on a null handle.
pub(crate) fn delete_context(ctx: &mut gss_ctx_id_t) {
    if ctx.is_null() {
        return;
    }
    let mut minor: OM_uint32 = 0;
    // SAFETY: `gss_delete_sec_context` frees `*ctx` and nulls it; we request no output token
    // (GSS_C_NO_BUFFER / null).
    #[allow(unsafe_code)]
    unsafe {
        gss_delete_sec_context(&mut minor, ctx, ptr::null_mut());
    }
}
