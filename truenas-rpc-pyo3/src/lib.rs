//! The embedded-CPython bridge — runs `truenas-rpc` `python:true` method bodies in an
//! embedded CPython interpreter. It implements the core's [`PyDispatcher`] seam by calling a
//! Python `dispatch(name, params_json, session_json, call) -> (status, payload, audit)` callable
//! (the contract `gen.py --python-out` emits): `status == 0` ⇒ `payload` is the result JSON; a
//! non-zero `status` is the JSON-RPC error code and `payload` is the message; `audit` is the
//! body's audit detail (`b""` for none).
//!
//! `call` is the in-process caller handed to the body: a Python callable
//! `call(name: str, params: bytes, elevated: bool = False) -> bytes` that routes back into the core
//! (the same by-name path a Rust handler uses via `cx.call_named_json`) and returns the bare-JSON
//! result. A core error is raised as `RuntimeError((code, message))`. It wraps the core's byte
//! [`InProcessCaller`] in a [`PyCapsule`](https://docs.python.org/3/c-api/capsule.html) + a
//! `PyCFunction`; the capsule owns the caller for the callable's lifetime.
//!
//! It speaks the raw CPython C-API directly through [`pyo3_ffi`] (no pyo3 framework, no
//! proc-macros). The Rust spine still does
//! routing / the session gate / authorization / audit — only the body crosses the FFI. The body
//! runs on the core's blocking pool (the GIL is held only inside a `Gil` guard, never across
//! an `.await`), so GIL contention can't stall the async runtime. This crate is **opt-in**: the
//! default workspace build links no libpython.

use std::ffi::CString;
use std::os::raw::{c_char, c_long, c_void};
use std::sync::{Arc, Once};

use pyo3_ffi as ffi;
use serde_json::value::RawValue;
use truenas_rpc::{ErrorCode, InProcessCaller, JsonRpcError, PyDispatcher, PyOutcome, PyResult};

/// Bring up the embedded interpreter exactly once. After `Py_InitializeEx` the calling thread
/// holds the GIL; `PyEval_SaveThread` releases it (and arms the per-thread GIL-state machinery)
/// so any blocking-pool worker can later acquire it via [`Gil`]. Process-global; we never
/// finalize (a long-running server), matching pyo3's `auto-initialize`.
#[allow(unsafe_code)]
fn ensure_initialized() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: guarded by `Once`, so `Py_InitializeEx` runs exactly once; `PyEval_SaveThread`
        // is the documented way to release the init thread's GIL for later `PyGILState_Ensure`.
        unsafe {
            ffi::Py_InitializeEx(0); // 0 = don't install signal handlers (we're a guest)
            let _ = ffi::PyEval_SaveThread();
        }
    });
}

/// RAII GIL guard: acquire on construction (initializing the interpreter on first use), release
/// on drop. Held only inside a synchronous dispatch — never across an `.await`.
struct Gil(ffi::PyGILState_STATE);

impl Gil {
    #[allow(unsafe_code)]
    fn acquire() -> Self {
        ensure_initialized();
        // SAFETY: the interpreter is initialized; `PyGILState_Ensure` is valid from any thread
        // and pairs with the `PyGILState_Release` in `Drop`.
        Gil(unsafe { ffi::PyGILState_Ensure() })
    }
}

impl Drop for Gil {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: `self.0` is the state returned by the matching `PyGILState_Ensure`.
        unsafe { ffi::PyGILState_Release(self.0) }
    }
}

/// A [`PyDispatcher`] backed by a Python `dispatch(name, params, session, call)` callable, held as
/// an owned reference for the bridge's lifetime.
pub struct PyBridge {
    dispatch: *mut ffi::PyObject,
}

// SAFETY: `dispatch` is a CPython object pointer that is only ever dereferenced/called while the
// GIL is held (every access goes through a `Gil` guard), so it is safe to send and share across
// threads — the same justification pyo3 uses for its `Py<T>` smart pointer.
#[allow(unsafe_code)]
unsafe impl Send for PyBridge {}
#[allow(unsafe_code)]
unsafe impl Sync for PyBridge {}

impl PyBridge {
    /// Import the Python `module` (e.g. the generated `rpc_py`) and hold its `dispatch`
    /// attribute, initializing the embedded interpreter on first use.
    #[allow(unsafe_code)]
    pub fn import(module: &str) -> Result<Self, BridgeError> {
        let _gil = Gil::acquire();
        let cmodule = cstring(module)?;
        // SAFETY: GIL held. `PyImport_ImportModule` returns a new ref (or null on error);
        // `PyObject_GetAttrString` returns a new ref we keep; the module ref is released.
        unsafe {
            let m = ffi::PyImport_ImportModule(cmodule.as_ptr());
            if m.is_null() {
                return Err(take_py_err("import"));
            }
            let dispatch = ffi::PyObject_GetAttrString(m, b"dispatch\0".as_ptr().cast::<c_char>());
            ffi::Py_XDECREF(m);
            if dispatch.is_null() {
                return Err(take_py_err("getattr dispatch"));
            }
            Ok(PyBridge { dispatch })
        }
    }

    /// Build the `(name, params, session, call)` argument tuple, call the Python `dispatch`, and map
    /// its `(status, payload, audit)` return onto a [`PyResult`]. `call` is the in-process caller
    /// (see [`make_call`]) the body reaches back into the core through. Must run with the GIL held.
    #[allow(unsafe_code)]
    unsafe fn call_locked(
        &self,
        name: &str,
        params: &[u8],
        session: &[u8],
        caller: Arc<dyn InProcessCaller>,
    ) -> PyResult {
        let args = ffi::PyTuple_New(4);
        if args.is_null() {
            return clear_and_internal();
        }
        // `PyTuple_SetItem` STEALS its item ref, so on success we only DecRef `args` (which frees
        // its items). Build all four items first so a mid-build failure can DecRef cleanly.
        let py_name =
            ffi::PyUnicode_FromStringAndSize(name.as_ptr().cast::<c_char>(), to_ssize(name.len()));
        if py_name.is_null() {
            ffi::Py_XDECREF(args);
            return clear_and_internal();
        }
        let py_params = ffi::PyBytes_FromStringAndSize(
            params.as_ptr().cast::<c_char>(),
            to_ssize(params.len()),
        );
        if py_params.is_null() {
            ffi::Py_XDECREF(py_name);
            ffi::Py_XDECREF(args);
            return clear_and_internal();
        }
        let py_sess = ffi::PyBytes_FromStringAndSize(
            session.as_ptr().cast::<c_char>(),
            to_ssize(session.len()),
        );
        if py_sess.is_null() {
            ffi::Py_XDECREF(py_name);
            ffi::Py_XDECREF(py_params);
            ffi::Py_XDECREF(args);
            return clear_and_internal();
        }
        let py_call = make_call(caller);
        if py_call.is_null() {
            ffi::Py_XDECREF(py_name);
            ffi::Py_XDECREF(py_params);
            ffi::Py_XDECREF(py_sess);
            ffi::Py_XDECREF(args);
            return clear_and_internal();
        }
        ffi::PyTuple_SetItem(args, 0, py_name);
        ffi::PyTuple_SetItem(args, 1, py_params);
        ffi::PyTuple_SetItem(args, 2, py_sess);
        ffi::PyTuple_SetItem(args, 3, py_call);

        let result = ffi::PyObject_CallObject(self.dispatch, args);
        ffi::Py_XDECREF(args);
        if result.is_null() {
            return clear_and_internal(); // the handler raised (uncaught) → INTERNAL_ERROR
        }

        // Expected shape: (status:int, payload:bytes, audit:bytes). `PyTuple_GetItem` borrows.
        let status_obj = ffi::PyTuple_GetItem(result, 0);
        if status_obj.is_null() {
            ffi::Py_XDECREF(result);
            return clear_and_internal();
        }
        let status = ffi::PyLong_AsLong(status_obj);
        if !ffi::PyErr_Occurred().is_null() {
            ffi::Py_XDECREF(result);
            return clear_and_internal();
        }
        let payload = match extract_bytes(ffi::PyTuple_GetItem(result, 1)) {
            Some(p) => p,
            None => {
                ffi::Py_XDECREF(result);
                return clear_and_internal();
            }
        };
        let audit = extract_bytes(ffi::PyTuple_GetItem(result, 2)).unwrap_or_default();
        ffi::Py_XDECREF(result);

        decode_outcome(status as i64, &payload, &audit)
    }
}

impl PyDispatcher for PyBridge {
    #[allow(unsafe_code)]
    fn dispatch(
        &self,
        name: &str,
        params_json: &[u8],
        session_json: &[u8],
        caller: Arc<dyn InProcessCaller>,
    ) -> PyResult {
        let _gil = Gil::acquire();
        // SAFETY: the GIL is held for the whole call (the guard drops at end of scope), and
        // `self.dispatch` is a live callable held since construction. `caller` is wrapped into the
        // `call` argument (a capsule that owns it) inside `call_locked`.
        unsafe { self.call_locked(name, params_json, session_json, caller) }
    }
}

impl Drop for PyBridge {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        let _gil = Gil::acquire();
        // SAFETY: GIL held; `self.dispatch` is the owned ref taken at construction.
        unsafe { ffi::Py_XDECREF(self.dispatch) }
    }
}

/// `len as Py_ssize_t`, saturating at `Py_ssize_t::MAX` (our buffers never approach it; this just
/// keeps the cast total).
fn to_ssize(len: usize) -> ffi::Py_ssize_t {
    len.min(ffi::Py_ssize_t::MAX as usize) as ffi::Py_ssize_t
}

/// Capsule tag for the `call` caller pointer — `PyCapsule_New`/`_GetPointer` must agree on it.
const CALL_CAPSULE_NAME: &[u8] = b"truenas_rpc.call\0";

/// A `Sync` wrapper so the `call` [`PyMethodDef`] can live in a `static`: CPython only ever reads it
/// (it stores the pointer in the `PyCFunction` object), and every field points at `'static` data.
struct CallMethodDef(ffi::PyMethodDef);
// SAFETY: read-only to CPython (never mutated) and all its pointers are to `'static` data.
#[allow(unsafe_code)]
unsafe impl Sync for CallMethodDef {}

/// The `PyMethodDef` backing every `call` callable: name `call`, `METH_VARARGS`, [`call_trampoline`].
static CALL_METHOD_DEF: CallMethodDef = CallMethodDef(ffi::PyMethodDef {
    ml_name: b"call\0".as_ptr().cast::<c_char>(),
    ml_meth: ffi::PyMethodDefPointer {
        PyCFunction: call_trampoline,
    },
    ml_flags: ffi::METH_VARARGS,
    ml_doc: std::ptr::null(),
});

/// Build the Python `call` callable that hands a body an in-process route back into the core: a
/// `PyCFunction` whose `self` is a capsule owning `caller`. The capsule's destructor drops the
/// caller when the callable is collected, so `caller` lives exactly as long as the `call` object.
/// Returns a new ref (or null with a Python error set). Must run with the GIL held.
#[allow(unsafe_code)]
unsafe fn make_call(caller: Arc<dyn InProcessCaller>) -> *mut ffi::PyObject {
    // The `Arc<dyn ..>` is a fat pointer; box it so the capsule can hold a thin `void*`.
    let boxed: *mut Arc<dyn InProcessCaller> = Box::into_raw(Box::new(caller));
    let capsule = ffi::PyCapsule_New(
        boxed.cast::<c_void>(),
        CALL_CAPSULE_NAME.as_ptr().cast::<c_char>(),
        Some(call_capsule_destructor),
    );
    if capsule.is_null() {
        // Creation failed (a Python error is set) — reclaim the box so the caller isn't leaked.
        drop(Box::from_raw(boxed));
        return std::ptr::null_mut();
    }
    // `PyCFunction_NewEx` INCREFs the capsule (its new `m_self`); drop our construction ref so the
    // callable is the capsule's sole owner. On failure it never INCREFs, so our DECREF frees the
    // capsule → its destructor reclaims the box.
    let call = ffi::PyCFunction_NewEx(
        &CALL_METHOD_DEF.0 as *const ffi::PyMethodDef as *mut ffi::PyMethodDef,
        capsule,
        std::ptr::null_mut(),
    );
    ffi::Py_XDECREF(capsule);
    call
}

/// Capsule destructor: reclaim and drop the boxed caller. Runs (GIL held) when the `call` callable
/// is collected.
#[allow(unsafe_code)]
unsafe extern "C" fn call_capsule_destructor(capsule: *mut ffi::PyObject) {
    let ptr = ffi::PyCapsule_GetPointer(capsule, CALL_CAPSULE_NAME.as_ptr().cast::<c_char>());
    if ptr.is_null() {
        ffi::PyErr_Clear(); // shouldn't happen (we always tag it); never leave an error pending
        return;
    }
    drop(Box::from_raw(ptr.cast::<Arc<dyn InProcessCaller>>()));
}

/// The `call(name, params, elevated=False) -> bytes` trampoline. `slf` is the capsule holding the
/// caller. A panic in a re-entered handler is caught and surfaced as a Python error (never allowed
/// to unwind across the FFI boundary).
#[allow(unsafe_code)]
unsafe extern "C" fn call_trampoline(
    slf: *mut ffi::PyObject,
    args: *mut ffi::PyObject,
) -> *mut ffi::PyObject {
    let ptr = ffi::PyCapsule_GetPointer(slf, CALL_CAPSULE_NAME.as_ptr().cast::<c_char>());
    if ptr.is_null() {
        return std::ptr::null_mut(); // capsule mismatch → CPython set the error
    }
    let caller: &dyn InProcessCaller = &**ptr.cast::<Arc<dyn InProcessCaller>>();
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| call_inner(caller, args))) {
        Ok(obj) => obj,
        Err(_) => {
            set_runtime_error("in-process call panicked");
            std::ptr::null_mut()
        }
    }
}

/// Parse the `call` args `(name: str, params: bytes[, elevated: bool])`, route through `caller`, and
/// return the bare-JSON result as `bytes` — or set a Python error and return null. Must run with
/// the GIL held.
#[allow(unsafe_code)]
unsafe fn call_inner(caller: &dyn InProcessCaller, args: *mut ffi::PyObject) -> *mut ffi::PyObject {
    let n = ffi::PyTuple_Size(args);
    if !(2..=3).contains(&n) {
        set_runtime_error("call(name, params[, elevated]) takes 2 or 3 arguments");
        return std::ptr::null_mut();
    }
    // name: str → borrowed UTF-8 (valid for this call; the tuple owns the str).
    let mut name_len: ffi::Py_ssize_t = 0;
    let name_ptr = ffi::PyUnicode_AsUTF8AndSize(ffi::PyTuple_GetItem(args, 0), &mut name_len);
    if name_ptr.is_null() {
        return std::ptr::null_mut(); // not a str → TypeError already set
    }
    let name = match std::str::from_utf8(std::slice::from_raw_parts(
        name_ptr.cast::<u8>(),
        name_len as usize,
    )) {
        Ok(s) => s,
        Err(_) => {
            set_runtime_error("call name was not valid UTF-8");
            return std::ptr::null_mut();
        }
    };
    // params: bytes → borrowed slice (valid for this call).
    let mut buf: *mut c_char = std::ptr::null_mut();
    let mut buf_len: ffi::Py_ssize_t = 0;
    if ffi::PyBytes_AsStringAndSize(ffi::PyTuple_GetItem(args, 1), &mut buf, &mut buf_len) != 0 {
        return std::ptr::null_mut(); // not bytes → TypeError already set
    }
    let params = std::slice::from_raw_parts(buf.cast::<u8>(), buf_len as usize);
    // elevated: optional bool.
    let elevated = if n == 3 {
        match ffi::PyObject_IsTrue(ffi::PyTuple_GetItem(args, 2)) {
            -1 => return std::ptr::null_mut(), // __bool__ raised
            truth => truth == 1,
        }
    } else {
        false
    };

    match caller.call_json(name, params, elevated) {
        Ok(raw) => {
            let s = raw.get();
            ffi::PyBytes_FromStringAndSize(s.as_ptr().cast::<c_char>(), to_ssize(s.len()))
        }
        Err(e) => {
            set_rpc_error(e.code, &e.message);
            std::ptr::null_mut()
        }
    }
}

/// Raise `RuntimeError((code, message))` so a body can inspect the JSON-RPC `code`/`message` of a
/// core-side failure (e.g. a role-gate denial). Must run with the GIL held.
#[allow(unsafe_code)]
unsafe fn set_rpc_error(code: i32, message: &str) {
    let tup = ffi::PyTuple_New(2);
    let c = ffi::PyLong_FromLong(code as c_long);
    let m = ffi::PyUnicode_FromStringAndSize(
        message.as_ptr().cast::<c_char>(),
        to_ssize(message.len()),
    );
    if tup.is_null() || c.is_null() || m.is_null() {
        // OOM building the payload — a Python error is already pending; fall back to a bare error.
        ffi::Py_XDECREF(tup);
        ffi::Py_XDECREF(c);
        ffi::Py_XDECREF(m);
        set_runtime_error(message);
        return;
    }
    ffi::PyTuple_SetItem(tup, 0, c); // steals
    ffi::PyTuple_SetItem(tup, 1, m); // steals
    ffi::PyErr_SetObject(ffi::PyExc_RuntimeError, tup);
    ffi::Py_XDECREF(tup); // `PyErr_SetObject` INCREFs its value
}

/// Raise `RuntimeError(msg)` (an interior NUL falls back to a fixed message). Must run with the GIL
/// held.
#[allow(unsafe_code)]
unsafe fn set_runtime_error(msg: &str) {
    match CString::new(msg) {
        Ok(c) => ffi::PyErr_SetString(ffi::PyExc_RuntimeError, c.as_ptr()),
        Err(_) => ffi::PyErr_SetString(
            ffi::PyExc_RuntimeError,
            b"call error\0".as_ptr().cast::<c_char>(),
        ),
    }
}

/// Copy a Python `bytes` object's contents into an owned `Vec` (so the result is independent of
/// the Python object's lifetime). `None` if `obj` is null / not a `bytes`. Must run with the GIL
/// held.
#[allow(unsafe_code)]
unsafe fn extract_bytes(obj: *mut ffi::PyObject) -> Option<Vec<u8>> {
    if obj.is_null() {
        return None;
    }
    let mut buf: *mut c_char = std::ptr::null_mut();
    let mut len: ffi::Py_ssize_t = 0;
    if ffi::PyBytes_AsStringAndSize(obj, &mut buf, &mut len) != 0 {
        ffi::PyErr_Clear();
        return None;
    }
    Some(std::slice::from_raw_parts(buf.cast::<u8>(), len as usize).to_vec())
}

/// Clear any pending Python error (printing the traceback to stderr — a bridge fault is a server
/// bug, not a client one) and return the canonical INTERNAL_ERROR. Must run with the GIL held.
#[allow(unsafe_code)]
unsafe fn clear_and_internal() -> PyResult {
    if !ffi::PyErr_Occurred().is_null() {
        ffi::PyErr_Print();
        ffi::PyErr_Clear();
    }
    PyResult {
        outcome: PyOutcome::Error(JsonRpcError::new(
            ErrorCode::InternalError,
            "Internal error",
        )),
        audit_message: None,
    }
}

/// Print + clear a pending Python error and wrap `context` in a [`BridgeError`]. Must run with
/// the GIL held.
#[allow(unsafe_code)]
unsafe fn take_py_err(context: &str) -> BridgeError {
    if !ffi::PyErr_Occurred().is_null() {
        ffi::PyErr_Print();
        ffi::PyErr_Clear();
    }
    BridgeError(format!("python {context} failed"))
}

/// Map the Python `(status, payload, audit)` tuple onto a [`PyResult`].
fn decode_outcome(status: i64, payload: &[u8], audit: &[u8]) -> PyResult {
    let audit_message = (!audit.is_empty()).then(|| String::from_utf8_lossy(audit).into_owned());
    let outcome = if status == 0 {
        match RawValue::from_string(String::from_utf8_lossy(payload).into_owned()) {
            Ok(raw) => PyOutcome::Ok(raw),
            Err(e) => PyOutcome::Error(JsonRpcError::internal(format!(
                "python result was not valid JSON: {e}"
            ))),
        }
    } else {
        // A non-zero status is the JSON-RPC error code; the payload is the message.
        PyOutcome::Error(JsonRpcError::custom(
            status as i32,
            String::from_utf8_lossy(payload).into_owned(),
        ))
    };
    PyResult {
        outcome,
        audit_message,
    }
}

/// Build a NUL-terminated C string from `s`, mapping an interior NUL to a [`BridgeError`].
fn cstring(s: &str) -> Result<CString, BridgeError> {
    CString::new(s).map_err(|e| BridgeError(e.to_string()))
}

/// An error importing the Python module or its `dispatch` attribute.
#[derive(Debug)]
pub struct BridgeError(String);

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "python bridge error: {}", self.0)
    }
}

impl std::error::Error for BridgeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use serde_json::{json, Value};
    use truenas_rpc::{
        Dispatched, JsonRpcError, JsonRpcProtocol, MethodDef, NullOutbound, RequestCtx, Roles,
        RpcMethod,
    };

    const ID: &str = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";

    /// A dir placed on `sys.path` (via `PYTHONPATH`, set **before** the interpreter initializes) that
    /// test handler modules are written into, so `PyBridge::import` can load them by name — the same
    /// path production uses (no arbitrary-source exec).
    fn modules_dir() -> &'static std::path::Path {
        static DIR: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
        DIR.get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("tnrpc-pyo3-mods-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            // Set before the first `PyBridge` call triggers `Py_InitializeEx` (which reads it).
            std::env::set_var("PYTHONPATH", &dir);
            dir
        })
    }

    /// Write `source` as `<name>.py` into the importable dir and load it with `PyBridge::import`.
    fn bridge_from(name: &str, source: &str) -> PyBridge {
        std::fs::write(modules_dir().join(format!("{name}.py")), source).unwrap();
        PyBridge::import(name).unwrap()
    }

    /// Build a `PyBridge` over a handler module implementing the contract. `call` is accepted (the
    /// 4-arg shape) but unused here.
    fn bridge() -> PyBridge {
        bridge_from(
            "pyo3_echo_handlers",
            r#"
import json
def dispatch(name, params, session, call):
    if name == "py.echo":
        p = json.loads(params)
        s = json.loads(session)
        out = {"echoed": p, "lifecycle": s["lifecycle"]}
        return (0, json.dumps(out).encode(), b"echoed in python")
    if name == "py.boom":
        return (-32603, b"boom", b"")
    return (-32601, b"Method not found", b"")
"#,
        )
    }

    /// A bridge whose bodies reach back into the core through `call`: `py.viacall` calls `op_add`,
    /// `py.viacall_elev` calls the ADMIN-gated `op_guarded` elevated, `py.viacall_gated` calls it
    /// as-the-caller and turns the raised `RuntimeError((code, message))` back into a status.
    fn call_bridge() -> PyBridge {
        bridge_from(
            "pyo3_call_handlers",
            r#"
def dispatch(name, params, session, call):
    if name == "py.viacall":
        return (0, call("op_add", b'{"a":2,"b":40}'), b"")
    if name == "py.viacall_elev":
        return (0, call("op_guarded", b'{"a":2,"b":40}', True), b"")
    if name == "py.viacall_gated":
        try:
            call("op_guarded", b'{"a":2,"b":40}')
            return (0, b"null", b"")
        except RuntimeError as e:
            code, message = e.args
            return (code, message.encode(), b"")
    return (-32601, b"Method not found", b"")
"#,
        )
    }

    async fn call(proto: &JsonRpcProtocol<()>, method: &str, params: &str) -> Value {
        let s = proto.new_session(Some(()), Arc::new(NullOutbound));
        let wire =
            format!(r#"{{"jsonrpc":"2.0","method":"{method}","id":"{ID}","params":{params}}}"#);
        match proto.dispatch(wire.as_bytes(), &s).await {
            Dispatched::Reply(b) => serde_json::from_slice(&b).unwrap(),
            Dispatched::Nothing => panic!("expected a reply"),
            Dispatched::Transfer(_) | Dispatched::Passthrough(_) | Dispatched::Sessions { .. } => {
                panic!("unexpected transfer/passthrough")
            }
        }
    }

    #[tokio::test]
    async fn python_body_runs_and_sees_params_and_session() {
        let proto = JsonRpcProtocol::<()>::builder("t", "1")
            .python_method(MethodDef::new("py.echo"))
            .unwrap()
            .python_method(MethodDef::new("py.boom"))
            .unwrap()
            .python_dispatcher(bridge())
            .build();

        // Success: the body received the params + the session view (lifecycle 0 = None).
        let v = call(&proto, "py.echo", r#"{"x": 1}"#).await;
        assert_eq!(v["result"]["echoed"]["x"], 1);
        assert_eq!(v["result"]["lifecycle"], 0);

        // Error: a non-zero status becomes the JSON-RPC error code.
        let v = call(&proto, "py.boom", "{}").await;
        assert_eq!(v["error"]["code"], -32603);
    }

    #[tokio::test]
    async fn python_body_calls_core_via_call() {
        // Two core methods a body can reach: `op_add` (open) and `op_guarded` (ADMIN-gated).
        let add = |p: Value, _c: &RequestCtx<()>| {
            let sum = p["a"].as_i64().unwrap_or(0) + p["b"].as_i64().unwrap_or(0);
            Ok::<_, JsonRpcError>(json!({ "sum": sum }))
        };
        let proto = JsonRpcProtocol::<()>::builder("t", "1")
            .roles(Roles::new(["ADMIN"]))
            .method(RpcMethod::new(MethodDef::new("op_add"), add))
            .unwrap()
            .method(RpcMethod::new(
                MethodDef::new("op_guarded").roles(["ADMIN"]),
                add,
            ))
            .unwrap()
            .python_method(MethodDef::new("py.viacall"))
            .unwrap()
            .python_method(MethodDef::new("py.viacall_elev"))
            .unwrap()
            .python_method(MethodDef::new("py.viacall_gated"))
            .unwrap()
            .python_dispatcher(call_bridge())
            .build();

        // The body reaches `op_add` in-process through `call` and returns its result.
        assert_eq!(call(&proto, "py.viacall", "{}").await["result"]["sum"], 42);
        // An elevated call bypasses the gate (the fresh session lacks ADMIN).
        assert_eq!(
            call(&proto, "py.viacall_elev", "{}").await["result"]["sum"],
            42
        );
        // As-the-caller, the ADMIN gate denies — the -32000 surfaces to the body and back out.
        assert_eq!(
            call(&proto, "py.viacall_gated", "{}").await["error"]["code"],
            -32000
        );
    }

    #[test]
    fn decode_outcome_maps_status_payload_audit() {
        // ok + audit
        let r = decode_outcome(0, br#"{"ok":true}"#, b"did it");
        assert!(matches!(r.outcome, PyOutcome::Ok(_)));
        assert_eq!(r.audit_message.as_deref(), Some("did it"));
        // error, no audit
        let r = decode_outcome(-32602, b"bad", b"");
        assert!(matches!(r.outcome, PyOutcome::Error(e) if e.code == -32602));
        assert_eq!(r.audit_message, None);
        // ok but non-JSON payload → internal error
        let r = decode_outcome(0, b"not json", b"");
        assert!(matches!(r.outcome, PyOutcome::Error(e) if e.code == -32603));
    }

    #[test]
    fn bridge_error_displays() {
        let e = BridgeError("no module".to_string());
        assert!(format!("{e}").contains("no module"));
    }
}
