//! The `RawClient` Python type (raw `pyo3-ffi` heap type) + the module-level `connect`. `RawClient`
//! owns a connected `truenas-rpc-client` engine and exposes a **byte boundary**:
//! `call(method: str, params: bytes) -> bytes`. It is created by `connect(path, protocol)` (or, when
//! embedding, by [`make_raw_client`]) — never by `RawClient()` directly.
//!
//! A call runs the async engine on the shared runtime with the **GIL released** (the params/method
//! are copied out first), so wire I/O never stalls other Python threads. A server error is raised as
//! `RpcError((code, message))`.

use std::mem::size_of;
use std::os::raw::{c_char, c_int, c_long, c_uint, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::OnceLock;

use pyo3_ffi as ffi;
use truenas_rpc_client::{JsonRpcClient, Negotiated};

use crate::bridge::{call_blocking, connect_unix};

const INTERNAL_ERROR: i32 = -32603;

/// A CPython object pointer stashed for the process lifetime (the `RawClient` type + the `RpcError`
/// exception). Only ever created/read under the GIL, so sharing it across threads is sound.
struct SendPtr(*mut ffi::PyObject);
// SAFETY: the pointer is only dereferenced under the GIL (CPython's global lock).
#[allow(unsafe_code)]
unsafe impl Send for SendPtr {}
#[allow(unsafe_code)]
unsafe impl Sync for SendPtr {}

static RAWCLIENT_TYPE: OnceLock<SendPtr> = OnceLock::new();
static RPC_ERROR: OnceLock<SendPtr> = OnceLock::new();

/// The Rust state a `RawClient` owns: the connected engine (its background recv/writer tasks live on
/// the shared runtime until this is dropped) + the `$/negotiate` result (surfaced by
/// `RawClient.negotiated()`; `None` for an embedder-built client that never negotiated).
struct RawInner {
    client: JsonRpcClient,
    negotiated: Option<Negotiated>,
}

/// The `RawClient` instance layout: the `PyObject` header followed by a thin pointer to the boxed
/// [`RawInner`] (null before init / after dealloc).
#[repr(C)]
struct RawClientObject {
    ob_base: ffi::PyObject,
    inner: *mut RawInner,
}

/// A `Sync` wrapper so a `PyMethodDef` array can live in a `static` (CPython only reads it).
struct MethodDefs<const N: usize>([ffi::PyMethodDef; N]);
// SAFETY: read-only to CPython; all pointers are to `'static` data.
#[allow(unsafe_code)]
unsafe impl<const N: usize> Sync for MethodDefs<N> {}

/// `RawClient`'s methods: `call` + `negotiated` (plus the null sentinel).
static RAWCLIENT_METHODS: MethodDefs<3> = MethodDefs([
    ffi::PyMethodDef {
        ml_name: c"call".as_ptr().cast::<c_char>(),
        ml_meth: ffi::PyMethodDefPointer {
            PyCFunction: rawclient_call,
        },
        ml_flags: ffi::METH_VARARGS,
        ml_doc: c"call(method: str, params: bytes) -> bytes"
            .as_ptr()
            .cast::<c_char>(),
    },
    ffi::PyMethodDef {
        ml_name: c"negotiated".as_ptr().cast::<c_char>(),
        ml_meth: ffi::PyMethodDefPointer {
            PyCFunction: rawclient_negotiated,
        },
        ml_flags: ffi::METH_NOARGS,
        ml_doc: c"negotiated() -> dict | None  ({'protocol','server','available'})"
            .as_ptr()
            .cast::<c_char>(),
    },
    ffi::PyMethodDef::zeroed(),
]);

/// The module's `connect` function table (referenced by `MODULE_DEF`).
static CONNECT_METHODS: MethodDefs<2> = MethodDefs([
    ffi::PyMethodDef {
        ml_name: c"connect".as_ptr().cast::<c_char>(),
        ml_meth: ffi::PyMethodDefPointer {
            PyCFunction: mod_connect,
        },
        ml_flags: ffi::METH_VARARGS,
        ml_doc: c"connect(path: str, protocol: str) -> RawClient  (AF_UNIX)"
            .as_ptr()
            .cast::<c_char>(),
    },
    ffi::PyMethodDef::zeroed(),
]);

static RAWCLIENT_DOC: &[u8] =
    b"A thin byte-boundary RPC client: call(method: str, params: bytes) -> bytes.\0";

/// Create the `RawClient` type + the `RpcError` exception and add them to `module`. Called once by
/// `PyInit_truenas_rpc_pyclient` (GIL held). Returns `0` on success, `-1` with a Python error set.
#[allow(unsafe_code)]
pub(crate) unsafe fn init_types(module: *mut ffi::PyObject) -> c_int {
    let mut slots = [
        ffi::PyType_Slot {
            slot: ffi::Py_tp_dealloc,
            pfunc: rawclient_dealloc as *mut c_void,
        },
        ffi::PyType_Slot {
            slot: ffi::Py_tp_new,
            pfunc: rawclient_tp_new as *mut c_void,
        },
        ffi::PyType_Slot {
            slot: ffi::Py_tp_methods,
            pfunc: (&RAWCLIENT_METHODS.0 as *const ffi::PyMethodDef as *mut c_void),
        },
        ffi::PyType_Slot {
            slot: ffi::Py_tp_doc,
            pfunc: RAWCLIENT_DOC.as_ptr() as *mut c_void,
        },
        ffi::PyType_Slot {
            slot: 0,
            pfunc: std::ptr::null_mut(),
        },
    ];
    let mut spec = ffi::PyType_Spec {
        name: c"truenas_rpc_pyclient.RawClient".as_ptr().cast::<c_char>(),
        basicsize: size_of::<RawClientObject>() as c_int,
        itemsize: 0,
        flags: ffi::Py_TPFLAGS_DEFAULT as c_uint,
        slots: slots.as_mut_ptr(),
    };
    let ty = ffi::PyType_FromSpec(&mut spec);
    if ty.is_null() {
        return -1;
    }
    let _ = RAWCLIENT_TYPE.set(SendPtr(ty)); // keep a process-lifetime ref (never decref'd)
    ffi::Py_INCREF(ty); // one for the module (AddObject steals), one for our stashed pointer
    if ffi::PyModule_AddObject(module, c"RawClient".as_ptr().cast::<c_char>(), ty) < 0 {
        ffi::Py_DECREF(ty);
        return -1;
    }

    let exc = ffi::PyErr_NewException(
        c"truenas_rpc_pyclient.RpcError".as_ptr().cast::<c_char>(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );
    if exc.is_null() {
        return -1;
    }
    let _ = RPC_ERROR.set(SendPtr(exc));
    ffi::Py_INCREF(exc);
    if ffi::PyModule_AddObject(module, c"RpcError".as_ptr().cast::<c_char>(), exc) < 0 {
        ffi::Py_DECREF(exc);
        return -1;
    }
    0
}

/// Wrap a connected engine in a fresh `RawClient` (no negotiate info), bypassing `tp_new` (the guard
/// is only for `RawClient()` from Python). For embedding: the host connects in Rust and hands the
/// object to Python. `RawClient.negotiated()` returns `None` for such a client.
///
/// # Safety
/// Must run with the GIL held (and after the module is initialized). Returns a new reference (or
/// null with a Python error set).
#[allow(unsafe_code)]
pub unsafe fn make_raw_client(client: JsonRpcClient) -> *mut ffi::PyObject {
    alloc_raw(client, None)
}

/// Like [`make_raw_client`], but records the `$/negotiate` result (surfaced by
/// `RawClient.negotiated()`).
///
/// # Safety
/// Must run with the GIL held (and after the module is initialized).
#[allow(unsafe_code)]
pub unsafe fn make_raw_client_negotiated(
    client: JsonRpcClient,
    negotiated: Negotiated,
) -> *mut ffi::PyObject {
    alloc_raw(client, Some(negotiated))
}

/// Allocate a `RawClient` wrapping `client` (+ optional negotiate info). Must run with the GIL held.
#[allow(unsafe_code)]
unsafe fn alloc_raw(client: JsonRpcClient, negotiated: Option<Negotiated>) -> *mut ffi::PyObject {
    let ty = match RAWCLIENT_TYPE.get() {
        Some(t) => t.0,
        None => {
            set_runtime_error("truenas_rpc_pyclient module was not initialized");
            return std::ptr::null_mut();
        }
    };
    let obj = ffi::PyType_GenericAlloc(ty.cast::<ffi::PyTypeObject>(), 0);
    if obj.is_null() {
        return std::ptr::null_mut();
    }
    (*(obj.cast::<RawClientObject>())).inner =
        Box::into_raw(Box::new(RawInner { client, negotiated }));
    obj
}

/// `tp_dealloc`: drop the owned engine (aborting its runtime tasks), then free the object and
/// release the heap type's per-instance ref.
#[allow(unsafe_code)]
unsafe extern "C" fn rawclient_dealloc(slf: *mut ffi::PyObject) {
    let obj = slf.cast::<RawClientObject>();
    if !(*obj).inner.is_null() {
        drop(Box::from_raw((*obj).inner));
        (*obj).inner = std::ptr::null_mut();
    }
    let ty = ffi::Py_TYPE(slf);
    let free = ffi::PyType_GetSlot(ty, ffi::Py_tp_free);
    if !free.is_null() {
        let free: ffi::freefunc = std::mem::transmute(free);
        free(slf.cast::<c_void>());
    }
    ffi::Py_DECREF(ty.cast::<ffi::PyObject>()); // instances of a heap type hold a ref on the type
}

/// `tp_new`: `RawClient` isn't constructible from Python — direct the caller to `connect(...)`.
#[allow(unsafe_code)]
unsafe extern "C" fn rawclient_tp_new(
    _ty: *mut ffi::PyTypeObject,
    _args: *mut ffi::PyObject,
    _kwds: *mut ffi::PyObject,
) -> *mut ffi::PyObject {
    set_runtime_error("RawClient() is not constructible; use truenas_rpc_pyclient.connect(...)");
    std::ptr::null_mut()
}

/// `RawClient.call(method, params) -> bytes`: parse the args, run the engine on the shared runtime
/// with the GIL released, and return the raw result bytes (or raise `RpcError`).
#[allow(unsafe_code)]
unsafe extern "C" fn rawclient_call(
    slf: *mut ffi::PyObject,
    args: *mut ffi::PyObject,
) -> *mut ffi::PyObject {
    let inner = (*(slf.cast::<RawClientObject>())).inner;
    if inner.is_null() {
        set_rpc_error(INTERNAL_ERROR, "RawClient is not connected");
        return std::ptr::null_mut();
    }
    // Parse (method: str, params: bytes) and copy them out so nothing Python is touched once the GIL
    // is released.
    let (method, params) = match parse_call_args(args) {
        Some(pair) => pair,
        None => return std::ptr::null_mut(),
    };

    let tstate = ffi::PyEval_SaveThread();
    let result = catch_unwind(AssertUnwindSafe(|| {
        call_blocking(&(*inner).client, &method, &params)
    }));
    ffi::PyEval_RestoreThread(tstate);

    match result {
        Ok(Ok(bytes)) => {
            ffi::PyBytes_FromStringAndSize(bytes.as_ptr().cast::<c_char>(), to_ssize(bytes.len()))
        }
        Ok(Err(e)) => {
            set_rpc_error(e.code, &e.message);
            std::ptr::null_mut()
        }
        Err(_) => {
            set_rpc_error(INTERNAL_ERROR, "call panicked");
            std::ptr::null_mut()
        }
    }
}

/// `RawClient.negotiated() -> dict | None`: the `$/negotiate` result as
/// `{"protocol": str, "server": str | None, "available": list[str]}`, or `None` if this client was
/// built without negotiating (the embedder path).
#[allow(unsafe_code)]
unsafe extern "C" fn rawclient_negotiated(
    slf: *mut ffi::PyObject,
    _args: *mut ffi::PyObject,
) -> *mut ffi::PyObject {
    let inner = (*(slf.cast::<RawClientObject>())).inner;
    if inner.is_null() {
        set_rpc_error(INTERNAL_ERROR, "RawClient is not connected");
        return std::ptr::null_mut();
    }
    match &(*inner).negotiated {
        Some(neg) => negotiated_dict(neg),
        None => {
            let none = ffi::Py_None();
            ffi::Py_INCREF(none);
            none
        }
    }
}

/// Build `{"protocol": str, "server": str | None, "available": list[str]}` from `neg`. Returns null
/// with a Python error set on failure. Must run with the GIL held.
#[allow(unsafe_code)]
unsafe fn negotiated_dict(neg: &Negotiated) -> *mut ffi::PyObject {
    let dict = ffi::PyDict_New();
    if dict.is_null() {
        return std::ptr::null_mut();
    }
    if !dict_set_str(dict, b"protocol\0", &neg.protocol) {
        ffi::Py_DECREF(dict);
        return std::ptr::null_mut();
    }
    // server: str | None. `PyDict_SetItemString` INCREFs its value, so `Py_None` needs no owned ref.
    let server_ok = match &neg.server {
        Some(s) => dict_set_str(dict, b"server\0", s),
        None => {
            ffi::PyDict_SetItemString(dict, c"server".as_ptr().cast::<c_char>(), ffi::Py_None())
                == 0
        }
    };
    if !server_ok {
        ffi::Py_DECREF(dict);
        return std::ptr::null_mut();
    }
    // available: list[str].
    let list = ffi::PyList_New(to_ssize(neg.available.len()));
    if list.is_null() {
        ffi::Py_DECREF(dict);
        return std::ptr::null_mut();
    }
    for (i, s) in neg.available.iter().enumerate() {
        let item = ffi::PyUnicode_FromStringAndSize(s.as_ptr().cast::<c_char>(), to_ssize(s.len()));
        if item.is_null() {
            ffi::Py_DECREF(list);
            ffi::Py_DECREF(dict);
            return std::ptr::null_mut();
        }
        ffi::PyList_SetItem(list, i as ffi::Py_ssize_t, item); // steals `item`
    }
    let rc = ffi::PyDict_SetItemString(dict, c"available".as_ptr().cast::<c_char>(), list);
    ffi::Py_DECREF(list); // `SetItemString` does not steal
    if rc != 0 {
        ffi::Py_DECREF(dict);
        return std::ptr::null_mut();
    }
    dict
}

/// `dict[key] = str(value)` (key is a NUL-terminated byte string); `false` on failure (error set).
/// Must run with the GIL held.
#[allow(unsafe_code)]
unsafe fn dict_set_str(dict: *mut ffi::PyObject, key: &[u8], value: &str) -> bool {
    let v =
        ffi::PyUnicode_FromStringAndSize(value.as_ptr().cast::<c_char>(), to_ssize(value.len()));
    if v.is_null() {
        return false;
    }
    let rc = ffi::PyDict_SetItemString(dict, key.as_ptr().cast::<c_char>(), v);
    ffi::Py_DECREF(v); // `SetItemString` INCREFs; drop our construction ref
    rc == 0
}

/// The module-level `connect(path, protocol) -> RawClient` (AF_UNIX). Connects on the shared runtime
/// with the GIL released.
#[allow(unsafe_code)]
unsafe extern "C" fn mod_connect(
    _self: *mut ffi::PyObject,
    args: *mut ffi::PyObject,
) -> *mut ffi::PyObject {
    if ffi::PyTuple_Size(args) != 2 {
        set_runtime_error("connect(path, protocol) takes 2 arguments");
        return std::ptr::null_mut();
    }
    let path = match utf8_arg(args, 0) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let protocol = match utf8_arg(args, 1) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };

    let tstate = ffi::PyEval_SaveThread();
    let connected = catch_unwind(AssertUnwindSafe(|| connect_unix(&path, &protocol)));
    ffi::PyEval_RestoreThread(tstate);

    match connected {
        Ok(Ok((client, negotiated))) => make_raw_client_negotiated(client, negotiated),
        Ok(Err(msg)) => {
            set_rpc_error(INTERNAL_ERROR, &msg);
            std::ptr::null_mut()
        }
        Err(_) => {
            set_rpc_error(INTERNAL_ERROR, "connect panicked");
            std::ptr::null_mut()
        }
    }
}

/// Parse `RawClient.call`'s `(method: str, params: bytes)` into owned Rust values, or set a Python
/// error and return `None`. Must run with the GIL held.
#[allow(unsafe_code)]
unsafe fn parse_call_args(args: *mut ffi::PyObject) -> Option<(String, Vec<u8>)> {
    if ffi::PyTuple_Size(args) != 2 {
        set_runtime_error("call(method, params) takes 2 arguments");
        return None;
    }
    let method = utf8_arg(args, 0)?;
    let mut buf: *mut c_char = std::ptr::null_mut();
    let mut len: ffi::Py_ssize_t = 0;
    if ffi::PyBytes_AsStringAndSize(ffi::PyTuple_GetItem(args, 1), &mut buf, &mut len) != 0 {
        return None; // not bytes → TypeError already set
    }
    let params = std::slice::from_raw_parts(buf.cast::<u8>(), len as usize).to_vec();
    Some((method, params))
}

/// Extract tuple item `idx` as an owned `String` (a `str`), or set a Python error and return `None`.
#[allow(unsafe_code)]
unsafe fn utf8_arg(args: *mut ffi::PyObject, idx: ffi::Py_ssize_t) -> Option<String> {
    let mut len: ffi::Py_ssize_t = 0;
    let ptr = ffi::PyUnicode_AsUTF8AndSize(ffi::PyTuple_GetItem(args, idx), &mut len);
    if ptr.is_null() {
        return None; // not a str → TypeError already set
    }
    match std::str::from_utf8(std::slice::from_raw_parts(ptr.cast::<u8>(), len as usize)) {
        Ok(s) => Some(s.to_string()),
        Err(_) => {
            set_runtime_error("argument was not valid UTF-8");
            None
        }
    }
}

/// Raise `RpcError((code, message))` (falling back to `RuntimeError` if the module's exception isn't
/// registered). Must run with the GIL held.
#[allow(unsafe_code)]
unsafe fn set_rpc_error(code: i32, message: &str) {
    let exc = RPC_ERROR
        .get()
        .map(|p| p.0)
        .unwrap_or(ffi::PyExc_RuntimeError);
    let tup = ffi::PyTuple_New(2);
    let c = ffi::PyLong_FromLong(code as c_long);
    let m = ffi::PyUnicode_FromStringAndSize(
        message.as_ptr().cast::<c_char>(),
        to_ssize(message.len()),
    );
    if tup.is_null() || c.is_null() || m.is_null() {
        ffi::Py_XDECREF(tup);
        ffi::Py_XDECREF(c);
        ffi::Py_XDECREF(m);
        set_runtime_error(message);
        return;
    }
    ffi::PyTuple_SetItem(tup, 0, c); // steals
    ffi::PyTuple_SetItem(tup, 1, m); // steals
    ffi::PyErr_SetObject(exc, tup);
    ffi::Py_XDECREF(tup); // `PyErr_SetObject` INCREFs its value
}

/// Raise `RuntimeError(msg)` (an interior NUL falls back to a fixed message). Must run with the GIL
/// held.
#[allow(unsafe_code)]
unsafe fn set_runtime_error(msg: &str) {
    match std::ffi::CString::new(msg) {
        Ok(c) => ffi::PyErr_SetString(ffi::PyExc_RuntimeError, c.as_ptr()),
        Err(_) => ffi::PyErr_SetString(
            ffi::PyExc_RuntimeError,
            c"raw client error".as_ptr().cast::<c_char>(),
        ),
    }
}

/// `len as Py_ssize_t`, saturating (our buffers never approach the max).
fn to_ssize(len: usize) -> ffi::Py_ssize_t {
    len.min(ffi::Py_ssize_t::MAX as usize) as ffi::Py_ssize_t
}

// --- the extension module ----------------------------------------------------

/// The module definition. It must be a `static mut`: CPython's `PyModuleDef_Init` writes the
/// def's `ob_base` (refcount + type) on first `PyModule_Create`, so it has to sit in **writable**
/// memory (a plain `static` lands in read-only `.rodata` and the write faults). Only ever touched by
/// `PyInit_truenas_rpc_pyclient` under the GIL.
static mut MODULE_DEF: ffi::PyModuleDef = ffi::PyModuleDef {
    m_base: ffi::PyModuleDef_HEAD_INIT,
    m_name: c"truenas_rpc_pyclient".as_ptr().cast::<c_char>(),
    m_doc: std::ptr::null(),
    m_size: -1, // no per-module state
    m_methods: &CONNECT_METHODS.0 as *const ffi::PyMethodDef as *mut ffi::PyMethodDef,
    m_slots: std::ptr::null_mut(),
    m_traverse: None,
    m_clear: None,
    m_free: None,
};

/// The extension-module initializer (the `import truenas_rpc_pyclient` entry point): create the
/// module and add the `RawClient` type + `RpcError` exception.
///
/// # Safety
/// A CPython init hook — call only via the interpreter (import / `PyImport_AppendInittab`), GIL held.
#[allow(unsafe_code)]
#[no_mangle]
pub unsafe extern "C" fn PyInit_truenas_rpc_pyclient() -> *mut ffi::PyObject {
    let module = ffi::PyModule_Create(std::ptr::addr_of_mut!(MODULE_DEF));
    if module.is_null() {
        return std::ptr::null_mut();
    }
    if init_types(module) < 0 {
        ffi::Py_DECREF(module);
        return std::ptr::null_mut();
    }
    module
}
