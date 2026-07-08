//! Stage 2 — the `self.cache` pattern: a handler owns its state store as `self.cache` (an
//! `Arc<Cache<V>>`) and reads/writes it while serving RPCs. This is how a generated `Handlers` impl
//! holds server-wide state; here the handler reaches it through a captured `Arc` (the closure form
//! the protocol builder accepts). **No core change** — `truenas-rpc` stays `unsafe_code = "forbid"`;
//! the cache is a dev-dependency of this crate only.
//!
//! Two tests, two properties:
//!   - [`cache_backed_handler_served_over_unix_socket`] — the pattern works over the **real server
//!     transport**: a note written by `note.put` is read back by `note.get` across an AF_UNIX socket
//!     (framing → negotiate → dispatch → handler → cache). Uses the in-memory backend.
//!   - [`persistent_cache_survives_env_reopen`] — a note written by a handler into the **persistent
//!     LMDB** backend survives the protocol and its `Env` being dropped and the `Env` reopened at the
//!     same path (a process restart). Driven through the in-process dispatcher so teardown is
//!     deterministic: with no background task holding an `Env`, dropping the scope actually closes
//!     the environment (the per-path env pool closes it on last drop) — the prerequisite for the
//!     reopen to be a genuine reopen rather than a shared live handle. The env pool itself is covered
//!     by the cache crate's own tests.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use truenas_rpc::{
    Dispatched, JsonRpcError, JsonRpcProtocol, MethodDef, NullOutbound, RequestCtx, RpcMethod,
    Session,
};
use truenas_rpc_cache::{Cache, Env, EnvFlags};
use truenas_rpc_server::{framing, JsonRpc, TruenasRpcServer, UnixConfig};

// Bound (non-`$/`) requests must carry a UUID id; reused across each connection's sequential calls.
const RID: &str = "123e4567-e89b-12d3-a456-426614174000";
const MAP_SIZE: usize = 64 << 20;
const MAX_DBS: u32 = 4;

/// A small serde record — a stand-in for the session / state data a real service keeps in the cache.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Note {
    author: String,
    body: String,
}

#[derive(Serialize, Deserialize)]
struct PutArgs {
    key: String,
    author: String,
    body: String,
}
#[derive(Serialize, Deserialize)]
struct GetArgs {
    key: String,
}

/// A handler that owns its state store as `self.cache` — the shape a generated `Handlers` impl
/// takes. `put` / `get` are ordinary methods that touch the cache (any backend); a cache error
/// surfaces as a JSON-RPC internal error. The backend is chosen by the caller who builds it.
struct Notes {
    cache: Arc<Cache<Note>>,
}

impl Notes {
    fn put(&self, a: PutArgs) -> Result<Value, JsonRpcError> {
        let note = Note {
            author: a.author,
            body: a.body,
        };
        // A one-hour TTL, like a session record; the deadline is wall-clock, so it survives reboots.
        self.cache
            .put(&a.key, &note, Some(Duration::from_secs(3600)))
            .map_err(|e| JsonRpcError::internal(e.to_string()))?;
        Ok(json!({ "stored": true }))
    }

    fn get(&self, a: GetArgs) -> Result<Value, JsonRpcError> {
        let note = self
            .cache
            .get(&a.key)
            .map_err(|e| JsonRpcError::internal(e.to_string()))?;
        Ok(json!({ "note": note }))
    }
}

/// Wire the `Notes` methods into a protocol; each handler holds a clone of the shared `Arc<Notes>`
/// and calls a method on it — i.e. it reaches state via `self.cache`.
fn proto(notes: Arc<Notes>) -> JsonRpcProtocol<()> {
    let put = Arc::clone(&notes);
    let get = notes;
    JsonRpcProtocol::<()>::builder("notes", "1")
        .method(RpcMethod::new(
            MethodDef::new("note.put"),
            move |a: PutArgs, _cx: &RequestCtx<()>| put.put(a),
        ))
        .unwrap()
        .method(RpcMethod::new(
            MethodDef::new("note.get"),
            move |a: GetArgs, _cx: &RequestCtx<()>| get.get(a),
        ))
        .unwrap()
        .build()
}

// --- Test A: over the real AF_UNIX transport ----------------------------------------------------

fn server(notes: Arc<Notes>) -> TruenasRpcServer<()> {
    // This protocol has no `$/sessionSetup`; opt past the network-auth guard (as the transport tests do).
    TruenasRpcServer::<()>::builder("notes-server")
        .protocol("notes", proto(notes))
        .allow_unauthenticated_network()
        .build()
}

/// Frame `req`, write it, then read + parse the one framed reply.
async fn wire_call(stream: &mut UnixStream, req: Value) -> Value {
    let bytes = serde_json::to_vec(&req).unwrap();
    stream.write_all(&framing::frame(&bytes)).await.unwrap();
    let reply = framing::read_message(stream, framing::DEFAULT_LIMIT)
        .await
        .unwrap()
        .unwrap();
    serde_json::from_slice(&reply).unwrap()
}

async fn negotiate(stream: &mut UnixStream) {
    let neg = wire_call(
        stream,
        json!({"jsonrpc":"2.0","method":"$/negotiate","id":"neg","params":{"protocol":"notes"}}),
    )
    .await;
    assert_eq!(neg["result"]["protocol"], "notes");
}

#[tokio::test]
async fn cache_backed_handler_served_over_unix_socket() {
    let sock = std::env::temp_dir().join(format!("tn-cache-sock-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock);

    // In-memory backend: the transport/handler/cache path, no persistence concern.
    let notes = Arc::new(Notes {
        cache: Arc::new(Cache::memory()),
    });
    let listener = TruenasRpcServer::<()>::bind_unix(&UnixConfig::new(&sock)).unwrap();
    let srv = server(notes);
    let task = tokio::spawn(async move { srv.serve_unix_listener(listener, JsonRpc).await });

    let mut c = UnixStream::connect(&sock).await.unwrap();
    negotiate(&mut c).await;

    let put = wire_call(
        &mut c,
        json!({"jsonrpc":"2.0","method":"note.put","id":RID,
               "params":{"key":"g","author":"alice","body":"hi over the wire"}}),
    )
    .await;
    assert_eq!(put["result"]["stored"], true, "put: {put}");

    let got = wire_call(
        &mut c,
        json!({"jsonrpc":"2.0","method":"note.get","id":RID,"params":{"key":"g"}}),
    )
    .await;
    assert_eq!(
        got["result"]["note"]["author"], "alice",
        "round-trip: {got}"
    );
    assert_eq!(got["result"]["note"]["body"], "hi over the wire");

    task.abort();
    let _ = std::fs::remove_file(&sock);
}

// --- Test B: persistence across an env reopen, via the in-process dispatcher ---------------------

/// Dispatch one JSON-RPC call in-process and return the parsed reply.
async fn dispatch_call(
    p: &JsonRpcProtocol<()>,
    s: &Arc<Session<()>>,
    method: &str,
    params: Value,
) -> Value {
    let wire = json!({"jsonrpc":"2.0","method":method,"id":RID,"params":params});
    match p.dispatch(wire.to_string().as_bytes(), s).await {
        Dispatched::Reply(b) => serde_json::from_slice(&b).unwrap(),
        _ => panic!("expected a Reply for {method}"),
    }
}

#[tokio::test]
async fn persistent_cache_survives_env_reopen() {
    let dir = std::env::temp_dir().join(format!("tn-cache-state-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    // --- Phase 1: a handler writes then reads a note through the persistent cache. ---
    {
        let env = Env::open(&dir, MAP_SIZE, MAX_DBS, EnvFlags::durable(), 0o600).unwrap();
        let notes = Arc::new(Notes {
            cache: Arc::new(Cache::persistent(&env, "notes").unwrap()),
        });
        let p = proto(notes);
        let s = p.new_session(Some(()), Arc::new(NullOutbound));

        let put = dispatch_call(
            &p,
            &s,
            "note.put",
            json!({"key":"greeting","author":"alice","body":"hello across reboots"}),
        )
        .await;
        assert_eq!(put["result"]["stored"], true, "put failed: {put}");

        let got = dispatch_call(&p, &s, "note.get", json!({"key":"greeting"})).await;
        assert_eq!(
            got["result"]["note"]["author"], "alice",
            "round-trip: {got}"
        );
        assert_eq!(got["result"]["note"]["body"], "hello across reboots");

        // Scope end drops p (→ handlers → Arc<Notes> → Arc<Cache> → its env handle), s, and env —
        // the last handles for this path, so the pool force-syncs and closes the environment here.
    }

    // --- Phase 2: reopen the env at the same path (as a restarted process would). It persisted. ---
    {
        let env = Env::open(&dir, MAP_SIZE, MAX_DBS, EnvFlags::durable(), 0o600).unwrap();
        let cache: Cache<Note> = Cache::persistent(&env, "notes").unwrap();
        assert_eq!(
            cache.get("greeting").unwrap(),
            Some(Note {
                author: "alice".into(),
                body: "hello across reboots".into(),
            }),
            "the note written via a handler must survive an env reopen",
        );
        // A key never written reads as absent — we're reading real persisted state, not a stub.
        assert_eq!(cache.get("absent").unwrap(), None);
    }

    let _ = std::fs::remove_dir_all(&dir);
}
