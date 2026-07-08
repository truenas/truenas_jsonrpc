//! In-process call primitive: a handler invoking other registered methods via `cx.call_op` /
//! `cx.call_named` with no wire round-trip. Covers success (sync / async / by-name), the role gate
//! (caller-privileged by default vs. explicit elevation), not-found / not-callable / handler-panic
//! errors, series-vs-scatter-gather batching (incl. a blocking sync op running in parallel on the
//! pool), and the opt-in elevated-audit policy. Generic — no naming of any future integration.

use std::any::Any;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use truenas_rpc::{
    AsyncRpcMethod, AuditOutcome, CompiledFilters, CompiledOptions, FilterableRpcMethod, Filtered,
    JsonRpcError, JsonRpcProtocol, JsonRpcProtocolBuilder, MethodDef, NullOutbound, RequestCtx,
    RequestInfo, Roles, RpcMethod, Session, SubscriptionDef,
};

const OP_ADD: u32 = 2001; // sync
const OP_SLOW: u32 = 2002; // sync, blocking sleep — used by the scatter/series timing test
const OP_AADD: u32 = 2003; // async
const OP_GUARDED: u32 = 2004; // sync, requires the ADMIN role
const OP_BOOM: u32 = 2005; // sync, panics
const SLEEP_MS: u64 = 60;
const K: usize = 4;

#[derive(Serialize, Deserialize, Clone)]
struct Pair {
    a: i64,
    b: i64,
}
#[derive(Serialize, Deserialize)]
struct Sum {
    sum: i64,
}

fn as_sum(b: Box<dyn Any + Send>) -> Sum {
    *b.downcast::<Sum>().expect("result is a Sum")
}

/// Register the callable sub-ops + the driver methods that exercise the in-process call surface.
/// Returns the builder so a test can layer on an audit sink / policy before `build()`.
fn base() -> JsonRpcProtocolBuilder<()> {
    JsonRpcProtocol::<()>::builder("t", "1")
        .roles(Roles::new(["ADMIN"]))
        // --- callable sub-operations ---
        .method(RpcMethod::new(
            MethodDef::new("op_add").xdr(OP_ADD),
            |p: Pair, _c: &RequestCtx<()>| Ok::<_, JsonRpcError>(Sum { sum: p.a + p.b }),
        ))
        .unwrap()
        .method(RpcMethod::new(
            MethodDef::new("op_slow").xdr(OP_SLOW),
            |_p: Pair, _c: &RequestCtx<()>| {
                std::thread::sleep(Duration::from_millis(SLEEP_MS)); // blocking I/O stand-in
                Ok::<_, JsonRpcError>(Sum { sum: 1 })
            },
        ))
        .unwrap()
        .async_method(AsyncRpcMethod::new(
            MethodDef::new("op_aadd").xdr(OP_AADD),
            |p: Pair, _c: RequestCtx<()>| async move { Ok::<_, JsonRpcError>(Sum { sum: p.a + p.b }) },
        ))
        .unwrap()
        .method(RpcMethod::new(
            MethodDef::new("op_guarded").xdr(OP_GUARDED).roles(["ADMIN"]),
            |p: Pair, _c: &RequestCtx<()>| Ok::<_, JsonRpcError>(Sum { sum: p.a + p.b }),
        ))
        .unwrap()
        .method(RpcMethod::new(
            MethodDef::new("op_boom").xdr(OP_BOOM),
            |_p: Pair, _c: &RequestCtx<()>| -> Result<Sum, JsonRpcError> {
                panic!("op handler blew up")
            },
        ))
        .unwrap()
        // a filterable method (by name) — internally callable returns an error
        .filterable(FilterableRpcMethod::<Pair, Sum, _>::new(
            MethodDef::new("op_filt"),
            |_p: Pair, _c: &RequestCtx<()>, _f: &CompiledFilters, _o: &CompiledOptions| {
                Ok::<_, JsonRpcError>(Filtered::Count(0))
            },
        ))
        .unwrap()
        // a subscription topic (by name) — not internally callable
        .subscription(SubscriptionDef::<Pair, Sum>::new(MethodDef::new("op_sub")))
        .unwrap()
        // --- drivers: each is dispatched on the wire and calls into the op-table in-process ---
        .async_method(AsyncRpcMethod::new(
            MethodDef::new("drv_sync"),
            |p: Pair, cx: RequestCtx<()>| async move {
                Ok::<_, JsonRpcError>(as_sum(cx.call_op(OP_ADD, Box::new(p)).await?))
            },
        ))
        .unwrap()
        .async_method(AsyncRpcMethod::new(
            MethodDef::new("drv_async"),
            |p: Pair, cx: RequestCtx<()>| async move {
                Ok::<_, JsonRpcError>(as_sum(cx.call_op(OP_AADD, Box::new(p)).await?))
            },
        ))
        .unwrap()
        .async_method(AsyncRpcMethod::new(
            MethodDef::new("drv_named"),
            |p: Pair, cx: RequestCtx<()>| async move {
                Ok::<_, JsonRpcError>(as_sum(cx.call_named("op_add", Box::new(p)).await?))
            },
        ))
        .unwrap()
        .async_method(AsyncRpcMethod::new(
            MethodDef::new("drv_guarded"),
            |p: Pair, cx: RequestCtx<()>| async move {
                Ok::<_, JsonRpcError>(as_sum(cx.call_op(OP_GUARDED, Box::new(p)).await?))
            },
        ))
        .unwrap()
        .async_method(AsyncRpcMethod::new(
            MethodDef::new("drv_guarded_elev"),
            |p: Pair, cx: RequestCtx<()>| async move {
                Ok::<_, JsonRpcError>(as_sum(cx.call_op_elevated(OP_GUARDED, Box::new(p)).await?))
            },
        ))
        .unwrap()
        .async_method(AsyncRpcMethod::new(
            MethodDef::new("drv_named_elev"),
            |p: Pair, cx: RequestCtx<()>| async move {
                Ok::<_, JsonRpcError>(as_sum(cx.call_named_elevated("op_guarded", Box::new(p)).await?))
            },
        ))
        .unwrap()
        .async_method(AsyncRpcMethod::new(
            MethodDef::new("drv_notfound"),
            |_p: Pair, cx: RequestCtx<()>| async move {
                Ok::<_, JsonRpcError>(as_sum(cx.call_op(9999, Box::new(Pair { a: 0, b: 0 })).await?))
            },
        ))
        .unwrap()
        .async_method(AsyncRpcMethod::new(
            MethodDef::new("drv_named_notfound"),
            |_p: Pair, cx: RequestCtx<()>| async move {
                Ok::<_, JsonRpcError>(as_sum(cx.call_named("nope", Box::new(())).await?))
            },
        ))
        .unwrap()
        .async_method(AsyncRpcMethod::new(
            MethodDef::new("drv_boom"),
            |p: Pair, cx: RequestCtx<()>| async move {
                Ok::<_, JsonRpcError>(as_sum(cx.call_op(OP_BOOM, Box::new(p)).await?))
            },
        ))
        .unwrap()
        .async_method(AsyncRpcMethod::new(
            MethodDef::new("drv_filt"),
            |_p: Pair, cx: RequestCtx<()>| async move {
                Ok::<_, JsonRpcError>(as_sum(cx.call_named("op_filt", Box::new(())).await?))
            },
        ))
        .unwrap()
        .async_method(AsyncRpcMethod::new(
            MethodDef::new("drv_sub"),
            |_p: Pair, cx: RequestCtx<()>| async move {
                Ok::<_, JsonRpcError>(as_sum(cx.call_named("op_sub", Box::new(())).await?))
            },
        ))
        .unwrap()
        .async_method(AsyncRpcMethod::new(
            MethodDef::new("drv_series"),
            |_p: Pair, cx: RequestCtx<()>| async move {
                let mut n = 0i64;
                for _ in 0..K {
                    cx.call_op(OP_SLOW, Box::new(Pair { a: 0, b: 0 })).await?;
                    n += 1;
                }
                Ok::<_, JsonRpcError>(Sum { sum: n })
            },
        ))
        .unwrap()
        .async_method(AsyncRpcMethod::new(
            MethodDef::new("drv_scatter"),
            |_p: Pair, cx: RequestCtx<()>| async move {
                // Scatter-gather: K independent ops in flight at once. The sync `op_slow` runs on
                // the blocking pool, so the K sleeps overlap.
                let mut set = tokio::task::JoinSet::new();
                for _ in 0..K {
                    let cx = cx.clone();
                    set.spawn(async move { cx.call_op(OP_SLOW, Box::new(Pair { a: 0, b: 0 })).await });
                }
                let mut n = 0i64;
                while let Some(joined) = set.join_next().await {
                    joined.expect("task")?;
                    n += 1;
                }
                Ok::<_, JsonRpcError>(Sum { sum: n })
            },
        ))
        .unwrap()
        // --- SYNC drivers: a sync handler makes a JSON in/out in-process call (`call_named_json`) ---
        .method(RpcMethod::new(
            MethodDef::new("drv_sync_call"),
            |p: Pair, cx: &RequestCtx<()>| json_sum(&cx.call_named_json("op_add", &to_json(&p))?),
        ))
        .unwrap()
        .method(RpcMethod::new(
            MethodDef::new("drv_sync_guarded"),
            |p: Pair, cx: &RequestCtx<()>| json_sum(&cx.call_named_json("op_guarded", &to_json(&p))?),
        ))
        .unwrap()
        .method(RpcMethod::new(
            MethodDef::new("drv_sync_elev"),
            |p: Pair, cx: &RequestCtx<()>| {
                json_sum(&cx.call_named_json_elevated("op_guarded", &to_json(&p))?)
            },
        ))
        .unwrap()
        .method(RpcMethod::new(
            MethodDef::new("drv_sync_async_target"),
            |p: Pair, cx: &RequestCtx<()>| json_sum(&cx.call_named_json("op_aadd", &to_json(&p))?),
        ))
        .unwrap()
}

/// Encode a `Pair` to JSON params for a byte (`call_named_json`) in-process call.
fn to_json(p: &Pair) -> Vec<u8> {
    serde_json::to_vec(p).unwrap()
}

/// Decode the bare-JSON `Sum` result of a byte in-process call.
fn json_sum(raw: &serde_json::value::RawValue) -> Result<Sum, JsonRpcError> {
    serde_json::from_str(raw.get()).map_err(|e| JsonRpcError::internal(e.to_string()))
}

fn session(proto: &JsonRpcProtocol<()>) -> Arc<Session<()>> {
    proto.new_session(Some(()), Arc::new(NullOutbound))
}

async fn call(proto: &JsonRpcProtocol<()>, s: &Arc<Session<()>>, method: &str) -> Value {
    let wire = json!({
        "jsonrpc": "2.0",
        "method": method,
        "id": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
        "params": { "a": 2, "b": 40 },
    })
    .to_string();
    let reply = proto
        .dispatch(wire.as_bytes(), s)
        .await
        .into_bytes()
        .unwrap();
    serde_json::from_slice(&reply).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_process_calls_succeed_sync_async_and_by_name() {
    let proto = base().build();
    let s = session(&proto);
    for m in ["drv_sync", "drv_async", "drv_named"] {
        let v = call(&proto, &s, m).await;
        assert_eq!(v["result"]["sum"], 42, "{m}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sync_in_process_calls_gate_elevate_and_reject_async() {
    let proto = base().build();
    let s = session(&proto); // fresh session: no ADMIN role granted
                             // A sync handler calls another sync method synchronously (no runtime hop).
    assert_eq!(call(&proto, &s, "drv_sync_call").await["result"]["sum"], 42);
    // The gate applies as-the-caller: the guarded op denies without ADMIN.
    assert_eq!(
        call(&proto, &s, "drv_sync_guarded").await["error"]["code"],
        -32000
    );
    // Elevated bypasses the gate.
    assert_eq!(call(&proto, &s, "drv_sync_elev").await["result"]["sum"], 42);
    // An async target isn't callable synchronously.
    assert_eq!(
        call(&proto, &s, "drv_sync_async_target").await["error"]["code"],
        -32603
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gate_applies_by_default_and_elevation_bypasses_it() {
    let proto = base().build();
    let s = session(&proto); // fresh session: no ADMIN role granted
                             // Caller-privileged: the guarded op's gate denies (fail-safe).
    let denied = call(&proto, &s, "drv_guarded").await;
    assert_eq!(
        denied["error"]["code"], -32000,
        "caller-privileged call must be gated"
    );
    // Elevated: bypasses the gate and runs.
    let elevated = call(&proto, &s, "drv_guarded_elev").await;
    assert_eq!(
        elevated["result"]["sum"], 42,
        "elevated call bypasses the gate"
    );
    let elevated_named = call(&proto, &s, "drv_named_elev").await;
    assert_eq!(elevated_named["result"]["sum"], 42);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_not_callable_and_panicking_ops_error() {
    let proto = base().build();
    let s = session(&proto);
    assert_eq!(
        call(&proto, &s, "drv_notfound").await["error"]["code"],
        -32601
    );
    assert_eq!(
        call(&proto, &s, "drv_named_notfound").await["error"]["code"],
        -32601
    );
    assert_eq!(call(&proto, &s, "drv_filt").await["error"]["code"], -32603); // filterable
    assert_eq!(call(&proto, &s, "drv_sub").await["error"]["code"], -32603); // subscription
    assert_eq!(call(&proto, &s, "drv_boom").await["error"]["code"], -32603); // panic → internal
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scatter_gather_runs_blocking_ops_in_parallel() {
    let proto = base().build();
    let s = session(&proto);
    let t = Instant::now();
    assert_eq!(
        call(&proto, &s, "drv_series").await["result"]["sum"],
        K as i64
    );
    let series = t.elapsed();
    let t = Instant::now();
    assert_eq!(
        call(&proto, &s, "drv_scatter").await["result"]["sum"],
        K as i64
    );
    let scatter = t.elapsed();
    // K blocking sleeps: series ≈ K·SLEEP, scatter ≈ SLEEP (parallel on the blocking pool). Generous
    // bound to avoid flakiness — scatter must be at least ~2x faster.
    assert!(
        scatter * 2 < series,
        "scatter-gather should overlap the blocking ops: series={series:?} scatter={scatter:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn elevated_internal_calls_are_unaudited_by_default_but_logged_under_policy() {
    // Default: no audit sink record for an (elevated) internal call.
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let proto = base()
        .audit_sink(
            move |_r: &RequestInfo, _o: AuditOutcome<'_>, _s: &Session<()>, _m: Option<&str>| {
                h.fetch_add(1, Ordering::SeqCst);
            },
        )
        .build(); // audit_internal_elevated defaults to OFF
    let s = session(&proto);
    assert_eq!(
        call(&proto, &s, "drv_guarded_elev").await["result"]["sum"],
        42
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0, "no audit churn by default");

    // Opt-in policy ON: one record per elevated internal call.
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let proto = base()
        .audit_internal_elevated(true)
        .audit_sink(
            move |_r: &RequestInfo, _o: AuditOutcome<'_>, _s: &Session<()>, _m: Option<&str>| {
                h.fetch_add(1, Ordering::SeqCst);
            },
        )
        .build();
    let s = session(&proto);
    assert_eq!(
        call(&proto, &s, "drv_guarded_elev").await["result"]["sum"],
        42
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "exactly one record per elevated call under policy"
    );
    // A *caller-privileged* internal call is never audited, even under the policy.
    let _ = call(&proto, &s, "drv_sync").await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "caller-privileged calls stay unaudited"
    );
}
