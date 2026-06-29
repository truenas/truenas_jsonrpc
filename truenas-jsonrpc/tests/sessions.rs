//! `$/sessions` — the FULL_ADMIN-gated session listing + the per-protocol registry.
//!
//! The core gates + audits the call and returns a `Dispatched::Sessions` directive (the server
//! assembles the server-wide list by walking every protocol's `render_sessions`). These tests
//! exercise the core side: the gate, the directive, the registry snapshot, the enriched default
//! entry (origin / credential / `current` / `created_at`), the augment-merge seam, and the
//! monotonic `created` age.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use truenas_jsonrpc::{
    AuditOutcome, Credential, Dispatched, JsonRpcProtocol, JsonRpcRequest, NullOutbound, RoleMask,
    Session, SessionOrigin,
};

const ID: &str = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";

fn req(method: &str, params: Option<Value>, id: Option<&str>) -> Vec<u8> {
    let mut m = serde_json::Map::new();
    m.insert("jsonrpc".into(), json!("2.0"));
    m.insert("method".into(), json!(method));
    if let Some(id) = id {
        m.insert("id".into(), json!(id));
    }
    if let Some(p) = params {
        m.insert("params".into(), p);
    }
    serde_json::to_vec(&Value::Object(m)).unwrap()
}

#[tokio::test]
async fn sessions_gate_listing_and_audit() {
    let audited: Arc<Mutex<Vec<(String, bool)>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = audited.clone();
    let proto = JsonRpcProtocol::<()>::builder("test", "1.0.0")
        .audit_sink(move |r: &JsonRpcRequest, o: AuditOutcome<'_>, _s: &Session<()>, _m: Option<&str>| {
            sink.lock().unwrap().push((r.method.clone(), o.succeeded()));
        })
        .build();
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));

    // A non-admin caller → audited `Not authorized` (a plain `Reply` error).
    let denied = match proto.dispatch(&req("$/sessions", None, Some(ID)), &s).await {
        Dispatched::Reply(b) => serde_json::from_slice::<Value>(&b).unwrap(),
        _ => panic!("expected a denial reply"),
    };
    assert_eq!(denied["error"]["message"], "Not authorized");

    // FULL_ADMIN + id → a `Sessions` directive carrying the caller's id (the server marks it
    // `current` and fulfills the listing).
    s.set_roles(RoleMask::FULL_ADMIN);
    match proto.dispatch(&req("$/sessions", None, Some(ID)), &s).await {
        Dispatched::Sessions { rid, caller } => {
            assert_eq!(rid, ID);
            assert_eq!(caller, s.id());
        }
        _ => panic!("expected a Sessions directive"),
    }
    // FULL_ADMIN, no id → a notification → nothing is sent.
    assert!(matches!(
        proto.dispatch(&req("$/sessions", None, None), &s).await,
        Dispatched::Nothing
    ));

    // Both the denial and the authorized call were audited.
    let log = audited.lock().unwrap();
    assert!(log.iter().any(|(m, ok)| m == "$/sessions" && !*ok), "denial audited");
    assert!(log.iter().any(|(m, ok)| m == "$/sessions" && *ok), "success audited");
    drop(log);

    // `render_sessions` snapshots the registry — the live session, default core fields, no identity.
    let entries = proto.render_sessions(s.id());
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["session_id"], s.id().to_string());
    assert_eq!(entries[0]["protocol"], "test");
    assert!(entries[0]["age_seconds"].as_f64().unwrap() >= 0.0);
    assert!(entries[0].get("user").is_none()); // the default renderer has no identity

    // Closing a session removes it; dropping its `Arc` prunes it (the `Weak` fails to upgrade).
    let s2 = proto.new_session(Some(()), Arc::new(NullOutbound));
    assert_eq!(proto.render_sessions(s.id()).len(), 2);
    proto.close_session(&s2);
    assert_eq!(proto.render_sessions(s.id()).len(), 1);
    let s3 = proto.new_session(Some(()), Arc::new(NullOutbound));
    assert_eq!(proto.render_sessions(s.id()).len(), 2);
    drop(s3);
    assert_eq!(proto.render_sessions(s.id()).len(), 1);
}

#[tokio::test]
async fn default_entry_surfaces_origin_credential_and_current() {
    let proto = JsonRpcProtocol::<()>::builder("test", "1.0.0").build();

    // A privileged local (AF_UNIX root) session with a credential set by the auth stack.
    let root = proto.new_session(Some(()), Arc::new(NullOutbound));
    root.set_origin(SessionOrigin { transport: "unix", remote: None, uid: Some(0), secure: true });
    root.set_credential(Credential { description: "UNIX_SOCKET uid=0".into(), uid: Some(0) });

    // A second, unprivileged session over TCP with no credential committed yet.
    let tcp = proto.new_session(Some(()), Arc::new(NullOutbound));
    tcp.set_origin(SessionOrigin {
        transport: "tcp",
        remote: Some("10.0.0.5:54321".into()),
        uid: None,
        secure: false,
    });

    // A local session whose peer-cred uid is unknown → origin is the bare transport name.
    let anon = proto.new_session(Some(()), Arc::new(NullOutbound));
    anon.set_origin(SessionOrigin { transport: "unix", remote: None, uid: None, secure: true });

    // Render from `root`'s perspective: it is `current`, the others are not.
    let entries = proto.render_sessions(root.id());
    let pick = |id: String| entries.iter().find(|e| e["session_id"] == id).unwrap().clone();

    let r = pick(root.id().to_string());
    assert_eq!(r["origin"], "unix:uid=0");
    assert_eq!(r["secure_transport"], true);
    assert_eq!(r["internal"], true); // root over a local socket
    assert_eq!(r["current"], true);
    assert_eq!(r["credential"]["description"], "UNIX_SOCKET uid=0");
    assert_eq!(r["credential"]["uid"], 0);
    // `created_at` is the wall-clock derive (now − age) — within a second of the real clock.
    let age = r["age_seconds"].as_f64().unwrap();
    let created_at = r["created_at"].as_f64().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    assert!((created_at - (now - age)).abs() < 1.0, "created_at ≈ now − age");

    let t = pick(tcp.id().to_string());
    assert_eq!(t["origin"], "10.0.0.5:54321"); // TCP remote, not a uid
    assert_eq!(t["secure_transport"], false);
    assert_eq!(t["internal"], false); // not a local root session
    assert_eq!(t["current"], false);
    assert!(t.get("credential").is_none()); // none committed

    let a = pick(anon.id().to_string());
    assert_eq!(a["origin"], "unix"); // local, but no peer-cred uid → bare transport
    assert_eq!(a["internal"], false); // uid unknown → not flagged internal
    assert!(a.get("credential").is_none());
}

#[tokio::test]
async fn sessions_custom_renderer_merges_onto_the_core_base() {
    // A custom `SessionInfo` renderer *augments* the core base with app-specific fields read from `S`.
    let proto = JsonRpcProtocol::<u32>::builder("test", "1.0.0")
        .session_info(|s: &Session<u32>| {
            let uid = s.with_internal(|st| st.copied().unwrap_or(0));
            json!({ "uid": uid })
        })
        .build();
    let a = proto.new_session(Some(7), Arc::new(NullOutbound));
    std::thread::sleep(Duration::from_millis(5));
    let b = proto.new_session(Some(9), Arc::new(NullOutbound));

    let entries = proto.render_sessions(a.id());
    assert_eq!(entries.len(), 2);
    // Sorted oldest-first (matches the TrueNAS middleware) → `a` before `b`.
    assert_eq!(entries[0]["session_id"], a.id().to_string());
    assert_eq!(entries[1]["session_id"], b.id().to_string());
    // The core base survives the merge (protocol / created_at present) AND the extra is folded in.
    assert_eq!(entries[0]["protocol"], "test");
    assert!(entries[0]["created_at"].as_f64().unwrap() > 0.0);
    assert_eq!(entries[0]["uid"], 7);
    assert_eq!(entries[1]["uid"], 9);
    // `current` marks only the caller's entry.
    assert_eq!(entries[0]["current"], true);
    assert_eq!(entries[1]["current"], false);

    // `a` was created before `b` → earlier `created` instant, larger age (monotonic, no clock).
    assert!(a.created() < b.created());
    assert!(a.created().elapsed() >= b.created().elapsed());
}
