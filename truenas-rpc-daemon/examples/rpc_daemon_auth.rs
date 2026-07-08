//! An **authenticated** turn-key daemon: one server + one session table shared across a
//! trusted-local AF_UNIX socket (peer-cred) and a reverse-proxied AF_UNIX socket (the network path).
//! Auth is declared once as an [`AuthStack`] and `install`ed onto the protocol; the daemon owns
//! config, signals, and lifecycle exactly as in the `rpc_daemon` example.
//!
//! This example wires **peer-cred** (always-on, works on the local socket). To also authenticate the
//! **proxied** socket — where nginx terminates TLS and forwards over the unix socket — add
//! SCRAM-SHA-512-PLUS with the keyring channel binding (see the README and `truenas-rpc-auth`):
//!
//! ```ignore
//! use truenas_rpc_auth::{KeyringChannelBinding, KeyringCredentials};
//! use truenas_rpc_utils_unsafe::keyring::{KeyringConfig, KeyringStore};
//! let store = KeyringStore::open(&KeyringConfig::from_json(r#"{"keyring_type":"persistent","keyring_identifier":0}"#)?)?;
//! stack = stack.scram_bound(
//!     KeyringCredentials::new(store.server_keys()),   // verifiers from the keyring
//!     KeyringChannelBinding::new(store.root()),       // published tls-server-end-point (proxied only)
//! );
//! ```
//!
//! Run: `cargo run -p truenas-rpc-daemon --example rpc_daemon_auth`

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::json;
use truenas_rpc::{JsonRpcError, JsonRpcProtocol, MethodDef, RequestCtx, RpcMethod};
use truenas_rpc_auth::{install, AuthSession, AuthStack};
use truenas_rpc_daemon::{ConfigFile, Daemon, DaemonError, Service, TruenasRpcServer};

/// Application config (all keys optional, with defaults).
#[derive(Debug)]
struct Config {
    local_sock: String,
    proxied_sock: String,
}

impl Config {
    fn from_ini(cfg: &ConfigFile) -> Result<Self, DaemonError> {
        Ok(Config {
            local_sock: cfg
                .get("service", "local_sock")?
                .unwrap_or_else(|| "/tmp/myservice.sock".to_string()),
            proxied_sock: cfg
                .get("service", "proxied_sock")?
                .unwrap_or_else(|| "/tmp/myservice-public.sock".to_string()),
        })
    }
}

#[derive(Deserialize, Serialize)]
struct WhoamiArgs {}

#[derive(Serialize)]
struct WhoamiResult {
    /// The uid the peer authenticated as (from the session's authenticated identity), if any.
    uid: Option<u64>,
}

/// The protocol: `$/sessionSetup` runs the auth stack; `whoami` reflects the authenticated identity.
fn protocol() -> JsonRpcProtocol<AuthSession> {
    // Declare the accepted mechanisms. Peer-cred authenticates a genuinely-local AF_UNIX peer by its
    // SO_PEERCRED uid; on the proxied socket add SCRAM (see the module docs).
    let stack = AuthStack::builder()
        .peercred(|ch| ch.ucred.map(|c| json!({ "uid": c.uid })))
        .build();

    install(
        JsonRpcProtocol::<AuthSession>::builder("myproto", "1"),
        stack,
    )
    .method(RpcMethod::new(
        MethodDef::new("whoami"),
        |_a: WhoamiArgs, cx: &RequestCtx<AuthSession>| {
            let uid = cx
                .session()
                .with_internal(|a| a.and_then(|s| s.identity().cloned()))
                .and_then(|id| id.get("uid").and_then(serde_json::Value::as_u64));
            Ok::<_, JsonRpcError>(WhoamiResult { uid })
        },
    ))
    .unwrap()
    .build()
}

fn main() -> Result<(), DaemonError> {
    Daemon::<Config>::builder("rpc-daemon-auth")
        .config_path("/etc/myservice/config.ini")
        .parse(Config::from_ini)
        .services(|h| {
            let cfg = h.config();
            let (local, proxied) = (cfg.local_sock.clone(), cfg.proxied_sock.clone());
            let _ = std::fs::remove_file(&local); // clear stale sockets from a previous run
            let _ = std::fs::remove_file(&proxied);
            eprintln!("rpc-daemon-auth: local {local} (peer-cred) / proxied {proxied}");

            // One server, one session table, served on both sockets (cheap Arc clone).
            let server = TruenasRpcServer::<AuthSession>::builder("myservice")
                .state_from_peer(AuthSession::from_peer)
                .protocol("myproto", protocol())
                .build();
            vec![
                Service::builder(server.clone()).listen_unix(local).build(),
                // Reverse-proxied (nginx → unix): network-facing, so the network-auth guard requires
                // $/sessionSetup (satisfied above). Peer-cred here is the proxy's, not the client's —
                // this socket authenticates clients via SCRAM (see the module docs).
                Service::builder(server)
                    .listen_unix_proxied(proxied)
                    .build(),
            ]
        })
        .on_init(|_ctx| async move {
            eprintln!("rpc-daemon-auth: ready");
            Ok(())
        })
        .periodic("gc", Duration::from_secs(60), |_ctx| async move { Ok(()) })
        .build()
        .run()
}
