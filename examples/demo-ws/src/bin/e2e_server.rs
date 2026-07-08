//! A `wss://` server for the TypeScript-client E2E: unbound-SCRAM auth + `echo`/`add` + a `ticks`
//! subscription pushed from a background task. Binds `127.0.0.1:0`, prints `PORT=<n>` on stdout, then
//! runs forever. Usage: `e2e_server --cert <cert.pem> --key <key.pem>` (user `e2e` / pass `e2e-secret`).

use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use demo_ws::{register, E2eHandlers, Tick};
use serde_json::json;
use tokio::net::TcpListener;
use truenas_rpc::JsonRpcProtocol;
use truenas_rpc_auth::{install, AuthSession, AuthStack, CredentialSource, ScramCredentials};
use truenas_rpc_server::{TlsConfig, TlsMode, TruenasRpcServer};

const USER: &str = "e2e";
const PASS: &[u8] = b"e2e-secret";

/// One in-memory user's SCRAM verifier.
struct Creds(HashMap<String, ScramCredentials>);
impl CredentialSource for Creds {
    fn scram_credentials(&self, username: &str) -> Option<ScramCredentials> {
        self.0.get(username).cloned()
    }
}

fn arg(flag: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    let i = args.iter().position(|a| a == flag)?;
    args.get(i + 1).cloned()
}

#[tokio::main]
async fn main() {
    let cert = std::fs::read(arg("--cert").expect("--cert <path> required")).expect("read cert");
    let key = std::fs::read(arg("--key").expect("--key <path> required")).expect("read key");
    let tls = TlsConfig::from_pem(&cert, &key, TlsMode::Userspace).expect("tls config");

    // The one test user's SCRAM verifier (fixed salt/iters — a test fixture; the client adapts to
    // whatever the server-first advertises).
    let creds = ScramCredentials::mint(
        PASS,
        b"e2e-fixed-salt16".to_vec(),
        4096,
        json!({ "user": USER }),
    );
    let source = Creds(HashMap::from([(USER.to_string(), creds)]));

    // The protocol: generated echo/add + the ticks subscription, gated by unbound SCRAM (browsers
    // can't do channel-bound SCRAM). Not calling `allow_unauthenticated_network`, so auth is required.
    let stack = AuthStack::builder().scram_unbound(source).build();
    let builder = register(
        JsonRpcProtocol::<AuthSession>::builder("e2e", "1.0.0"),
        Arc::new(E2eHandlers),
    )
    .expect("register");
    let proto = install(builder, stack).build();

    let server = Arc::new(
        TruenasRpcServer::<AuthSession>::builder("e2e-server")
            .state_from_peer(AuthSession::from_peer)
            .protocol("e2e", proto)
            .build(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    println!("PORT={}", listener.local_addr().expect("addr").port());
    let _ = std::io::stdout().flush();

    // Push a tick every 200ms so a subscriber receives events.
    let notifier = server.clone();
    tokio::spawn(async move {
        let mut seq = 0i64;
        loop {
            tokio::time::sleep(Duration::from_millis(200)).await;
            seq += 1;
            let _ = notifier.send_notification(
                "e2e",
                "ticks",
                &Tick {
                    seq,
                    msg: format!("tick {seq}"),
                },
            );
        }
    });

    server
        .serve_wss_listener(listener, tls)
        .await
        .expect("serve wss");
}
