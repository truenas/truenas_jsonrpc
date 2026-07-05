//! Behavioral tests for the daemon lifecycle.
//!
//! Signal handling is exercised with **thread-directed** signals (`pthread_kill`) delivered to a
//! current-thread runtime: the daemon's signalfd is created on the test thread, so a signal sent to
//! that thread reaches it — without blocking signals process-wide (which would need a pre-`main`
//! constructor whose generated `unsafe` this crate forbids) and without leaking signals to other
//! harness threads. A process-global lock serializes the heavy tests (they share the `NOTIFY_SOCKET`
//! env var and the process signal state).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nix::sys::pthread::{pthread_kill, pthread_self};
use nix::sys::signal::{SigSet, Signal};
use truenas_rpc::{JsonRpcError, JsonRpcProtocol, MethodDef, RequestCtx, RpcMethod};
use truenas_rpc_daemon::{Daemon, Service, TruenasRpcServer};

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn lock() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(serde::Deserialize, serde::Serialize)]
struct HelloArgs {
    name: String,
}
#[derive(serde::Serialize)]
struct HelloResult {
    msg: String,
}

/// A one-method protocol over unit session state, for the serve round-trip.
fn hello_protocol() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("demo", "1")
        .method(RpcMethod::new(
            MethodDef::new("greeting.hello"),
            |a: HelloArgs, _cx: &RequestCtx<()>| {
                Ok::<_, JsonRpcError>(HelloResult {
                    msg: format!("hi, {}!", a.name),
                })
            },
        ))
        .unwrap()
        .build()
}

/// A trivial protocol over `u32` session state — only used to prove heterogeneous services coexist.
fn u32_protocol() -> JsonRpcProtocol<u32> {
    JsonRpcProtocol::<u32>::builder("demo", "1").build()
}

/// Frame a `$/negotiate` then a `greeting.hello` over the socket and return the `result.msg`.
async fn call_hello(sock: &std::path::Path) -> String {
    use tokio::io::AsyncWriteExt;
    use truenas_rpc_server::framing;

    let mut s = tokio::net::UnixStream::connect(sock).await.unwrap();
    let neg = serde_json::json!({
        "jsonrpc": "2.0", "id": "1", "method": "$/negotiate", "params": {"protocol": "demo"}
    });
    s.write_all(&framing::frame(&serde_json::to_vec(&neg).unwrap()))
        .await
        .unwrap();
    framing::read_message(&mut s, framing::DEFAULT_LIMIT)
        .await
        .unwrap()
        .unwrap();

    let call = serde_json::json!({
        "jsonrpc": "2.0", "id": "00000000-0000-0000-0000-000000000002",
        "method": "greeting.hello", "params": {"name": "world"}
    });
    s.write_all(&framing::frame(&serde_json::to_vec(&call).unwrap()))
        .await
        .unwrap();
    let reply = framing::read_message(&mut s, framing::DEFAULT_LIMIT)
        .await
        .unwrap()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&reply).unwrap();
    v["result"]["msg"].as_str().unwrap().to_string()
}

/// Drain all buffered datagrams from a non-blocking `sd_notify` capture socket.
fn drain_notify(sock: &std::os::unix::net::UnixDatagram) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = [0u8; 256];
    while let Ok(n) = sock.recv(&mut buf) {
        if n == 0 {
            break;
        }
        out.push(String::from_utf8_lossy(&buf[..n]).into_owned());
    }
    out
}

#[test]
fn lifecycle_serves_and_shuts_down() {
    let _g = lock();
    let events = Arc::new(Mutex::new(Vec::<String>::new()));
    let ticks = Arc::new(AtomicUsize::new(0));
    let reply = Arc::new(Mutex::new(None::<String>));

    let pid = std::process::id();
    let sock = std::env::temp_dir().join(format!("daemon-test-{pid}.sock"));
    let notify_path = std::env::temp_dir().join(format!("daemon-notify-{pid}.sock"));
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_file(&notify_path);
    let notify_rx = std::os::unix::net::UnixDatagram::bind(&notify_path).unwrap();
    notify_rx.set_nonblocking(true).unwrap();
    std::env::set_var("NOTIFY_SOCKET", &notify_path);

    let ev_init = events.clone();
    let ev_shutdown = events.clone();
    let ticks_p = ticks.clone();
    let reply_slot = reply.clone();
    let sock_svc = sock.clone();
    let sock_driver = sock.clone();

    let daemon = Daemon::<()>::builder("test")
        .load_config(|| Ok(()))
        .shutdown_grace(Duration::from_secs(2))
        .services(move |_h| {
            let server = TruenasRpcServer::<()>::builder("test")
                .protocol("demo", hello_protocol())
                .build();
            vec![Service::builder(server).listen_unix(&sock_svc).build()]
        })
        .on_init(move |_ctx| {
            let ev = ev_init.clone();
            async move {
                ev.lock().unwrap().push("init".into());
                Ok(())
            }
        })
        .periodic("tick", Duration::from_millis(20), move |_ctx| {
            let ticks = ticks_p.clone();
            async move {
                ticks.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        })
        .on_shutdown(move |_ctx| {
            let ev = ev_shutdown.clone();
            async move {
                ev.lock().unwrap().push("shutdown".into());
                Ok(())
            }
        })
        .task("driver", move |ctx| {
            let sock = sock_driver.clone();
            let reply_slot = reply_slot.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(120)).await;
                let got = call_hello(&sock).await;
                *reply_slot.lock().unwrap() = Some(got);
                ctx.trigger_shutdown();
                Ok(())
            }
        })
        .task("watchdog", |ctx| async move {
            if ctx
                .until_shutdown(tokio::time::sleep(Duration::from_secs(5)))
                .await
                .is_some()
            {
                ctx.trigger_shutdown();
            }
            Ok(())
        })
        .build();

    daemon.run().unwrap();

    let events = events.lock().unwrap();
    assert!(events.iter().any(|e| e == "init"), "init ran: {events:?}");
    assert!(
        events.iter().any(|e| e == "shutdown"),
        "shutdown ran: {events:?}"
    );
    assert!(ticks.load(Ordering::SeqCst) >= 1, "periodic ticked");
    assert_eq!(
        reply.lock().unwrap().as_deref(),
        Some("hi, world!"),
        "served a real request"
    );

    let msgs = drain_notify(&notify_rx);
    assert!(msgs.iter().any(|m| m == "READY=1"), "READY sent: {msgs:?}");
    assert!(
        msgs.iter().any(|m| m == "STOPPING=1"),
        "STOPPING sent: {msgs:?}"
    );

    std::env::remove_var("NOTIFY_SOCKET");
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_file(&notify_path);
}

#[test]
fn signals_drive_reload_and_custom_hook() {
    let _g = lock();
    let events = Arc::new(Mutex::new(Vec::<String>::new()));
    let ini = std::env::temp_dir().join(format!("daemon-cfg-{}.ini", std::process::id()));
    std::fs::write(&ini, "[s]\ngreeting = alpha\n").unwrap();

    // Block the handled set on THIS thread; the daemon will run on a current-thread runtime here, so
    // its signalfd is created on this thread and reads the thread-directed signals below.
    let mut set = SigSet::empty();
    for s in [
        Signal::SIGHUP,
        Signal::SIGINT,
        Signal::SIGTERM,
        Signal::SIGUSR1,
        Signal::SIGUSR2,
    ] {
        set.add(s);
    }
    set.thread_block().unwrap();
    let target = pthread_self();

    let ini_helper = ini.clone();
    let helper = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        std::fs::write(&ini_helper, "[s]\ngreeting = beta\n").unwrap();
        let _ = pthread_kill(target, Signal::SIGHUP);
        std::thread::sleep(Duration::from_millis(150));
        let _ = pthread_kill(target, Signal::SIGUSR1);
        std::thread::sleep(Duration::from_millis(150));
        let _ = pthread_kill(target, Signal::SIGTERM);
    });

    let ev_reload = events.clone();
    let ev_usr1 = events.clone();
    let daemon = Daemon::<String>::builder("sig-test")
        .config_path(ini.clone())
        .parse(|cfg| Ok(cfg.get("s", "greeting")?.unwrap_or_else(|| "none".into())))
        .on_reload(move |ctx| {
            let ev = ev_reload.clone();
            async move {
                ev.lock().unwrap().push(format!("reload:{}", ctx.config()));
                Ok(())
            }
        })
        .on_signal(Signal::SIGUSR1, move |_ctx| {
            let ev = ev_usr1.clone();
            async move {
                ev.lock().unwrap().push("usr1".into());
                Ok(())
            }
        })
        .task("watchdog", |ctx| async move {
            if ctx
                .until_shutdown(tokio::time::sleep(Duration::from_secs(5)))
                .await
                .is_some()
            {
                ctx.trigger_shutdown();
            }
            Ok(())
        })
        .build();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(daemon.run_async()).unwrap();
    helper.join().unwrap();

    let events = events.lock().unwrap();
    assert!(
        events.iter().any(|e| e == "reload:beta"),
        "SIGHUP reload picked up the new config: {events:?}"
    );
    assert!(
        events.iter().any(|e| e == "usr1"),
        "SIGUSR1 hook fired: {events:?}"
    );

    let _ = std::fs::remove_file(&ini);
}

#[test]
fn heterogeneous_services_build() {
    // Two servers with *different* session types (`()` and `u32`) coexist in one `Vec<Service>` and
    // register together — the erasure that lets `Daemon` stay generic only over the config type.
    let _daemon = Daemon::<()>::builder("hetero")
        .load_config(|| Ok(()))
        .services(|_h| {
            let a = TruenasRpcServer::<()>::builder("a")
                .protocol("demo", hello_protocol())
                .build();
            let b = TruenasRpcServer::<u32>::builder("b")
                .protocol("demo", u32_protocol())
                .build();
            vec![
                Service::builder(a)
                    .listen_unix("/tmp/unbound-a.sock")
                    .build(),
                Service::builder(b)
                    .listen_unix("/tmp/unbound-b.sock")
                    .build(),
            ]
        })
        .build();
    // Reaching here means the heterogeneous `Vec<Service>` type-checked and the daemon built.
}
