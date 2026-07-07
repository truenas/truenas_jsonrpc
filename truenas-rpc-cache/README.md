# truenas-rpc-cache

A cache & state store for `truenas-rpc` services — one uniform `Cache<V>` over two backends the caller
picks per cache: a fast **in-memory** map (ephemeral) and a **persistent LMDB** store that survives
reboots. The op-set mirrors the TrueNAS middleware cache (`middlewared/plugins/cache.py`).

```rust
use std::time::Duration;
use truenas_rpc_cache::{Cache, Env, EnvFlags};

// In-memory (default; no features): ephemeral, lost on exit.
let sessions: Cache<u64> = Cache::memory();
sessions.put("alice", &1000, Some(Duration::from_secs(300)))?;   // 5-minute TTL
let uid = sessions.get("alice")?;                                // -> Some(1000)

// Persistent (the `lmdb` feature): survives reboots across the same path.
let env = Env::open("/var/db/myservice".as_ref(), 256 << 20, 8, EnvFlags::durable(), 0o600)?;
let state: Cache<String> = Cache::persistent(&env, "state")?;
state.put("last_run", &"2026-07-05".to_string(), None)?;
```

## API

`Cache<V>` (`V: Clone + Serialize + DeserializeOwned`), keys are `impl AsRef<[u8]>`:

- `get` / `put(key, &value, ttl)` / `has_key` / `delete` / `clear`
- `pop` — atomic get + remove
- `get_or_put(key, ttl, || value)` — atomic compute-if-absent (the producer runs only on a miss)
- `traverse(|key, value| ControlFlow…)` — visit every live entry (skips expired), early-break with a value
- `cleanup_expired()` — sweep expired entries (run it periodically to bound growth)

TTL is per entry (`Option<Duration>`, `None` = no expiry); expiry is **lazy** on read and swept by
`cleanup_expired`. `Cache` is `Send + Sync` — share it as `Arc<Cache<V>>` across handlers/tasks. The
sync API is meant to be driven from `spawn_blocking` in an async server (an LMDB write txn holds a
process-global writer lock).

## Backends

| | in-memory (`Cache::memory`) | persistent (`Cache::persistent`, `lmdb` feature) |
|---|---|---|
| durability | none (lost on exit) | crash-safe, **survives reboots** |
| speed | ~tens of ns | reads RAM-warm + deserialize (~10–50×); durable writes fsync-bound |
| scope | this process | on disk, cross-process |
| deps | pure-safe Rust, no C | vendored liblmdb (our own FFI) + `truenas-xdr` codec |

Pick per cache by what the data needs. The LMDB backend links a **vendored, pinned liblmdb 0.9.35**
(hand-written FFI, compiled via `cc`; no `bindgen`), so the C version is controlled by us.

## Features & lint

`lmdb` (off by default) enables the persistent backend. The crate is `unsafe_code = "deny"`; the LMDB
FFI is a module-scoped allow with `// SAFETY:` notes, and a memory-only build contains no `unsafe`.
