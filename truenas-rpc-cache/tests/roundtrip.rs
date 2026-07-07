//! Behavioral tests for both cache backends. The generic suites run against the in-memory backend
//! (always) and — under the `lmdb` feature — against a temp LMDB store, so the two backends must
//! agree. The LMDB module adds the reboot property, `MapFull`, and concurrency.

use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::Duration;

use truenas_rpc_cache::Cache;

// --- generic suites over any Cache<String> -------------------------------------------------------

fn basic(c: &Cache<String>) {
    assert_eq!(c.get("a").unwrap(), None);
    assert!(!c.has_key("a").unwrap());

    c.put("a", &"one".to_string(), None).unwrap();
    assert_eq!(c.get("a").unwrap(), Some("one".to_string()));
    assert!(c.has_key("a").unwrap());

    c.put("a", &"two".to_string(), None).unwrap(); // overwrite
    assert_eq!(c.get("a").unwrap(), Some("two".to_string()));

    assert!(c.delete("a").unwrap());
    assert_eq!(c.get("a").unwrap(), None);
    assert!(!c.delete("a").unwrap());
}

fn pop_atomic(c: &Cache<String>) {
    c.put("k", &"v".to_string(), None).unwrap();
    assert_eq!(c.pop("k").unwrap(), Some("v".to_string()));
    assert_eq!(c.get("k").unwrap(), None); // pop removed it
    assert_eq!(c.pop("k").unwrap(), None);
}

fn get_or_put_once(c: &Cache<String>) {
    let calls = std::cell::Cell::new(0);
    let v1 = c
        .get_or_put("k", None, || {
            calls.set(calls.get() + 1);
            "first".to_string()
        })
        .unwrap();
    assert_eq!(v1, "first"); // miss → computes
    let v2 = c
        .get_or_put("k", None, || {
            calls.set(calls.get() + 1);
            "second".to_string()
        })
        .unwrap();
    assert_eq!(v2, "first"); // hit → cached, producer not run
    assert_eq!(calls.get(), 1, "the producer ran only on the miss");
}

fn ttl_expiry(c: &Cache<String>) {
    c.put("k", &"v".to_string(), Some(Duration::from_millis(50)))
        .unwrap();
    assert_eq!(c.get("k").unwrap(), Some("v".to_string()));

    std::thread::sleep(Duration::from_millis(120));
    assert_eq!(c.get("k").unwrap(), None, "expired reads as absent");
    assert!(!c.has_key("k").unwrap());
    assert_eq!(c.cleanup_expired().unwrap(), 1, "swept the expired entry");
    assert_eq!(c.cleanup_expired().unwrap(), 0, "nothing left to sweep");
}

fn traverse_and_clear(c: &Cache<String>) {
    for (k, v) in [("a", "1"), ("b", "2"), ("c", "3")] {
        c.put(k, &v.to_string(), None).unwrap();
    }
    // An expired entry must be skipped by traverse.
    c.put("gone", &"x".to_string(), Some(Duration::from_millis(20)))
        .unwrap();
    std::thread::sleep(Duration::from_millis(60));

    let mut seen: Vec<String> = Vec::new();
    let broke = c
        .traverse(|k, v| {
            seen.push(format!("{}={v}", String::from_utf8_lossy(k)));
            ControlFlow::<()>::Continue(())
        })
        .unwrap();
    assert!(broke.is_none(), "visited every live entry");
    seen.sort();
    assert_eq!(seen, ["a=1", "b=2", "c=3"], "expired 'gone' was skipped");

    // Early break returns a value.
    let first = c.traverse(|_k, v| ControlFlow::Break(v)).unwrap();
    assert!(first.is_some());

    c.clear().unwrap();
    assert_eq!(c.get("a").unwrap(), None);
    let mut n = 0;
    c.traverse(|_, _| {
        n += 1;
        ControlFlow::<()>::Continue(())
    })
    .unwrap();
    assert_eq!(n, 0, "cleared");
}

fn concurrent(cache: Cache<u64>) {
    let c = Arc::new(cache);
    let handles: Vec<_> = (0..4u64)
        .map(|t| {
            let c = Arc::clone(&c);
            std::thread::spawn(move || {
                for i in 0..100u64 {
                    let k = t * 100 + i;
                    c.put(k.to_le_bytes(), &k, None).unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    for k in 0..400u64 {
        assert_eq!(c.get(k.to_le_bytes()).unwrap(), Some(k));
    }
}

// --- in-memory backend ---------------------------------------------------------------------------

#[test]
fn memory_basic() {
    basic(&Cache::memory());
}
#[test]
fn memory_pop() {
    pop_atomic(&Cache::memory());
}
#[test]
fn memory_get_or_put() {
    get_or_put_once(&Cache::memory());
}
#[test]
fn memory_ttl() {
    ttl_expiry(&Cache::memory());
}
#[test]
fn memory_traverse() {
    traverse_and_clear(&Cache::memory());
}
#[test]
fn memory_concurrent() {
    concurrent(Cache::memory());
}

// --- persistent LMDB backend ---------------------------------------------------------------------

#[cfg(feature = "lmdb")]
mod lmdb {
    use truenas_rpc_cache::{Cache, CacheError, Env, EnvFlags};

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("trcache-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }
    fn env(name: &str, map: usize) -> Env {
        Env::open(&temp_dir(name), map, 8, EnvFlags::durable(), 0o600).unwrap()
    }
    fn cache<V: truenas_rpc_cache::CacheValue>(name: &str) -> Cache<V> {
        Cache::persistent(&env(name, 8 << 20), "c").unwrap()
    }

    #[test]
    fn basic() {
        super::basic(&cache("basic"));
    }
    #[test]
    fn pop() {
        super::pop_atomic(&cache("pop"));
    }
    #[test]
    fn get_or_put() {
        super::get_or_put_once(&cache("gop"));
    }
    #[test]
    fn ttl() {
        super::ttl_expiry(&cache("ttl"));
    }
    #[test]
    fn traverse() {
        super::traverse_and_clear(&cache("trav"));
    }
    #[test]
    fn concurrent() {
        super::concurrent(Cache::persistent(&env("conc", 32 << 20), "c").unwrap());
    }

    #[test]
    fn persists_across_reopen() {
        // The reboot property: write, close the environment, reopen a fresh one at the same path.
        let dir = temp_dir("persist");
        {
            let e = Env::open(&dir, 8 << 20, 8, EnvFlags::durable(), 0o600).unwrap();
            let c: Cache<String> = Cache::persistent(&e, "c").unwrap();
            c.put("k", &"survives".to_string(), None).unwrap();
        }
        {
            let e = Env::open(&dir, 8 << 20, 8, EnvFlags::durable(), 0o600).unwrap();
            let c: Cache<String> = Cache::persistent(&e, "c").unwrap();
            assert_eq!(c.get("k").unwrap(), Some("survives".to_string()));
        }
    }

    #[test]
    fn map_full_is_reported() {
        let c: Cache<Vec<u8>> = Cache::persistent(&env("full", 64 * 1024), "c").unwrap();
        let big = vec![7u8; 500];
        let mut hit = false;
        for i in 0..10_000u32 {
            if let Err(e) = c.put(i.to_le_bytes(), &big, None) {
                assert!(
                    matches!(e, CacheError::MapFull),
                    "expected MapFull, got {e}"
                );
                hit = true;
                break;
            }
        }
        assert!(hit, "expected to hit MapFull with a tiny map");
    }

    #[test]
    fn no_sync_round_trips() {
        let e = Env::open(&temp_dir("nosync"), 8 << 20, 8, EnvFlags::no_sync(), 0o600).unwrap();
        let c: Cache<String> = Cache::persistent(&e, "c").unwrap();
        c.put("k", &"v".to_string(), None).unwrap();
        assert_eq!(c.get("k").unwrap(), Some("v".to_string()));
        e.sync(true).unwrap();
    }
}
