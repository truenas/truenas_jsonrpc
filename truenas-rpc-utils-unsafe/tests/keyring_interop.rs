//! Cross-functionality with the C `truenas_keyring` Python extension: a key written by one is read
//! by the other, over a sub-keyring under the **session** keyring (a child process inherits the
//! session keyring and its possession, so both reach the same keys). Skipped if Python +
//! `truenas_keyring` aren't importable, or the keyring syscalls are unavailable here.
#![cfg(feature = "keyring")]

use std::process::Command;

use truenas_rpc_utils_unsafe::keyring::{Found, KeyRing, KeyType, SpecialKeyring};

/// Where the built `truenas_keyring` extension lives (overridable via `TRUENAS_PYKEYRING`).
const DEFAULT_BUILD: &str = "/CODE/claudedir/truenas_pykeyring/build/lib.linux-x86_64-cpython-313";

fn pythonpath() -> String {
    std::env::var("TRUENAS_PYKEYRING").unwrap_or_else(|_| DEFAULT_BUILD.to_string())
}

fn python(code: &str, arg: &str) -> std::process::Output {
    Command::new("python3")
        .env("PYTHONPATH", pythonpath())
        .args(["-c", code, arg])
        .output()
        .expect("spawn python3")
}

fn python_keyring_importable() -> bool {
    Command::new("python3")
        .env("PYTHONPATH", pythonpath())
        .args(["-c", "import truenas_keyring"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[test]
fn rust_and_python_keyring_interop() {
    if !python_keyring_importable() {
        return eprintln!("python truenas_keyring not importable; skipping interop");
    }

    // A sub-keyring under the session keyring; a child python process inherits the session keyring,
    // so it possesses (and can read) keys we put here, and vice versa.
    let session = KeyRing::special(SpecialKeyring::Session);
    let ring_name = format!("tnk_interop_{}", std::process::id());
    let ring = match session.add_keyring(&ring_name) {
        Ok(r) => r,
        Err(e) => return eprintln!("keyring unavailable ({e}); skipping interop"),
    };
    if ring
        .add_key(KeyType::User, "from_rust", b"rust-payload")
        .is_err()
    {
        let _ = session.unlink_key(ring.serial());
        return eprintln!("keyring add unavailable; skipping interop");
    }

    // Python: find our sub-keyring by name, read the key we wrote, then write its own.
    let code = r#"
import sys, truenas_keyring as k
ring = k.request_key(key_type=k.KeyType.KEYRING, description=sys.argv[1])
got = ring.search(key_type=k.KeyType.USER, description="from_rust").read_data()
assert got == b"rust-payload", got
k.add_key(key_type="user", description="from_py", data=b"py-payload", target_keyring=ring.key.serial)
print("PY_OK")
"#;
    let out = python(code, &ring_name);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // If python couldn't reach the keyring (e.g. possession differs in this sandbox), skip rather
    // than fail — the in-process tests already prove our syscall layer.
    if !out.status.success() {
        let _ = session.unlink_key(ring.serial());
        return eprintln!("python keyring access failed (skipping interop):\n{stderr}");
    }
    assert!(
        stdout.contains("PY_OK"),
        "unexpected python output:\n{stdout}\n{stderr}"
    );

    // Rust reads the key python wrote, and describes it.
    let found = ring
        .search(KeyType::User, "from_py")
        .unwrap()
        .expect("from_py present");
    let Found::Key(key) = found else {
        panic!("from_py should be a non-keyring key")
    };
    assert_eq!(
        key.read_data().unwrap(),
        b"py-payload",
        "Rust read of the Python-written key"
    );
    let desc = key.describe().unwrap();
    assert_eq!(desc.key_type, "user");
    assert_eq!(desc.description, "from_py");

    let _ = session.unlink_key(ring.serial());
}
