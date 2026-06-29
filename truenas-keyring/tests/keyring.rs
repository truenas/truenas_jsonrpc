//! Config validation (pure) + best-effort keyring exercises (skipped if the environment blocks the
//! keyring syscalls): the high-level record round-trip and the low-level `Key`/`KeyRing` primitives.

use truenas_keyring::{
    Found, KeyRing, KeyType, KeyringConfig, KeyringStore, RoleRecord, ScramRecord, SpecialKeyring,
};

fn sample(username: &str) -> ScramRecord {
    ScramRecord {
        username: username.into(),
        algorithm: "SHA512".into(),
        iterations: 500_000,
        salt: "c2FsdA==".into(),
        stored_key: "c3RvcmVkS2V5".into(),
        server_key: "c2VydmVyS2V5".into(),
        expiry: 0,
    }
}

/// A fresh, isolated sub-keyring for a test (under the per-test thread keyring), or `None` to skip
/// if the keyring syscalls are unavailable here.
fn scratch() -> Option<KeyRing> {
    KeyRing::special(SpecialKeyring::Thread).add_keyring("tnk_scratch").ok()
}

// --- config schema validation (no keyring needed) -----------------------------------------------

#[test]
fn persistent_requires_an_identifier() {
    assert!(KeyringConfig::from_json(r#"{ "keyring_type": "persistent", "keyring_identifier": 0 }"#).is_ok());
    let err = KeyringConfig::from_json(r#"{ "keyring_type": "persistent" }"#).unwrap_err();
    assert!(err.to_string().contains("requires keyring_identifier"), "{err}");
}

#[test]
fn identifier_is_rejected_for_non_persistent() {
    let err = KeyringConfig::from_json(r#"{ "keyring_type": "session", "keyring_identifier": 0 }"#).unwrap_err();
    assert!(err.to_string().contains("only valid with keyring_type \"persistent\""), "{err}");
}

#[test]
fn unknown_type_and_unknown_field_are_schema_errors() {
    assert!(KeyringConfig::from_json(r#"{ "keyring_type": "bogus" }"#).is_err());
    assert!(KeyringConfig::from_json(r#"{ "keyring_type": "session", "nope": 1 }"#).is_err());
    assert!(KeyringConfig::from_json("{}").is_err()); // missing keyring_type
}

#[test]
fn subkeyring_names_are_validated() {
    assert!(KeyringConfig::from_json(r#"{ "keyring_type": "session", "subkeyrings": ["extra"] }"#).is_ok());
    let err = KeyringConfig::from_json(r#"{ "keyring_type": "session", "subkeyrings": ["server_keys"] }"#).unwrap_err();
    assert!(err.to_string().contains("built-in"), "{err}");
    let err = KeyringConfig::from_json(r#"{ "keyring_type": "session", "subkeyrings": ["server_roles"] }"#).unwrap_err();
    assert!(err.to_string().contains("built-in"), "{err}");
    let err = KeyringConfig::from_json(r#"{ "keyring_type": "session", "subkeyrings": ["a", "a"] }"#).unwrap_err();
    assert!(err.to_string().contains("duplicate"), "{err}");
    assert!(KeyringConfig::from_json(r#"{ "keyring_type": "session", "subkeyrings": [""] }"#).is_err());
}

// --- high-level store: record round-trip (best-effort) ------------------------------------------

#[test]
fn store_record_roundtrip() {
    let config = KeyringConfig::from_json(r#"{ "keyring_type": "thread", "subkeyrings": ["extra"] }"#).unwrap();
    let store = match KeyringStore::open(&config) {
        Ok(s) => s,
        Err(e) => return eprintln!("keyring unavailable ({e}); skipping"),
    };
    let sk = store.server_keys();
    if sk.put_record("alice", &sample("alice"), None).is_err() {
        return eprintln!("keyring put unavailable; skipping");
    }
    let got: ScramRecord = sk.get_record("alice").unwrap().expect("alice present");
    assert_eq!(got.username, "alice");
    assert_eq!(got.server_key, "c2VydmVyS2V5");
    assert!(sk.get_record::<ScramRecord>("nobody").unwrap().is_none());
    assert!(sk.remove_record("alice").unwrap());
    assert!(!sk.remove_record("alice").unwrap());

    // server_roles: uid → roles, keyed by the uid's decimal string.
    let sr = store.server_roles();
    let rec = RoleRecord { uid: 1000, roles: vec!["READONLY".into(), "SHARING_WRITE".into()] };
    if sr.put_record("1000", &rec, None).is_ok() {
        let got: RoleRecord = sr.get_record("1000").unwrap().expect("uid 1000 present");
        assert_eq!(got.uid, 1000);
        assert_eq!(got.roles, ["READONLY", "SHARING_WRITE"]);
        assert!(sr.get_record::<RoleRecord>("4242").unwrap().is_none());
    }

    assert_ne!(store.server_keys().serial(), store.client_keys().serial());
    assert_ne!(store.server_roles().serial(), store.server_keys().serial());
    assert!(store.subkeyring("extra").is_some());
    assert!(store.subkeyring("missing").is_none());
    let _ = store.root().serial();
}

// --- low-level primitives (best-effort) ---------------------------------------------------------

#[test]
fn describe_and_read_a_user_key() {
    let Some(ring) = scratch() else { return eprintln!("keyring unavailable; skipping") };
    let key = match ring.add_key(KeyType::User, "k1", b"payload-bytes") {
        Ok(k) => k,
        Err(e) => return eprintln!("add_key unavailable ({e}); skipping"),
    };
    assert_eq!(key.read_data().unwrap(), b"payload-bytes");
    let d = key.describe().unwrap();
    assert_eq!(d.key_type, "user");
    assert_eq!(d.description, "k1");
    assert!(d.uid.is_some() && d.permissions.is_some()); // describe parsed the numeric fields
}

#[test]
fn search_dispatches_key_vs_keyring() {
    let Some(ring) = scratch() else { return eprintln!("keyring unavailable; skipping") };
    if ring.add_key(KeyType::User, "akey", b"x").is_err() {
        return eprintln!("keyring unavailable; skipping");
    }
    let sub = ring.add_keyring("akeyring").unwrap();

    assert!(matches!(ring.search(KeyType::User, "akey").unwrap(), Some(Found::Key(_))));
    match ring.search(KeyType::Keyring, "akeyring").unwrap() {
        Some(Found::Keyring(r)) => assert_eq!(r.serial(), sub.serial()),
        other => panic!("expected a keyring, got {other:?}"),
    }
    assert!(ring.search(KeyType::User, "missing").unwrap().is_none());
}

#[test]
fn list_contents_and_invalidate() {
    let Some(ring) = scratch() else { return eprintln!("keyring unavailable; skipping") };
    if ring.add_key(KeyType::User, "a", b"1").is_err() {
        return eprintln!("keyring unavailable; skipping");
    }
    let b = ring.add_key(KeyType::User, "b", b"2").unwrap();
    assert_eq!(ring.list_contents(false, false).unwrap().len(), 2);
    assert_eq!(ring.contents().unwrap().len(), 2);

    // Invalidate one → it drops out of the listing.
    b.invalidate().unwrap();
    // (Invalidation is asynchronous-ish but immediate for listing; the survivor count is <= 1.)
    assert!(ring.list_contents(true, true).unwrap().len() <= 1);
}
