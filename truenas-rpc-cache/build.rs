//! Compiles the vendored liblmdb (LMDB 0.9.35, `vendor/lmdb/` — upstream tag `LMDB_0.9.35`) into the
//! crate — **only** when the `lmdb` feature is enabled. A memory-only build never touches a C compiler.

fn main() {
    // `cc` is always a build-dependency (so build.rs compiles), but we only invoke it for the
    // persistent backend. Cargo sets `CARGO_FEATURE_LMDB` iff the `lmdb` feature is active.
    if std::env::var_os("CARGO_FEATURE_LMDB").is_none() {
        return;
    }
    for f in [
        "vendor/lmdb/mdb.c",
        "vendor/lmdb/midl.c",
        "vendor/lmdb/lmdb.h",
        "vendor/lmdb/midl.h",
    ] {
        println!("cargo:rerun-if-changed={f}");
    }
    cc::Build::new()
        .file("vendor/lmdb/mdb.c")
        .file("vendor/lmdb/midl.c")
        .include("vendor/lmdb")
        // liblmdb's own C carries a handful of benign warnings; don't let them fail a -Werror consumer.
        .warnings(false)
        .compile("lmdb"); // -> liblmdb.a, linked statically into this rlib
}
