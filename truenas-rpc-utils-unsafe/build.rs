//! Locate the system MIT krb5 GSSAPI and emit the link directives — **only** when the `gssapi`
//! feature is enabled (otherwise this crate links no krb5). Prefer pkg-config (it emits the
//! `rustc-link-search`/`rustc-link-lib` lines itself), falling back to `krb5-config --prefix` + a
//! direct `-lgssapi_krb5`. Dynamic link only — `libgssapi_krb5.so`'s `NEEDED` pulls in
//! `krb5`/`k5crypto`/`com_err`.

fn main() {
    // Cargo sets `CARGO_FEATURE_GSSAPI` iff the `gssapi` feature is on. With it off, emit nothing —
    // the `links = "gssapi_krb5"` key is still declared (it must be static), but nothing is linked.
    if std::env::var_os("CARGO_FEATURE_GSSAPI").is_none() {
        return;
    }

    // pkg-config probes `mit-krb5-gssapi` (MIT) then `krb5-gssapi`; on success it has already
    // emitted the cargo link directives.
    let cfg = pkg_config::Config::new();
    if cfg.probe("mit-krb5-gssapi").is_ok() || cfg.probe("krb5-gssapi").is_ok() {
        return;
    }

    // Fallback: ask krb5-config for the install prefix to find the lib dir, then link gssapi_krb5.
    if let Ok(out) = std::process::Command::new("krb5-config")
        .arg("--prefix")
        .output()
    {
        if out.status.success() {
            let prefix = String::from_utf8_lossy(&out.stdout);
            println!("cargo:rustc-link-search=native={}/lib", prefix.trim());
        }
    }
    println!("cargo:rustc-link-lib=gssapi_krb5");
}
