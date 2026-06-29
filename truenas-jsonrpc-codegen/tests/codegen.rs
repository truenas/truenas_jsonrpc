//! Codegen tests: golden server/client output, the OpenRPC A/B vs the committed
//! `openrpc.json`, branch coverage via the `full`/`python` fixtures, a bad-spec validation
//! corpus (one case per error path), determinism, the `Build` helper, and `run_cli`.

use std::path::PathBuf;

use truenas_jsonrpc_codegen::{
    generate_client, generate_openrpc, generate_server, run_cli, Build, Spec,
};

fn sample() -> Spec {
    Spec::load_dir("tests/fixtures/sample").unwrap()
}

fn tmp(name: &str) -> PathBuf {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/test-tmp").join(name);
    std::fs::create_dir_all(&p).unwrap();
    p
}

// --- golden output -----------------------------------------------------------

#[test]
fn server_matches_golden() {
    assert_eq!(generate_server(&sample()).unwrap(), include_str!("fixtures/expected_server.rs"));
}

#[test]
fn client_matches_golden() {
    assert_eq!(generate_client(&sample()).unwrap(), include_str!("fixtures/expected_client.rs"));
}

#[test]
fn openrpc_matches_cross_language_golden() {
    let mut got: serde_json::Value = serde_json::from_str(&generate_openrpc(&sample()).unwrap()).unwrap();
    let mut golden: serde_json::Value = serde_json::from_str(include_str!("fixtures/openrpc.json")).unwrap();
    got.as_object_mut().unwrap().remove("x-generated");
    golden.as_object_mut().unwrap().remove("x-generated");
    assert_eq!(got, golden, "generated OpenRPC must equal the committed golden");
}

#[test]
fn generation_is_deterministic() {
    assert_eq!(generate_server(&sample()).unwrap(), generate_server(&sample()).unwrap());
    assert_eq!(generate_client(&sample()).unwrap(), generate_client(&sample()).unwrap());
    assert_eq!(generate_openrpc(&sample()).unwrap(), generate_openrpc(&sample()).unwrap());
}

// --- branch coverage via the `full` fixture ----------------------------------

#[test]
fn full_fixture_exercises_remaining_branches() {
    let spec = Spec::load_dir("tests/fixtures/full").unwrap();
    let s = generate_server(&spec).unwrap();

    // Subscription: a register line, but NO Handlers trait method.
    assert!(s.contains("SubscriptionDef::<Sub, Event>::new"));
    assert!(!s.contains("fn events("));
    // Flags.
    assert!(s.contains(".pre_auth()"));
    assert!(s.contains(".cancellable()"));
    assert!(s.contains(r#".roles(["admin", "ops"])"#));
    assert!(s.contains(".audit()"));
    // xdr-reachable optional: `note` is Option with `#[serde(default)]` and NO skip.
    assert!(s.contains("#[serde(default)]\n    pub note: Option<String>"));
    assert!(!s.contains("skip_serializing_if"));
    // Every default kind.
    assert!(s.contains(r#"#[serde(default = "default_optargs_name")]"#));
    assert!(s.contains(r#"fn default_optargs_name() -> String { "anon".to_string() }"#));
    assert!(s.contains("fn default_optargs_count() -> i64 { 7i64 }"));
    assert!(s.contains("fn default_optargs_active() -> bool { true }"));
    assert!(s.contains("fn default_optargs_ratio() -> f64 { 2.5f64 }"));
    assert!(s.contains("fn default_optargs_mode() -> OptArgsMode { OptArgsMode::Fast }"));
    // Type-default fields (level 0) use bare `#[serde(default)]`.
    assert!(s.contains("#[serde(default)]\n    pub level: i64"));
    // The xdr method binds `.xdr(2001u32)`.
    assert!(s.contains(".xdr(2001u32)"));
    // Audit is on by default (no `audit` block) — service defaults to the spec name.
    assert!(s.contains("pub fn make_audit_sink") && s.contains(r#"builder("full")"#));

    // The client + OpenRPC also generate cleanly for the full spec.
    assert!(generate_client(&spec).unwrap().contains("subscribe_events"));
    assert!(generate_openrpc(&spec).unwrap().contains("\"x-direction\": \"server_client\""));
}

#[test]
fn python_methods_table_and_no_handler() {
    let spec = Spec::load_dir("tests/fixtures/python").unwrap();
    let s = generate_server(&spec).unwrap();
    assert!(s.contains(r#"PYTHON_METHODS: &[&str] = &["py.greet", "py.add", "py.boom"]"#));
    assert!(s.contains(".python_method("));
    assert!(s.contains("pub struct GreetArgs")); // structs still emitted
    assert!(!s.contains("fn greet(")); // python methods are NOT in the Handlers trait
    assert!(s.contains(r#".audit_message("greeting")"#)); // flags preserved
}

// --- audit config (on by default; spec-configurable) -------------------------

#[test]
fn audit_config() {
    // No `audit` block → on by default; `service` defaults to the spec `name`, no queue bound.
    let default_on = r##"{"name":"svc","version":"1","$defs":{"A":{"type":"object","properties":{},"required":[]}},"methods":{"m":{"handler":"m","params":{"$ref":"#/$defs/A"},"result":{"$ref":"#/$defs/A"}}}}"##;
    let s = generate_server(&Spec::parse(default_on, "spec").unwrap()).unwrap();
    assert!(s.contains("pub fn make_audit_sink"));
    assert!(s.contains(r#"truenas_audit::LinuxAuditSink::<S>::builder("svc").identity"#));
    assert!(s.contains(".audit_sink(make_audit_sink::<S, _>("));

    // Configured service + queue bound are baked into `make_audit_sink`.
    let configured = r##"{"name":"svc","version":"1","audit":{"service":"truenas-api","queueBound":256},"$defs":{},"methods":{}}"##;
    let s = generate_server(&Spec::parse(configured, "spec").unwrap()).unwrap();
    assert!(s.contains(r#"builder("truenas-api").queue_bound(256usize).identity"#));

    // Disabled → no audit wiring at all (so a consumer needs no `truenas-audit` dependency).
    let disabled = r##"{"name":"svc","version":"1","audit":{"enabled":false},"$defs":{},"methods":{}}"##;
    let s = generate_server(&Spec::parse(disabled, "spec").unwrap()).unwrap();
    assert!(!s.contains("make_audit_sink") && !s.contains("truenas_audit") && !s.contains(".audit_sink("));

    // Validation: a given service must be non-empty, a given queue bound > 0, keys are closed.
    assert!(parse_err(r##"{"name":"t","version":"1","audit":{"service":""},"methods":{}}"##).contains("audit.service must be a non-empty"));
    assert!(parse_err(r##"{"name":"t","version":"1","audit":{"queueBound":0},"methods":{}}"##).contains("audit.queueBound must be greater than 0"));
    assert!(parse_err(r##"{"name":"t","version":"1","audit":{"bogus":1},"methods":{}}"##).contains("unknown field"));
}

// --- load_dir / merge / sources ----------------------------------------------

#[test]
fn load_dir_reports_sources() {
    let spec = sample();
    assert_eq!(spec.source_files().len(), 1);
    assert!(spec.source_files()[0].ends_with("sample.json"));
}

#[test]
fn empty_dir_is_an_error() {
    let dir = tmp("empty");
    assert!(Spec::load_dir(&dir).unwrap_err().to_string().contains("no *.json"));
}

#[test]
fn multi_file_merges_and_rejects_duplicates() {
    let dir = tmp("multi");
    std::fs::write(dir.join("a.json"), r##"{"name":"svc","version":"1","$defs":{"A":{"type":"object","properties":{"x":{"type":"integer"}},"required":["x"]}},"methods":{"m1":{"handler":"m1","params":{"$ref":"#/$defs/A"},"result":{"$ref":"#/$defs/A"}}}}"##).unwrap();
    std::fs::write(dir.join("b.json"), r##"{"name":"ignored","version":"9","$defs":{"B":{"type":"object","properties":{},"required":[]}},"methods":{"m2":{"handler":"m2","params":{"$ref":"#/$defs/B"},"result":{"$ref":"#/$defs/A"}}}}"##).unwrap();
    let spec = Spec::load_dir(&dir).unwrap(); // b.m2 result $ref A resolves across files
    let s = generate_server(&spec).unwrap();
    assert!(s.contains("pub struct A") && s.contains("pub struct B"));
    assert!(s.contains("fn m1(") && s.contains("fn m2("));

    let dup = tmp("multi-dup");
    std::fs::write(dup.join("a.json"), r##"{"name":"s","version":"1","$defs":{"A":{"type":"object","properties":{},"required":[]}},"methods":{"m":{"handler":"m","params":{"$ref":"#/$defs/A"},"result":{"$ref":"#/$defs/A"}}}}"##).unwrap();
    std::fs::write(dup.join("b.json"), r##"{"name":"s","version":"1","$defs":{"B":{"type":"object","properties":{},"required":[]}},"methods":{"m":{"handler":"m2","params":{"$ref":"#/$defs/B"},"result":{"$ref":"#/$defs/B"}}}}"##).unwrap();
    assert!(Spec::load_dir(&dup).unwrap_err().to_string().contains("duplicate method"));

    let dupd = tmp("multi-dupdef");
    std::fs::write(dupd.join("a.json"), r##"{"name":"s","version":"1","$defs":{"A":{"type":"object","properties":{},"required":[]}},"methods":{}}"##).unwrap();
    std::fs::write(dupd.join("b.json"), r##"{"name":"s","version":"1","$defs":{"A":{"type":"object","properties":{},"required":[]}},"methods":{}}"##).unwrap();
    assert!(Spec::load_dir(&dupd).unwrap_err().to_string().contains("duplicate $def"));
}

// --- bad-spec validation corpus ----------------------------------------------

fn parse_err(json: &str) -> String {
    Spec::parse(json, "spec").unwrap_err().to_string()
}
fn gen_err(defs: &str) -> String {
    let json = format!(r#"{{"name":"t","version":"1","$defs":{defs},"methods":{{}}}}"#);
    generate_server(&Spec::parse(&json, "spec").unwrap()).unwrap_err().to_string()
}

#[test]
fn structural_errors() {
    assert!(parse_err(r##"{"name":"t","version":"1","methods":{},"bogus":1}"##).contains("unknown field"));
    assert!(parse_err(r##"{"name":"t","version":"1"}"##).contains("missing field"));
    assert!(parse_err(r##"{"name":"t","version":"1","$defs":{"A":{"type":"object"}},"methods":{"m":{"params":{"$ref":"#/$defs/A"}}}}"##).contains("missing field"));
}

#[test]
fn cross_cutting_errors() {
    let m = |body: &str| format!(r##"{{"name":"t","version":"1","$defs":{{"A":{{"type":"object","properties":{{}},"required":[]}}}},"methods":{{"x":{{"handler":"x","params":{{"$ref":"#/$defs/A"}}{body}}}}}}}"##);
    assert!(parse_err(r##"{"name":"t","version":"1","$defs":{"A":{"type":"object"}},"methods":{"x":{"handler":"1bad","params":{"$ref":"#/$defs/A"},"result":{"$ref":"#/$defs/A"}}}}"##).contains("not a valid identifier"));
    assert!(parse_err(&m(r##","filterable":true"##)).contains("filterable requires an 'entry'"));
    assert!(parse_err(&m(r##","filterable":true,"entry":{"$ref":"#/$defs/A"},"result":{"$ref":"#/$defs/A"}"##)).contains("must not have 'result'"));
    assert!(parse_err(&m(r##","xdr":true"##)).contains("xdr requires 'xdr_id'"));
    assert!(parse_err(&m(r##","xdr":true,"xdr_id":500"##)).contains("reserved"));
    assert!(parse_err(&m(r##","python":true"##)).contains("python requires 'result'"));
    assert!(parse_err(&m(r##","python":true,"result":{"$ref":"#/$defs/A"},"xdr":true,"xdr_id":1001"##)).contains("python cannot combine"));
    assert!(parse_err(&m(r##","result":{"$ref":"#/$defs/Missing"}"##)).contains("unknown $defs type"));
    assert!(parse_err(&m(r##","result":{"$ref":"#/components/X"}"##)).contains("unsupported $ref"));
    assert!(parse_err(r##"{"name":"t","version":"1","$defs":{"A":{"type":"object"}},"methods":{"x":{"handler":"x","params":{"$ref":"#/$defs/A"},"result":{"$ref":"#/$defs/A"},"xdr":true,"xdr_id":1001},"y":{"handler":"y","params":{"$ref":"#/$defs/A"},"result":{"$ref":"#/$defs/A"},"xdr":true,"xdr_id":1001}}}"##).contains("collides"));
}

#[test]
fn type_mapping_errors() {
    assert!(gen_err(r#"{"A":{"type":"object","properties":{"f":{"enum":[1,2]}}}}"#).contains("must all be strings"));
    assert!(gen_err(r#"{"A":{"type":"object","properties":{"f":{"enum":[]}}}}"#).contains("at least one value"));
    assert!(gen_err(r#"{"A":{"type":"object","properties":{"f":{"type":"array"}}}}"#).contains("must have an object 'items'"));
    assert!(gen_err(r#"{"A":{"type":"object","properties":{"f":{"type":"object","properties":{}}}}}"#).contains("inline object types"));
    assert!(gen_err(r#"{"A":{"type":"object","properties":{"f":{}}}}"#).contains("unsupported schema"));
    assert!(gen_err(r#"{"A":{"type":"object","properties":{"bad-name":{"type":"string"}}}}"#).contains("not a valid identifier"));
    assert!(gen_err(r#"{"A":{"type":"string"}}"#).contains("must be a JSON object schema"));
    assert!(gen_err(r#"{"A":{"type":"object","properties":{"f":{"enum":["!!!"]}}}}"#).contains("no identifier characters"));
}

#[test]
fn default_value_errors() {
    assert!(gen_err(r#"{"A":{"type":"object","properties":{"f":{"type":"array","items":{"type":"string"},"default":["x"]}}}}"#).contains("only an empty-array default"));
    assert!(gen_err(r#"{"A":{"type":"object","properties":{"f":{"type":"string","default":5}}}}"#).contains("string default must be a string"));
    assert!(gen_err(r#"{"A":{"type":"object","properties":{"f":{"type":"integer","default":"x"}}}}"#).contains("integer default must be an integer"));
    assert!(gen_err(r#"{"A":{"type":"object","properties":{"f":{"type":"number","default":"x"}}}}"#).contains("number default must be a number"));
    assert!(gen_err(r#"{"A":{"type":"object","properties":{"f":{"type":"boolean","default":"x"}}}}"#).contains("boolean default must be a boolean"));
    assert!(gen_err(r#"{"A":{"type":"object","properties":{"f":{"enum":["a"],"default":5}}}}"#).contains("enum default must be a string"));
    assert!(gen_err(r##"{"A":{"type":"object","properties":{"f":{"$ref":"#/$defs/B","default":{}}}},"B":{"type":"object","properties":{},"required":[]}}"##).contains("unsupported default for type"));
}

#[test]
fn io_and_non_object_errors() {
    assert!(Spec::load_dir("tests/fixtures/does-not-exist").is_err()); // read_dir → io error
    // `methods` present but not an object → the OrderedMap visitor's `expecting` fires.
    assert!(Spec::parse(r##"{"name":"t","version":"1","methods":[]}"##, "spec").is_err());
}

#[test]
fn keyword_field_and_digit_enum() {
    let spec = r##"{"name":"t","version":"1","$defs":{"A":{"type":"object","properties":{"type":{"type":"string"},"kind":{"type":"string","enum":["1st","2nd"]}},"required":["type","kind"]}},"methods":{}}"##;
    let s = generate_server(&Spec::parse(spec, "spec").unwrap()).unwrap();
    assert!(s.contains("pub r#type: String")); // keyword field → raw identifier
    assert!(s.contains("_1st")); // digit-leading enum variant is `_`-prefixed
}

#[test]
fn emit_error_paths() {
    // Inline (non-$ref) params → all three emitters reject it.
    let inline = r##"{"name":"t","version":"1","$defs":{"A":{"type":"object","properties":{},"required":[]}},"methods":{"m":{"handler":"m","params":{"type":"object","properties":{}},"result":{"$ref":"#/$defs/A"}}}}"##;
    let spec = Spec::parse(inline, "spec").unwrap();
    assert!(generate_server(&spec).unwrap_err().to_string().contains("must be a $ref"));
    assert!(generate_client(&spec).is_err());
    assert!(generate_openrpc(&spec).is_err());

    // A plain method with no result.
    let no_result = r##"{"name":"t","version":"1","$defs":{"A":{"type":"object","properties":{},"required":[]}},"methods":{"m":{"handler":"m","params":{"$ref":"#/$defs/A"}}}}"##;
    let spec = Spec::parse(no_result, "spec").unwrap();
    assert!(generate_server(&spec).unwrap_err().to_string().contains("missing 'result'"));
    assert!(generate_client(&spec).is_err());
    assert!(generate_openrpc(&spec).is_ok()); // OpenRPC simply omits the result

    // A server_client method with no notifies.
    let no_notifies = r##"{"name":"t","version":"1","$defs":{"A":{"type":"object","properties":{},"required":[]}},"methods":{"m":{"handler":"m","params":{"$ref":"#/$defs/A"},"direction":"server_client"}}}"##;
    let spec = Spec::parse(no_notifies, "spec").unwrap();
    assert!(generate_server(&spec).unwrap_err().to_string().contains("missing 'notifies'"));
    assert!(generate_client(&spec).is_err());
    assert!(generate_openrpc(&spec).is_ok()); // OpenRPC simply omits x-notifies

    // OpenRPC rejects an unmappable property type in a reachable def.
    let bad_type = r##"{"name":"t","version":"1","$defs":{"A":{"type":"object","properties":{"f":{"type":"null"}},"required":[]}},"methods":{"m":{"handler":"m","params":{"$ref":"#/$defs/A"},"result":{"$ref":"#/$defs/A"}}}}"##;
    assert!(generate_openrpc(&Spec::parse(bad_type, "spec").unwrap()).is_err());
}

// --- Build helper ------------------------------------------------------------

#[test]
fn build_emits_artifacts_with_explicit_out() {
    let out = tmp("build-out");
    let abs = std::fs::canonicalize("tests/fixtures/sample").unwrap();
    let server = Build::new().json_idl(&abs).out_dir(&out).emit_server().unwrap();
    assert!(server.ends_with("server_gen.rs"));
    assert!(std::fs::read_to_string(&server).unwrap().contains("pub fn register"));
    let client = Build::new().json_idl(&abs).out_dir(&out).emit_client().unwrap();
    assert!(std::fs::read_to_string(&client).unwrap().contains("pub trait Transport"));
    let openrpc = Build::new().json_idl(&abs).out_dir(&out).emit_openrpc().unwrap();
    assert!(std::fs::read_to_string(&openrpc).unwrap().contains("\"openrpc\""));
    assert!(Build::new().out_dir(&out).emit_server().is_err()); // missing json_idl
}

#[test]
fn build_resolves_env() {
    std::env::set_var("CARGO_MANIFEST_DIR", env!("CARGO_MANIFEST_DIR"));
    let out = tmp("build-env");
    std::env::set_var("OUT_DIR", &out);
    let p = Build::new().json_idl("tests/fixtures/sample").emit_openrpc().unwrap(); // relative path
    assert!(p.starts_with(&out));
    std::env::remove_var("OUT_DIR");
    let abs = std::fs::canonicalize("tests/fixtures/sample").unwrap();
    assert!(Build::new().json_idl(&abs).emit_server().is_err()); // no out_dir + no OUT_DIR

    // Relative json_idl with CARGO_MANIFEST_DIR unset → used as-is (resolved against cwd).
    std::env::remove_var("CARGO_MANIFEST_DIR");
    let out2 = tmp("build-env2");
    let p2 = Build::new().json_idl("tests/fixtures/sample").out_dir(&out2).emit_server().unwrap();
    assert!(p2.starts_with(&out2));
    std::env::set_var("CARGO_MANIFEST_DIR", env!("CARGO_MANIFEST_DIR")); // restore
}

// --- CLI ---------------------------------------------------------------------

#[test]
fn cli_subcommands_out_and_errors() {
    for sub in ["server", "client", "openrpc"] {
        let mut buf = Vec::new();
        run_cli(&[sub.to_string(), "tests/fixtures/sample".to_string()], &mut buf).unwrap();
        assert!(!buf.is_empty(), "{sub} produced output");
    }
    let out = tmp("cli").join("server_gen.rs");
    run_cli(
        &["server".into(), "tests/fixtures/sample".into(), "--out".into(), out.to_string_lossy().into_owned()],
        &mut Vec::new(),
    )
    .unwrap();
    assert!(std::fs::read_to_string(&out).unwrap().contains("register"));
    assert!(run_cli(&[], &mut Vec::new()).is_err());
    assert!(run_cli(&["server".into()], &mut Vec::new()).is_err());
    assert!(run_cli(&["server".into(), "tests/fixtures/sample".into(), "--out".into()], &mut Vec::new()).is_err());
    assert!(run_cli(&["server".into(), "tests/fixtures/sample".into(), "--nope".into(), "x".into()], &mut Vec::new()).is_err());
    assert!(run_cli(&["bogus".into(), "tests/fixtures/sample".into()], &mut Vec::new()).is_err());
}
