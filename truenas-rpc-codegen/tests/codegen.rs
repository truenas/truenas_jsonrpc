//! Codegen tests: golden server/client output, the OpenRPC A/B vs the committed
//! `openrpc.json`, branch coverage via the `full`/`python` fixtures, a bad-spec validation
//! corpus (one case per error path), determinism, the `Build` helper, and `run_cli`.

use std::path::PathBuf;

use truenas_rpc_codegen::{
    generate_client, generate_openrpc, generate_py_client, generate_py_server, generate_py_structs,
    generate_server, generate_types, run_cli, Build, Spec,
};

fn sample() -> Spec {
    Spec::load_dir("tests/fixtures/sample").unwrap()
}

#[test]
#[ignore = "regenerates golden fixtures; run explicitly"]
fn regen_fixtures() {
    let s = sample();
    std::fs::write(
        "tests/fixtures/expected_types.rs",
        generate_types(&s).unwrap(),
    )
    .unwrap();
    std::fs::write(
        "tests/fixtures/expected_server.rs",
        generate_server(&s).unwrap(),
    )
    .unwrap();
    std::fs::write(
        "tests/fixtures/expected_client.rs",
        generate_client(&s).unwrap(),
    )
    .unwrap();
    std::fs::write(
        "tests/fixtures/expected_structs.py",
        generate_py_structs(&s).unwrap(),
    )
    .unwrap();
    std::fs::write(
        "tests/fixtures/expected_client.py",
        generate_py_client(&s).unwrap(),
    )
    .unwrap();
    std::fs::write(
        "tests/fixtures/expected_server.py",
        generate_py_server(&s).unwrap(),
    )
    .unwrap();
    std::fs::write("tests/fixtures/openrpc.json", generate_openrpc(&s).unwrap()).unwrap();
}

fn tmp(name: &str) -> PathBuf {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/test-tmp")
        .join(name);
    std::fs::create_dir_all(&p).unwrap();
    p
}

// --- golden output -----------------------------------------------------------

#[test]
fn types_matches_golden() {
    assert_eq!(
        generate_types(&sample()).unwrap(),
        include_str!("fixtures/expected_types.rs")
    );
}

#[test]
fn server_matches_golden() {
    assert_eq!(
        generate_server(&sample()).unwrap(),
        include_str!("fixtures/expected_server.rs")
    );
}

#[test]
fn client_matches_golden() {
    assert_eq!(
        generate_client(&sample()).unwrap(),
        include_str!("fixtures/expected_client.rs")
    );
}

#[test]
fn py_structs_matches_golden() {
    assert_eq!(
        generate_py_structs(&sample()).unwrap(),
        include_str!("fixtures/expected_structs.py")
    );
}

#[test]
fn py_client_matches_golden() {
    assert_eq!(
        generate_py_client(&sample()).unwrap(),
        include_str!("fixtures/expected_client.py")
    );
}

#[test]
fn py_server_matches_golden() {
    assert_eq!(
        generate_py_server(&sample()).unwrap(),
        include_str!("fixtures/expected_server.py")
    );
}

#[test]
fn openrpc_matches_cross_language_golden() {
    let mut got: serde_json::Value =
        serde_json::from_str(&generate_openrpc(&sample()).unwrap()).unwrap();
    let mut golden: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/openrpc.json")).unwrap();
    got.as_object_mut().unwrap().remove("x-generated");
    golden.as_object_mut().unwrap().remove("x-generated");
    assert_eq!(
        got, golden,
        "generated OpenRPC must equal the committed golden"
    );
}

#[test]
fn generation_is_deterministic() {
    assert_eq!(
        generate_types(&sample()).unwrap(),
        generate_types(&sample()).unwrap()
    );
    assert_eq!(
        generate_server(&sample()).unwrap(),
        generate_server(&sample()).unwrap()
    );
    assert_eq!(
        generate_client(&sample()).unwrap(),
        generate_client(&sample()).unwrap()
    );
    assert_eq!(
        generate_py_structs(&sample()).unwrap(),
        generate_py_structs(&sample()).unwrap()
    );
    assert_eq!(
        generate_py_client(&sample()).unwrap(),
        generate_py_client(&sample()).unwrap()
    );
    assert_eq!(
        generate_py_server(&sample()).unwrap(),
        generate_py_server(&sample()).unwrap()
    );
    assert_eq!(
        generate_openrpc(&sample()).unwrap(),
        generate_openrpc(&sample()).unwrap()
    );
}

// --- branch coverage via the `full` fixture ----------------------------------

#[test]
fn full_fixture_exercises_remaining_branches() {
    let spec = Spec::load_dir("tests/fixtures/full").unwrap();
    let s = generate_server(&spec).unwrap();
    let t = generate_types(&spec).unwrap();

    // Subscription: a register line, but NO Handlers trait method.
    assert!(s.contains("SubscriptionDef::<Sub, Event>::new"));
    assert!(!s.contains("fn events("));
    // Flags.
    assert!(s.contains(".pre_auth()"));
    assert!(s.contains(".cancellable()"));
    assert!(s.contains(r#".roles(["admin", "ops"])"#));
    assert!(s.contains(".audit()"));
    // xdr-reachable optional: `note` is Option with `#[serde(default)]` and NO skip. (In the types.)
    assert!(t.contains("#[serde(default)]\n    pub note: Option<String>"));
    assert!(!t.contains("skip_serializing_if"));
    // Every default kind (in the types module).
    assert!(t.contains(r#"#[serde(default = "default_optargs_name")]"#));
    assert!(t.contains(r#"fn default_optargs_name() -> String { "anon".to_string() }"#));
    assert!(t.contains("fn default_optargs_count() -> i64 { 7i64 }"));
    assert!(t.contains("fn default_optargs_active() -> bool { true }"));
    assert!(t.contains("fn default_optargs_ratio() -> f64 { 2.5f64 }"));
    assert!(t.contains("fn default_optargs_mode() -> OptArgsMode { OptArgsMode::Fast }"));
    // Type-default fields (level 0) use bare `#[serde(default)]`.
    assert!(t.contains("#[serde(default)]\n    pub level: i64"));
    // The xdr method binds `.xdr(2001u32)`.
    assert!(s.contains(".xdr(2001u32)"));
    // Audit is on by default (no `audit` block) — service defaults to the spec name.
    assert!(s.contains("pub fn make_audit_sink") && s.contains(r#"builder("full")"#));

    // The client + OpenRPC also generate cleanly for the full spec.
    assert!(generate_client(&spec).unwrap().contains("subscribe_events"));
    assert!(generate_openrpc(&spec)
        .unwrap()
        .contains("\"x-direction\": \"server_client\""));
}

#[test]
fn python_methods_table_and_no_handler() {
    let spec = Spec::load_dir("tests/fixtures/python").unwrap();
    let s = generate_server(&spec).unwrap();
    assert!(s.contains(r#"PYTHON_METHODS: &[&str] = &["py.greet", "py.add", "py.boom"]"#));
    assert!(s.contains(".python_method("));
    assert!(generate_types(&spec)
        .unwrap()
        .contains("pub struct GreetArgs")); // structs in the types module
    assert!(!s.contains("fn greet(")); // python methods are NOT in the Handlers trait
    assert!(s.contains(r#".audit_message("greeting")"#)); // flags preserved
}

// --- Python (msgspec) emitters -----------------------------------------------

#[test]
fn py_structs_full_fixture_type_breadth() {
    let spec = Spec::load_dir("tests/fixtures/full").unwrap();
    let s = generate_py_structs(&spec).unwrap();

    // A generated StrEnum + its members.
    assert!(s.contains("class OptArgsMode(enum.StrEnum):"));
    assert!(s.contains("    FAST = \"fast\"") && s.contains("    SLOW = \"slow\""));
    // Every default kind renders as a Python literal / factory / enum member.
    assert!(s.contains(r#"name: str = "anon""#));
    assert!(s.contains(r#"label: str = """#));
    assert!(s.contains("level: int = 0"));
    assert!(s.contains("count: int = 7"));
    assert!(s.contains("active: bool = True"));
    assert!(s.contains("flag: bool = False"));
    assert!(s.contains("ratio: float = 2.5"));
    assert!(s.contains("tags: list[str] = msgspec.field(default_factory=list)"));
    assert!(s.contains("mode: OptArgsMode = OptArgsMode.FAST"));
    // Required $ref field + an optional (no default) field.
    assert!(s.contains("evt: Event"));
    assert!(s.contains("note: str | None = None"));
    // METHODS lists the plain methods; the subscription is not a row.
    assert!(s.contains(r#""secure.do": (OptArgs, OptResult)"#));
    assert!(s.contains(r#""fast.ping": (PingArgs, PingResult)"#));
    assert!(!s.contains("ev.sub"));
    // No secret in this fixture → no Annotated import.
    assert!(!s.contains("from typing import Annotated"));

    // The client skips the subscription (a comment) and exposes the plain methods; the server
    // imports the METHODS table.
    let c = generate_py_client(&spec).unwrap();
    assert!(c.contains("class FullClient:"));
    assert!(c.contains("# ev.sub: server->client subscription — not in the basic msgspec client."));
    assert!(c.contains("def secure_do(self, request: OptArgs) -> OptResult:"));
    assert!(!c.contains("def events("));
    assert!(generate_py_server(&spec)
        .unwrap()
        .contains("from full_types import METHODS"));
}

#[test]
fn py_secret_and_module_naming() {
    // The sample fixture carries secret fields → the Annotated import + Meta wrap.
    let s = generate_py_structs(&sample()).unwrap();
    assert!(s.contains("from typing import Annotated"));
    assert!(s.contains(r#"password: Annotated[str, msgspec.Meta(extra={"secret": True})]"#));

    // The python fixture: module/class names derive from the (underscored) service name, and each
    // python:true method is a plain METHODS row + a client method.
    let spec = Spec::load_dir("tests/fixtures/python").unwrap();
    assert!(generate_py_structs(&spec)
        .unwrap()
        .contains(r#""py.greet": (GreetArgs, GreetResult)"#));
    let c = generate_py_client(&spec).unwrap();
    assert!(c.contains("from python_sample_types import"));
    assert!(c.contains("class PythonSampleClient:"));
    assert!(c.contains("def greet(self, request: GreetArgs) -> GreetResult:"));
    assert!(generate_py_server(&spec)
        .unwrap()
        .contains("from python_sample_types import METHODS"));
}

#[test]
fn versioned_protocol_name_clients() {
    // A dotted, versioned service name (the `$/negotiate` discriminator): the module id is sanitized
    // (`api.v1` -> `api_v1`), the class keeps the version (`ApiV1Client`), and both clients pin the
    // protocol identity + expose a negotiating `connect` — instantiating the class selects the version.
    let spec = Spec::parse(
        r##"{"name":"api.v1","version":"2.0.0","$defs":{"A":{"type":"object","properties":{},"required":[]}},"methods":{"m":{"handler":"m","params":{"$ref":"#/$defs/A"},"result":{"$ref":"#/$defs/A"}}}}"##,
        "spec",
    )
    .unwrap();

    // Rust client: pinned consts + a concrete connecting constructor over the built-in engine.
    let rs = generate_client(&spec).unwrap();
    assert!(rs.contains("pub struct ApiV1Client<E>"));
    assert!(rs.contains(r#"pub const PROTOCOL: &str = "api.v1";"#));
    assert!(rs.contains(r#"pub const VERSION: &str = "2.0.0";"#));
    assert!(rs.contains("impl ApiV1Client<truenas_rpc_client::JsonRpcClient> {"));
    assert!(rs.contains("pub async fn connect("));
    assert!(rs.contains("connect_negotiate(endpoint, Self::PROTOCOL, config)"));

    // Python client: sanitized module import, pinned identity, negotiating classmethod + properties.
    let py = generate_py_client(&spec).unwrap();
    assert!(py.contains("class ApiV1Client:"));
    assert!(py.contains("from api_v1_types import"));
    assert!(py.contains(r#"    PROTOCOL = "api.v1""#));
    assert!(py.contains(r#"    VERSION = "2.0.0""#));
    assert!(py.contains("    def connect(cls, endpoint: str) -> ApiV1Client:"));
    assert!(py.contains("truenas_rpc_pyclient.connect(endpoint, cls.PROTOCOL)"));
    assert!(py.contains("    def negotiated(self) -> truenas_rpc_pyclient.Negotiated | None:"));
    assert!(py.contains("    def available(self) -> list[str] | None:"));

    // The types + server modules use the sanitized module name too.
    assert!(generate_py_server(&spec)
        .unwrap()
        .contains("from api_v1_types import METHODS"));
}

#[test]
fn generated_python_goldens_pass_ruff() {
    // Opportunistic guard: the committed `.py` goldens stay `ruff`-clean. Skipped where `ruff` isn't
    // installed (a minimal image). `mypy --strict` cleanliness is verified out of band (it needs a
    // Python env with `msgspec` + the `truenas_rpc_pyclient` stub, so it's not gated here).
    use std::process::Command;
    let have_ruff = Command::new("ruff")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !have_ruff {
        return;
    }
    let out = Command::new("ruff")
        .args([
            "check",
            "--no-cache",
            "tests/fixtures/expected_structs.py",
            "tests/fixtures/expected_client.py",
            "tests/fixtures/expected_server.py",
        ])
        .output()
        .expect("run ruff");
    assert!(
        out.status.success(),
        "ruff on the generated .py goldens failed:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn py_emitter_errors() {
    let structs_err = |spec: &str| {
        generate_py_structs(&Spec::parse(spec, "spec").unwrap())
            .unwrap_err()
            .to_string()
    };
    // A non-object $def and a non-identifier field are rejected.
    assert!(structs_err(
        r##"{"name":"t","version":"1","$defs":{"A":{"type":"string"}},"methods":{}}"##
    )
    .contains("must be a JSON object schema"));
    assert!(structs_err(r##"{"name":"t","version":"1","$defs":{"A":{"type":"object","properties":{"bad-name":{"type":"string"}}}},"methods":{}}"##)
        .contains("not a valid identifier"));

    // A plain method's params/result must be a `$ref`, with a `result` present (shared validation
    // surfaces in structs, client, and server).
    let m = |body: &str| {
        format!(
            r##"{{"name":"t","version":"1","$defs":{{"A":{{"type":"object","properties":{{}},"required":[]}}}},"methods":{{"m":{{"handler":"m",{body}}}}}}}"##
        )
    };
    assert!(structs_err(&m(
        r##""params":{"type":"object","properties":{}},"result":{"$ref":"#/$defs/A"}"##
    ))
    .contains("params must be a $ref"));
    assert!(structs_err(&m(r##""params":{"$ref":"#/$defs/A"}"##)).contains("missing 'result'"));

    // A dotted / hyphenated service name is sanitized into a valid module id (both client and server
    // generate): `bad-name` -> module `bad_name`, class `BadNameClient`.
    let bad_name = r##"{"name":"bad-name","version":"1","$defs":{},"methods":{}}"##;
    assert!(generate_py_client(&Spec::parse(bad_name, "spec").unwrap())
        .unwrap()
        .contains("class BadNameClient:"));
    assert!(generate_py_server(&Spec::parse(bad_name, "spec").unwrap())
        .unwrap()
        .contains("from bad_name_types import METHODS"));
    // Only a name with no usable identifier characters is an error.
    let empty_name = r##"{"name":"","version":"1","$defs":{},"methods":{}}"##;
    assert!(
        generate_py_client(&Spec::parse(empty_name, "spec").unwrap())
            .unwrap_err()
            .to_string()
            .contains("no characters usable in a Python module identifier")
    );
    assert!(generate_py_server(
        &Spec::parse(&m(r##""params":{"$ref":"#/$defs/A"}"##), "spec").unwrap()
    )
    .unwrap_err()
    .to_string()
    .contains("missing 'result'"));
}

#[test]
fn build_and_cli_emit_py_artifacts() {
    // Build writes `<service>_{types,client,server}.py` (the modules import each other by name).
    let out = tmp("build-py");
    let abs = std::fs::canonicalize("tests/fixtures/sample").unwrap();
    let structs = Build::new()
        .json_idl(&abs)
        .out_dir(&out)
        .emit_py_structs()
        .unwrap();
    assert!(structs.ends_with("sample_types.py"));
    assert!(std::fs::read_to_string(&structs)
        .unwrap()
        .contains("METHODS: MappingProxyType[str, tuple[type, type]] = MappingProxyType("));
    let client = Build::new()
        .json_idl(&abs)
        .out_dir(&out)
        .emit_py_client()
        .unwrap();
    assert!(client.ends_with("sample_client.py"));
    assert!(std::fs::read_to_string(&client)
        .unwrap()
        .contains("from sample_types import"));
    let server = Build::new()
        .json_idl(&abs)
        .out_dir(&out)
        .emit_py_server()
        .unwrap();
    assert!(server.ends_with("sample_server.py"));
    assert!(std::fs::read_to_string(&server)
        .unwrap()
        .contains("def dispatch(name"));

    // CLI subcommands produce output.
    for sub in ["py-structs", "py-client", "py-server"] {
        let mut buf = Vec::new();
        run_cli(
            &[sub.to_string(), "tests/fixtures/sample".to_string()],
            &mut buf,
        )
        .unwrap();
        assert!(!buf.is_empty(), "{sub} produced output");
    }
}

// --- audit config (on by default; spec-configurable) -------------------------

#[test]
fn audit_config() {
    // No `audit` block → on by default; `service` defaults to the spec `name`, no queue bound.
    let default_on = r##"{"name":"svc","version":"1","$defs":{"A":{"type":"object","properties":{},"required":[]}},"methods":{"m":{"handler":"m","params":{"$ref":"#/$defs/A"},"result":{"$ref":"#/$defs/A"}}}}"##;
    let s = generate_server(&Spec::parse(default_on, "spec").unwrap()).unwrap();
    assert!(s.contains("pub fn make_audit_sink"));
    assert!(s.contains(
        r#"truenas_rpc_utils_unsafe::audit::LinuxAuditSink::<S>::builder("svc").identity"#
    ));
    assert!(s.contains(".audit_sink(make_audit_sink::<S, _>("));

    // Configured service + queue bound are baked into `make_audit_sink`.
    let configured = r##"{"name":"svc","version":"1","audit":{"service":"truenas-api","queueBound":256},"$defs":{},"methods":{}}"##;
    let s = generate_server(&Spec::parse(configured, "spec").unwrap()).unwrap();
    assert!(s.contains(r#"builder("truenas-api").queue_bound(256usize).identity"#));

    // Disabled → no audit wiring at all (so a consumer needs no `truenas-rpc-utils-unsafe` dependency).
    let disabled =
        r##"{"name":"svc","version":"1","audit":{"enabled":false},"$defs":{},"methods":{}}"##;
    let s = generate_server(&Spec::parse(disabled, "spec").unwrap()).unwrap();
    assert!(
        !s.contains("make_audit_sink")
            && !s.contains("truenas_rpc_utils_unsafe")
            && !s.contains(".audit_sink(")
    );

    // Validation: a given service must be non-empty, a given queue bound > 0, keys are closed.
    assert!(
        parse_err(r##"{"name":"t","version":"1","audit":{"service":""},"methods":{}}"##)
            .contains("audit.service must be a non-empty")
    );
    assert!(
        parse_err(r##"{"name":"t","version":"1","audit":{"queueBound":0},"methods":{}}"##)
            .contains("audit.queueBound must be greater than 0")
    );
    assert!(
        parse_err(r##"{"name":"t","version":"1","audit":{"bogus":1},"methods":{}}"##)
            .contains("unknown field")
    );
}

#[test]
fn protocols_const() {
    // Default: PROTOCOLS lists json-rpc; no ONC constants emitted.
    let s = generate_server(&sample()).unwrap();
    assert!(s.contains(r#"pub const PROTOCOLS: &[&str] = &["json-rpc"];"#));
    assert!(!s.contains("ONC_PROGRAM"));

    // onc-rpc declared (with an xdr method) → PROTOCOLS + the default ONC program/version.
    let onc = r##"{"name":"svc","version":"1","protocols":["json-rpc","onc-rpc"],"$defs":{"A":{"type":"object","properties":{},"required":[]}},"methods":{"m":{"handler":"m","params":{"$ref":"#/$defs/A"},"result":{"$ref":"#/$defs/A"},"xdr":true,"xdr_id":1001}}}"##;
    let s = generate_server(&Spec::parse(onc, "spec").unwrap()).unwrap();
    assert!(s.contains(r#"pub const PROTOCOLS: &[&str] = &["json-rpc", "onc-rpc"];"#));
    assert!(s.contains("pub const ONC_PROGRAM: u32 = 0x2000_0001;"));
    assert!(s.contains("pub const ONC_VERSION: u32 = 1;"));
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
    assert!(Spec::load_dir(&dir)
        .unwrap_err()
        .to_string()
        .contains("no *.json"));
}

#[test]
fn multi_file_merges_and_rejects_duplicates() {
    let dir = tmp("multi");
    std::fs::write(dir.join("a.json"), r##"{"name":"svc","version":"1","$defs":{"A":{"type":"object","properties":{"x":{"type":"integer"}},"required":["x"]}},"methods":{"m1":{"handler":"m1","params":{"$ref":"#/$defs/A"},"result":{"$ref":"#/$defs/A"}}}}"##).unwrap();
    std::fs::write(dir.join("b.json"), r##"{"name":"ignored","version":"9","$defs":{"B":{"type":"object","properties":{},"required":[]}},"methods":{"m2":{"handler":"m2","params":{"$ref":"#/$defs/B"},"result":{"$ref":"#/$defs/A"}}}}"##).unwrap();
    let spec = Spec::load_dir(&dir).unwrap(); // b.m2 result $ref A resolves across files
    let s = generate_server(&spec).unwrap();
    let t = generate_types(&spec).unwrap();
    assert!(t.contains("pub struct A") && t.contains("pub struct B")); // merged $defs in the types module
    assert!(s.contains("fn m1(") && s.contains("fn m2("));

    let dup = tmp("multi-dup");
    std::fs::write(dup.join("a.json"), r##"{"name":"s","version":"1","$defs":{"A":{"type":"object","properties":{},"required":[]}},"methods":{"m":{"handler":"m","params":{"$ref":"#/$defs/A"},"result":{"$ref":"#/$defs/A"}}}}"##).unwrap();
    std::fs::write(dup.join("b.json"), r##"{"name":"s","version":"1","$defs":{"B":{"type":"object","properties":{},"required":[]}},"methods":{"m":{"handler":"m2","params":{"$ref":"#/$defs/B"},"result":{"$ref":"#/$defs/B"}}}}"##).unwrap();
    assert!(Spec::load_dir(&dup)
        .unwrap_err()
        .to_string()
        .contains("duplicate method"));

    let dupd = tmp("multi-dupdef");
    std::fs::write(dupd.join("a.json"), r##"{"name":"s","version":"1","$defs":{"A":{"type":"object","properties":{},"required":[]}},"methods":{}}"##).unwrap();
    std::fs::write(dupd.join("b.json"), r##"{"name":"s","version":"1","$defs":{"A":{"type":"object","properties":{},"required":[]}},"methods":{}}"##).unwrap();
    assert!(Spec::load_dir(&dupd)
        .unwrap_err()
        .to_string()
        .contains("duplicate $def"));
}

// --- bad-spec validation corpus ----------------------------------------------

fn parse_err(json: &str) -> String {
    Spec::parse(json, "spec").unwrap_err().to_string()
}
fn gen_err(defs: &str) -> String {
    let json = format!(r#"{{"name":"t","version":"1","$defs":{defs},"methods":{{}}}}"#);
    // Type/default emission (and its errors) live in the shared types module now.
    generate_types(&Spec::parse(&json, "spec").unwrap())
        .unwrap_err()
        .to_string()
}

#[test]
fn structural_errors() {
    assert!(
        parse_err(r##"{"name":"t","version":"1","methods":{},"bogus":1}"##)
            .contains("unknown field")
    );
    assert!(parse_err(r##"{"name":"t","version":"1"}"##).contains("missing field"));
    assert!(parse_err(r##"{"name":"t","version":"1","$defs":{"A":{"type":"object"}},"methods":{"m":{"params":{"$ref":"#/$defs/A"}}}}"##).contains("missing field"));
}

#[test]
fn cross_cutting_errors() {
    let m = |body: &str| {
        format!(
            r##"{{"name":"t","version":"1","$defs":{{"A":{{"type":"object","properties":{{}},"required":[]}}}},"methods":{{"x":{{"handler":"x","params":{{"$ref":"#/$defs/A"}}{body}}}}}}}"##
        )
    };
    assert!(parse_err(r##"{"name":"t","version":"1","$defs":{"A":{"type":"object"}},"methods":{"x":{"handler":"1bad","params":{"$ref":"#/$defs/A"},"result":{"$ref":"#/$defs/A"}}}}"##).contains("not a valid identifier"));
    assert!(parse_err(&m(r##","filterable":true"##)).contains("filterable requires an 'entry'"));
    assert!(parse_err(&m(
        r##","filterable":true,"entry":{"$ref":"#/$defs/A"},"result":{"$ref":"#/$defs/A"}"##
    ))
    .contains("must not have 'result'"));
    assert!(parse_err(&m(r##","xdr":true"##)).contains("xdr requires 'xdr_id'"));
    assert!(parse_err(&m(r##","xdr":true,"xdr_id":500"##)).contains("reserved"));
    assert!(parse_err(&m(r##","python":true"##)).contains("python requires 'result'"));
    assert!(parse_err(&m(
        r##","python":true,"result":{"$ref":"#/$defs/A"},"xdr":true,"xdr_id":1001"##
    ))
    .contains("python cannot combine"));
    assert!(
        parse_err(&m(r##","result":{"$ref":"#/$defs/Missing"}"##)).contains("unknown $defs type")
    );
    assert!(parse_err(&m(r##","result":{"$ref":"#/components/X"}"##)).contains("unsupported $ref"));
    assert!(parse_err(r##"{"name":"t","version":"1","$defs":{"A":{"type":"object"}},"methods":{"x":{"handler":"x","params":{"$ref":"#/$defs/A"},"result":{"$ref":"#/$defs/A"},"xdr":true,"xdr_id":1001},"y":{"handler":"y","params":{"$ref":"#/$defs/A"},"result":{"$ref":"#/$defs/A"},"xdr":true,"xdr_id":1001}}}"##).contains("collides"));
    // transfer: needs a `result`, and can't combine with any other dispatch kind.
    assert!(parse_err(&m(r##","transfer":{"direction":"download"}"##))
        .contains("transfer requires 'result'"));
    assert!(parse_err(&m(
        r##","result":{"$ref":"#/$defs/A"},"transfer":{"direction":"upload"},"cancellable":true"##
    ))
    .contains("transfer cannot combine"));
}

#[test]
fn async_methods() {
    // An `async: true` method emits an RPITIT trait method + an `async_method` registration (awaited
    // inline on the runtime — no `spawn_blocking` hop).
    let ok = r##"{"name":"t","version":"1","$defs":{"A":{"type":"object","properties":{},"required":[]}},"methods":{"go":{"handler":"go","async":true,"params":{"$ref":"#/$defs/A"},"result":{"$ref":"#/$defs/A"}}}}"##;
    let s = generate_server(&Spec::parse(ok, "spec").unwrap()).unwrap();
    assert!(s.contains(
        "fn go(&self, request: A, cx: truenas_rpc::RequestCtx<S>) -> impl ::core::future::Future"
    ));
    assert!(s.contains("builder.async_method(truenas_rpc::AsyncRpcMethod::new"));
    assert!(s.contains("async move { h.go(request, cx).await }"));

    // Validation: async needs a `result`; it can't combine with filterable/python/server_client.
    let m = |body: &str| {
        format!(
            r##"{{"name":"t","version":"1","$defs":{{"A":{{"type":"object","properties":{{}},"required":[]}}}},"methods":{{"go":{{"handler":"go","async":true,"params":{{"$ref":"#/$defs/A"}}{body}}}}}}}"##
        )
    };
    assert!(parse_err(&m("")).contains("async requires 'result'"));
    assert!(
        parse_err(&m(r##","result":{"$ref":"#/$defs/A"},"python":true"##))
            .contains("async cannot combine")
    );
}

#[test]
fn protocol_errors() {
    // A spec with one plain method + an overridable `protocols` list.
    let with = |protos: &str| {
        format!(
            r##"{{"name":"t","version":"1","protocols":{protos},"$defs":{{"A":{{"type":"object","properties":{{}},"required":[]}}}},"methods":{{"x":{{"handler":"x","params":{{"$ref":"#/$defs/A"}},"result":{{"$ref":"#/$defs/A"}}}}}}}}"##
        )
    };
    // Empty / unsupported / duplicate are rejected; the message names only the supported protocols.
    assert!(parse_err(&with("[]")).contains("at least one wire protocol"));
    let unsup = parse_err(&with(r##"["json-rpc","ftp"]"##));
    assert!(unsup.contains("unsupported protocol \"ftp\"") && unsup.contains("json-rpc, onc-rpc"));
    assert!(parse_err(&with(r##"["json-rpc","json-rpc"]"##)).contains("listed twice"));
    // onc-rpc with no xdr-reachable method serves only the NULL probe → rejected.
    assert!(parse_err(&with(r##"["onc-rpc"]"##)).contains("no method is xdr-reachable"));

    // Omitting `protocols` defaults to json-rpc; xdr under json-rpc alone is valid (the TXDR
    // sub-wire — NOT coupled to onc-rpc); json-rpc + onc-rpc with an xdr method is valid.
    let xdr = |protos: &str| {
        format!(
            r##"{{"name":"t","version":"1","protocols":{protos},"$defs":{{"A":{{"type":"object","properties":{{}},"required":[]}}}},"methods":{{"x":{{"handler":"x","params":{{"$ref":"#/$defs/A"}},"result":{{"$ref":"#/$defs/A"}},"xdr":true,"xdr_id":1001}}}}}}"##
        )
    };
    assert!(Spec::parse(&xdr(r##"["json-rpc"]"##), "spec").is_ok());
    assert!(Spec::parse(&xdr(r##"["json-rpc","onc-rpc"]"##), "spec").is_ok());

    // A server_client subscription cannot be xdr (the binary wire has no server-push).
    let sub_xdr = r##"{"name":"t","version":"1","$defs":{"A":{"type":"object","properties":{},"required":[]}},"methods":{"e":{"handler":"e","params":{"$ref":"#/$defs/A"},"direction":"server_client","notifies":{"$ref":"#/$defs/A"},"xdr":true,"xdr_id":1001}}}"##;
    assert!(parse_err(sub_xdr).contains("server_client subscription cannot be xdr"));
}

#[test]
fn type_mapping_errors() {
    assert!(
        gen_err(r#"{"A":{"type":"object","properties":{"f":{"enum":[1,2]}}}}"#)
            .contains("must all be strings")
    );
    assert!(
        gen_err(r#"{"A":{"type":"object","properties":{"f":{"enum":[]}}}}"#)
            .contains("at least one value")
    );
    assert!(
        gen_err(r#"{"A":{"type":"object","properties":{"f":{"type":"array"}}}}"#)
            .contains("must have an object 'items'")
    );
    assert!(gen_err(
        r#"{"A":{"type":"object","properties":{"f":{"type":"object","properties":{}}}}}"#
    )
    .contains("inline object types"));
    assert!(
        gen_err(r#"{"A":{"type":"object","properties":{"f":{}}}}"#).contains("unsupported schema")
    );
    assert!(
        gen_err(r#"{"A":{"type":"object","properties":{"bad-name":{"type":"string"}}}}"#)
            .contains("not a valid identifier")
    );
    assert!(gen_err(r#"{"A":{"type":"string"}}"#).contains("must be a JSON object schema"));
    assert!(
        gen_err(r#"{"A":{"type":"object","properties":{"f":{"enum":["!!!"]}}}}"#)
            .contains("no identifier characters")
    );
}

#[test]
fn default_value_errors() {
    assert!(gen_err(r#"{"A":{"type":"object","properties":{"f":{"type":"array","items":{"type":"string"},"default":["x"]}}}}"#).contains("only an empty-array default"));
    assert!(
        gen_err(r#"{"A":{"type":"object","properties":{"f":{"type":"string","default":5}}}}"#)
            .contains("string default must be a string")
    );
    assert!(gen_err(
        r#"{"A":{"type":"object","properties":{"f":{"type":"integer","default":"x"}}}}"#
    )
    .contains("integer default must be an integer"));
    assert!(gen_err(
        r#"{"A":{"type":"object","properties":{"f":{"type":"number","default":"x"}}}}"#
    )
    .contains("number default must be a number"));
    assert!(gen_err(
        r#"{"A":{"type":"object","properties":{"f":{"type":"boolean","default":"x"}}}}"#
    )
    .contains("boolean default must be a boolean"));
    assert!(
        gen_err(r#"{"A":{"type":"object","properties":{"f":{"enum":["a"],"default":5}}}}"#)
            .contains("enum default must be a string")
    );
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
    let s = generate_types(&Spec::parse(spec, "spec").unwrap()).unwrap();
    assert!(s.contains("pub r#type: String")); // keyword field → raw identifier
    assert!(s.contains("_1st")); // digit-leading enum variant is `_`-prefixed
}

#[test]
fn emit_error_paths() {
    // Inline (non-$ref) params → all three emitters reject it.
    let inline = r##"{"name":"t","version":"1","$defs":{"A":{"type":"object","properties":{},"required":[]}},"methods":{"m":{"handler":"m","params":{"type":"object","properties":{}},"result":{"$ref":"#/$defs/A"}}}}"##;
    let spec = Spec::parse(inline, "spec").unwrap();
    assert!(generate_server(&spec)
        .unwrap_err()
        .to_string()
        .contains("must be a $ref"));
    assert!(generate_client(&spec).is_err());
    assert!(generate_openrpc(&spec).is_err());

    // A plain method with no result.
    let no_result = r##"{"name":"t","version":"1","$defs":{"A":{"type":"object","properties":{},"required":[]}},"methods":{"m":{"handler":"m","params":{"$ref":"#/$defs/A"}}}}"##;
    let spec = Spec::parse(no_result, "spec").unwrap();
    assert!(generate_server(&spec)
        .unwrap_err()
        .to_string()
        .contains("missing 'result'"));
    assert!(generate_client(&spec).is_err());
    assert!(generate_openrpc(&spec).is_ok()); // OpenRPC simply omits the result

    // A server_client method with no notifies.
    let no_notifies = r##"{"name":"t","version":"1","$defs":{"A":{"type":"object","properties":{},"required":[]}},"methods":{"m":{"handler":"m","params":{"$ref":"#/$defs/A"},"direction":"server_client"}}}"##;
    let spec = Spec::parse(no_notifies, "spec").unwrap();
    assert!(generate_server(&spec)
        .unwrap_err()
        .to_string()
        .contains("missing 'notifies'"));
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
    let server = Build::new()
        .json_idl(&abs)
        .out_dir(&out)
        .emit_server()
        .unwrap();
    assert!(server.ends_with("server_gen.rs"));
    assert!(std::fs::read_to_string(&server)
        .unwrap()
        .contains("pub fn register"));
    let client = Build::new()
        .json_idl(&abs)
        .out_dir(&out)
        .emit_client()
        .unwrap();
    assert!(std::fs::read_to_string(&client)
        .unwrap()
        .contains("truenas_rpc_client::CallEngine"));
    let openrpc = Build::new()
        .json_idl(&abs)
        .out_dir(&out)
        .emit_openrpc()
        .unwrap();
    assert!(std::fs::read_to_string(&openrpc)
        .unwrap()
        .contains("\"openrpc\""));
    assert!(Build::new().out_dir(&out).emit_server().is_err()); // missing json_idl
}

#[test]
fn build_resolves_env() {
    std::env::set_var("CARGO_MANIFEST_DIR", env!("CARGO_MANIFEST_DIR"));
    let out = tmp("build-env");
    std::env::set_var("OUT_DIR", &out);
    let p = Build::new()
        .json_idl("tests/fixtures/sample")
        .emit_openrpc()
        .unwrap(); // relative path
    assert!(p.starts_with(&out));
    std::env::remove_var("OUT_DIR");
    let abs = std::fs::canonicalize("tests/fixtures/sample").unwrap();
    assert!(Build::new().json_idl(&abs).emit_server().is_err()); // no out_dir + no OUT_DIR

    // Relative json_idl with CARGO_MANIFEST_DIR unset → used as-is (resolved against cwd).
    std::env::remove_var("CARGO_MANIFEST_DIR");
    let out2 = tmp("build-env2");
    let p2 = Build::new()
        .json_idl("tests/fixtures/sample")
        .out_dir(&out2)
        .emit_server()
        .unwrap();
    assert!(p2.starts_with(&out2));
    std::env::set_var("CARGO_MANIFEST_DIR", env!("CARGO_MANIFEST_DIR")); // restore
}

// --- CLI ---------------------------------------------------------------------

#[test]
fn cli_subcommands_out_and_errors() {
    for sub in ["types", "server", "client", "openrpc"] {
        let mut buf = Vec::new();
        run_cli(
            &[sub.to_string(), "tests/fixtures/sample".to_string()],
            &mut buf,
        )
        .unwrap();
        assert!(!buf.is_empty(), "{sub} produced output");
    }
    let out = tmp("cli").join("server_gen.rs");
    run_cli(
        &[
            "server".into(),
            "tests/fixtures/sample".into(),
            "--out".into(),
            out.to_string_lossy().into_owned(),
        ],
        &mut Vec::new(),
    )
    .unwrap();
    assert!(std::fs::read_to_string(&out).unwrap().contains("register"));
    assert!(run_cli(&[], &mut Vec::new()).is_err());
    assert!(run_cli(&["server".into()], &mut Vec::new()).is_err());
    assert!(run_cli(
        &[
            "server".into(),
            "tests/fixtures/sample".into(),
            "--out".into()
        ],
        &mut Vec::new()
    )
    .is_err());
    assert!(run_cli(
        &[
            "server".into(),
            "tests/fixtures/sample".into(),
            "--nope".into(),
            "x".into()
        ],
        &mut Vec::new()
    )
    .is_err());
    assert!(run_cli(
        &["bogus".into(), "tests/fixtures/sample".into()],
        &mut Vec::new()
    )
    .is_err());
}
