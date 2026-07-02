//! Differential conformance — the gating proof that the Rust engine matches the TrueNAS
//! middleware's `truenas_pyfilter` C engine byte-for-byte.
//!
//! Replays a committed, frozen case matrix (`conformance/golden.json`, derived from the upstream
//! engine's own `test_filter_list.py` and recorded against the C engine) through the **Rust**
//! engine and asserts the rows / count / error-kind are identical.

use serde_json::Value;
use truenas_filter::{
    compile_filters, compile_options, tnfilter, tnmatch, FilterError, Filtered, QueryOptions,
};

const GOLDEN: &str = include_str!("conformance/golden.json");

/// Run one filter case through the Rust engine, mirroring `compile → compile → tnfilter`
/// so a compile-time error surfaces as `Compile` and a runtime one as `Eval`.
fn run_filter(
    data: Vec<Value>,
    filters: &[Value],
    opts: &QueryOptions,
) -> Result<Filtered<Value>, FilterError> {
    let cf = compile_filters(filters)?;
    let co = compile_options(opts)?;
    tnfilter(data, &cf, &co)
}

fn check_result(label: &str, expected: &Value, actual: Result<Filtered<Value>, FilterError>) {
    if let Some(kind) = expected.get("error").and_then(Value::as_str) {
        match actual {
            Err(FilterError::Compile(_)) => {
                assert_eq!(
                    kind, "compile",
                    "{label}: expected {kind} error, got Compile"
                )
            }
            Err(FilterError::Eval(_)) => {
                assert_eq!(kind, "eval", "{label}: expected {kind} error, got Eval")
            }
            Ok(v) => panic!("{label}: expected {kind} error, got Ok({v:?})"),
        }
    } else if let Some(count) = expected.get("count") {
        match actual {
            Ok(Filtered::Count(n)) => {
                assert_eq!(n, count.as_i64().unwrap(), "{label}: count mismatch")
            }
            other => panic!("{label}: expected count, got {other:?}"),
        }
    } else {
        let rows = expected["rows"].as_array().expect("rows array");
        match actual {
            Ok(Filtered::Rows(got)) => assert_eq!(&got, rows, "{label}: rows mismatch"),
            other => panic!("{label}: expected rows, got {other:?}"),
        }
    }
}

#[test]
fn differential_against_c_engine() {
    let golden: Value = serde_json::from_str(GOLDEN).expect("golden.json parses");
    let datasets = golden["datasets"].as_object().expect("datasets object");
    let cases = golden["cases"].as_array().expect("cases array");
    assert!(
        cases.len() >= 50,
        "suspiciously small corpus: {}",
        cases.len()
    );

    for case in cases {
        let label = case["label"].as_str().unwrap();
        let ds = case["dataset"].as_str().unwrap();
        let data = datasets[ds]
            .as_array()
            .expect("dataset is an array")
            .clone();
        let filters = case["filters"].as_array().expect("filters array").clone();
        let opts: QueryOptions = serde_json::from_value(case["options"].clone())
            .unwrap_or_else(|e| panic!("{label}: options deserialize failed: {e}"));

        let actual = run_filter(data, &filters, &opts);
        check_result(label, &case["result"], actual);
    }

    // match() cases — a pure predicate (no select), so compare the boolean outcome.
    for m in golden["match_cases"].as_array().expect("match_cases array") {
        let label = m["label"].as_str().unwrap();
        let item = m["item"].clone();
        let filters = m["filters"].as_array().unwrap().clone();
        let cf = compile_filters(&filters).expect("match filters compile");
        let got = tnmatch(&item, &cf).expect("match should not error");
        assert_eq!(
            Value::Bool(got),
            m["result"]["matched"],
            "{label}: match mismatch"
        );
    }
}
