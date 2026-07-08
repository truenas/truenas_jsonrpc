//! Rust-identifier helpers for emitted code.

/// Rust keywords that need raw-escaping (`r#kw`) to be used as identifiers.
const RAW_ESCAPABLE_KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "else", "enum", "extern", "false", "fn", "for", "if",
    "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "static",
    "struct", "trait", "true", "type", "unsafe", "use", "where", "while", "async", "await", "dyn",
    "abstract", "become", "box", "do", "final", "macro", "override", "priv", "typeof", "unsized",
    "virtual", "yield", "try", "union",
];

/// Keywords that cannot be raw identifiers — a field/type named one of these is rejected.
const UNESCAPABLE_KEYWORDS: &[&str] = &["crate", "self", "Self", "super"];

/// True if `s` matches `^[A-Za-z_][A-Za-z0-9_]*$` (the json-idl handler/field rule).
pub fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// The token to use for a field/struct/method identifier (raw-escaping a keyword), or
/// `None` if `name` cannot be a Rust identifier.
pub fn rust_ident(name: &str) -> Option<String> {
    if !is_ident(name) || UNESCAPABLE_KEYWORDS.contains(&name) {
        return None;
    }
    if RAW_ESCAPABLE_KEYWORDS.contains(&name) {
        Some(format!("r#{name}"))
    } else {
        Some(name.to_string())
    }
}

/// A PascalCase identifier derived from an arbitrary string (non-alphanumeric runs are word
/// breaks). Used for enum-variant idents and generated nested-enum type names. A leading
/// digit is prefixed with `_` to stay a valid identifier.
pub fn pascal_case(s: &str) -> String {
    let mut out = String::new();
    let mut new_word = true;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            if new_word {
                out.extend(c.to_uppercase());
            } else {
                out.push(c);
            }
            new_word = false;
        } else {
            new_word = true;
        }
    }
    if out.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}
