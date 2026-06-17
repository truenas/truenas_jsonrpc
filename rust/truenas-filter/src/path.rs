//! Dotted-path splitting, shared by filter and order specs.
//!
//! A field name is a dotted path with backslash-escaped dots: split on every `.`, then
//! merge a piece into the next when it ends with `\` (the escape is stripped and the dot
//! restored) — so `"foo\.bar.baz"` → `["foo.bar", "baz"]`. Each component is tested once
//! for `*` (wildcard) and for an all-digit list index, so traversal needs no string work.

/// One pre-split path component.
pub(crate) struct PathPart {
    /// The component as a dict key / attribute name.
    pub key: String,
    /// `true` when the component is `*` (match any list element).
    pub is_wildcard: bool,
    /// `Some(i)` when the component is a non-negative decimal list index.
    pub index: Option<usize>,
}

impl PathPart {
    fn new(seg: String) -> Self {
        let is_wildcard = seg == "*";
        // Mirror the C engine's `strtol` index test: non-empty, all ASCII digits, fits.
        let index = if !is_wildcard
            && !seg.is_empty()
            && seg.bytes().all(|b| b.is_ascii_digit())
        {
            seg.parse::<usize>().ok()
        } else {
            None
        };
        PathPart { key: seg, is_wildcard, index }
    }
}

/// Split a dotted path into [`PathPart`]s, honoring `\.` escapes.
pub(crate) fn split_path(name: &str) -> Vec<PathPart> {
    let pieces: Vec<&str> = name.split('.').collect();
    let mut parts = Vec::new();
    let mut i = 0;
    while i < pieces.len() {
        let mut seg = pieces[i].to_string();
        i += 1;
        // Merge while the current segment ends with the escape backslash.
        while i < pieces.len() && seg.ends_with('\\') {
            seg.pop();
            seg.push('.');
            seg.push_str(pieces[i]);
            i += 1;
        }
        parts.push(PathPart::new(seg));
    }
    parts
}
