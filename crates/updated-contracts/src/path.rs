//! The one place path-traversal safety is decided. Every value that is later joined onto a trusted
//! root — a bundle member, a TUF target reference, a node identity, a `product` directory — is
//! confined here first, so the "can this escape the directory it lands in?" question has a single
//! answer the whole system shares instead of each call site hand-rolling (and drifting on) its own
//! component check.
//!
//! It lives in the contracts crate because protocol grammars (the enrollment assignment path, a
//! signed target reference, a telemetry node identity) must apply exactly the same rule as the
//! node-side code that later joins those values onto a real directory. `std::path` is used purely as a parser
//! here; nothing in this module touches the filesystem.

use std::path::{Component, Path};

/// A single safe path *component*: one directory or file name that, joined onto any root, can never
/// escape it. Non-empty, neither `.` nor `..`, containing no path separator (`/` or `\`), no
/// drive/scheme colon, and no control character. Everything the system joins as exactly one
/// segment — a `product`, a node name, a version directory — is gated on this.
pub fn is_safe_component(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && !segment.contains(['/', '\\', ':'])
        && !segment.chars().any(char::is_control)
}

/// A *confined relative path*: a non-empty, `/`-separated sequence of [`is_safe_component`]
/// segments with no leading `/` (absolute) and no `\` anywhere. Confined means joined onto any
/// root it stays within it — no `..` climb, no absolute reset, no Windows drive or separator.
/// Values that legitimately carry subdirectories (bundle members, target references) validate
/// here; a value that must be a single segment uses [`is_safe_component`].
pub fn is_confined_relative(path: &str) -> bool {
    if path.is_empty() || path.starts_with('/') || path.contains('\\') {
        return false;
    }
    // Cross-check the string split against the OS path parser: every component must be a plain
    // `Normal` name (this rejects any absolute prefix, root, or `.`/`..` the split might miss on
    // an exotic platform), and each split segment must independently be a safe component.
    let confined = Path::new(path)
        .components()
        .all(|component| matches!(component, Component::Normal(_)));
    confined && path.split('/').all(is_safe_component)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_component_confines_a_single_segment() {
        for ok in ["app", "agent-7", "lifecycle", "v1.2.3-deadbeef"] {
            assert!(is_safe_component(ok), "{ok} should be a safe component");
        }
        for bad in ["", ".", "..", "a/b", "a\\b", "C:", "a:b", "a\0b", "..\\x"] {
            assert!(!is_safe_component(bad), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn confined_relative_rejects_every_traversal_shape() {
        for ok in ["a", "a/b", "a/b/c", "dir/file.txt"] {
            assert!(is_confined_relative(ok), "{ok} should be confined");
        }
        for bad in [
            "",
            "/etc/passwd",
            "../secret",
            "a/../b",
            "a/./b",
            "a//b",
            "a/",
            "a\\b",
            "C:\\windows",
            "a/b:c",
        ] {
            assert!(!is_confined_relative(bad), "{bad:?} must be rejected");
        }
    }
}
