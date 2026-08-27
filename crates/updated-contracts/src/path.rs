//! The one place path-traversal safety is decided. Every value that is later joined onto a trusted
//! root — a bundle member, a TUF target reference, or another arbitrary filesystem name — is
//! confined here first, so the "can this escape the directory it lands in?" question has a single
//! answer the whole system shares instead of each call site hand-rolling (and drifting on) its own
//! component check.
//!
//! It lives in the contracts crate because protocol grammars (the enrollment assignment path, a
//! signed target reference, a telemetry node identity) must apply exactly the same rule as the
//! node-side code that later joins those values onto a real directory. `std::path` is used purely as a parser
//! here; nothing in this module touches the filesystem.

use std::path::{Component, Path};

/// The one character class both grammars below are built from: every character a path component
/// may carry. Held in a macro because `concat!` takes literals, and held ONCE because
/// [`SAFE_COMPONENT_PATTERN`] and [`CONFINED_RELATIVE_PATTERN`] are the same rule at two scopes —
/// a class that could be edited in one and not the other is the drift these constants exist to end.
///
/// Excludes the two separators and the drive/scheme colon, plus the Unicode `Cc` control ranges
/// (`U+0000`-`U+001F` and `U+007F`-`U+009F`) that [`is_safe_component`] refuses via
/// `char::is_control`.
macro_rules! component_class {
    () => {
        "[^/\\\\:\\u0000-\\u001f\\u007f-\\u009f]"
    };
}

/// [`is_safe_component`] written as a regular expression, for enforcers that cannot call Rust.
///
/// `schemas/*.schema.json` is the normative wire contract — integrators write producers against
/// those files, not against this crate — so each carries its own copy of this rule. The copy in
/// `desired-deployment.schema.json` was missing the `.`/`..` exclusion and the upper control range,
/// so the published schema blessed a snapshot file named `.`, a value that resolves to the
/// containing directory and that every Rust caller refuses. Exported so the schema is asserted
/// against the predicate rather than against a hand-typed approximation of it.
pub const SAFE_COMPONENT_PATTERN: &str = concat!("^(?!\\.{1,2}$)", component_class!(), "+$");

/// [`is_confined_relative`] written as a regular expression, for enforcers that cannot call Rust.
///
/// Same reason, one scope up. The copy `target-reference.schema.json` carried was wrong in both
/// directions at once: it admitted `a//b` and a trailing `a/`, which split into an EMPTY component
/// that `is_safe_component` rejects — so the published contract blessed target names the fleet
/// refuses to parse — while narrowing the character class to `[A-Za-z0-9._/-]`, refusing names the
/// fleet accepts. That is what an unpinned second copy of a rule decays into.
pub const CONFINED_RELATIVE_PATTERN: &str = concat!(
    "^(?!.*(?:^|/)\\.{1,2}(?:/|$))",
    component_class!(),
    "+(?:/",
    component_class!(),
    "+)*$"
);

/// A single safe path *component*: one directory or file name that, joined onto any root, can never
/// escape it. Non-empty, neither `.` nor `..`, containing no path separator (`/` or `\`), no
/// drive/scheme colon, and no control character. Protocol identities use the stricter portable
/// grammars in [`crate::identity`] or [`crate::telemetry`]; this predicate is for arbitrary file
/// components that legitimately preserve case.
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
#[cfg_attr(coverage_nightly, coverage(off))]
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

    /// The exported patterns and the predicates accept exactly the same strings.
    ///
    /// Clause by clause rather than with a regex engine, which this workspace deliberately does not
    /// depend on (the same approach `foundation::digest` and `crate::identity` take). Editing a
    /// predicate fails this, which is the prompt to edit the pattern — and the schema conformance
    /// tests then require the published schemas to follow.
    #[test]
    fn the_exported_patterns_describe_exactly_what_the_predicates_accept() {
        assert_eq!(
            SAFE_COMPONENT_PATTERN,
            "^(?!\\.{1,2}$)[^/\\\\:\\u0000-\\u001f\\u007f-\\u009f]+$"
        );
        assert_eq!(
            CONFINED_RELATIVE_PATTERN,
            "^(?!.*(?:^|/)\\.{1,2}(?:/|$))[^/\\\\:\\u0000-\\u001f\\u007f-\\u009f]+\
             (?:/[^/\\\\:\\u0000-\\u001f\\u007f-\\u009f]+)*$"
        );

        // The character class, swept over every code point that could plausibly be excluded: the
        // two separators, the colon, and both Unicode `Cc` ranges are out; everything else is in.
        for code in (0u32..=0xa0).chain([0x2f, 0x5c, 0x3a, 0xff, 0x100, 0x2603]) {
            let Some(ch) = char::from_u32(code) else {
                continue;
            };
            let in_class = !matches!(ch, '/' | '\\' | ':') && !ch.is_control();
            assert_eq!(
                is_safe_component(&format!("a{ch}b")),
                in_class,
                "the component class and the predicate disagree about {ch:?} ({code:#x})"
            );
        }

        // The `(?!\.{1,2}$)` lookahead: exactly the two relative names, and nothing longer.
        assert!(!is_safe_component("."));
        assert!(!is_safe_component(".."));
        assert!(is_safe_component("..."));
        assert!(is_safe_component(".hidden"));

        // `CONFINED_RELATIVE_PATTERN`'s segment structure: one or more non-empty components joined
        // by single slashes. The empty component is what the published schema used to admit.
        for empty_segment in ["a//b", "a/", "/a", "", "x//"] {
            assert!(
                !is_confined_relative(empty_segment),
                "{empty_segment:?} has an empty component and must be refused"
            );
        }
        // ...and the same relative-name lookahead applies to EVERY segment, not just the first.
        for traversal in ["./a", "../a", "a/./b", "a/../b", "a/.", "a/.."] {
            assert!(
                !is_confined_relative(traversal),
                "{traversal:?} carries a relative component and must be refused"
            );
        }
        for ok in ["a", "a/b", "a/b/c", "dir/file.txt", "a/...", "a b"] {
            assert!(is_confined_relative(ok), "{ok:?} is confined");
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
