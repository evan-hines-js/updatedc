//! Reading a Cargo manifest well enough to audit what a crate *ships*.
//!
//! Several crates enforce a dependency rule against their own (or another crate's) `Cargo.toml`:
//! the launcher may link only platform bindings, this crate may link only system bindings, no
//! production crate may link a demo or test package. Each of those rules is an assertion about the
//! same fact — "what does this manifest make the crate depend on" — so the fact is derived here
//! once. Hand-rolled per test, it had already drifted into two answers.

/// The crates a manifest makes the built artifact depend on: `[dependencies]`,
/// `[build-dependencies]`, their `[target.'cfg(…)'.…]` forms, and the `[dependencies.<name>]`
/// sub-table form.
///
/// `[dev-dependencies]` is excluded by design — it is compiled only into that crate's own test
/// binaries and never links into anything that ships, so a dependency rule about the shipped
/// artifact must not read it.
///
/// Not a TOML parser: it recognizes table headers and `key = …` entries, which is the whole of a
/// dependency table, and ignores comments and blank lines.
pub fn shipped_dependency_names(manifest: &str) -> Vec<&str> {
    const KINDS: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];
    let mut names = Vec::new();
    let mut in_shipped_table = false;
    for line in manifest.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some(header) = line
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        else {
            if in_shipped_table {
                if let Some(name) = entry_name(line) {
                    names.push(name);
                }
            }
            continue;
        };
        let segments: Vec<&str> = header.split('.').collect();
        // A dependency table is any table one of whose path segments names a dependency kind:
        // `[dependencies]`, `[build-dependencies]`, `[target.'cfg(unix)'.dependencies]`, and the
        // per-crate sub-table `[dependencies.serde]`, whose trailing segment IS the crate name.
        let Some(kind) = segments.iter().position(|segment| KINDS.contains(segment)) else {
            in_shipped_table = false;
            continue;
        };
        let ships = segments[kind] != "dev-dependencies";
        match segments.get(kind + 1) {
            Some(name) => {
                in_shipped_table = false;
                if ships {
                    names.push(name.trim_matches(['"', '\'']));
                }
            }
            None => in_shipped_table = ships,
        }
    }
    names
}

/// The crate a dependency entry declares, in any of its key forms: `name = …`, `"name" = …`, and
/// the dotted `name.workspace = true`.
fn entry_name(line: &str) -> Option<&str> {
    let key = line.split('=').next()?.trim();
    let name = key.split('.').next()?.trim().trim_matches(['"', '\'']);
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_shipped_dependency_form_is_seen_and_dev_dependencies_are_not() {
        let manifest = r#"
[package]
name = "example"

[dependencies]
serde = { workspace = true }
libc.workspace = true
"quoted" = "1"
# a comment = not-a-dep

[dependencies.detailed]
version = "1"
features = ["derive"]

[build-dependencies]
cc = "1"

[target.'cfg(unix)'.dependencies]
libc = "0.2"

[dev-dependencies]
tempfile = "3"

[dev-dependencies.criterion]
version = "0.5"

[target.'cfg(windows)'.dev-dependencies]
windows-sys = "0.5"

[features]
default = []
"#;
        assert_eq!(
            shipped_dependency_names(manifest),
            vec!["serde", "libc", "quoted", "detailed", "cc", "libc"]
        );
    }

    #[test]
    fn a_non_dependency_table_after_one_ends_the_scan() {
        // Without this, `[features]`' own keys read as dependency names and every rule built on
        // this function starts failing on a feature flag someone added.
        let manifest = "[dependencies]\nserde = \"1\"\n\n[features]\nchaos = []\n";
        assert_eq!(shipped_dependency_names(manifest), vec!["serde"]);
    }
}
