//! The controller's API-server write boundary must admit exactly the objects it writes.
//!
//! `deploy/charts/updatec/templates/controller-write-boundary.yaml` is the object-level half of the
//! controller's fence: RBAC cannot constrain CREATE by name, so a `ValidatingAdmissionPolicy`
//! restricts this identity to its own durable-state ConfigMaps and to inventory ConfigMaps owned by
//! an `UpdateBackend`. It is CEL, so it cannot call [`super::admitted::admitted_state_shard_name`]
//! or [`super::backend::backend_inventory_name`] — it carries its own copy of every naming rule,
//! shard bound, and label those functions apply.
//!
//! Nothing tied the two together. The policy is `failurePolicy: Fail` with `validationActions:
//! [Deny]`, so drift is not a widened boundary but an outage: raise
//! [`super::MAX_ADMITTED_STATE_SHARDS`] past what the policy's regex admits and the controller's
//! own state writes start coming back `Forbidden`, on every pass, forever — with the cause sitting
//! in a chart regex nowhere near the constant that moved. The chart's name helper already refuses
//! to reproduce Rust's hashing for exactly this reason, and says so; this is the same argument
//! applied to the rules it does reproduce.
//!
//! The policy's regexes are compiled and checked against the names this controller actually
//! generates, rather than compared as text: `0[0-9]|[1-5][0-9]` and `[0-5][0-9]` are one rule
//! spelled two ways, so a text assertion would fail on a rewrite that changed nothing and pass on
//! a bound that changed everything.

use super::*;

/// One chart template, read as written. The rules pinned here are plain CEL or plain Helm — no
/// value interpolation touches them — so the source is what the API server ends up evaluating.
fn chart_template(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy/charts/updatec/templates")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()))
}

fn policy_source() -> String {
    chart_template("controller-write-boundary.yaml")
}

/// Every `matches('...')` argument in the policy, compiled.
///
/// A rule the policy converges by regex is one this test can evaluate exactly as the API server
/// would, for any candidate name.
fn policy_patterns() -> Vec<regex::Regex> {
    let source = policy_source();
    let mut patterns = Vec::new();
    let mut rest = source.as_str();
    while let Some(start) = rest.find(".matches('") {
        rest = &rest[start + ".matches('".len()..];
        let end = rest
            .find("')")
            .expect("a closing quote on a matches() call");
        let pattern = &rest[..end];
        patterns.push(
            regex::Regex::new(pattern)
                .unwrap_or_else(|error| panic!("compiling policy pattern {pattern:?}: {error}")),
        );
        rest = &rest[end..];
    }
    assert!(
        !patterns.is_empty(),
        "found no matches() calls in the controller write boundary; this test is not checking \
         anything (did the policy move or change shape?)"
    );
    patterns
}

/// Whether some rule in the policy accepts `name`.
///
/// The policy converges its name regexes alongside prefix and label checks, so "some pattern matches"
/// is the right question here: this test pins the SHARD BOUND, and the surrounding conditions are
/// pinned by the assertions below.
fn policy_admits_name(patterns: &[regex::Regex], name: &str) -> bool {
    patterns.iter().any(|pattern| pattern.is_match(name))
}

/// Every admitted-state shard this controller can name is one the boundary admits, and the first
/// one past the bound is not.
///
/// The upper edge is the half that matters. A policy that admits too few denies real writes; one
/// that admits too many is a quietly widened fence. Both are caught by walking to the boundary and
/// one step past it.
#[test]
fn the_boundary_admits_exactly_this_controllers_admitted_state_shards() {
    let patterns = policy_patterns();
    let base = admitted::admitted_configmap_name("default");

    for slot in [
        admitted::AdmittedStateSlot::A,
        admitted::AdmittedStateSlot::B,
    ] {
        for index in 0..MAX_ADMITTED_STATE_SHARDS {
            let name = admitted::admitted_state_shard_name(&base, slot, index);
            assert!(
                policy_admits_name(&patterns, &name),
                "the controller writes {name}, but the write boundary's patterns refuse it — this \
                 is a Forbidden on every reconcile, not a warning"
            );
        }
        // One past the bound. `admitted_state_shard_name` debug-asserts the index, so the name is
        // built here the way the format string would.
        let over = format!("{base}-{}-{MAX_ADMITTED_STATE_SHARDS:02}", slot.name());
        assert!(
            !policy_admits_name(&patterns, &over),
            "the write boundary admits {over}, past MAX_ADMITTED_STATE_SHARDS \
             ({MAX_ADMITTED_STATE_SHARDS}) — the fence is wider than the rule it is fencing"
        );
    }
}

/// The same walk for the backend inventory family, whose width is fixed by the protocol.
#[test]
fn the_boundary_admits_exactly_the_backend_inventory_shards() {
    let patterns = policy_patterns();
    let base = backend::backend_resource_name("edge");
    let shards = updated_contracts::backend::BACKEND_INVENTORY_SHARDS;

    for index in 0..shards {
        let name = backend::backend_inventory_name(&base, index);
        assert!(
            policy_admits_name(&patterns, &name),
            "the controller writes {name}, but the write boundary's patterns refuse it"
        );
    }
    let over = format!("{base}-inventory-{shards:02}");
    assert!(
        !policy_admits_name(&patterns, &over),
        "the write boundary admits {over}, past BACKEND_INVENTORY_SHARDS ({shards})"
    );
}

/// The prefixes and labels the policy gates on are the ones this controller stamps.
///
/// These are `startsWith` / equality checks rather than regexes, so they are pinned as the exact
/// CEL text — but the values come from the builders, never from a literal retyped here.
#[test]
fn the_boundary_gates_on_the_names_and_labels_this_controller_stamps() {
    let policy = policy_source();

    // Name prefixes, taken from what the builders actually produce for a known input.
    let backend_base = backend::backend_resource_name("edge");
    let backend_prefix = backend_base
        .strip_suffix("edge")
        .expect("the backend base is its prefix plus the resource name");
    assert!(
        policy.contains(&format!("startsWith('{backend_prefix}')")),
        "the boundary must gate backend inventory on the {backend_prefix:?} prefix that \
         `backend_resource_name` produces"
    );

    // The admitted-state name reaches the policy through the chart's own helper rather than as a
    // literal, so the prefix is pinned where the helper spells it. That helper deliberately does
    // NOT reproduce this controller's hashing — it fails the render on an over-long repository
    // instead — but the prefix itself is a rule both sides must agree on, or the policy denies
    // every state write.
    let admitted_base = admitted::admitted_configmap_name("default");
    let admitted_prefix = admitted_base
        .strip_suffix("default")
        .expect("the admitted base is its prefix plus the repository name");
    let helpers = chart_template("_helpers.tpl");
    assert!(
        helpers.contains(admitted_prefix),
        "the chart's admittedConfigMapName helper must build on the {admitted_prefix:?} prefix \
         that `admitted_configmap_name` produces"
    );

    // Labels, from the builders rather than retyped.
    for (key, value) in backend::backend_labels(&backend_base) {
        if key == "app" {
            continue; // per-resource, not a fence the policy gates on
        }
        assert!(
            policy.contains(&format!("labels['{key}'] == '{value}'")),
            "the boundary must gate backend inventory on {key}={value}, the label \
             `backend_labels` stamps"
        );
    }

    // The shard suffix width the policy asserts with `size() == len(base) + 5`, derived from a
    // real generated name rather than counted by hand.
    let suffix =
        admitted::admitted_state_shard_name(&admitted_base, admitted::AdmittedStateSlot::A, 0)
            .len()
            - admitted_base.len();
    assert!(
        policy.contains(&format!("}}) {suffix} }}}}"))
            || policy.contains(&format!(" {suffix} }}}}")),
        "the boundary asserts the shard-name length as base + {suffix}; \
         `admitted_state_shard_name` appends {suffix} characters"
    );
}
