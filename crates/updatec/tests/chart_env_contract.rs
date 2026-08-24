//! The chart may only set environment variables the controller actually reads.
//!
//! `updatec` is configured entirely from the environment, and the Helm chart is what supplies it.
//! Every name is therefore a contract between Rust and YAML, and until this test existed it was
//! written twice with nothing tying the halves together.
//!
//! The failure mode is quiet, which is why this is worth a test rather than a convention. Most of
//! these settings are optional: rename `UPDATED_ALERT_URL` on either side and the controller starts
//! normally with alerting switched off, which looks exactly like a fleet with nothing to report.
//! Only the three required variables would fail loudly, and only in the mode that needs them.
//!
//! The check is one-directional on purpose. Every `UPDATED_*` the chart sets must be a name
//! `updatec::env::ALL` declares — that catches a rename or a typo on either side. The reverse is
//! deliberately not asserted: most variables are optional with in-process defaults, and a chart that
//! leaves them unset is a valid deployment, not a drift.

/// Every `- name: UPDATED_*` the chart's templates set, with the file it came from.
fn chart_environment() -> Vec<(String, String)> {
    let templates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy/charts/updatec/templates");
    let mut found = Vec::new();
    let entries = std::fs::read_dir(&templates)
        .unwrap_or_else(|error| panic!("reading {}: {error}", templates.display()));
    for entry in entries {
        let path = entry.expect("a readable directory entry").path();
        // `.tpl` as well as `.yaml`: the environment both workloads share lives in a Helm
        // partial (`_helpers.tpl`), so a scan limited to manifests silently covered only the
        // per-workload additions — including neither required variable.
        if path
            .extension()
            .is_none_or(|ext| ext != "yaml" && ext != "tpl")
        {
            continue;
        }
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
        let file = path
            .file_name()
            .expect("a template file name")
            .to_string_lossy()
            .into_owned();
        for line in body.lines() {
            // `- name: FOO` in a container's `env:` list. Values are on their own `value:` /
            // `valueFrom:` lines, so a bare name line is the declaration.
            let Some(name) = line.trim().strip_prefix("- name: ") else {
                continue;
            };
            let name = name.trim();
            if name.starts_with("UPDATED_") {
                found.push((name.to_string(), file.clone()));
            }
        }
    }
    found
}

/// The chart sets nothing the controller does not read.
#[test]
fn every_variable_the_chart_sets_is_one_the_controller_reads() {
    let declared: std::collections::BTreeSet<&str> = updatec::env::ALL.iter().copied().collect();
    let chart = chart_environment();

    assert!(
        !chart.is_empty(),
        "found no UPDATED_* environment variables in the chart templates; this test is not \
         actually checking anything (did the templates move?)"
    );

    for (name, file) in &chart {
        assert!(
            declared.contains(name.as_str()),
            "the chart sets {name} in {file}, but no such variable is declared in \
             `updatec::env`. Either the controller stopped reading it — in which case the chart \
             is configuring nothing and the setting silently does not apply — or one of the two \
             sides was renamed without the other."
        );
    }
}

/// The variables the controller refuses to start without are actually supplied.
///
/// These are the only names where the chart omitting them is unambiguously a broken deployment
/// rather than a deliberate default, so they are the only ones asserted in this direction.
#[test]
fn the_chart_supplies_every_variable_the_controller_requires() {
    let chart: std::collections::BTreeSet<String> = chart_environment()
        .into_iter()
        .map(|(name, _)| name)
        .collect();

    for required in [
        updatec::env::PUBLIC_URL,
        updatec::env::HEALTHPROXY_IMAGE,
        updatec::env::ENROLLMENT_LOCK_NAME,
    ] {
        assert!(
            chart.contains(required),
            "{required} has no in-process default — the controller refuses to start without it — \
             so the chart must set it"
        );
    }
}
