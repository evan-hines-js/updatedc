//! Choosing the newest installable target from verified TUF metadata — the single
//! selection path shared by the supervisor (both the application and its own
//! self-update) and the one-shot updater.
//!
//! It operates only on already-[`VerifiedTarget`]s and the signed custom metadata a
//! [`TargetPolicy`] authorizes. The caller injects the rejection predicate (which
//! bytes to skip) and a sink for skip diagnostics, so this stays free of any
//! logging or rejection-store dependency and can be tested in isolation.

use semver::Version;

use crate::{DefaultPolicy, TrustedRepository, VerifiedTarget};

/// Hex sha256 of a verified target — its content hash. This is the identity that
/// accepts a corrected republish (new bytes ⇒ new hash) and rejects exactly the
/// bytes that failed. Empty only if the (already verified) metadata lacks a sha256,
/// which the [`DefaultPolicy`] then refuses anyway.
pub fn target_sha(target: &VerifiedTarget) -> String {
    target
        .hashes
        .get("sha256")
        .map(hex::encode)
        .unwrap_or_default()
}

fn matching_targets(
    repo: &TrustedRepository,
    policy: &DefaultPolicy,
) -> Vec<(VerifiedTarget, Version)> {
    let mut targets: Vec<_> = repo
        .all_targets()
        .into_iter()
        .filter_map(|target| policy.candidate_version(&target).ok().map(|v| (target, v)))
        .collect();
    targets.sort_by(|a, b| b.1.cmp(&a.1));
    targets
}

/// The newest eligible target in `targets` (already newest-first): not `current`,
/// not `rejected`, and authorized by `policy`. Scanning newest-first means a
/// rejected or policy-ineligible head release never hides a good intermediate one.
///
/// Rejection is keyed by content hash — the exact bytes that failed — not the
/// version string, so a corrected republish is eligible at once and the same bad
/// bytes stay blocked even under a different label. Each policy-skipped candidate is
/// reported to `note_skip` for diagnostics.
fn select_update_from(
    targets: impl IntoIterator<Item = (VerifiedTarget, Version)>,
    policy: &DefaultPolicy,
    current: Option<&str>,
    mut note_skip: impl FnMut(&str),
    mut rejected: impl FnMut(&VerifiedTarget, &str) -> bool,
) -> Option<(VerifiedTarget, String)> {
    // Newest-first ordering lets the installed version act as a watermark.
    let current_version = current.and_then(|v| Version::parse(v).ok());
    let mut saw_current = false;
    for (target, version) in targets {
        if current_version
            .as_ref()
            .is_some_and(|installed| &version == installed)
        {
            // Older entries after the installed target are repository history, not
            // attempted downgrades worth logging on every poll.
            saw_current = true;
        }
        if current_version
            .as_ref()
            .is_some_and(|installed| &version < installed)
        {
            if !saw_current {
                note_skip(&format!(
                    "no eligible update: downgrade policy blocks releases below {}",
                    current_version.as_ref().expect("checked above")
                ));
            }
            break;
        }
        let version = version.to_string();
        if current == Some(version.as_str()) || rejected(&target, &version) {
            continue;
        }
        match policy.authorize(current, &target) {
            Ok(()) => return Some((target, version)),
            Err(e) => note_skip(&format!("skipping {version}: {e}")),
        }
    }
    None
}

/// An authenticated release selected by policy but not downloaded yet.
pub struct SelectedRelease {
    pub target: VerifiedTarget,
    pub version: String,
    pub sha256: String,
}

/// Shared select-and-download path used by supervised and one-shot modes.
impl TrustedRepository {
    pub fn select_release(
        &self,
        policy: &DefaultPolicy,
        current: Option<&str>,
        note_skip: impl FnMut(&str),
        rejected: impl FnMut(&VerifiedTarget, &str) -> bool,
    ) -> Option<SelectedRelease> {
        let (target, version) = select_update_from(
            matching_targets(self, policy),
            policy,
            current,
            note_skip,
            rejected,
        )?;
        let sha256 = target_sha(&target);
        Some(SelectedRelease {
            target,
            version,
            sha256,
        })
    }

    pub async fn stage_release(
        &self,
        selected: &SelectedRelease,
        destination: &std::path::Path,
    ) -> Result<(), crate::Error> {
        self.download_target(&selected.target, destination).await
    }

    pub async fn stage_update(
        &self,
        policy: &DefaultPolicy,
        current: Option<&str>,
        destination: &std::path::Path,
        note_skip: impl FnMut(&str),
        rejected: impl FnMut(&VerifiedTarget, &str) -> bool,
    ) -> Result<Option<SelectedRelease>, crate::Error> {
        let Some(selected) = self.select_release(policy, current, note_skip, rejected) else {
            return Ok(None);
        };
        self.stage_release(&selected, destination).await?;
        Ok(Some(selected))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn candidate(version: &str, sha: u8) -> (VerifiedTarget, Version) {
        let mut hashes = BTreeMap::new();
        hashes.insert("sha256".to_string(), vec![sha; 32]);
        (
            VerifiedTarget {
                path: format!(
                    "products/app/stable/{version}/{}-{}/app",
                    std::env::consts::OS,
                    std::env::consts::ARCH
                ),
                length: 1,
                hashes,
                custom: serde_json::json!({
                    "product": "app",
                    "channel": "stable",
                    "version": version,
                    "os": std::env::consts::OS,
                    "arch": std::env::consts::ARCH,
                }),
            },
            Version::parse(version).unwrap(),
        )
    }

    fn policy() -> DefaultPolicy {
        DefaultPolicy::current("app", "stable")
    }

    #[test]
    fn skips_current_and_rejected_head_for_healthy_intermediate() {
        let targets = vec![
            candidate("4.0.0", 4),
            candidate("3.0.0", 3),
            candidate("2.0.0", 2),
        ];
        let selected = select_update_from(
            targets,
            &policy(),
            Some("2.0.0"),
            |_| {},
            |_, v| v == "4.0.0",
        )
        .unwrap();
        assert_eq!(selected.1, "3.0.0");
    }

    #[test]
    fn refuses_downgrades() {
        let targets = vec![candidate("2.0.0", 2), candidate("1.0.0", 1)];
        let mut diagnostics = Vec::new();
        assert!(select_update_from(
            targets.clone(),
            &policy(),
            Some("3.0.0"),
            |message| diagnostics.push(message.to_string()),
            |_, _| false,
        )
        .is_none());
        assert!(
            diagnostics.iter().any(|message| message
                == "no eligible update: downgrade policy blocks releases below 3.0.0"),
            "crossing the installed watermark should explain why selection stopped"
        );
    }

    #[test]
    fn current_release_silently_ends_selection_before_repository_history() {
        let targets = vec![
            candidate("4.0.0", 4),
            candidate("3.0.0", 3),
            candidate("2.0.0", 2),
        ];
        let mut diagnostics = Vec::new();
        assert!(select_update_from(
            targets,
            &policy(),
            Some("4.0.0"),
            |message| diagnostics.push(message.to_string()),
            |_, _| false,
        )
        .is_none());
        assert!(
            diagnostics.is_empty(),
            "older repository history is not an attempted downgrade"
        );
    }

    #[test]
    fn rejects_by_hash_and_accepts_corrected_republish() {
        let rejected_hash = target_sha(&candidate("2.0.0", 1).0);
        let targets = vec![candidate("2.0.0", 1), candidate("2.0.0", 2)];
        let selected = select_update_from(
            targets,
            &policy(),
            Some("1.0.0"),
            |_| {},
            |t, _| target_sha(t) == rejected_hash,
        )
        .unwrap();
        assert_eq!(target_sha(&selected.0), hex::encode(vec![2; 32]));
    }
}
