//! Choosing the newest installable target from verified TUF metadata — the single
//! selection path shared by the supervisor (both the application and its own
//! self-update) and the one-shot updater.
//!
//! It operates only on already-[`VerifiedTarget`]s and the signed custom metadata a
//! [`DefaultPolicy`] authorizes. The caller injects the rejection predicate (which
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
    ceiling: Option<&Version>,
    head_sha: Option<&str>,
    mut note_skip: impl FnMut(&str),
    mut rejected: impl FnMut(&VerifiedTarget, &str) -> bool,
) -> Option<(VerifiedTarget, String)> {
    // Newest-first ordering lets the installed version act as a watermark.
    let current_version = current.and_then(|v| Version::parse(v).ok());
    let mut saw_current = false;
    for (target, version) in targets {
        // An assigned-application ceiling caps ordered fallback at the version the
        // control plane assigned: never select anything newer, even though the
        // shared targets metadata contains other groups' higher releases.
        if ceiling.is_some_and(|ceiling| &version > ceiling) {
            continue;
        }
        // At the assigned head version, only the exact assigned bytes are acceptable.
        // Two TUF-authentic targets can share the head version; without this pin ordered
        // fallback could install bytes other than the sha256 the control plane assigned.
        // A head-version candidate that isn't those bytes is skipped so descent continues
        // to a lower, well-defined version rather than picking an ambiguous sibling.
        if let (Some(ceiling), Some(head_sha)) = (ceiling, head_sha) {
            if &version == ceiling && target_sha(&target) != head_sha {
                note_skip(&format!(
                    "skipping {version}: not the assigned head bytes (sha256 mismatch)"
                ));
                continue;
            }
        }
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
    /// The provider set signed *into this app version* — populated only when ordered
    /// fallback descended below the assigned head. `None` at the assigned head, where the
    /// assignment's own `provider_set` governs (so providers stay independently revisable).
    pub provider_set: Option<updated::config::TargetReference>,
}

/// The provider set an application target was published with, read from its signed custom
/// metadata (see [`crate::repo::PublishTarget::with_provider_set`]). Absent for app targets
/// published without a bound provider set.
fn signed_provider_set(target: &VerifiedTarget) -> Option<updated::config::TargetReference> {
    serde_json::from_value(target.custom.get("provider_set")?.clone()).ok()
}

/// Shared select-and-download path used by supervised and one-shot modes.
impl TrustedRepository {
    /// Resolve and authorize the application selected by the signed deployment
    /// assignment.
    ///
    /// By default this pins the exact assigned bytes and never substitutes a
    /// different target when they are unavailable or rejected. When the signed
    /// assignment sets `ordered_install_fallback` *and* this is a first install
    /// (`current` is `None`, so there is no anti-rollback floor), it instead
    /// descends from the assigned version — the ceiling — to the newest healthy,
    /// non-rejected, policy-authorized target at or below it. That lets a stateless
    /// node recover from a broken head assignment without stranding, while the
    /// signed opt-in ensures only the publisher can authorize a floor-less descent.
    pub fn assigned_application(
        &self,
        policy: &DefaultPolicy,
        current: Option<&str>,
        note_skip: impl FnMut(&str),
        mut rejected: impl FnMut(&VerifiedTarget, &str) -> bool,
    ) -> Result<Option<SelectedRelease>, crate::Error> {
        let assignment = self.assignment().ok_or_else(|| {
            crate::Error::Trust("release repository has no desired deployment".into())
        })?;
        let target = self.exact_target(&assignment.application)?;
        let ceiling = policy
            .candidate_version(&target)
            .map_err(|error| crate::Error::Trust(error.to_string()))?;

        if assignment.ordered_install_fallback && current.is_none() {
            let selected = select_update_from(
                matching_targets(self, policy),
                policy,
                current,
                Some(&ceiling),
                Some(assignment.application.sha256.as_str()),
                note_skip,
                rejected,
            )
            .map(|(target, version)| SelectedRelease {
                sha256: target_sha(&target),
                // Descended below the assigned head: pin the providers this app version
                // was signed with, so app + providers roll back together.
                provider_set: signed_provider_set(&target),
                target,
                version,
            });
            return Ok(selected);
        }

        let version = ceiling.to_string();
        if current == Some(version.as_str()) {
            return Ok(None);
        }
        if rejected(&target, &version) {
            return Ok(None);
        }
        policy
            .authorize(current, &target)
            .map_err(|error| crate::Error::Trust(error.to_string()))?;
        let sha256 = target_sha(&target);
        Ok(Some(SelectedRelease {
            target,
            version,
            sha256,
            // At the assigned head: the assignment's `provider_set` governs, keeping
            // providers independently revisable without republishing the app.
            provider_set: None,
        }))
    }

    /// A human-readable audit of every candidate ordered fallback could descend to and why each
    /// is or isn't selectable — for diagnosing an empty selection ("no installable application").
    /// `is_rejected_sha` mirrors the caller's content-hash rejection check.
    pub fn selection_diagnostics(
        &self,
        policy: &DefaultPolicy,
        current: Option<&str>,
        mut is_rejected_sha: impl FnMut(&str) -> bool,
    ) -> String {
        let Some(assignment) = self.assignment() else {
            return "no desired deployment in the release repository".into();
        };
        let ceiling = self
            .exact_target(&assignment.application)
            .ok()
            .and_then(|target| policy.candidate_version(&target).ok());
        let mut lines = vec![format!(
            "assigned={} ordered_install_fallback={} ceiling={} current={}",
            assignment.application.path,
            assignment.ordered_install_fallback,
            ceiling
                .as_ref()
                .map_or_else(|| "<none>".to_string(), |v| v.to_string()),
            current.unwrap_or("<none>"),
        )];
        let candidates = matching_targets(self, policy);
        if candidates.is_empty() {
            lines.push(
                "  no policy-matching app targets (check product/channel/os/arch custom metadata)"
                    .into(),
            );
        }
        for (target, version) in candidates {
            let sha = target_sha(&target);
            let short = &sha[..sha.len().min(12)];
            let rejected = is_rejected_sha(&sha);
            let above_ceiling = ceiling.as_ref().is_some_and(|c| &version > c);
            let authorized = policy.authorize(current, &target).is_ok();
            lines.push(format!(
                "  candidate {version} ({}) sha={short} rejected={rejected} above_ceiling={above_ceiling} authorized={authorized}",
                target.path,
            ));
        }
        lines.join("\n")
    }

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
            None,
            None,
            note_skip,
            rejected,
        )?;
        let sha256 = target_sha(&target);
        Some(SelectedRelease {
            target,
            version,
            sha256,
            // A forward upgrade (not an assigned-fallback descent) carries providers via the
            // assignment head, not a version-pinned set.
            provider_set: None,
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
            None,
            None,
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
            None,
            None,
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
            None,
            None,
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
    fn ordered_fallback_pins_the_assigned_sha_at_the_head_version() {
        let ceiling = Version::parse("2.0.0").unwrap();
        let assigned_head_sha = target_sha(&candidate("2.0.0", 2).0);

        // A different, still TUF-authentic target sits at the head version (bytes sha=9), but
        // it is not the assigned sha. With the head pin, that candidate is skipped and ordered
        // fallback descends to the well-defined predecessor rather than installing foreign
        // head bytes.
        let foreign_head = vec![candidate("2.0.0", 9), candidate("1.0.0", 1)];
        let selected = select_update_from(
            foreign_head,
            &policy(),
            None,
            Some(&ceiling),
            Some(assigned_head_sha.as_str()),
            |_| {},
            |_, _| false,
        )
        .expect("descends past the unassigned head bytes");
        assert_eq!(selected.1, "1.0.0");

        // When the exact assigned bytes are present at the head, they are selected.
        let with_assigned_head = vec![candidate("2.0.0", 2), candidate("1.0.0", 1)];
        let selected = select_update_from(
            with_assigned_head,
            &policy(),
            None,
            Some(&ceiling),
            Some(assigned_head_sha.as_str()),
            |_| {},
            |_, _| false,
        )
        .expect("the assigned head bytes are selectable");
        assert_eq!(selected.1, "2.0.0");
        assert_eq!(target_sha(&selected.0), assigned_head_sha);
    }

    #[test]
    fn rejects_by_hash_and_accepts_corrected_republish() {
        let rejected_hash = target_sha(&candidate("2.0.0", 1).0);
        let targets = vec![candidate("2.0.0", 1), candidate("2.0.0", 2)];
        let selected = select_update_from(
            targets,
            &policy(),
            Some("1.0.0"),
            None,
            None,
            |_| {},
            |t, _| target_sha(t) == rejected_hash,
        )
        .unwrap();
        assert_eq!(target_sha(&selected.0), hex::encode(vec![2; 32]));
    }
}

/// The provider set signed with each app version binds app+providers as one rollback unit.
/// These author a real release repo (app 1.0.0 with provider set A, 2.0.0 with provider set B)
/// and drive [`TrustedRepository::assigned_application`] end to end.
#[cfg(test)]
mod provider_binding {
    use super::*;
    use crate::{repo, TrustedRepository};

    const OS: &str = std::env::consts::OS;
    const ARCH: &str = std::env::consts::ARCH;

    fn app_path(version: &str) -> String {
        format!("products/app/stable/{version}/{OS}-{ARCH}/app")
    }

    fn runtime() -> updated::config::ManagedRuntime {
        updated::config::ManagedRuntime {
            product: "app".into(),
            channel: "stable".into(),
            install_root: "/app".into(),
            args: vec![],
            health_checks: vec![],
            repository: updated::config::ManagedRepositoryLimits {
                metadata_limit: 1,
                target_limit: 1,
                transport_timeout_seconds: 1,
            },
            storage: updated::config::ManagedStorage {
                inactive_releases: 1,
                inactive_providers: 1,
                inactive_supervisors: 1,
                inactive_bytes: 1,
                inactive_repository_caches: 1,
            },
            timeouts: updated::config::ManagedTimeouts {
                check_interval_seconds: 1,
                health_grace_seconds: 1,
                health_successes: 1,
                health_interval_seconds: 1,
                retry_after_seconds: 1,
                refresh_retry_seconds: 1,
                confirmation_window_seconds: 1,
                supervisor_check_interval_seconds: 1,
                drain_hold_seconds: Some(0),
            },
        }
    }

    /// Author the repo and return a repository loaded with an assignment that pins app 2.0.0
    /// as the head (its provider set B), with ordered fallback opted in.
    async fn repo_with_assignment(fallback: bool) -> TrustedRepository {
        let tmp = std::env::temp_dir().join(format!(
            "updated-provider-binding-{}-{}",
            std::process::id(),
            updated::rand::token().unwrap()
        ));
        let repo_dir = tmp.join("repo");
        let keys = repo::generate_keys(&tmp.join("keys")).await.unwrap();
        repo::init(&repo_dir, &keys, 365).await.unwrap();

        // Two app versions, each with the provider set it shipped with signed into its metadata.
        let v1_src = tmp.join("app-1");
        let v2_src = tmp.join("app-2");
        std::fs::write(&v1_src, b"app-1.0.0").unwrap();
        std::fs::write(&v2_src, b"app-2.0.0").unwrap();
        let v1 =
            repo::PublishTarget::application("app", "stable", "1.0.0", OS, ARCH, "app", v1_src)
                .with_provider_set("provider-sets/a.json", &"a".repeat(64));
        let v2 =
            repo::PublishTarget::application("app", "stable", "2.0.0", OS, ARCH, "app", v2_src)
                .with_provider_set("provider-sets/b.json", &"b".repeat(64));
        repo::add_release(&repo_dir, &keys, vec![v1, v2], 365)
            .await
            .unwrap();
        let head_sha = repo::target_sha256(&repo_dir, &app_path("2.0.0"))
            .await
            .unwrap();

        let url = |sub: &str| {
            url::Url::from_directory_path(std::fs::canonicalize(repo_dir.join(sub)).unwrap())
                .unwrap()
                .to_string()
        };
        let source = updated::config::RepositorySource {
            metadata_url: url("metadata"),
            targets_url: url("targets"),
            root: repo_dir.join("metadata/root.json"),
            metadata_limit: 1024 * 1024,
            target_limit: 100 * 1024 * 1024,
            transport_timeout: std::time::Duration::from_secs(5),
            // Same convention as the roundtrip tests: file:// is offline, so the identity's
            // paths are never read by the transport.
            mtls: updated::tls::Identity::new(
                repo_dir.join("client.crt"),
                repo_dir.join("client.key"),
                repo_dir.join("ca.crt"),
            ),
        };
        let mut repository = TrustedRepository::load(&source, &tmp.join("datastore"))
            .await
            .unwrap();
        // The assigned head is 2.0.0 + provider set B — both published together.
        repository.assignment = Some(updated::config::RepositoryAssignment {
            schema: 2,
            deployment: "deploy".into(),
            metadata_url: source.metadata_url.clone(),
            targets_url: source.targets_url.clone(),
            report_url: None,
            application: updated::config::TargetReference {
                path: app_path("2.0.0"),
                sha256: head_sha,
            },
            ordered_install_fallback: fallback,
            provider_set: updated::config::TargetReference {
                path: "provider-sets/b.json".into(),
                sha256: "b".repeat(64),
            },
            release_root: serde_json::json!({}),
            runtime: runtime(),
        });
        repository
    }

    fn policy() -> DefaultPolicy {
        DefaultPolicy::current("app", "stable")
    }

    #[test]
    fn signed_provider_set_reads_and_ignores_absent() {
        let target = repo::PublishTarget::application(
            "app",
            "stable",
            "1.0.0",
            OS,
            ARCH,
            "app",
            std::path::PathBuf::from("unused"),
        )
        .with_provider_set("provider-sets/a.json", &"a".repeat(64));
        let verified = VerifiedTarget {
            path: target.name.clone(),
            length: 1,
            hashes: Default::default(),
            custom: serde_json::to_value(&target.custom).unwrap(),
        };
        let bound = signed_provider_set(&verified).unwrap();
        assert_eq!(bound.path, "provider-sets/a.json");
        assert_eq!(bound.sha256, "a".repeat(64));

        let plain = VerifiedTarget {
            custom: serde_json::json!({"product": "app"}),
            ..verified
        };
        assert!(signed_provider_set(&plain).is_none());
    }

    // The head assignment (2.0.0) is broken, so a first-install node with ordered fallback
    // descends to 1.0.0 — and must roll back to the provider set signed with 1.0.0 (A), not
    // the assignment head's B. This is the app+provider-as-one-unit rollback.
    #[tokio::test]
    async fn ordered_fallback_descends_to_the_app_versions_own_provider_set() {
        let repo = repo_with_assignment(true).await;
        let selected = repo
            .assigned_application(&policy(), None, |_| {}, |_, version| version == "2.0.0")
            .unwrap()
            .expect("a healthy predecessor is selectable");
        assert_eq!(selected.version, "1.0.0");
        assert_eq!(
            selected
                .provider_set
                .expect("descent binds a provider set")
                .path,
            "provider-sets/a.json",
            "a descended app must roll back to the providers signed with it"
        );
    }

    // First install with a healthy head stays at 2.0.0 and carries B — the pair published
    // together.
    #[tokio::test]
    async fn first_install_at_head_carries_the_heads_signed_provider_set() {
        let repo = repo_with_assignment(true).await;
        let selected = repo
            .assigned_application(&policy(), None, |_| {}, |_, _| false)
            .unwrap()
            .expect("the head is selectable");
        assert_eq!(selected.version, "2.0.0");
        assert_eq!(
            selected
                .provider_set
                .expect("head binds its provider set")
                .path,
            "provider-sets/b.json"
        );
    }

    // An established node (exact-pin, no floor-less descent) leaves provider selection to the
    // assignment's own `provider_set`, so a provider-only revision reconciles at the head
    // WITHOUT an app change: `provider_set` is `None`, and the supervisor uses the assignment's.
    #[tokio::test]
    async fn established_node_defers_providers_to_the_assignment_for_provider_only_updates() {
        let repo = repo_with_assignment(false).await;
        let selected = repo
            .assigned_application(&policy(), Some("1.0.0"), |_| {}, |_, _| false)
            .unwrap()
            .expect("the assigned head is an upgrade from 1.0.0");
        assert_eq!(selected.version, "2.0.0");
        assert!(
            selected.provider_set.is_none(),
            "at the head the assignment's provider_set governs, so providers stay \
             independently revisable without republishing the app"
        );
    }
}
