//! Choosing the newest installable target from verified TUF metadata — the single
//! selection path shared by the agent (both the application and its own
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
/// bytes that failed. Every verified target carries one, so this never falls back
/// to a placeholder a digest comparison could match.
pub fn target_sha(target: &VerifiedTarget) -> String {
    hex::encode(&target.sha256)
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
    // Newest first, and the path breaks ties: `all_targets` comes out of a HashMap, so a version
    // tie left to input order would make two runs of the same node install different bytes and
    // print the candidates in a different order each time.
    targets.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.path.cmp(&b.0.path)));
    targets
}

/// What the node already has, in the terms selection judges candidates by.
///
/// The two questions a selector asks about an installed release are NOT one question, and
/// collapsing them into a single `Option<&str>` is what let a repair silently downgrade a node.
/// Passing `None` to mean "re-acquire the version I already have" also said "there is no
/// anti-rollback floor" — which is the exact condition a signed `orderedInstallFallback` descends
/// below the assigned head under. So `repair.rs`, running on a node with a release installed, took
/// the branch reserved for stateless first installs: with the head's bytes rejected it would
/// descend to an older release and install it, past the floor `selection.rs` refuses to cross.
///
/// Spelling the stance out is what makes that unrepresentable. A caller can lift the "already
/// installed, nothing to do" short-circuit ([`Stance::Reacquire`]) without lifting the floor, and
/// it cannot lift the floor without saying, in as many words, that nothing is installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stance<'a> {
    /// Nothing is installed. There is no anti-rollback floor, and this is the ONLY stance under
    /// which a signed `orderedInstallFallback` may descend below the assigned head.
    Nothing,
    /// `version` is installed: it is the anti-rollback floor, and re-selecting it is a no-op.
    Installed(&'a str),
    /// `version` is installed and its bytes must be re-acquired anyway — a repair republishing a
    /// drifted tree over the release the node is already committed to. Still the anti-rollback
    /// floor and still no descent; only the "already installed, nothing to do" short-circuit is
    /// lifted, because re-selecting it is the entire point.
    Reacquire(&'a str),
}

impl<'a> Stance<'a> {
    /// The version no candidate may fall below, and what the downgrade policy authorizes against.
    /// `None` only when nothing is installed, because only then is there nothing to roll back from.
    pub fn floor(self) -> Option<&'a str> {
        match self {
            Self::Nothing => None,
            Self::Installed(version) | Self::Reacquire(version) => Some(version),
        }
    }

    /// The version whose re-selection is a no-op, if any. A repair has none: re-selecting what is
    /// already installed is exactly what it is for.
    fn already_have(self) -> Option<&'a str> {
        match self {
            Self::Installed(version) => Some(version),
            Self::Nothing | Self::Reacquire(_) => None,
        }
    }

    /// Whether a signed `orderedInstallFallback` may descend below the assigned head.
    fn may_descend(self) -> bool {
        matches!(self, Self::Nothing)
    }

    /// How the stance reads in operator-facing diagnostics.
    fn describe(self) -> String {
        match self {
            Self::Nothing => "<none>".into(),
            Self::Installed(version) => version.to_string(),
            Self::Reacquire(version) => format!("{version} (re-acquiring)"),
        }
    }
}

/// Why one candidate is or is not the release to install.
///
/// The single per-candidate judgement, so the selector and [`TrustedRepository::selection_diagnostics`]
/// cannot disagree about a release. Diagnostics used to re-derive its own three facts — rejected,
/// above-ceiling, authorized — and simply did not know about two of the gates the selector applies:
/// the assigned-head-bytes pin and the downgrade watermark. An operator debugging why
/// `orderedInstallFallback` refused a release was shown a candidate that looked eligible in every
/// column the tool printed, with nothing naming the gate that actually stopped it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CandidateVerdict {
    /// Install this one.
    Eligible,
    /// Newer than the version the control plane assigned. The shared targets metadata holds other
    /// groups' higher releases; ordered fallback must never climb into them.
    AboveCeiling,
    /// At the assigned head version but not the assigned bytes. Two TUF-authentic targets can share
    /// a version, so without this pin fallback could install a sibling the control plane never
    /// named.
    NotAssignedHeadBytes,
    /// Already running.
    Installed,
    /// Below the running version: repository history, not an update.
    BelowInstalled,
    /// These exact bytes were attempted and rolled back. Keyed by content hash, so a corrected
    /// republish is eligible at once and the same bad bytes stay blocked under any label.
    Rejected,
    /// Refused by policy — product, channel, platform, or the upgrade-only rule.
    Unauthorized(String),
}

impl CandidateVerdict {
    /// The operator-facing reason, used verbatim by both readers.
    fn reason(&self) -> String {
        match self {
            Self::Eligible => "eligible".into(),
            Self::AboveCeiling => "above the assigned ceiling".into(),
            Self::NotAssignedHeadBytes => "not the assigned head bytes (sha256 mismatch)".into(),
            Self::Installed => "already installed".into(),
            Self::BelowInstalled => "below the installed version (downgrade policy)".into(),
            Self::Rejected => "these bytes were attempted and rolled back".into(),
            Self::Unauthorized(error) => error.clone(),
        }
    }
}

/// Judge one candidate against every gate, in the order the selector applies them.
#[allow(clippy::too_many_arguments)]
fn judge_candidate(
    target: &VerifiedTarget,
    version: &Version,
    policy: &DefaultPolicy,
    stance: Stance<'_>,
    floor: Option<&Version>,
    ceiling: Option<&Version>,
    head_sha: Option<&str>,
    rejected: &mut impl FnMut(&VerifiedTarget, &str) -> bool,
) -> CandidateVerdict {
    if ceiling.is_some_and(|ceiling| version > ceiling) {
        return CandidateVerdict::AboveCeiling;
    }
    if let (Some(ceiling), Some(head_sha)) = (ceiling, head_sha) {
        // Through `digest::digests_match`, like every digest comparison on the trust path. The
        // assignment already requires canonical lowercase hex; the shared comparison also fails
        // closed if a locally corrupted value bypasses that boundary.
        if version == ceiling
            && !updated_contracts::digest::digests_match(&target_sha(target), head_sha)
        {
            return CandidateVerdict::NotAssignedHeadBytes;
        }
    }
    // The anti-rollback floor. It comes off the stance, never off "is there a version string
    // here", so lifting the no-op short-circuit below cannot lift this with it.
    if floor.is_some_and(|floor| version < floor) {
        return CandidateVerdict::BelowInstalled;
    }
    let text = version.to_string();
    if stance.already_have() == Some(text.as_str()) {
        return CandidateVerdict::Installed;
    }
    if rejected(target, &text) {
        return CandidateVerdict::Rejected;
    }
    match policy.authorize(stance.floor(), target) {
        Ok(()) => CandidateVerdict::Eligible,
        Err(error) => CandidateVerdict::Unauthorized(error.to_string()),
    }
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
    stance: Stance<'_>,
    ceiling: Option<&Version>,
    head_sha: Option<&str>,
    mut note_skip: impl FnMut(&str),
    mut rejected: impl FnMut(&VerifiedTarget, &str) -> bool,
) -> Option<(VerifiedTarget, String)> {
    // Newest-first ordering lets the anti-rollback floor act as a watermark.
    let floor = stance.floor().and_then(|v| Version::parse(v).ok());
    let mut saw_current = false;
    for (target, version) in targets {
        let verdict = judge_candidate(
            &target,
            &version,
            policy,
            stance,
            floor.as_ref(),
            ceiling,
            head_sha,
            &mut rejected,
        );
        // Only once past the ceiling gates does an equal version count as "we have reached the
        // installed release": a candidate the ceiling excluded says nothing about where the node is.
        if !matches!(
            verdict,
            CandidateVerdict::AboveCeiling | CandidateVerdict::NotAssignedHeadBytes
        ) && floor
            .as_ref()
            .is_some_and(|installed| &version == installed)
        {
            saw_current = true;
        }
        match verdict {
            CandidateVerdict::Eligible => return Some((target, version.to_string())),
            CandidateVerdict::BelowInstalled => {
                // Older entries after the installed target are repository history, not attempted
                // downgrades worth logging on every poll.
                if !saw_current {
                    note_skip(&format!(
                        "no eligible update: downgrade policy blocks releases below {}",
                        floor.as_ref().expect("a version to be below")
                    ));
                }
                break;
            }
            // Silent skips: neither is a surprise worth a line on every poll.
            CandidateVerdict::AboveCeiling | CandidateVerdict::Installed => {}
            CandidateVerdict::Rejected => {}
            other => note_skip(&format!("skipping {version}: {}", other.reason())),
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
    pub provider_set: Option<updated_contracts::artifact::TargetReference>,
}

/// The provider set an application target was published with, read from its signed custom
/// metadata (see [`crate::repo::PublishTarget::with_provider_set`]).
///
/// `Ok(None)` means this app version was published without a bound provider set. `Err` means one
/// is bound but this build cannot read it — a field a newer publisher added (`TargetReference` is
/// `deny_unknown_fields`), a renamed key, a digest that is not sha256 hex. The two must stay
/// distinguishable, because "absent" is what makes a descended app defer to the *assignment's*
/// provider set: reporting an unreadable binding as absent would pair the rolled-back app with the
/// head's newer reconciler, the exact mispairing the descent exists to prevent. Every sibling
/// document on this seam refuses what it cannot read; so does this.
fn signed_provider_set(
    target: &VerifiedTarget,
) -> Result<Option<updated_contracts::artifact::TargetReference>, String> {
    let Some(value) = target.custom.get("provider_set") else {
        return Ok(None);
    };
    let reference: updated_contracts::artifact::TargetReference =
        serde_json::from_value(value.clone())
            .map_err(|error| format!("its signed provider set is unreadable ({error})"))?;
    if !reference.is_valid() {
        return Err("its signed provider set reference is invalid".into());
    }
    Ok(Some(reference))
}

/// Shared select-and-download path used by the long-running and one-shot modes.
impl TrustedRepository {
    /// Resolve and authorize the application selected by the signed deployment
    /// assignment.
    ///
    /// By default this pins the exact assigned bytes and never substitutes a
    /// different target when they are unavailable or rejected. When the signed
    /// assignment sets `ordered_install_fallback` *and* this is a first install
    /// ([`Stance::Nothing`], so there is no anti-rollback floor), it instead
    /// descends from the assigned version — the ceiling — to the newest healthy,
    /// non-rejected, policy-authorized target at or below it. That lets a stateless
    /// node recover from a broken head assignment without stranding, while the
    /// signed opt-in ensures only the publisher can authorize a floor-less descent.
    /// A candidate *below* the head is installable only together with the provider set signed
    /// into it, so one whose signed `provider_set` this build cannot read is skipped and the
    /// descent continues past it.
    pub fn assigned_application(
        &self,
        policy: &DefaultPolicy,
        stance: Stance<'_>,
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

        if assignment.ordered_install_fallback && stance.may_descend() {
            let head_sha = assignment.application.sha256.as_str();
            let mut note_skip = note_skip;
            // Reported after the walk: `select_update_from` holds `note_skip` for its duration.
            let mut unbindable = Vec::new();
            let selected = select_update_from(
                matching_targets(self, policy),
                policy,
                stance,
                Some(&ceiling),
                Some(head_sha),
                &mut note_skip,
                |target, version| {
                    if rejected(target, version) {
                        return true;
                    }
                    // Below the head, the app version's own signed provider set is what makes the
                    // descent a rollback of app and providers as one unit. A binding this build
                    // cannot read makes the candidate uninstallable, not provider-less: selecting
                    // it would report `None` and defer to the assignment's set — this older app
                    // against the head's newer reconciler. Refuse it and keep descending, the same
                    // treatment a policy-ineligible target gets. At the head there is nothing to
                    // pin (the assignment governs), so its binding is not consulted at all.
                    if updated_contracts::digest::digests_match(&target_sha(target), head_sha) {
                        return false;
                    }
                    match signed_provider_set(target) {
                        Ok(_) => false,
                        Err(error) => {
                            unbindable.push(format!("skipping {version}: {error}"));
                            true
                        }
                    }
                },
            )
            .map(|(target, version)| {
                let sha256 = target_sha(&target);
                // Only a descent pins the providers this app version was signed with, so that a
                // rolled-back app and its providers move together. Ordered fallback normally
                // selects the assigned head itself — a first install on a healthy assignment —
                // and there the assignment's own `provider_set` governs, exactly as it does for
                // an already-enrolled node taking the exact-pin branch below. Pinning the
                // baked-in set here instead would strand every freshly enrolled node on the
                // provider set the app was published with, so a provider-set-only assignment
                // revision would silently reach enrolled nodes and not new ones, and the two
                // would run different reconcilers at the same app version indefinitely.
                let descended = !updated_contracts::digest::digests_match(&sha256, head_sha);
                SelectedRelease {
                    // A descended candidate whose binding could not be read was refused above, so
                    // this re-read is the one that already succeeded.
                    provider_set: descended
                        .then(|| signed_provider_set(&target).ok().flatten())
                        .flatten(),
                    sha256,
                    target,
                    version,
                }
            });
            for message in unbindable {
                note_skip(&message);
            }
            return Ok(selected);
        }

        let version = ceiling.to_string();
        if stance.already_have() == Some(version.as_str()) {
            return Ok(None);
        }
        if rejected(&target, &version) {
            return Ok(None);
        }
        policy
            .authorize(stance.floor(), &target)
            .map_err(|error| crate::Error::Trust(error.to_string()))?;
        let sha256 = target_sha(&target);
        Ok(Some(SelectedRelease {
            target,
            version,
            sha256,
            provider_set: None,
        }))
    }

    /// A human-readable audit of every candidate ordered fallback could descend to and why each
    /// is or isn't selectable — for diagnosing an empty selection ("no installable application").
    /// `is_rejected_sha` mirrors the caller's content-hash rejection check.
    pub fn selection_diagnostics(
        &self,
        policy: &DefaultPolicy,
        stance: Stance<'_>,
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
            stance.describe(),
        )];
        let candidates = matching_targets(self, policy);
        if candidates.is_empty() {
            lines.push(
                "  no policy-matching app targets (check product/channel/os/arch custom metadata)"
                    .into(),
            );
        }
        let floor = stance.floor().and_then(|v| Version::parse(v).ok());
        // The same pin `assigned_application` walks with: the digest the control plane named.
        let head_sha = ceiling
            .as_ref()
            .map(|_| assignment.application.sha256.clone());
        for (target, version) in candidates {
            let sha = target_sha(&target);
            let short = &sha[..sha.len().min(12)];
            // The selector's own judgement, not a second opinion assembled here: every gate it
            // applies is named, in the order it applies them, including the two this listing used
            // to be blind to.
            let verdict = judge_candidate(
                &target,
                &version,
                policy,
                stance,
                floor.as_ref(),
                ceiling.as_ref(),
                head_sha.as_deref(),
                &mut |target, _| is_rejected_sha(&target_sha(target)),
            );
            lines.push(format!(
                "  candidate {version} ({}) sha={short} verdict={}",
                target.path,
                verdict.reason(),
            ));
        }
        lines.join("\n")
    }

    pub fn select_release(
        &self,
        policy: &DefaultPolicy,
        stance: Stance<'_>,
        note_skip: impl FnMut(&str),
        rejected: impl FnMut(&VerifiedTarget, &str) -> bool,
    ) -> Option<SelectedRelease> {
        let (target, version) = select_update_from(
            matching_targets(self, policy),
            policy,
            stance,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(version: &str, sha: u8) -> (VerifiedTarget, Version) {
        (
            VerifiedTarget {
                path: format!(
                    "products/app/stable/{version}/{}-{}/app",
                    std::env::consts::OS,
                    std::env::consts::ARCH
                ),
                length: 1,
                sha256: vec![sha; 32],
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

    /// Every gate the selector applies, named by the one judgement both readers consume.
    ///
    /// This is the contract that stopped `selection_diagnostics` from being able to disagree with
    /// the selector: it reported three of these and silently knew nothing about `AboveCeiling`'s
    /// sibling gates, so a release refused by the head-bytes pin or the downgrade watermark showed
    /// up as eligible in every column the operator could see.
    #[test]
    fn one_judgement_names_every_gate_the_selector_applies() {
        let policy = policy();
        let never = &mut |_: &VerifiedTarget, _: &str| false;
        let always = &mut |_: &VerifiedTarget, _: &str| true;
        let judge = |target: &VerifiedTarget,
                     version: &Version,
                     stance: Stance<'_>,
                     floor: Option<&Version>,
                     ceiling: Option<&Version>,
                     head: Option<&str>,
                     rejected: &mut dyn FnMut(&VerifiedTarget, &str) -> bool| {
            judge_candidate(
                target,
                version,
                &policy,
                stance,
                floor,
                ceiling,
                head,
                &mut |t, v| rejected(t, v),
            )
        };

        let (target, version) = candidate("2.0.0", 1);
        let head_sha = target_sha(&target);
        let ceiling = Version::parse("1.5.0").unwrap();
        let installed = Version::parse("1.0.0").unwrap();

        assert_eq!(
            judge(
                &target,
                &version,
                Stance::Nothing,
                None,
                Some(&ceiling),
                None,
                never
            ),
            CandidateVerdict::AboveCeiling
        );
        // At the ceiling version, bytes other than the assigned digest are refused.
        let at_ceiling = Version::parse("2.0.0").unwrap();
        assert_eq!(
            judge(
                &target,
                &version,
                Stance::Nothing,
                None,
                Some(&at_ceiling),
                Some(&"f".repeat(64)),
                never
            ),
            CandidateVerdict::NotAssignedHeadBytes
        );
        // ...and the assigned digest itself passes that gate.
        assert_eq!(
            judge(
                &target,
                &version,
                Stance::Nothing,
                None,
                Some(&at_ceiling),
                Some(&head_sha),
                never
            ),
            CandidateVerdict::Eligible
        );
        let (older, older_version) = candidate("0.9.0", 2);
        assert_eq!(
            judge(
                &older,
                &older_version,
                Stance::Installed("1.0.0"),
                Some(&installed),
                None,
                None,
                never
            ),
            CandidateVerdict::BelowInstalled
        );
        assert_eq!(
            judge(
                &target,
                &version,
                Stance::Installed("2.0.0"),
                None,
                None,
                None,
                never
            ),
            CandidateVerdict::Installed
        );
        assert_eq!(
            judge(&target, &version, Stance::Nothing, None, None, None, always),
            CandidateVerdict::Rejected
        );
        // A downgrade the policy itself refuses, distinct from the watermark above.
        let wrong = DefaultPolicy::current("other-product", "stable");
        assert!(matches!(
            judge_candidate(
                &target,
                &version,
                &wrong,
                Stance::Nothing,
                None,
                None,
                None,
                never
            ),
            CandidateVerdict::Unauthorized(_)
        ));
        assert_eq!(
            judge(&target, &version, Stance::Nothing, None, None, None, never),
            CandidateVerdict::Eligible
        );
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
            Stance::Installed("2.0.0"),
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
            Stance::Installed("3.0.0"),
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
            Stance::Installed("4.0.0"),
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
            Stance::Nothing,
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
            Stance::Nothing,
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
            Stance::Installed("1.0.0"),
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
    use crate::fixture::runtime;
    use crate::{repo, TrustedRepository};

    const OS: &str = std::env::consts::OS;
    const ARCH: &str = std::env::consts::ARCH;

    fn app_path(version: &str) -> String {
        format!("products/app/stable/{version}/{OS}-{ARCH}/app")
    }

    /// Author the repo and return a repository loaded with an assignment that pins app 2.0.0
    /// as the head (its provider set B), with ordered fallback opted in.
    async fn repo_with_assignment(fallback: bool) -> (tempfile::TempDir, TrustedRepository) {
        repo_with_assignment_where(fallback, false).await
    }

    /// As [`repo_with_assignment`], plus a third, older release (0.9.0 with provider set Z) so a
    /// descent has somewhere to go past 1.0.0. When `unreadable_predecessor_binding` is set,
    /// 1.0.0's signed `provider_set` carries a field this build's `TargetReference` cannot
    /// deserialize — the newer-publisher case.
    async fn repo_with_assignment_where(
        fallback: bool,
        unreadable_predecessor_binding: bool,
    ) -> (tempfile::TempDir, TrustedRepository) {
        let guard = tempfile::tempdir().unwrap();
        let tmp = guard.path().to_path_buf();
        let repo_dir = tmp.join("repo");
        let keys = repo::generate_keys(&tmp.join("keys")).await.unwrap();
        repo::init(&repo_dir, &keys, 365).await.unwrap();

        // Three app versions, each with the provider set it shipped with signed into its metadata.
        let v0_src = tmp.join("app-0");
        let v1_src = tmp.join("app-1");
        let v2_src = tmp.join("app-2");
        std::fs::write(&v0_src, b"app-0.9.0").unwrap();
        std::fs::write(&v1_src, b"app-1.0.0").unwrap();
        std::fs::write(&v2_src, b"app-2.0.0").unwrap();
        let v0 =
            repo::PublishTarget::application("app", "stable", "0.9.0", OS, ARCH, "app", v0_src)
                .with_provider_set("provider-sets/z.json", &"c".repeat(64));
        let mut v1 =
            repo::PublishTarget::application("app", "stable", "1.0.0", OS, ARCH, "app", v1_src)
                .with_provider_set("provider-sets/a.json", &"a".repeat(64));
        if unreadable_predecessor_binding {
            v1.custom.insert(
                "provider_set".into(),
                serde_json::json!({
                    "path": "provider-sets/a.json",
                    "sha256": "a".repeat(64),
                    "successor": "provider-sets/a2.json",
                }),
            );
        }
        let v2 =
            repo::PublishTarget::application("app", "stable", "2.0.0", OS, ARCH, "app", v2_src)
                .with_provider_set("provider-sets/b.json", &"b".repeat(64));
        repo::add_release(&repo_dir, &keys, vec![v0, v1, v2], 365)
            .await
            .unwrap();
        let head_sha = repo::target_sha256(&repo_dir, &app_path("2.0.0"))
            .await
            .unwrap();

        let source = crate::testing::offline_source(&repo_dir);
        let mut repository = TrustedRepository::load(&source, &tmp.join("datastore"))
            .await
            .unwrap();
        // The assigned head is 2.0.0 + provider set B — both published together.
        repository.assignment = Some(updated_contracts::assignment::RepositoryAssignment {
            schema: updated_contracts::assignment::RepositoryAssignment::SCHEMA,
            deployment: "deploy".into(),
            metadata_url: source.metadata_url.clone(),
            targets_url: source.targets_url.clone(),
            application: updated_contracts::artifact::TargetReference {
                path: app_path("2.0.0"),
                sha256: head_sha,
            },
            ordered_install_fallback: fallback,
            provider_set: updated_contracts::artifact::TargetReference {
                path: "provider-sets/b.json".into(),
                sha256: "b".repeat(64),
            },
            release_root: serde_json::json!({}),
            runtime: runtime(),
        });
        (guard, repository)
    }

    fn policy() -> DefaultPolicy {
        DefaultPolicy::current("app", "stable")
    }

    #[test]
    fn signed_provider_set_separates_absent_from_unreadable() {
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
            sha256: vec![0u8; 32],
            custom: serde_json::to_value(&target.custom).unwrap(),
        };
        let bound = signed_provider_set(&verified)
            .expect("readable")
            .expect("bound");
        assert_eq!(bound.path, "provider-sets/a.json");
        assert_eq!(bound.sha256, "a".repeat(64));

        let plain = VerifiedTarget {
            custom: serde_json::json!({"product": "app"}),
            ..verified.clone()
        };
        assert!(
            signed_provider_set(&plain).expect("readable").is_none(),
            "no binding at all is the absent case"
        );

        // A binding this build cannot read must NOT report as absent: absent means "defer to the
        // assignment's provider set", which for a descended app is the head's newer reconciler.
        let newer_publisher = VerifiedTarget {
            custom: serde_json::json!({
                "provider_set": {
                    "path": "provider-sets/a.json",
                    "sha256": "a".repeat(64),
                    "successor": "provider-sets/a2.json",
                }
            }),
            ..verified.clone()
        };
        assert!(signed_provider_set(&newer_publisher).is_err());
        let malformed_digest = VerifiedTarget {
            custom: serde_json::json!({
                "provider_set": {"path": "provider-sets/a.json", "sha256": "not-a-digest"}
            }),
            ..verified
        };
        assert!(signed_provider_set(&malformed_digest).is_err());
    }

    // A descent must never hand back "no bound provider set" for a version that HAS one it could
    // not read: that answer means "use the assignment's set", pairing this older app with the
    // head's newer reconciler — the mispairing ordered fallback exists to prevent. So 1.0.0 is
    // uninstallable here and the descent continues to 0.9.0 and its own set.
    #[tokio::test]
    async fn a_descent_skips_a_version_whose_signed_provider_set_it_cannot_read() {
        let (_tmp, repo) = repo_with_assignment_where(true, true).await;
        let mut skips = Vec::new();
        let selected = repo
            .assigned_application(
                &policy(),
                Stance::Nothing,
                |skip| skips.push(skip.to_string()),
                |_, version| version == "2.0.0",
            )
            .unwrap()
            .expect("a readable predecessor is selectable");
        assert_eq!(selected.version, "0.9.0");
        assert_eq!(
            selected
                .provider_set
                .expect("descent binds a provider set")
                .path,
            "provider-sets/z.json"
        );
        assert!(
            skips
                .iter()
                .any(|skip| skip.starts_with("skipping 1.0.0:") && skip.contains("provider set")),
            "the refusal is diagnosable, not silent: {skips:?}"
        );
    }

    // The head assignment (2.0.0) is broken, so a first-install node with ordered fallback
    // descends to 1.0.0 — and must roll back to the provider set signed with 1.0.0 (A), not
    // the assignment head's B. This is the app+provider-as-one-unit rollback.
    #[tokio::test]
    async fn ordered_fallback_descends_to_the_app_versions_own_provider_set() {
        let (_tmp, repo) = repo_with_assignment(true).await;
        let selected = repo
            .assigned_application(
                &policy(),
                Stance::Nothing,
                |_| {},
                |_, version| version == "2.0.0",
            )
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

    // First install with a healthy head stays at 2.0.0 and, like every other way of arriving at
    // the head, defers to the assignment's own `provider_set`. Binding the app's baked-in set
    // here would make a fresh node and an enrolled node at the same app version run different
    // provider sets the moment a provider-set-only assignment revision is published.
    #[tokio::test]
    async fn first_install_at_head_defers_providers_to_the_assignment_like_every_other_node() {
        let (_tmp, repo) = repo_with_assignment(true).await;
        let selected = repo
            .assigned_application(&policy(), Stance::Nothing, |_| {}, |_, _| false)
            .unwrap()
            .expect("the head is selectable");
        assert_eq!(selected.version, "2.0.0");
        assert!(
            selected.provider_set.is_none(),
            "ordered fallback binds a provider set only where it descended BELOW the assigned \
             head; at the head the assignment governs, so a provider-set-only revision reaches \
             newly enrolled and long-enrolled nodes alike"
        );
    }

    // An established node (exact-pin, no floor-less descent) leaves provider selection to the
    // assignment's own `provider_set`, so a provider-only revision reconciles at the head
    // WITHOUT an app change: `provider_set` is `None`, and the agent uses the assignment's.
    /// A repair must not become a downgrade.
    ///
    /// `repair.rs` re-acquires the release the node is ALREADY committed to, so it has to lift the
    /// "you already have that version" short-circuit. It used to do that by passing `None`, which
    /// is the selector's word for "nothing is installed" — the one stance a signed
    /// `orderedInstallFallback` descends under. On a node whose assigned head was rejected, that
    /// walked a repair down to an older release and installed it, past the anti-rollback floor the
    /// ordinary update path refuses to cross.
    ///
    /// [`Stance::Reacquire`] separates the two: the head is re-selectable, and the descent is not
    /// available at all. When the head is unselectable the repair comes back empty (its caller then
    /// falls back to the journaled predecessor revert) rather than quietly installing 1.0.0.
    #[tokio::test]
    async fn a_repair_re_acquires_the_head_without_becoming_a_descent() {
        let (_tmp, repo) = repo_with_assignment(true).await;

        // The version the node already has IS the assigned head: a repair must still select it,
        // where an ordinary `Installed` stance correctly answers "nothing to do".
        let repaired = repo
            .assigned_application(&policy(), Stance::Reacquire("2.0.0"), |_| {}, |_, _| false)
            .unwrap()
            .expect("a repair re-selects the release it is repairing");
        assert_eq!(repaired.version, "2.0.0");
        assert!(
            repo.assigned_application(&policy(), Stance::Installed("2.0.0"), |_| {}, |_, _| false)
                .unwrap()
                .is_none(),
            "an ordinary pass over the installed head has nothing to do"
        );

        // The head is rejected. `Nothing` — a genuine cold install — descends to 1.0.0, which is
        // the whole point of ordered fallback. A repair on a node holding 2.0.0 must NOT: that
        // would be a downgrade past the floor, so it selects nothing instead.
        let head_rejected = |_: &VerifiedTarget, version: &str| version == "2.0.0";
        assert_eq!(
            repo.assigned_application(&policy(), Stance::Nothing, |_| {}, head_rejected)
                .unwrap()
                .expect("a first install descends past the rejected head")
                .version,
            "1.0.0"
        );
        assert!(
            repo.assigned_application(&policy(), Stance::Reacquire("2.0.0"), |_| {}, head_rejected)
                .unwrap()
                .is_none(),
            "a repair must not descend below the release the node is committed to"
        );
    }

    #[tokio::test]
    async fn established_node_defers_providers_to_the_assignment_for_provider_only_updates() {
        let (_tmp, repo) = repo_with_assignment(false).await;
        let selected = repo
            .assigned_application(&policy(), Stance::Installed("1.0.0"), |_| {}, |_, _| false)
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
