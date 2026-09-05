//! Choosing a release from verified TUF metadata.
//!
//! Ordinary updates inspect only the repository head: if that exact release is
//! rejected or cannot be authorized, the node holds its last confirmed release.
//! Walking backward through repository history is a separate operation, admitted
//! only for a stateless first install by a signed `coldInstallFallback`.
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
/// anti-rollback floor" — which is the exact condition a signed `coldInstallFallback` descends
/// below the assigned head under. So `repair.rs`, running on a node with a release installed, took
/// the branch reserved for stateless first installs: with the head's bytes rejected it would
/// descend to an older release and install it, past the floor `selection.rs` refuses to cross.
///
/// Spelling the stance out is what makes that unrepresentable. A caller can explicitly request an
/// exact reacquisition without lifting the floor, and it cannot lift the floor without saying, in
/// as many words, that nothing is installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stance<'a> {
    /// Nothing is installed. There is no anti-rollback floor, and this is the ONLY stance under
    /// which a signed `coldInstallFallback` may descend below the assigned head.
    Nothing,
    /// `version` is installed: it is the anti-rollback floor, and re-selecting it is a no-op.
    Installed(&'a str),
    /// These exact installed bytes must be re-acquired — a repair republishing a drifted tree over
    /// the release the node is already committed to. Both version and digest are required: a
    /// version-only repair followed the assignment when it moved and became an unjournaled second
    /// update path. This identity is still the anti-rollback floor and can never descend.
    Reacquire { version: &'a str, sha256: &'a str },
}

impl<'a> Stance<'a> {
    /// The version no candidate may fall below, and what the downgrade policy authorizes against.
    /// `None` only when nothing is installed, because only then is there nothing to roll back from.
    pub fn floor(self) -> Option<&'a str> {
        match self {
            Self::Nothing => None,
            Self::Installed(version) | Self::Reacquire { version, .. } => Some(version),
        }
    }

    /// The version whose re-selection is a no-op, if any. A repair has none: re-selecting what is
    /// already installed is exactly what it is for.
    fn already_have(self) -> Option<&'a str> {
        match self {
            Self::Installed(version) => Some(version),
            Self::Nothing | Self::Reacquire { .. } => None,
        }
    }

    /// Whether a signed `coldInstallFallback` may descend below the assigned head.
    fn may_descend(self) -> bool {
        matches!(self, Self::Nothing)
    }

    /// How the stance reads in operator-facing diagnostics.
    fn describe(self) -> String {
        match self {
            Self::Nothing => "<none>".into(),
            Self::Installed(version) => version.to_string(),
            Self::Reacquire { version, .. } => format!("{version} (re-acquiring exact bytes)"),
        }
    }
}

/// Why one candidate is or is not the release to install.
///
/// The single per-candidate judgement, so the selector and [`TrustedRepository::selection_diagnostics`]
/// cannot disagree about a release. Diagnostics used to re-derive its own three facts — rejected,
/// above-ceiling, authorized — and simply did not know about two of the gates the selector converges:
/// the assigned-head-bytes pin and the downgrade watermark. An operator debugging why
/// `coldInstallFallback` refused a release was shown a candidate that looked eligible in every
/// column the tool printed, with nothing naming the gate that actually stopped it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CandidateVerdict {
    /// Install this one.
    Eligible,
    /// Newer than the version the control plane assigned. The shared targets metadata holds other
    /// groups' higher releases; cold-install fallback must never climb into them.
    AboveCeiling,
    /// At the assigned head version but not the assigned bytes. Two TUF-authentic targets can share
    /// a version, so without this pin fallback could install a sibling the control plane never
    /// named.
    NotAssignedHeadBytes,
    /// Already running.
    Installed,
    /// Below the running version: repository history, not an update.
    BelowInstalled,
    /// An artifact or this exact application/provider deployment was rejected. Every verdict is
    /// content-addressed, so corrected content or a new artifact combination is eligible at once
    /// while the exact failed identity stays blocked under any label.
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
            Self::Rejected => "its artifact or exact deployment was rejected".into(),
            Self::Unauthorized(error) => error.clone(),
        }
    }

    /// Interpret the verdict for an exact target rather than a fallback walk.
    ///
    /// An already-installed or rejected target is an ordinary no-op. Every other refusal is a
    /// trust/configuration failure: exact selection has no lower candidate to continue to, so
    /// silently returning `None` would hide a malformed or unauthorized assignment.
    fn exact_outcome(self) -> Result<bool, crate::Error> {
        match self {
            Self::Eligible => Ok(true),
            Self::Installed | Self::Rejected => Ok(false),
            other => Err(crate::Error::Trust(other.reason())),
        }
    }
}

/// The assigned ceiling is one indivisible version-and-digest pin.
///
/// Keeping the two values in one type makes it impossible to apply a version ceiling without the
/// corresponding assigned bytes, or a digest pin at an unrelated version.
#[derive(Clone, Copy)]
struct AssignedCeiling<'a> {
    version: &'a Version,
    sha256: &'a str,
}

/// The complete immutable context for one candidate judgement.
///
/// Selection and diagnostics construct this once per walk and hand the same value to every
/// candidate. The floor is derived here from the stance, and an assigned ceiling carries its digest
/// in one value, so neither shared invariant can drift at a call site.
struct CandidateRules<'policy, 'stance, 'ceiling> {
    policy: &'policy DefaultPolicy,
    stance: Stance<'stance>,
    floor: Option<Version>,
    ceiling: Option<AssignedCeiling<'ceiling>>,
}

impl<'policy, 'stance, 'ceiling> CandidateRules<'policy, 'stance, 'ceiling> {
    fn new(
        policy: &'policy DefaultPolicy,
        stance: Stance<'stance>,
        ceiling: Option<AssignedCeiling<'ceiling>>,
    ) -> Self {
        Self {
            policy,
            stance,
            floor: stance
                .floor()
                .and_then(|version| Version::parse(version).ok()),
            ceiling,
        }
    }
}

/// Judge one candidate against every gate, in the order the selector converges them.
fn judge_candidate(
    target: &VerifiedTarget,
    version: &Version,
    rules: &CandidateRules<'_, '_, '_>,
    rejected: &mut impl FnMut(&VerifiedTarget, &str) -> bool,
) -> CandidateVerdict {
    if let Some(ceiling) = rules.ceiling {
        if version > ceiling.version {
            return CandidateVerdict::AboveCeiling;
        }
        // Through `digest::digests_match`, like every digest comparison on the trust path. The
        // assignment already requires canonical lowercase hex; the shared comparison also fails
        // closed if a locally corrupted value bypasses that boundary.
        if version == ceiling.version
            && !updated_contracts::digest::digests_match(&target_sha(target), ceiling.sha256)
        {
            return CandidateVerdict::NotAssignedHeadBytes;
        }
    }
    // The anti-rollback floor. It comes off the stance, never off "is there a version string
    // here", so lifting the no-op short-circuit below cannot lift this with it.
    if rules.floor.as_ref().is_some_and(|floor| version < floor) {
        return CandidateVerdict::BelowInstalled;
    }
    let text = version.to_string();
    if rules.stance.already_have() == Some(text.as_str()) {
        return CandidateVerdict::Installed;
    }
    if rejected(target, &text) {
        return CandidateVerdict::Rejected;
    }
    match rules.policy.authorize(rules.stance.floor(), target) {
        Ok(()) => CandidateVerdict::Eligible,
        Err(error) => CandidateVerdict::Unauthorized(error.to_string()),
    }
}

/// The first eligible target in `targets` (already newest-first): not `current`,
/// not `rejected`, and authorized by `policy`.
///
/// Rejection is keyed by content hash — the exact bytes that failed — not the
/// version string, so a corrected republish is eligible at once and the same bad
/// bytes stay blocked even under a different label. Each policy-skipped candidate is
/// reported to `note_skip` for diagnostics.
fn select_first_eligible_from(
    targets: impl IntoIterator<Item = (VerifiedTarget, Version)>,
    policy: &DefaultPolicy,
    stance: Stance<'_>,
    ceiling: Option<AssignedCeiling<'_>>,
    mut note_skip: impl FnMut(&str),
    mut rejected: impl FnMut(&VerifiedTarget, &str) -> bool,
) -> Option<(VerifiedTarget, String)> {
    // Newest-first ordering lets the anti-rollback floor act as a watermark.
    let rules = CandidateRules::new(policy, stance, ceiling);
    let mut saw_current = false;
    for (target, version) in targets {
        let verdict = judge_candidate(&target, &version, &rules, &mut rejected);
        // Only once past the ceiling gates does an equal version count as "we have reached the
        // installed release": a candidate the ceiling excluded says nothing about where the node is.
        if !matches!(
            verdict,
            CandidateVerdict::AboveCeiling | CandidateVerdict::NotAssignedHeadBytes
        ) && rules
            .floor
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
                        rules.floor.as_ref().expect("a version to be below")
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

/// Select only from the newest version in repository metadata.
///
/// Multiple targets at that version are considered so a corrected content-addressed
/// republish is immediately usable, but an unhealthy head can never turn an update
/// into an implicit walk through older releases.
fn select_head_from(
    targets: impl IntoIterator<Item = (VerifiedTarget, Version)>,
    policy: &DefaultPolicy,
    stance: Stance<'_>,
    note_skip: impl FnMut(&str),
    rejected: impl FnMut(&VerifiedTarget, &str) -> bool,
) -> Option<(VerifiedTarget, String)> {
    let mut targets = targets.into_iter().peekable();
    let head = targets.peek()?.1.clone();
    select_first_eligible_from(
        targets.take_while(|(_, version)| version == &head),
        policy,
        stance,
        None,
        note_skip,
        rejected,
    )
}

/// An authenticated release selected by policy but not downloaded yet.
pub struct SelectedRelease {
    pub target: VerifiedTarget,
    pub version: String,
    pub sha256: String,
}

/// Shared select-and-download path used by the long-running and one-shot modes.
impl TrustedRepository {
    /// Resolve and authorize the application selected by the signed deployment
    /// assignment.
    ///
    /// By default this pins the exact assigned bytes and never substitutes a
    /// different target when they are unavailable or rejected. When the signed
    /// assignment sets `cold_install_fallback` *and* this is a first install
    /// ([`Stance::Nothing`], so there is no anti-rollback floor), it instead
    /// descends from the assigned version — the ceiling — to the newest healthy,
    /// non-rejected, policy-authorized target at or below it. That lets a stateless
    /// node recover from a broken head assignment without stranding, while the
    /// signed opt-in ensures only the publisher can authorize a floor-less descent.
    pub fn assigned_application(
        &self,
        policy: &DefaultPolicy,
        stance: Stance<'_>,
        note_skip: impl FnMut(&str),
        mut rejected: impl FnMut(&VerifiedTarget, &str) -> bool,
    ) -> Result<Option<SelectedRelease>, crate::Error> {
        // Repair is not desired-state selection. It is reconstruction of the exact immutable
        // artifact already committed on this node. Bind that request to both identity halves and
        // resolve it from authenticated targets without requiring or consulting desired state. If
        // the assignment moved or is temporarily absent, the ordinary update loop handles that
        // separately; repair cannot activate a new head as a side effect.
        if let Stance::Reacquire { version, sha256 } = stance {
            let selected =
                matching_targets(self, policy)
                    .into_iter()
                    .find(|(target, candidate)| {
                        candidate.to_string() == version
                            && updated_contracts::digest::digests_match(&target_sha(target), sha256)
                    });
            let Some((target, candidate)) = selected else {
                return Ok(None);
            };
            // Repair carries the already-committed provider unchanged, so only the application
            // archive participates in selection here.
            let rules = CandidateRules::new(policy, stance, None);
            if !judge_candidate(&target, &candidate, &rules, &mut |target, version| {
                rejected(target, version)
            })
            .exact_outcome()?
            {
                return Ok(None);
            }
            return Ok(Some(SelectedRelease {
                sha256: target_sha(&target),
                target,
                version: candidate.to_string(),
            }));
        }
        let assignment = self
            .assignment_context()
            .ok_or_else(|| {
                crate::Error::Trust("release repository has no desired deployment".into())
            })?
            .document();
        let target = self.exact_target(&assignment.application)?;
        let ceiling = policy
            .candidate_version(&target)
            .map_err(|error| crate::Error::Trust(error.to_string()))?;

        if assignment.cold_install_fallback && stance.may_descend() {
            let head_sha = assignment.application.sha256.as_str();
            let mut note_skip = note_skip;
            // Reported after the walk: `select_first_eligible_from` holds `note_skip` for its
            // duration.
            let selected = select_first_eligible_from(
                matching_targets(self, policy),
                policy,
                stance,
                Some(AssignedCeiling {
                    version: &ceiling,
                    sha256: head_sha,
                }),
                &mut note_skip,
                |target, version| rejected(target, version),
            )
            .map(|(target, version)| SelectedRelease {
                sha256: target_sha(&target),
                target,
                version,
            });
            return Ok(selected);
        }

        let version = ceiling.to_string();
        let rules = CandidateRules::new(
            policy,
            stance,
            Some(AssignedCeiling {
                version: &ceiling,
                sha256: &assignment.application.sha256,
            }),
        );
        if !judge_candidate(&target, &ceiling, &rules, &mut |target, version| {
            rejected(target, version)
        })
        .exact_outcome()?
        {
            return Ok(None);
        }
        let sha256 = target_sha(&target);
        Ok(Some(SelectedRelease {
            target,
            version,
            sha256,
        }))
    }

    /// A human-readable audit of every candidate cold-install fallback could descend to and why each
    /// is or isn't selectable — for diagnosing an empty selection ("no installable application").
    /// `is_rejected` mirrors the selector's deployed-unit rejection check. The provider argument
    /// is absent only for a `Reacquire`, whose contract is to reproduce the already-committed
    /// application archive rather than choose a new deployment.
    pub fn selection_diagnostics(
        &self,
        policy: &DefaultPolicy,
        stance: Stance<'_>,
        mut is_rejected: impl FnMut(&str) -> bool,
    ) -> String {
        let Some(assignment) = self.assignment_context() else {
            return "no desired deployment in the release repository".into();
        };
        let assignment = assignment.document();
        let ceiling = self
            .exact_target(&assignment.application)
            .ok()
            .and_then(|target| policy.candidate_version(&target).ok());
        let mut lines = vec![format!(
            "assigned={} cold_install_fallback={} ceiling={} current={}",
            assignment.application.path,
            assignment.cold_install_fallback,
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
        // The same indivisible pin `assigned_application` walks with: the version and digest the
        // control plane named.
        let rules = CandidateRules::new(
            policy,
            stance,
            ceiling.as_ref().map(|version| AssignedCeiling {
                version,
                sha256: &assignment.application.sha256,
            }),
        );
        for (target, version) in candidates {
            let sha = target_sha(&target);
            let short = &sha[..sha.len().min(12)];
            let verdict = judge_candidate(&target, &version, &rules, &mut |target, _| {
                is_rejected(&target_sha(target))
            });
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
        let (target, version) = select_head_from(
            matching_targets(self, policy),
            policy,
            stance,
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
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
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

    /// Every gate the selector converges, named by the one judgement both readers consume.
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
                     ceiling: Option<AssignedCeiling<'_>>,
                     rejected: &mut dyn FnMut(&VerifiedTarget, &str) -> bool| {
            let rules = CandidateRules::new(&policy, stance, ceiling);
            judge_candidate(target, version, &rules, &mut |t, v| rejected(t, v))
        };

        let (target, version) = candidate("2.0.0", 1);
        let head_sha = target_sha(&target);
        let ceiling = Version::parse("1.5.0").unwrap();

        assert_eq!(
            judge(
                &target,
                &version,
                Stance::Nothing,
                Some(AssignedCeiling {
                    version: &ceiling,
                    sha256: &head_sha,
                }),
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
                Some(AssignedCeiling {
                    version: &at_ceiling,
                    sha256: &"f".repeat(64),
                }),
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
                Some(AssignedCeiling {
                    version: &at_ceiling,
                    sha256: &head_sha,
                }),
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
                None,
                never
            ),
            CandidateVerdict::BelowInstalled
        );
        assert_eq!(
            judge(&target, &version, Stance::Installed("2.0.0"), None, never),
            CandidateVerdict::Installed
        );
        assert_eq!(
            judge(&target, &version, Stance::Nothing, None, always),
            CandidateVerdict::Rejected
        );
        // A downgrade the policy itself refuses, distinct from the watermark above.
        let wrong = DefaultPolicy::current("other-product", "stable");
        let wrong_rules = CandidateRules::new(&wrong, Stance::Nothing, None);
        assert!(matches!(
            judge_candidate(&target, &version, &wrong_rules, never),
            CandidateVerdict::Unauthorized(_)
        ));
        assert_eq!(
            judge(&target, &version, Stance::Nothing, None, never),
            CandidateVerdict::Eligible
        );
    }

    #[test]
    fn explicit_cold_install_walk_skips_a_rejected_head_for_a_healthy_intermediate() {
        let targets = vec![
            candidate("4.0.0", 4),
            candidate("3.0.0", 3),
            candidate("2.0.0", 2),
        ];
        let selected = select_first_eligible_from(
            targets,
            &policy(),
            Stance::Installed("2.0.0"),
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
        assert!(select_first_eligible_from(
            targets.clone(),
            &policy(),
            Stance::Installed("3.0.0"),
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
        assert!(select_first_eligible_from(
            targets,
            &policy(),
            Stance::Installed("4.0.0"),
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
    fn cold_install_fallback_pins_the_assigned_sha_at_the_head_version() {
        let ceiling = Version::parse("2.0.0").unwrap();
        let assigned_head_sha = target_sha(&candidate("2.0.0", 2).0);

        // A different, still TUF-authentic target sits at the head version (bytes sha=9), but
        // it is not the assigned sha. With the head pin, that candidate is skipped and ordered
        // fallback descends to the well-defined predecessor rather than installing foreign
        // head bytes.
        let foreign_head = vec![candidate("2.0.0", 9), candidate("1.0.0", 1)];
        let selected = select_first_eligible_from(
            foreign_head,
            &policy(),
            Stance::Nothing,
            Some(AssignedCeiling {
                version: &ceiling,
                sha256: assigned_head_sha.as_str(),
            }),
            |_| {},
            |_, _| false,
        )
        .expect("descends past the unassigned head bytes");
        assert_eq!(selected.1, "1.0.0");

        // When the exact assigned bytes are present at the head, they are selected.
        let with_assigned_head = vec![candidate("2.0.0", 2), candidate("1.0.0", 1)];
        let selected = select_first_eligible_from(
            with_assigned_head,
            &policy(),
            Stance::Nothing,
            Some(AssignedCeiling {
                version: &ceiling,
                sha256: assigned_head_sha.as_str(),
            }),
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
        let selected = select_head_from(
            targets,
            &policy(),
            Stance::Installed("1.0.0"),
            |_| {},
            |t, _| target_sha(t) == rejected_hash,
        )
        .unwrap();
        assert_eq!(target_sha(&selected.0), hex::encode(vec![2; 32]));
    }

    #[test]
    fn a_rejected_head_never_turns_an_upgrade_into_an_intermediate_release() {
        let rejected_hash = target_sha(&candidate("0.7.0", 7).0);
        let targets = vec![
            candidate("0.7.0", 7),
            candidate("0.6.0", 6),
            candidate("0.1.0", 1),
        ];
        assert!(select_head_from(
            targets,
            &policy(),
            Stance::Installed("0.1.0"),
            |_| {},
            |target, _| target_sha(target) == rejected_hash,
        )
        .is_none());
    }

    #[test]
    fn an_upgrade_jumps_directly_from_the_confirmed_release_to_the_repository_head() {
        let targets = vec![
            candidate("0.7.0", 7),
            candidate("0.6.0", 6),
            candidate("0.1.0", 1),
        ];
        let selected = select_head_from(
            targets,
            &policy(),
            Stance::Installed("0.1.0"),
            |_| {},
            |_, _| false,
        )
        .expect("the repository head is the one desired transition");

        assert_eq!(selected.1, "0.7.0");
        assert_eq!(target_sha(&selected.0), hex::encode(vec![7; 32]));
    }
}

/// The provider set signed with each app version binds app+providers as one rollback unit.
/// These author a real release repo (app 1.0.0 with provider set A, 2.0.0 with provider set B)
/// and drive [`TrustedRepository::assigned_application`] end to end.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod assigned_packages {
    use super::*;
    use crate::fixture::runtime;
    use crate::{repo, TrustedRepository};

    const OS: &str = std::env::consts::OS;
    const ARCH: &str = std::env::consts::ARCH;

    fn app_path(version: &str) -> String {
        format!("products/app/stable/{version}/{OS}-{ARCH}/app")
    }

    /// Three signed package versions provide a bounded fallback route.
    async fn repo_with_assignment(fallback: bool) -> (tempfile::TempDir, TrustedRepository) {
        let guard = tempfile::tempdir().unwrap();
        let tmp = guard.path().to_path_buf();
        let repo_dir = tmp.join("repo");
        let keys = repo::generate_keys(&tmp.join("keys")).await.unwrap();
        repo::init(&repo_dir, &keys, 365).await.unwrap();

        // Three complete package identities.
        let v0_src = tmp.join("app-0");
        let v1_src = tmp.join("app-1");
        let v2_src = tmp.join("app-2");
        std::fs::write(&v0_src, b"app-0.9.0").unwrap();
        std::fs::write(&v1_src, b"app-1.0.0").unwrap();
        std::fs::write(&v2_src, b"app-2.0.0").unwrap();
        let v0 =
            repo::PublishTarget::application("app", "stable", "0.9.0", OS, ARCH, "app", v0_src);
        let v1 =
            repo::PublishTarget::application("app", "stable", "1.0.0", OS, ARCH, "app", v1_src);

        let v2 =
            repo::PublishTarget::application("app", "stable", "2.0.0", OS, ARCH, "app", v2_src);
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
        let document = updated_contracts::assignment::RepositoryAssignment {
            schema: updated_contracts::assignment::RepositoryAssignment::SCHEMA,
            deployment: "deploy".into(),
            metadata_url: source.metadata_url.clone(),
            targets_url: source.targets_url.clone(),
            application: updated_contracts::artifact::TargetReference {
                path: app_path("2.0.0"),
                sha256: head_sha,
            },
            cold_install_fallback: fallback,
            release_root: serde_json::json!({}),
            runtime: runtime(),
        };
        let repository_lineage =
            updated::state::RepositoryLineage::from_metadata_url(&document.metadata_url)
                .expect("fixture metadata URL is valid");
        repository.assignment = Some(crate::AssignmentContext {
            document,
            sha256: updated_contracts::digest::sha256_bytes(b"assignment fixture"),
            repository_lineage,
        });
        (guard, repository)
    }

    fn policy() -> DefaultPolicy {
        DefaultPolicy::current("app", "stable")
    }

    /// A repair must not become a downgrade.
    ///
    /// `repair.rs` re-acquires the release the node is ALREADY committed to, so it has to lift the
    /// "you already have that version" short-circuit. It used to do that by passing `None`, which
    /// is the selector's word for "nothing is installed" — the one stance a signed
    /// `coldInstallFallback` descends under. On a node whose assigned head was rejected, that
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
        let head_sha = repo
            .assignment_context()
            .expect("the fixture has an assignment")
            .document()
            .application
            .sha256
            .clone();
        let repaired = repo
            .assigned_application(
                &policy(),
                Stance::Reacquire {
                    version: "2.0.0",
                    sha256: &head_sha,
                },
                |_| {},
                |_, _| false,
            )
            .unwrap()
            .expect("a repair re-selects the release it is repairing");
        assert_eq!(repaired.version, "2.0.0");
        assert!(
            repo.assigned_application(&policy(), Stance::Installed("2.0.0"), |_| {}, |_, _| false,)
                .unwrap()
                .is_none(),
            "an ordinary pass over the installed head has nothing to do"
        );

        // The head is rejected. `Nothing` — a genuine cold install — descends to 1.0.0, which is
        // the whole point of cold-install fallback. A repair on a node holding 2.0.0 must NOT: that
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
            repo.assigned_application(
                &policy(),
                Stance::Reacquire {
                    version: "2.0.0",
                    sha256: &head_sha,
                },
                |_| {},
                head_rejected,
            )
            .unwrap()
            .is_none(),
            "a repair must not descend below the release the node is committed to"
        );
    }

    #[tokio::test]
    async fn a_repair_reacquires_the_committed_bytes_not_a_moved_assignment() {
        let (_tmp, mut repo) = repo_with_assignment(true).await;
        let (target, _) = matching_targets(&repo, &policy())
            .into_iter()
            .find(|(_, version)| version.to_string() == "1.0.0")
            .expect("the committed predecessor is still authenticated by targets metadata");
        let committed_sha = target_sha(&target);
        // Repair is reconstruction of committed state, not desired-state selection. It remains
        // possible while an assignment is absent, provided TUF still authenticates the exact
        // committed version and digest.
        repo.assignment = None;

        let repaired = repo
            .assigned_application(
                &policy(),
                Stance::Reacquire {
                    version: "1.0.0",
                    sha256: &committed_sha,
                },
                |_| {},
                |_, _| false,
            )
            .unwrap()
            .expect("the exact committed bytes remain repairable");
        assert_eq!(repaired.version, "1.0.0");
        assert_eq!(repaired.sha256, committed_sha);

        assert!(
            repo.assigned_application(
                &policy(),
                Stance::Reacquire {
                    version: "1.0.0",
                    sha256: &"0".repeat(64),
                },
                |_| {},
                |_, _| false,
            )
            .unwrap()
            .is_none(),
            "a version match cannot substitute differently packed bytes"
        );
    }
}
