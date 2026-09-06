//! Every status write the pass makes: group, group-set, agent and repository conditions,
//! quarantine, and the failure statuses an operator reads when a pass cannot complete.

use super::*;

/// Publish each `UpdateGroupSet`'s observed rollout state as its status.
pub(crate) async fn publish_group_set_statuses(
    sets: &Api<UpdateGroupSet>,
    set_resources: &[UpdateGroupSet],
    statuses: &[SetStatus],
    alerts: Option<&Arc<crate::alerts::AlertSink>>,
) -> Result<(), kube::Error> {
    let params = PatchParams::default();
    let by_name: HashMap<&str, &SetStatus> = statuses
        .iter()
        .map(|status| (status.name.as_str(), status))
        .collect();
    for set in set_resources {
        let name = set.name_any();
        let Some(status) = by_name.get(name.as_str()) else {
            continue;
        };
        // Edge-triggered logging, from the ONE place that knows both the value just computed and
        // the one last published. Freezing and calendar exhaustion are steady states that last for
        // days; logged from the planner they emitted a line per reconcile (one second) per set.
        let last = set.status.as_ref();
        if last.and_then(|status| status.frozen) != Some(status.frozen) {
            tracing::info!(
                set = %name,
                frozen = status.frozen,
                "UpdateGroupSet crossed its rollout schedule boundary (windows/calendar)"
            );
        }
        if status.calendar_exhausted
            && last.and_then(|status| status.calendar_exhausted) != Some(true)
        {
            tracing::warn!(
                set = %name,
                "UpdateGroupSet calendar has run out; it is now UNGATED and will roll at any hour \
                 — add a future approved window (or a rollout window) to re-gate it"
            );
        }
        if status.emergency
            != last
                .map(|status| status.emergency.clone())
                .unwrap_or_default()
        {
            tracing::warn!(
                set = %name,
                emergency = ?status.emergency,
                "members declaring spec.emergencyCorrection changed; these members bypass this \
                 set's rollout schedule until the flag is cleared"
            );
        }
        // Edge-triggered like `frozen`: a halt is a steady state that persists until the operator
        // stages corrected bytes, and the regression verdict is recomputed once per second.
        if status.halted != last.map(|status| status.halted.clone()).unwrap_or_default() {
            tracing::warn!(
                set = %name,
                halted = ?status.halted,
                "the regression verdict changed: enough nodes proved a staged deployment bad. \
                 Admission to each halted deployment is stopped in every member group until a \
                 deployment with a different identity is published."
            );
        }
        // The alertable set conditions, beside Ready: the regression verdict, and whether the
        // reconcile loop itself is converging. Transitions only reach the webhook.
        let previous = last
            .map(|status| status.conditions.as_slice())
            .unwrap_or_default();
        let mut conditions = vec![ready_condition(
            set.metadata.generation,
            "Reconciled",
            "This set's rollout throttle is reconciled.",
        )];
        let mut fired_events = Vec::new();
        for next in [
            crate::alerts::deployment_halted(
                set.metadata.generation,
                &status.halted,
                chrono::Utc::now(),
            ),
            // This writer only runs on a pass that has succeeded this far, so the streak it
            // reports is zero by construction; the failing loop's own writer
            // (`record_reconcile_failing`) is the only place a non-zero streak can come from.
            crate::alerts::reconcile_failing(set.metadata.generation, 0, chrono::Utc::now()),
        ] {
            let condition_type = next.condition_type.clone();
            let (published, fired) = crate::alerts::carry_transition(
                crate::alerts::existing(previous, &condition_type),
                next,
            );
            if fired {
                fired_events.push(crate::alerts::AlertEvent::from_condition(
                    "UpdateGroupSet",
                    &name,
                    &published,
                ));
            }
            conditions.push(published);
        }
        let published = UpdateGroupSetStatus {
            observed_generation: set.metadata.generation,
            member_count: Some(status.member_count as u32),
            max_concurrent: Some(status.max_concurrent as u32),
            rolling_count: Some(status.rolling.len() as u32),
            rolling: status.rolling.clone(),
            settled: status.settled.clone(),
            failed: status.failed.clone(),
            unobservable: status.unobservable.clone(),
            shared: status.shared.clone(),
            emergency: status.emergency.clone(),
            // Emit the explicit bool, never `None`: the status is applied as a JSON *merge*
            // patch, and a merge that omits `frozen` leaves the previous value in place — so a
            // set that unfreezes (its calendar cleared or window reopened) would keep a stale
            // `frozen: true` forever. Writing `false` overwrites it and the gate reads open.
            frozen: Some(status.frozen),
            // Same merge-patch reasoning as `frozen`: write the explicit bool so a set that
            // re-gates (a new approved window added after exhaustion) clears a stale `true`.
            calendar_exhausted: Some(status.calendar_exhausted),
            halted: status.halted.clone(),
            conditions: crate::alerts::merge_conditions(previous, conditions),
        };
        if !status_unchanged(&published, last) {
            sets.patch_status(
                &name,
                &params,
                &Patch::Merge(serde_json::json!({"status": published})),
            )
            .await?;
        }
        if let Some(sink) = alerts {
            sink.spawn(fired_events);
        }
    }
    Ok(())
}

/// A `Ready` [`ResourceCondition`] for `generation`, reporting success (`status: "True"`) or
/// failure (`status: "False"`). The single place a Ready condition's fields are assembled;
/// [`ready_condition`] and [`failed_condition`] are the two named entry points.
/// Alert constructors and subscriptions use the same [`crate::status_contract::condition`]
/// assembler with their explicit observation clocks; this wrapper supplies the status writer's
/// current clock and is not a second condition shape.
///
/// The stamped time is this OBSERVATION's, which is not what the field means, so a condition built
/// here is never written as it stands: every writer merges its array through
/// [`crate::alerts::merge_conditions`], which replaces the stamp with the previous one whenever the
/// status did not change. Writing the fresh stamp made the patched document differ on every pass —
/// an etcd write and a watch event per custom resource per second on a completely idle fleet.
pub(crate) fn condition(
    condition_type: &str,
    ok: bool,
    generation: Option<i64>,
    reason: &str,
    message: &str,
) -> ResourceCondition {
    crate::status_contract::condition(
        condition_type,
        ok,
        generation,
        reason,
        message,
        chrono::Utc::now().to_rfc3339(),
    )
}

/// Whether applying a computed status as an RFC 7386 JSON merge patch would leave the resource's
/// observed status unchanged, in which case the API write is skipped.
///
/// The loop recomputes every status once per second for every resource, so an unconditional patch is
/// an apiserver round trip per resource per second on a fleet where nothing is happening — the same
/// discipline `record_reconcile_failing` converges to its own condition, and the reason every writer's
/// conditions array is stabilized by [`crate::alerts::merge_conditions`] first. Compared as the JSON
/// merge EFFECT, not as whole serialized structs: omitted fields survive a merge patch, so a partial
/// failure status can be a no-op even though it deliberately does not repeat the last successful
/// publication's fields.
pub(crate) fn status_unchanged<T: serde::Serialize>(next: &T, observed: Option<&T>) -> bool {
    let Some(observed) = observed else {
        return false;
    };
    match (serde_json::to_value(next), serde_json::to_value(observed)) {
        (Ok(next), Ok(observed)) => merge_patch_unchanged(&next, &observed),
        _ => false,
    }
}

/// Compare one RFC 7386 merge patch with its target without materializing a second document.
/// Objects merge recursively, `null` deletes a member, and every other value (arrays included)
/// replaces its target wholesale. A typed Kubernetes status cannot distinguish an absent optional
/// field from an explicit `null` after deserialization, so those two wire shapes are treated as
/// semantically equal; a stale non-null value still makes the delete a required change.
fn merge_patch_unchanged(patch: &serde_json::Value, target: &serde_json::Value) -> bool {
    let serde_json::Value::Object(patch) = patch else {
        return patch == target;
    };
    let serde_json::Value::Object(target) = target else {
        return false;
    };
    patch.iter().all(|(key, value)| {
        if value.is_null() {
            return target.get(key).is_none_or(serde_json::Value::is_null);
        }
        target
            .get(key)
            .is_some_and(|observed| merge_patch_unchanged(value, observed))
    })
}

/// Whether this repository's trust anchor is being kept fresh, reported unconditionally alongside
/// `Ready`. A root renewal that fails deliberately does not stop content publication (see
/// [`renew_expiring_root`]), so without a condition of its own the only symptom would be the root
/// silently marching to its hard expiry — at which point every agent's metadata refresh fails at
/// once, and nothing recovers from inside the loop.
pub(crate) fn root_renewal_condition(
    generation: Option<i64>,
    failure: Option<&str>,
) -> ResourceCondition {
    condition(
        crate::status_contract::ROOT_RENEWAL_CONDITION,
        failure.is_none(),
        generation,
        if failure.is_some() {
            "RenewalFailed"
        } else {
            "Current"
        },
        failure.unwrap_or("The TUF root is signed and outside its renewal window."),
    )
}

pub(crate) fn ready_condition(
    generation: Option<i64>,
    reason: &str,
    message: &str,
) -> ResourceCondition {
    condition(
        crate::status_contract::READY_CONDITION,
        true,
        generation,
        reason,
        message,
    )
}

pub(crate) fn failed_condition(
    generation: Option<i64>,
    reason: &str,
    message: &str,
) -> ResourceCondition {
    condition(
        crate::status_contract::READY_CONDITION,
        false,
        generation,
        reason,
        message,
    )
}

/// The `ReleaseAdmission` condition, which this writer speaks for on EVERY pass — including the
/// pass on which `spec.admissionPolicyRef` is cleared and there is no policy left to consult.
/// [`crate::alerts::merge_conditions`] carries forward every condition the writer does not emit, so
/// a writer that fell silent when admission was disabled pinned the last verdict — `False`, naming a
/// policy object that no longer exists — on the repository and every group for ever, with no writer
/// able to clear it and `status_unchanged` suppressing any further write. An explicit
/// `PolicyDisabled` entry is the same discipline the merge-patch fields already use.
pub(crate) fn admission_condition(
    evaluation: &crate::admission::AdmissionEvaluation,
    generation: Option<i64>,
    deployment: &crate::DesiredDeployment,
) -> ResourceCondition {
    // One spelling of the condition type, for both outcomes: this constructor is where
    // `ReleaseAdmission` is named by the same status vocabulary every condition producer and
    // exact consumer imports; no writer gets a private spelling of a shared wire type.
    let (allowed, reason, message) = match evaluation.status(deployment) {
        Some(status) => (status.allowed, status.reason, status.message),
        None => (
            true,
            "PolicyDisabled",
            "No UpdateAdmissionPolicy is referenced; releases are not gated.".to_string(),
        ),
    };
    condition(
        crate::status_contract::RELEASE_ADMISSION_CONDITION,
        allowed,
        generation,
        reason,
        &message,
    )
}

/// An [`UpdateGroupStatus`] carrying the generation-scoped fields (matched count, digest,
/// condition). Centralized so the status shape lives in one place instead of being re-stated at
/// every writer.
pub(crate) fn group_generation_status(
    generation: Option<i64>,
    matched_agents: Option<u32>,
    published_digest: Option<String>,
    condition: ResourceCondition,
) -> UpdateGroupStatus {
    UpdateGroupStatus {
        observed_generation: generation,
        matched_agents,
        published_digest,
        held_agents: None,
        conditions: vec![condition],
    }
}

/// Fail a single misconfigured `UpdateGroup`'s own status and log it, so the rest of the
/// repository still publishes. The prior published digest is carried forward; the group simply
/// takes no part in this generation until it is fixed.
pub(crate) async fn quarantine_group(
    groups: &Api<UpdateGroup>,
    group: &UpdateGroup,
    reason: &str,
    message: &str,
) -> Result<(), kube::Error> {
    tracing::warn!(group = %group.name_any(), reason, message, "quarantining UpdateGroup for this generation");
    let observed = group.status.as_ref();
    let mut status = group_generation_status(
        group.metadata.generation,
        None,
        observed.and_then(|status| status.published_digest.clone()),
        failed_condition(group.metadata.generation, reason, message),
    );
    // A merge patch replaces the conditions array wholesale, so this writer speaks only for Ready
    // and carries every other condition forward untouched, with its transition time — the rule
    // `alerts::merge_conditions` owns for every writer. Rewriting the array bare deleted the group's
    // alert conditions, losing their transition times and re-firing their webhooks when the group
    // healed.
    status.conditions = crate::alerts::merge_conditions(
        observed
            .map(|status| status.conditions.as_slice())
            .unwrap_or_default(),
        status.conditions,
    );
    if status_unchanged(&status, observed) {
        return Ok(());
    }
    groups
        .patch_status(
            &group.name_any(),
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({"status": status})),
        )
        .await?;
    Ok(())
}

/// Fail a single misconfigured `UpdateAgent`'s own status and log it, leaving the rest of the
/// fleet to publish. The agent's assignment and enrollment object are withheld until it is
/// fixed; its last reported running state is preserved for observability.
pub(crate) async fn quarantine_agent(
    agents: &Api<UpdateAgent>,
    agent: &UpdateAgent,
    reason: &str,
    message: &str,
) -> Result<(), kube::Error> {
    tracing::warn!(agent = %agent.name_any(), reason, message, "quarantining UpdateAgent for this generation");
    let prior = agent.status.as_ref();
    let status = UpdateAgentStatus {
        observed_generation: agent.metadata.generation,
        selected_group: None,
        assignment_path: None,
        published_digest: prior.and_then(|status| status.published_digest.clone()),
        assignment_sha256: None,
        enrollment_object_key: None,
        reported_version: prior.and_then(|status| status.reported_version.clone()),
        reported_ready: prior.and_then(|status| status.reported_ready),
        last_reconciliation: prior.and_then(|status| status.last_reconciliation.clone()),
        held: Some(agent.spec.hold),
        cordoned: Some(agent.spec.cordon),
        // Same wholesale-replacement rule as `quarantine_group`: speak for Ready alone, carry
        // every foreign condition forward.
        conditions: crate::alerts::merge_conditions(
            prior
                .map(|status| status.conditions.as_slice())
                .unwrap_or_default(),
            vec![failed_condition(agent.metadata.generation, reason, message)],
        ),
    };
    if status_unchanged(&status, prior) {
        return Ok(());
    }
    agents
        .patch_status(
            &agent.name_any(),
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({"status": status})),
        )
        .await?;
    Ok(())
}

/// The three custom-resource API handles the reconcile loop threads together when writing back
/// status. Bundled so the status-publishing helpers take one handle instead of three positional
/// arguments.
pub(crate) struct ResourceApis<'a> {
    pub(crate) repositories: &'a Api<UpdateRepository>,
    pub(crate) groups: &'a Api<UpdateGroup>,
    pub(crate) agents: &'a Api<UpdateAgent>,
}

pub(crate) struct StatusSnapshot<'a> {
    pub(crate) repository: &'a UpdateRepository,
    pub(crate) storage_ownership: RepositoryStorageOwnership,
    /// SHA-256 of the `root.json` this publisher signs with, recorded into the repository's status
    /// so enrollment can pin the store-served root against a value only the control plane writes.
    ///
    /// Already resolved by the caller — the digest this pass read, else the one the status already
    /// carries — and written here exactly as given. Re-deriving the fallback inside this writer made
    /// the value it WRITES a second definition of the value enrollment PINS against, which the whole
    /// ordering below depends on being one.
    pub(crate) routing_root_sha256: Option<String>,
    /// Why this pass could not renew the TUF root, when it tried and failed. Carried into the
    /// repository's status because the failure is deliberately not fatal: publication continues and
    /// this condition is the only thing that tells the operator the trust anchor is going stale.
    pub(crate) root_renewal_failure: Option<String>,
    pub(crate) groups: &'a [UpdateGroup],
    pub(crate) agents: &'a [Arc<UpdateAgent>],
    pub(crate) plan: &'a crate::PublicationPlan,
    pub(crate) reports: &'a HashMap<String, Envelope>,
    /// Each group's verdict for this generation as the rollout planner decided it — the single
    /// source for whether a group is held, rolling, settled, or unobservable.
    pub(crate) group_progress: &'a BTreeMap<String, crate::rollout::GroupProgress>,
    pub(crate) public_keys: &'a HashMap<String, P256PublicKey>,
    /// The pass's verified reports. Status projects what planning already established; it does not
    /// re-establish it. Before this, writing a status re-verified every agent's signature — a
    /// second full pass of the most expensive work the controller does, over the identical bytes
    /// the planner had just checked.
    pub(crate) verified: &'a crate::evidence::VerifiedReports,
    /// Per-group node accounting from the planner, for the alert conditions and the `heldAgents`
    /// projection.
    pub(crate) node_counts: &'a BTreeMap<String, crate::rollout::GroupNodes>,
    /// Groups bound by the regression verdict, for the per-group `DeploymentHalted` condition —
    /// the one place a halted SET-LESS group is operator-visible.
    pub(crate) halted_groups: &'a BTreeMap<String, crate::HaltedDeployment>,
    /// The one external-admission verdict used by planning this generation; status projects this
    /// exact object rather than calling Draupnir or re-deriving policy.
    pub(crate) admission: &'a crate::admission::AdmissionEvaluation,
    /// Manual-agent name to the exact repository-relative enrollment object published this pass.
    pub(crate) enrollment_objects: &'a BTreeMap<String, String>,
    pub(crate) now: chrono::DateTime<chrono::Utc>,
}

/// The `stuckAfterSeconds` governing a group: the tightest value among the sets whose selectors
/// claim it, else the default. A group in no set still gets the default — a stuck rollout is worth
/// naming whether or not a set throttles it.
pub(crate) fn stuck_after_seconds(sets: &[UpdateGroupSet], group: &UpdateGroup) -> u64 {
    sets.iter()
        .filter(|set| crate::selector_matches(&set.spec.selector.match_labels, group.labels()))
        .filter_map(|set| set.spec.stuck_after_seconds)
        .min()
        .unwrap_or(crate::alerts::DEFAULT_STUCK_AFTER_SECONDS)
}

pub(crate) async fn publish_resource_statuses(
    apis: ResourceApis<'_>,
    snapshot: StatusSnapshot<'_>,
    sets: &[UpdateGroupSet],
    progress_marks: &mut crate::alerts::ProgressTracker,
    alerts: Option<&Arc<crate::alerts::AlertSink>>,
) -> Result<(), kube::Error> {
    let ResourceApis {
        repositories,
        groups,
        agents,
    } = apis;
    let StatusSnapshot {
        repository,
        storage_ownership,
        routing_root_sha256,
        root_renewal_failure,
        groups: group_resources,
        agents: agent_resources,
        plan,
        reports,
        group_progress,
        public_keys,
        verified,
        node_counts,
        halted_groups,
        admission,
        enrollment_objects,
        now,
    } = snapshot;
    // The stuck clock only tracks groups that still exist; a deleted group's mark must not linger.
    progress_marks.retain(|name| group_progress.contains_key(name));
    let params = PatchParams::default();
    let repository_generation = repository.metadata.generation;
    let previous = repository
        .status
        .as_ref()
        .map(|status| status.conditions.as_slice())
        .unwrap_or_default();
    let mut repository_conditions = vec![
        ready_condition(
            repository_generation,
            "Published",
            "The complete routing generation is published.",
        ),
        enrollment_capacity_condition(repository_generation, agent_resources.len()),
        root_renewal_condition(repository_generation, root_renewal_failure.as_deref()),
    ];
    // The `Err` arm is unreachable, and must stay that way: planning converts this same spec first
    // (`domain::plan_reconcile`) and fails the whole pass on `PlanError::InvalidDeployment`, so a
    // repository that reaches this writer has a convertible default. That matters because falling
    // silent here does not clear `ReleaseAdmission` — `merge_conditions` carries the last verdict
    // forward — so a reachable failure would strand it exactly as a disabled policy once did.
    if let Ok(default) =
        crate::DesiredDeployment::try_from(repository.spec.default_deployment.clone())
    {
        // Pushed raw: the `merge_conditions` below carries every entry's transition time forward
        // against this same `previous` slice. Carrying it here first as well was a no-op — the
        // second application re-copies the timestamp the first one copied — and the one reason to
        // carry early, the `fired` flag the alertable block uses, is discarded on this path.
        repository_conditions.push(admission_condition(
            admission,
            repository_generation,
            &default,
        ));
    }
    // The default cohort's halt, projected where its operator can see it. The planner keys the
    // repository default's entry under the reserved `DEFAULT_GROUP` name (no real UpdateGroup may
    // hold it), because the machines it freezes have no group and no set to carry a status: with
    // `spec.defaultDeployment` halted, the fleet-wide switch stops moving while the repository
    // otherwise reports Ready/Published and nothing anywhere names the body or its evidence. Built
    // by the one halt builder every other cohort uses, so the condition reads identically wherever
    // it appears, and carried early for the same reason the group's alertable block does: the
    // `fired` flag is what reaches the webhook.
    let default_halt = halted_groups
        .get(crate::DEFAULT_GROUP)
        .map(std::slice::from_ref)
        .unwrap_or(&[]);
    let (halted_condition, halt_fired) = crate::alerts::carry_transition(
        crate::alerts::existing(
            previous,
            crate::status_contract::DEPLOYMENT_HALTED_CONDITION,
        ),
        crate::alerts::deployment_halted(repository_generation, default_halt, now),
    );
    repository_conditions.push(halted_condition.clone());
    let repository_status = UpdateRepositoryStatus {
        observed_generation: repository_generation,
        published_digest: Some(plan.digest.clone()),
        agent_count: Some(agent_resources.len() as u32),
        routing_root_sha256,
        storage_ownership: Some(storage_ownership),
        conditions: crate::alerts::merge_conditions(previous, repository_conditions),
    };
    if !status_unchanged(&repository_status, repository.status.as_ref()) {
        repositories
            .patch_status(
                &repository.name_any(),
                &params,
                &Patch::Merge(serde_json::json!({"status": repository_status})),
            )
            .await?;
    }
    // Enqueued once the condition is durably written, exactly as the group loop does.
    if let (Some(sink), true) = (alerts, halt_fired) {
        sink.spawn(vec![crate::alerts::AlertEvent::from_condition(
            "UpdateRepository",
            &repository.name_any(),
            &halted_condition,
        )]);
    }

    for group in group_resources {
        let name = group.name_any();
        let matched = plan
            .node_groups
            .values()
            .filter(|selected| *selected == &name)
            .count();
        // The verdict is the planner's, never re-derived here. Deciding it locally — `previous` for
        // "rolling" and a deployment-NAME comparison for "held" — reported a group Ready while a
        // change to its digest, arguments, or resolved inputs was still unadmitted, because the
        // planner deliberately compares the whole desired deployment and this did not.
        // Every group reaching here has a verdict: `reconcile_once` retained `group_resources` to
        // exactly the non-quarantined groups, and the planner decides one for every planned group
        // — a group waiting on its inputs or a prerequisite is classified `Held`, not omitted. A
        // group with none is one this pass cannot speak for, so its status is left as it stands
        // rather than given a locally invented verdict.
        let Some(progress) = group_progress.get(&name).copied() else {
            continue;
        };
        let condition = match progress {
            crate::rollout::GroupProgress::Held => failed_condition(
                group.metadata.generation,
                "Held",
                "This group's desired deployment is waiting for rollout capacity, a rollout \
                 window, its inputs, or a prerequisite group.",
            ),
            crate::rollout::GroupProgress::Rolling => failed_condition(
                group.metadata.generation,
                "Rolling",
                "This group is incrementally advancing to its admitted deployment.",
            ),
            // Frozen, not advancing. Distinct from `Rolling` because the remedy is different and
            // the wait is unbounded: nothing moves onto this deployment until the halt clears or the
            // operator publishes different bytes. The `DeploymentHalted` condition beside this one
            // names the body and the evidence.
            crate::rollout::GroupProgress::Blocked => failed_condition(
                group.metadata.generation,
                "Blocked",
                "No node may move onto this group's admitted deployment: its identity is halted by \
                 the fleet-wide regression verdict or refused by a compliance block. See the \
                 DeploymentHalted condition for the body and the evidence.",
            ),
            crate::rollout::GroupProgress::Settled => ready_condition(
                group.metadata.generation,
                "Published",
                "This group's deployment is fully admitted in the published routing generation.",
            ),
            // The rollout is over and it FAILED: this group's nodes attempted the admitted
            // deployment and durably rejected it, and nothing is still moving toward it. NOT ready
            // — the operator's change is not live and never will be under these bytes — and a
            // distinct reason from `Rolling`, because nothing here is advancing and waiting changes
            // nothing. The exit is a deployment with a different identity.
            crate::rollout::GroupProgress::Failed => failed_condition(
                group.metadata.generation,
                crate::status_contract::REJECTED_REASON,
                "This group's nodes attempted its admitted deployment and durably rejected it, \
                 rolling back to what they were running; the rollout has ended. Publish corrected \
                 bytes (a new digest) to move this group.",
            ),
            // Published in full, but nothing can confirm it: every agent this group selects was
            // provisioned offline (no pinned key) or it selects none at all. Ready — it is not
            // waiting on anything — but the reason says what the claim rests on.
            crate::rollout::GroupProgress::Unobservable => ready_condition(
                group.metadata.generation,
                "PublishedUnobservable",
                "This group's deployment is published to every agent it selects, but none of them \
                 can report telemetry, so its health is unconfirmed.",
            ),
        };
        let mut status = group_generation_status(
            group.metadata.generation,
            Some(matched as u32),
            Some(plan.digest.clone()),
            condition,
        );
        let counts = node_counts.get(&name).cloned().unwrap_or_default();
        // A forgotten hold must be a visible condition, not a mystery: the count of this group's
        // held agents rides its status every pass, taken from the planner's own membership (the
        // group this pass's labels select) and never re-derived here. Keying it on the PUBLISHED
        // routing instead attributed the hold to whichever group the node was last published under:
        // a held node is skipped by `assign_nodes` and carried forward on its previous routing, so
        // relabelling one left the group whose rollout the hold actually wedges reporting zero.
        status.held_agents = Some(counts.held as u32);
        // The alertable conditions, appended beside Ready every pass and cleared the same way —
        // standard condition semantics, never deleted. Each is a projection of a verdict computed
        // above (the planner's progress, the freshness counts admission already read); no new
        // detection logic lives here. The previous value is read off the resource itself, so a
        // transition time survives a leader change and only genuine flips reach the webhook.
        let previous = group
            .status
            .as_ref()
            .map(|status| status.conditions.as_slice())
            .unwrap_or_default();
        // Unreachable `Err`, for the same reason as the repository default above: a group whose
        // deployment does not convert is quarantined at `reconcile_once` and dropped from
        // `group_resources`, and one that is here has a planner verdict. If it ever became
        // reachable it would be a silent strand, not a missing condition — the merge carries the
        // last `ReleaseAdmission` forward, and no other writer can clear it.
        if let Ok(deployment) = crate::DesiredDeployment::try_from(group.spec.deployment.clone()) {
            // Raw, like the repository's: the `merge_conditions` at the end of this loop carries
            // it against the same `previous`, so carrying it here as well only did that twice.
            status.conditions.push(admission_condition(
                admission,
                group.metadata.generation,
                &deployment,
            ));
        }
        let progressed_at =
            progress_marks.observe(&name, counts.target.clone(), counts.on_target, now);
        // A halted group's own status carries the verdict — the fleet-wide halt binds set-less
        // groups too, and a freeze with no visible cause is not a control.
        let bound = halted_groups
            .get(&name)
            .map(std::slice::from_ref)
            .unwrap_or(&[]);
        let alertable = [
            crate::alerts::rollout_stuck(
                group.metadata.generation,
                progress.is_advancing(),
                progressed_at,
                stuck_after_seconds(sets, group),
                now,
            ),
            crate::alerts::reports_stale(
                group.metadata.generation,
                counts.fresh,
                counts.observable,
                group.spec.max_unavailable.unwrap_or(1),
                now,
            ),
            crate::alerts::deployment_halted(group.metadata.generation, bound, now),
        ];
        let mut fired_events = Vec::new();
        for next in alertable {
            let condition_type = next.condition_type.clone();
            let (published, fired) = crate::alerts::carry_transition(
                crate::alerts::existing(previous, &condition_type),
                next,
            );
            if fired {
                fired_events.push(crate::alerts::AlertEvent::from_condition(
                    "UpdateGroup",
                    &name,
                    &published,
                ));
            }
            status.conditions.push(published);
        }
        // Ready is carried here too — the alertable entries already are, individually, for their
        // `fired` flags — so a group whose verdict has not changed produces the document it already
        // has, and the write below is skipped rather than restamping every group once a second.
        status.conditions = crate::alerts::merge_conditions(previous, status.conditions);
        if !status_unchanged(&status, group.status.as_ref()) {
            groups
                .patch_status(
                    &name,
                    &params,
                    &Patch::Merge(serde_json::json!({"status": status})),
                )
                .await?;
        }
        // Enqueued the moment the condition is durably written, never later: transitions that
        // waited for the whole projection were silently lost when a later stage failed, and the
        // edge trigger meant they never re-fired.
        if let Some(sink) = alerts {
            sink.spawn(fired_events);
        }
    }

    for agent in agent_resources {
        let name = agent.name_any();
        // A node withheld from this generation (its group is quarantined, or awaiting its first
        // admission) is not in `plan.node_groups`, and no assignment target was signed for it.
        let selected = plan.node_groups.get(&name).cloned();
        // So it must not claim one. Reporting `Ready=True`/`Published` with a concrete
        // assignmentPath here showed a withheld agent as healthy and published while its machine's
        // TUF fetch of that exact target 404s forever, and left the operator no signal at all that
        // it is blocked on a quarantined group. The published fields are omitted with the same
        // discipline a failed reconcile omits them (see [`UpdateRepositoryStatus`]): a claim only a
        // published assignment can make is not made.
        let assignment_sha256 = plan.node_assignments.get(&name).cloned();
        let fully_published = selected.is_some() && assignment_sha256.is_some();
        let (assignment_path, published_digest, condition) = if fully_published {
            (
                Some(updated_contracts::telemetry::assignment_object_key(
                    &repository.spec.assignment_prefix,
                    &name,
                )),
                Some(plan.digest.clone()),
                ready_condition(
                    agent.metadata.generation,
                    "Published",
                    "This agent's exact assignment and its signed private-input commitment are published.",
                ),
            )
        } else if selected.is_none() {
            (
                None,
                None,
                failed_condition(
                    agent.metadata.generation,
                    "Withheld",
                    "This agent is not routed in the published generation: its group is waiting \
                     for rollout capacity, a rollout window, its inputs, or a prerequisite group, \
                     or it is held out of admission entirely.",
                ),
            )
        } else {
            (
                None,
                None,
                failed_condition(
                    agent.metadata.generation,
                    "AssignmentUnavailable",
                    "This agent's publication is incomplete because it has no signed assignment.",
                ),
            )
        };
        // The gate returns the report only when it is authentic, so a status can never be written
        // from an unverified envelope: there is no report value to read unless verification
        // succeeded. It reads the pass's one verification rather than performing a second.
        let report = public_keys.get(&name).and_then(|key| {
            let now_ms = now.timestamp_millis().max(0) as u64;
            reports
                .get(&name)
                .and_then(|envelope| verified.fresh(&name, envelope, key, now_ms))
        });
        let status = UpdateAgentStatus {
            observed_generation: agent.metadata.generation,
            selected_group: selected,
            assignment_path,
            published_digest,
            assignment_sha256: if fully_published {
                assignment_sha256
            } else {
                None
            },
            reported_version: report
                .as_ref()
                .map(|report| report.version.clone())
                .filter(|version| !version.is_empty()),
            reported_ready: report.as_ref().map(|report| report.healthy),
            last_reconciliation: report
                .as_ref()
                .and_then(|report| report.reconciliation.as_ref())
                .map(crate::ReconciliationStatus::from),
            // Explicit bools, never omitted: this status is a merge patch, and omitting the field
            // would leave a cleared hold or cordon reading `true` forever.
            held: Some(agent.spec.hold),
            cordoned: Some(agent.spec.cordon),
            enrollment_object_key: enrollment_objects.get(&name).cloned(),
            conditions: crate::alerts::merge_conditions(
                agent
                    .status
                    .as_ref()
                    .map(|status| status.conditions.as_slice())
                    .unwrap_or_default(),
                vec![condition],
            ),
        };
        if !status_unchanged(&status, agent.status.as_ref()) {
            agents
                .patch_status(
                    &name,
                    &params,
                    &Patch::Merge(serde_json::json!({"status": status})),
                )
                .await?;
        }
    }
    Ok(())
}

/// A GENERIC, categorized failure message safe to write into the `UpdateRepository` `.status`,
/// which anyone with `get` on the CR can read. The underlying `object_store`/`kube` error can carry
/// infrastructure detail (bucket, endpoint, object key), so it must NEVER be serialized into status
/// — the caller logs the full `error` at error-level for operators and writes only this category
/// here. Downcast is best-effort; anything unrecognized maps to the fully generic bucket.
pub fn generic_failure_status(
    error: &(dyn std::error::Error + 'static),
) -> std::borrow::Cow<'static, str> {
    if let Some(crate::PlanError::ReleasePreflight { node, message }) =
        error.downcast_ref::<crate::PlanError>()
    {
        return format!("rollout preflight blocked for {node}: {message}").into();
    }
    let message = if error.is::<kube::Error>() {
        "reconciliation failed: kubernetes API error (see controller logs)"
    } else if error.is::<StorageError>() {
        "reconciliation failed: repository storage error (see controller logs)"
    } else if error.is::<std::io::Error>() {
        "reconciliation failed: local state error (see controller logs)"
    } else if error.is::<serde_json::Error>() {
        "reconciliation failed: serialization error (see controller logs)"
    } else {
        "reconciliation failed (see controller logs)"
    };
    message.into()
}

/// Write a failure to the `UpdateRepository` `.status`. `message` MUST be a generic, non-sensitive
/// string (see [`generic_failure_status`]); the full error belongs only in the controller log.
pub async fn record_repository_failure(
    client: Client,
    namespace: &str,
    repository_name: &str,
    message: &str,
) -> Result<(), kube::Error> {
    let repositories: Api<UpdateRepository> = Api::namespaced(client, namespace);
    let repository = repositories.get(repository_name).await?;
    let observed = repository
        .status
        .as_ref()
        .map(|status| status.conditions.as_slice())
        .unwrap_or_default();
    let status = failure_status(repository.metadata.generation, message, observed);
    if status_unchanged(&status, repository.status.as_ref()) {
        return Ok(());
    }
    repositories
        .patch_status(
            repository_name,
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({"status": status})),
        )
        .await?;
    Ok(())
}

/// Record a failed pass against every `UpdateGroupSet`: bump the failure streak and write the
/// `ReconcileFailing` condition, which rises on CONSECUTIVE failures (one failed pass is an
/// ordinary transient the next second retries). Called from the loop's failure branch, where
/// `publish_group_set_statuses` — the success-path writer of the same condition — never runs; the
/// conditions array is patched alone, with every foreign condition carried forward, so a failing
/// loop can still raise the one condition that says so. Transitions go to the same webhook sink.
pub async fn record_reconcile_failing(
    client: Client,
    namespace: &str,
    hooks: &mut ReconcileHooks,
) -> Result<(), kube::Error> {
    hooks.consecutive_failures = hooks.consecutive_failures.saturating_add(1);
    let sets: Api<UpdateGroupSet> = Api::namespaced(client, namespace);
    for set in sets.list(&ListParams::default()).await? {
        let name = set.name_any();
        let observed = set
            .status
            .as_ref()
            .map(|status| status.conditions.as_slice())
            .unwrap_or_default();
        let next = crate::alerts::reconcile_failing(
            set.metadata.generation,
            hooks.consecutive_failures,
            chrono::Utc::now(),
        );
        let (published, fired) = crate::alerts::carry_transition(
            crate::alerts::existing(
                observed,
                crate::status_contract::RECONCILE_FAILING_CONDITION,
            ),
            next,
        );
        // The condition's message is streak-independent, so once it has stabilized every further
        // failed pass would patch an identical document: skip the write — a failing loop must not
        // also be an apiserver write per set per second.
        if !fired
            && crate::alerts::existing(
                observed,
                crate::status_contract::RECONCILE_FAILING_CONDITION,
            ) == Some(&published)
        {
            continue;
        }
        let event = crate::alerts::AlertEvent::from_condition("UpdateGroupSet", &name, &published);
        // A merge patch replaces the conditions array wholesale, so every condition this writer
        // does not speak for is carried forward untouched — assembled where every other status
        // writer assembles it, so this path (the one that runs when the loop is broken) cannot
        // drift from the rule. Passing `published` back through the merge re-converges
        // `carry_transition` against the same `observed`, which is a no-op on it.
        let conditions = crate::alerts::merge_conditions(observed, vec![published]);
        sets.patch_status(
            &name,
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({"status": {"conditions": conditions}})),
        )
        .await?;
        // Enqueued per set, after ITS durable write: a later set's failed patch must not lose an
        // earlier set's already-recorded transition.
        if fired {
            if let Some(sink) = &hooks.alerts {
                sink.spawn(vec![event]);
            }
        }
    }
    Ok(())
}

/// The status document a failed reconcile patches in. A failure observes the generation and nothing
/// else: the published digest, the agent count, the trust anchor, and the controller-bound storage
/// scope are all claims a failure cannot replace, so they are omitted and the last successful
/// reconcile's values survive the merge patch (see [`UpdateRepositoryStatus`]). Pure, so that
/// omission is testable —
/// sending `null` for the agent count deleted the field `gateway::at_enrollment_capacity` reads,
/// which silently uncapped enrollment for as long as the failure lasted.
///
/// `observed` is the conditions array the repository currently carries. A merge patch REPLACES an
/// array wholesale, so the same omission rule converges to the entries of this one: a failure speaks
/// only for [`crate::status_contract::READY_CONDITION`] and carries every other condition forward
/// untouched, which is what [`crate::alerts::merge_conditions`] does for every writer. Rewriting
/// the array with just its own
/// entry deleted `EnrollmentCapacity` — the only operator-visible sign that `/enroll` is at its
/// ceiling — for the entire duration of any reconcile failure. The merge also keeps the failure's
/// own transition time, so a loop that stays down patches a document identical to the stored one
/// instead of an etcd write per second.
pub(crate) fn failure_status(
    generation: Option<i64>,
    message: &str,
    observed: &[ResourceCondition],
) -> UpdateRepositoryStatus {
    UpdateRepositoryStatus {
        observed_generation: generation,
        published_digest: None,
        agent_count: None,
        routing_root_sha256: None,
        storage_ownership: None,
        conditions: crate::alerts::merge_conditions(
            observed,
            vec![failed_condition(
                generation,
                "ReconciliationFailed",
                message,
            )],
        ),
    }
}

pub(crate) fn desired_publication_digest(
    repository: &crate::UpdateRepositorySpec,
    plan_digest: &str,
) -> Result<String, serde_json::Error> {
    // Admission policy affects which movement is permitted and stateMaxShards affects only the
    // in-cluster durable representation; neither changes bytes in an already-equal publication.
    // Normalize both so operational CRD edits cannot re-sign a no-op TUF generation. Any newly
    // allowed deployment still changes `plan_digest` in the same pass.
    let mut publication_spec = repository.clone();
    publication_spec.admission_policy_ref = None;
    publication_spec.state_max_shards = 0;
    let mut digest = updated_contracts::digest::Sha256Hasher::new();
    digest.update(&serde_json::to_vec(&publication_spec)?);
    digest.update(&[0]);
    digest.update(plan_digest.as_bytes());
    Ok(digest.finish_hex())
}

pub(crate) async fn materialize_signing_keys(
    secret: &Secret,
    directory: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let data = secret.data.as_ref().ok_or("signing Secret has no data")?;
    updated_tuf::repo::validate_complete_signing_key_set(
        data.iter()
            .map(|(name, bytes)| (name.as_str(), bytes.0.as_slice())),
    )
    .map_err(|error| format!("signing Secret contains an invalid key set: {error}"))?;

    let mut material = Vec::with_capacity(updated_tuf::repo::KEY_FILE_NAMES.len());
    for name in updated_tuf::repo::KEY_FILE_NAMES {
        let bytes = data
            .get(name)
            .ok_or_else(|| format!("signing Secret is missing {name}"))?;
        material.push((name, bytes));
    }

    // Validate the complete rotatable set, including every key's cryptographic shape and role
    // separation, before touching disk. A malformed Secret therefore cannot leave a convincing
    // partial key directory for a later path to mistake as initialized. The gate above is the same
    // one file-backed TUF authoring uses; projected and local signing keys cannot drift into
    // separate definitions.
    tokio::fs::create_dir_all(directory).await?;
    for (name, bytes) in material {
        let path = directory.join(name);
        if foundation::file::path_entry_exists(&path)? {
            if read_local_bounded(&path, bytes.0.len()).await? != bytes.0 {
                return Err(format!("signing key {name} changed in place").into());
            }
        } else {
            foundation::durable::atomic_write(&path, ".key-", &bytes.0)?;
        }
    }
    Ok(())
}

/// A Secret entry that may legitimately be absent, unlike [`secret_string`] which requires it.
pub(crate) fn optional_secret_string(
    secret: Option<&Secret>,
    key: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let Some(bytes) = secret
        .and_then(|secret| secret.data.as_ref())
        .and_then(|data| data.get(key))
    else {
        return Ok(None);
    };
    Ok(Some(String::from_utf8(bytes.0.clone())?))
}

pub(crate) fn secret_string(
    secret: Option<&Secret>,
    key: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    secret
        .map(|secret| {
            let bytes = secret
                .data
                .as_ref()
                .and_then(|data| data.get(key))
                .ok_or_else(|| format!("credentials Secret is missing {key}"))?;
            String::from_utf8(bytes.0.clone()).map_err(|e| e.into())
        })
        .transpose()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod merge_patch_tests {
    use super::merge_patch_unchanged;

    #[test]
    fn no_op_detection_follows_merge_patch_semantics_recursively() {
        let target = serde_json::json!({
            "kept": "value",
            "nil": null,
            "nested": { "one": 1, "two": 2 },
            "array": [1, 2],
        });

        assert!(merge_patch_unchanged(
            &serde_json::json!({ "nested": { "one": 1 } }),
            &target,
        ));
        assert!(merge_patch_unchanged(&serde_json::json!({}), &target));
        assert!(!merge_patch_unchanged(
            &serde_json::json!({ "nested": { "one": 3 } }),
            &target,
        ));
        assert!(!merge_patch_unchanged(
            &serde_json::json!({ "array": [1] }),
            &target,
        ));
        assert!(!merge_patch_unchanged(
            &serde_json::json!({ "kept": null }),
            &target,
        ));
        assert!(merge_patch_unchanged(
            &serde_json::json!({ "absent": null }),
            &target,
        ));
        assert!(merge_patch_unchanged(
            &serde_json::json!({ "nil": null }),
            &target,
        ));
    }
}
