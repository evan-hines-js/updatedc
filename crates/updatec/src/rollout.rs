//! Rollout throttling across an [`UpdateGroupSet`](crate::UpdateGroupSet).
//!
//! A set caps how many of its member groups roll at once. The control plane can never
//! reach a node, so "rolling" and "settled" are decided entirely from node telemetry the
//! agents write to shared storage: a member group is *settled* once every agent it
//! selects reports the deployment identity the operator most recently published for that
//! group, healthy. Held-back members keep their last-admitted deployment — the admitted
//! set is persisted durably in-cluster by the operator (see `runtime`), not on node-local
//! disk — so the signed generation pins them until a slot frees, and a leader change or a
//! cold PVC can never re-seed a fresh baseline and mass-admit an entire set at once.
//!
//! Every deployment planned here reports: a [`DesiredDeployment`] enters this crate only as the
//! output of `TryFrom<DeploymentSpec>`, where `reportUrl` is required. There is no
//! telemetry-less rollout path, and nothing below branches as though there were one.
//!
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::{DesiredDeployment, ResolvedGroup, UpdateGroupSet};
use serde::{Deserialize, Serialize};
use updated_contracts::telemetry::{Envelope, NodeReport};

/// Durable group rollout state: the deployment this group is rolling TOWARD, and every deployment
/// its nodes may still be held ON.
///
/// `previous` is a list, most recent first, because a group's nodes are not always spread across
/// only two deployments. Retargeting a rollout that is half-way through leaves nodes on the
/// abandoned `current` as well as on the deployment it was staging away from, and a state that can
/// name only one of them has no way to say "leave that node where it is": every node not on
/// `current` or `previous` got assigned `previous`, so a single retarget reverted every advanced
/// node in one signed generation, `maxUnavailable` and all. Each entry is retired by
/// [`finish_staged_rollouts`] the moment no node is on it, down to the single most recent one that
/// is kept solely to mean "a rollout is still staged", so the list holds the deployments the group
/// is actually running and never accumulates.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct AdmittedDeployment {
    pub current: DesiredDeployment,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub previous: Vec<DesiredDeployment>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RolloutPlan {
    pub sets: Vec<SetStatus>,
    pub node_deployments: BTreeMap<String, DesiredDeployment>,
    /// Every planned group's verdict for this pass, computed once by [`classify`]. The
    /// `UpdateGroupSet` status lists and each `UpdateGroup`'s own status are both projections of
    /// this map — no consumer re-derives "rolling" or "held" from a name comparison of its own.
    pub groups: BTreeMap<String, GroupProgress>,
}

/// What the control plane can say about ONE group relative to what the operator asked for.
///
/// The single answer to "is my change live?", produced by exactly one function ([`classify`]) and
/// read by every consumer: the set status, the group's own Kubernetes status, and the tests.
/// Deciding it independently anywhere else is what let a group whose deployment body changed
/// without a rename report `Ready` while the change was not admitted at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupProgress {
    /// The desired deployment is not the admitted one: it is waiting for a slot, a schedule
    /// window, resolved inputs, or a prerequisite. Whatever is published for this group is NOT
    /// what the operator most recently asked for.
    Held,
    /// The desired deployment is admitted and still arriving: some node has not been handed it, or
    /// some observable node does not yet report it healthy.
    Rolling,
    /// The desired deployment is admitted, has been handed to every node, and every node that can
    /// be observed reports it healthy.
    Settled,
    /// The desired deployment is admitted and fully handed out, but no evidence can ever arrive —
    /// the group selects no agent, or every agent it selects was provisioned offline and has no
    /// pinned key. Never `Settled`, because settlement is evidence, and never `Rolling`, because
    /// nothing is in flight.
    Unobservable,
}

/// Per-set observation the operator publishes as `UpdateGroupSet` status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetStatus {
    pub name: String,
    pub member_count: usize,
    pub max_concurrent: usize,
    pub rolling: Vec<String>,
    pub settled: Vec<String>,
    /// Members no evidence can ever come from — they select no agent, or EVERY agent they select
    /// was provisioned offline and has no pinned public key. They are neither rolling nor settled:
    /// they hold no concurrency slot, and nothing gated on their settling will ever open. A member
    /// with only SOME blind agents is not here: it has a real rollout, staged and throttled like
    /// any other, judged on the agents that can be observed.
    pub unobservable: Vec<String>,
    /// Members also claimed by another set — rolled up safely (admitted only when every
    /// governing set has a slot). The UI shows these as spanning sets, not plain members.
    pub shared: Vec<String>,
    /// Members whose spec declares `emergencyCorrection`: the operator has stated that their
    /// desired deployment is an emergency correction, so it is admitted without waiting for this
    /// set's schedule. Surfaced for as long as the flag is set — an override an operator forgets to
    /// clear must not be invisible.
    pub emergency: Vec<String>,
    /// True when the set is outside its rollout schedule: no new rollout is admitted this pass
    /// (members already rolling keep settling, and a member the operator declared an EMERGENCY
    /// CORRECTION is still admitted — see `admit_pending`). Always false for a set with neither
    /// windows nor a calendar.
    pub frozen: bool,
    /// True when the set's dated calendar has run out — every approved window is in the past, so the
    /// calendar has stopped gating and the set is now ungated at any hour (`window::calendar_open`
    /// fails open). Surfaced so an operator can distinguish "actively inside an approved window"
    /// from "silently expired, now rolling at any time." False for a set with no calendar or one
    /// still active/pending.
    pub calendar_exhausted: bool,
}

/// Everything `plan_rollouts` needs about the current generation, kept separate from
/// Kubernetes types so the core admission logic is pure and unit-testable.
pub struct RolloutInputs<'a> {
    /// Desired member groups by name. Admission never rewrites desired state; its exact result is
    /// returned through `RolloutPlan::node_deployments`.
    pub groups: &'a BTreeMap<String, ResolvedGroup>,
    /// Each group's Kubernetes metadata labels — what a set's selector matches on.
    pub group_labels: &'a BTreeMap<String, BTreeMap<String, String>>,
    /// Node → selected group name, from the publication plan's routing.
    pub node_groups: &'a BTreeMap<String, String>,
    /// Node → its latest self-reported running state.
    pub reports: &'a HashMap<String, Envelope>,
    /// Node → its pinned public key (raw EC point), set at enrollment from the node's CSR. A report
    /// is trusted only if its signature verifies against this key, so rollout decisions act on
    /// end-to-end evidence (node → planner), not gateway write-hop authentication. A node with no
    /// pinned key is [`NodeEvidence::Blind`]: nothing it writes is evidence, now or ever.
    pub public_keys: &'a HashMap<String, Vec<u8>>,
    /// Node → the deployment identity the LAST signed generation published for it, from the durable
    /// rollout state. A node that has already been handed `current` is never demoted back to the
    /// predecessor because it went quiet (rebooting to apply the very update it was handed is the
    /// ordinary case), so a node's assignment only ever moves forward within a rollout. It is also
    /// the only way a blind node can be staged at all: it produces no telemetry, so "has it been
    /// moved yet" can only be answered by what was published to it.
    pub published: &'a BTreeMap<String, String>,
    /// Groups quarantined by validation this pass, with the deployment each is still pinned to.
    ///
    /// They are deliberately NOT planned here — a quarantined group has no usable spec to plan
    /// from — but the control plane is still holding their nodes on these deployments, so the
    /// deployments are running in the fleet. `assign_nodes` needs them for exactly that: a node
    /// relabelled OUT of a quarantined group (the documented remediation) arrives in its new group
    /// running one of them, and a group that cannot recognize where that node is hands it a
    /// backward move no `maxUnavailable` budget is checked against.
    pub held: &'a BTreeMap<String, HeldGroup>,
}

/// A group quarantined by validation this pass: the deployment it is still pinned to, plus the
/// selector that says which agents are ITS agents.
///
/// The selector is carried because quarantine must not change where a node belongs. A group absent
/// from the plan makes its nodes resolve to the `default` pseudo-group, and an agent enrolled while
/// the group is broken has no previous routing to be carried forward on — so without the selector it
/// was published with the repository's fleet-wide `default_deployment`, which is exactly the ungated
/// deployment swap quarantine exists to prevent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldGroup {
    pub state: AdmittedDeployment,
    /// The group's own `spec.selector.matchLabels`. EMPTY means the selector itself is what
    /// quarantined the group, and an empty selector selects NOTHING here — reading it as "matches
    /// every agent" would hold the whole fleet on one broken group's pin.
    pub match_labels: BTreeMap<String, String>,
}

impl HeldGroup {
    /// Whether an agent carrying `labels` belongs to this quarantined group.
    pub(crate) fn selects(&self, labels: &BTreeMap<String, String>) -> bool {
        !self.match_labels.is_empty() && crate::selector_matches(&self.match_labels, labels)
    }
}

/// What is known about ONE node's state relative to one deployment identity.
///
/// This is the single per-node verdict every gate reads. The distinction that matters is between
/// "no evidence right now" and "no evidence ever": a node that has a pinned key but is silent is
/// mid-something and holds a rollout back, while a node with no pinned key (an offline-provisioned
/// `kind: manual` agent) can never produce evidence at all. Reading the second as the first is what
/// let one such node wedge its whole group — permanently rolling, permanently un-updatable, and
/// permanently holding its set's concurrency slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NodeEvidence {
    /// A verified, fresh report says this node is acting on this exact assignment and is healthy.
    Healthy,
    /// A verified, fresh report says this node is acting on this exact assignment and is NOT
    /// healthy. It is already disrupted, which is what makes it the node a staged rollout moves
    /// FIRST: moving something that is already down cannot spend more availability.
    Broken,
    /// This node's reports can be verified and none of them places it on this assignment — it is
    /// elsewhere, its report is stale, or it is not reporting at all. Unknown, so it is counted
    /// unavailable and never moved out of turn.
    Silent,
    /// No report of this node is evidence of anything: it has no pinned key. It is never counted
    /// healthy and never counted unavailable — treating an absence of possible evidence as a
    /// failure spends a group's whole availability budget on a node that can never release it.
    Blind,
}

impl NodeEvidence {
    /// Whether this node counts against the group's `maxUnavailable` budget. Only positively
    /// observed health clears it, and only impossible-to-observe clears it for free: silence is
    /// unavailable (the conservative reading), health is available, and a blind node is neither.
    fn unavailable(self) -> bool {
        matches!(self, Self::Broken | Self::Silent)
    }
}

/// What telemetry can say about a group's progress toward one deployment.
///
/// The three states are kept apart deliberately. Collapsing "cannot be observed" into "still
/// rolling" made a group that can NEVER produce evidence — one that selects no node, or whose
/// nodes are all offline-provisioned and have no pinned key — hold its set's concurrency slot
/// forever and refuse every retarget, with no operator-visible cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Progress {
    /// Every node this group selects that CAN be observed reports this exact deployment, healthy.
    /// Blind nodes are excluded rather than assumed healthy — the status carries them separately so
    /// an operator sees that the claim is "as far as anything can be observed".
    Settled,
    /// Evidence can arrive and has not (yet) shown every observable node healthy on this deployment.
    Rolling,
    /// No evidence can EVER arrive: the group selects no node, every node it selects is blind, or
    /// the deployment cannot be encoded so it has no identity. Never settled — settlement is
    /// evidence — but never in flight either.
    Unobservable,
}

struct Observations<'a> {
    node_groups: &'a BTreeMap<String, String>,
    reports: &'a HashMap<String, Envelope>,
    public_keys: &'a HashMap<String, Vec<u8>>,
    /// Node → the deployment identity the last signed generation handed it.
    published: &'a BTreeMap<String, String>,
    now_ms: u64,
    /// One verification per node per planning pass. `progress` walks every node of a group and is
    /// itself called from admission, set planning, and status building, so an uncached gate costs a
    /// full ECDSA verify per node per call — work an untrusted writer chooses the size of.
    verified: RefCell<HashMap<String, Option<NodeReport>>>,
}

impl<'a> Observations<'a> {
    fn new(
        node_groups: &'a BTreeMap<String, String>,
        reports: &'a HashMap<String, Envelope>,
        public_keys: &'a HashMap<String, Vec<u8>>,
        published: &'a BTreeMap<String, String>,
        now_ms: u64,
    ) -> Self {
        Self {
            node_groups,
            reports,
            public_keys,
            published,
            now_ms,
            verified: RefCell::new(HashMap::new()),
        }
    }

    /// This node's report, or `None` when there is nothing trustworthy to read. The gate returns the
    /// report itself, so an unverified envelope yields no value to inspect rather than a value a caller
    /// might use before checking it. The verdict is memoized for the pass; the inputs cannot change
    /// mid-pass, so a repeat lookup is the same answer at no cryptographic cost.
    fn report(&self, node: &str) -> Option<NodeReport> {
        if let Some(cached) = self.verified.borrow().get(node) {
            return cached.clone();
        }
        let verdict = self.verify(node);
        self.verified
            .borrow_mut()
            .insert(node.to_string(), verdict.clone());
        verdict
    }

    fn verify(&self, node: &str) -> Option<NodeReport> {
        let envelope = self.reports.get(node)?;
        let public_key = self.public_keys.get(node)?;
        updated_contracts::telemetry::report_is_authentic_and_fresh(
            envelope,
            node,
            public_key,
            self.now_ms,
        )
    }

    /// What is known about `node` relative to the exact assignment `identity` names — the digest of
    /// the published configuration document, not the deployment's name. A name says nothing about
    /// which revision of that deployment the node actually has.
    ///
    /// The ONE place a node's evidence is classified. Settlement, the availability budget, and the
    /// status all read this, so "unverifiable", "silent", and "unhealthy" cannot mean three
    /// different things in three places.
    fn evidence(&self, node: &str, identity: &str) -> NodeEvidence {
        if !self.public_keys.contains_key(node) {
            return NodeEvidence::Blind;
        }
        match self.report(node) {
            Some(report) if report.assignment_sha256 == identity => {
                if report.healthy {
                    NodeEvidence::Healthy
                } else {
                    NodeEvidence::Broken
                }
            }
            _ => NodeEvidence::Silent,
        }
    }

    /// The nodes this group selects, in a stable order.
    fn nodes(&self, group: &str) -> Vec<&'a String> {
        self.node_groups
            .iter()
            .filter_map(|(node, selected)| (selected.as_str() == group).then_some(node))
            .collect()
    }

    /// The deployment this node is actually running: what the last signed generation handed it, or
    /// failing that what it reports acting on. `None` for a node nothing is known about — never
    /// published, never reported — which is the only case with no "where it is" to hold it on.
    ///
    /// What was PUBLISHED is preferred over what is REPORTED for the same reason [`advanced`] takes
    /// either: a node that reboots into the update it was just handed goes quiet for longer than
    /// telemetry lives, and republishing what it already has must stay a no-op while it does.
    fn placement(&self, node: &str) -> Option<String> {
        self.published
            .get(node)
            .cloned()
            .or_else(|| self.report(node).map(|report| report.assignment_sha256))
    }

    /// Whether the last signed generation already handed `identity` to this node, or the node
    /// itself reports acting on it. Either one means the node has moved: absence of telemetry is
    /// not evidence of NOT having moved, and it is the only signal a blind node ever has.
    fn advanced(&self, node: &str, identity: &str) -> bool {
        self.published
            .get(node)
            .is_some_and(|last| last == identity)
            || self
                .report(node)
                .is_some_and(|report| report.assignment_sha256 == identity)
    }

    /// How far this group has progressed toward the deployment it is admitted to. The single
    /// classifier every gate reads, so "settled", "still rolling", and "no evidence is possible"
    /// cannot be decided differently in three places.
    fn progress(&self, group: &str, state: &AdmittedDeployment) -> Progress {
        let Some(identity) = crate::deployment_identity(&state.current) else {
            return Progress::Unobservable;
        };
        // Staging comes first, because it is in flight whether or not anything can be observed.
        // `finish_staged_rollouts` retires `previous` at exactly the moment every selected node has
        // been HANDED `current`, so a surviving predecessor means `assign_nodes` is still moving
        // nodes one batch per generation. Judging on telemetry alone reported a mixed group settled
        // — releasing its set's concurrency slot and claiming the rollout was over — as soon as its
        // two observable nodes converged, while fifty blind ones were still being moved.
        //
        // Asked as "has every node this group selects been handed `current`?" rather than as
        // "is `previous` empty?", because `previous` also carries bodies retained purely so a node
        // that left this group mid-rollout can still be held where it is. A body nobody in this
        // group is on is not a rollout in flight, and reading it as one held the group's set
        // concurrency slot for as long as the departed node lived.
        if !state.previous.is_empty() && !self.fully_handed(group, &state.current) {
            return Progress::Rolling;
        }
        let mut observable = false;
        let mut settled = true;
        for node in self.nodes(group) {
            match self.evidence(node, &identity) {
                NodeEvidence::Healthy => observable = true,
                NodeEvidence::Broken | NodeEvidence::Silent => {
                    observable = true;
                    settled = false;
                }
                // Excluded from the verdict entirely, in BOTH directions: a blind node is never
                // counted healthy (it is reported separately so the claim stays honest) and never
                // counted as holding the group back (it can never stop). A group nobody can observe
                // at all — no nodes, or every node blind — is therefore Unobservable.
                NodeEvidence::Blind => {}
            }
        }
        match (observable, settled) {
            (false, _) => Progress::Unobservable,
            (true, true) => Progress::Settled,
            (true, false) => Progress::Rolling,
        }
    }

    /// Whether every node of this group has already been handed `deployment` — the staging question,
    /// answered from what was PUBLISHED rather than from telemetry. A group whose nodes can never be
    /// observed still has a staged rollout, and it still finishes.
    fn fully_handed(&self, group: &str, deployment: &DesiredDeployment) -> bool {
        let Some(identity) = crate::deployment_identity(deployment) else {
            return false;
        };
        self.nodes(group)
            .into_iter()
            .all(|node| self.advanced(node, &identity))
    }

    /// Whether ANY node in the fleet is still placed on `deployment`, whatever group it is in now.
    ///
    /// The single retention rule for deployment BODIES. A node's group is a label, so the machine
    /// running a deployment routinely outlives the group that handed it out: the group is deleted,
    /// or the node is relabelled away mid-rollout. Once the body is gone the control plane cannot
    /// say where that node is, and every fallback for an unaccountable node ends in handing it the
    /// new group's `current` with no `maxUnavailable` staging and no health gate. So a body is
    /// retired on exactly one question — is anyone still on it? — asked of the whole fleet.
    fn placed_anywhere(&self, deployment: &DesiredDeployment) -> bool {
        let Some(identity) = crate::deployment_identity(deployment) else {
            return false;
        };
        self.node_groups
            .keys()
            .any(|node| self.advanced(node, &identity))
    }
}

/// The ONE place a group's verdict is decided, for every consumer. `Held` is the operator-facing
/// question — is the deployment I asked for the admitted one? — answered on the whole
/// `DesiredDeployment`, never on its name: a corrected digest, a changed argument, or a dependency
/// input the control plane itself resolved is a real change nodes must receive, and comparing names
/// reported those groups `Ready` while they were still holding the old configuration.
fn classify(
    name: &str,
    desired: &BTreeMap<String, DesiredDeployment>,
    admitted: &BTreeMap<String, AdmittedDeployment>,
    observations: &Observations<'_>,
) -> GroupProgress {
    match admitted.get(name) {
        Some(state) if desired.get(name) == Some(&state.current) => {
            match observations.progress(name, state) {
                Progress::Settled => GroupProgress::Settled,
                Progress::Rolling => GroupProgress::Rolling,
                Progress::Unobservable => GroupProgress::Unobservable,
            }
        }
        _ => GroupProgress::Held,
    }
}

/// The two independent admission gates a set imposes, each expressed exactly once.
struct SetPlan {
    members: Vec<String>,
    max_concurrent: usize,
    /// Free CONCURRENCY slots: `max_concurrent` minus the members currently rolling. Never
    /// encodes the schedule — see `frozen`.
    slots: usize,
    /// Whether the set is outside its rollout schedule. The single representation of that
    /// condition; every gate that consults the schedule reads this field, so the emergency
    /// waiver in `admit_pending` cannot lift one instance of it and be caught by another.
    frozen: bool,
}

/// Plan group-set admission and exact node assignments. Desired inventory remains immutable;
/// admission changes are written only to `admitted` and the returned node map.
///
/// `admitted` is the durable admitted-set map: group name → the deployment that group is
/// currently pinned to. It is loaded from the in-cluster store before this call and written
/// back after (see `runtime::{load,store}_admitted_state`). Passing state in and out rather
/// than reading node-local disk is the fix for HA leader failover: the admitted baseline is
/// seeded exactly once in a group's lifetime and then survives every leader change and PVC
/// loss, so a fresh leader can never re-baseline every member to the current desired and
/// admit them all at once — the breach of `max_concurrent` that node-local state allowed.
///
/// A group's FIRST admission runs through the same gates as every later one (`admit_pending`):
/// resolved inputs and settled prerequisites. It is exempt only from a set's concurrency slots and
/// schedule, because there is no predecessor to stage away from and nothing yet published to
/// protect. A group that has not been admitted at all publishes nothing for its nodes, and
/// `domain::plan_reconcile` leaves them out of the generation entirely.
pub(crate) fn plan_rollouts(
    sets: &[UpdateGroupSet],
    inputs: RolloutInputs<'_>,
    admitted: &mut BTreeMap<String, AdmittedDeployment>,
    now: chrono::DateTime<chrono::Utc>,
) -> RolloutPlan {
    let RolloutInputs {
        groups,
        group_labels,
        node_groups,
        reports,
        public_keys,
        published,
        held,
    } = inputs;

    let desired: BTreeMap<String, DesiredDeployment> = groups
        .iter()
        .map(|(name, group)| (name.clone(), group.deployment.clone()))
        .collect();
    let observations = Observations::new(
        node_groups,
        reports,
        public_keys,
        published,
        now.timestamp_millis().max(0) as u64,
    );
    // Only pruning happens outside admission. A group is never *seeded* here: first admission runs
    // through `admit_pending` like every later one, so a group's very first published deployment is
    // gated on the same things a retarget is — resolved inputs and settled prerequisites. Seeding
    // here instead would publish a cold cluster's consumer group with empty `runtime.inputs`.
    retire_deleted_groups(admitted, &desired, &observations);
    finish_staged_rollouts(admitted, &desired, &observations);
    let (mut plans, group_plans) =
        build_set_plans(sets, &desired, group_labels, admitted, &observations, now);
    admit_pending(
        groups,
        &desired,
        &group_plans,
        &mut plans,
        admitted,
        &observations,
    );
    // Computed once, after admission, and then only projected: the set status lists below and the
    // per-group Kubernetes status the runtime writes are the same verdicts, not two derivations.
    let group_progress: BTreeMap<String, GroupProgress> = desired
        .keys()
        .map(|name| {
            (
                name.clone(),
                classify(name, &desired, admitted, &observations),
            )
        })
        .collect();
    let emergency: BTreeSet<String> = groups
        .iter()
        .filter(|(_, group)| group.emergency_correction)
        .map(|(name, _)| name.clone())
        .collect();
    let statuses = build_statuses(sets, &plans, &group_plans, &group_progress, &emergency, now);
    let node_deployments = assign_nodes(groups, admitted, held, &observations);
    RolloutPlan {
        sets: statuses,
        node_deployments,
        groups: group_progress,
    }
}

/// Retire the predecessors of every rollout whose staging is finished, and the individual ones no
/// node is left on.
///
/// A predecessor exists for exactly one purpose: to be the deployment that the nodes NOT YET handed
/// `current` keep running while the rollout moves them one `maxUnavailable` batch at a time. It is
/// therefore retired on the staging question — has every selected node been handed `current`? —
/// which is answered from what was published, not from telemetry.
///
/// Deciding this on telemetry instead was the wedge in both directions. Requiring evidence of
/// health held the predecessor forever for a group that can produce none. Retiring it whenever the
/// group stopped being observable did the opposite and worse: `assign_nodes` takes the
/// no-predecessor path when it is absent and hands `current` to EVERY node in one generation, so a
/// group that lost its pinned keys mid-rollout silently turned a throttled rollout into an
/// unthrottled fleet-wide swap. Staging is a property of publication, so it is decided on
/// publication and applies to every generation change, rollbacks included.
/// Keep the admitted entry of a group the operator DELETED for exactly as long as some node is
/// still placed on one of its deployments, compacted to those deployments alone.
///
/// A deleted group stops being planned immediately, but its deployment is still what its former
/// nodes are RUNNING — they are relabelled into another group in the same commit, or fall to the
/// pseudo-group `default`. Dropping the entry outright dropped the only copy of that body, so the
/// group those nodes arrived in could not recognize where they were and handed them its own
/// `current` in one signed generation, `maxUnavailable` and health gate skipped. The entry survives
/// here as a BODY and nothing else: the group is absent from `desired`, so it is never planned,
/// admitted, classified, counted against a set's concurrency, or assigned nodes.
fn retire_deleted_groups(
    admitted: &mut BTreeMap<String, AdmittedDeployment>,
    desired: &BTreeMap<String, DesiredDeployment>,
    observations: &Observations<'_>,
) {
    admitted.retain(|name, state| {
        if desired.contains_key(name) {
            return true;
        }
        let mut live: Vec<DesiredDeployment> = std::iter::once(&state.current)
            .chain(state.previous.iter())
            .filter(|deployment| observations.placed_anywhere(deployment))
            .cloned()
            .collect();
        if live.is_empty() {
            return false;
        }
        state.current = live.remove(0);
        state.previous = live;
        true
    });
}

fn finish_staged_rollouts(
    admitted: &mut BTreeMap<String, AdmittedDeployment>,
    desired: &BTreeMap<String, DesiredDeployment>,
    observations: &Observations<'_>,
) {
    // The bodies some group's `current` already provides. A `current` is never retired, so a
    // predecessor holding the identical body is redundant — the fleet-wide index `assign_nodes`
    // builds is keyed by identity and answers from that `current` — and keeping it made a group
    // that merely shares a deployment with another one carry a predecessor it had finished staging
    // away from, for as long as the sibling ran it: permanently non-empty `previous`, on every
    // group of a fleet that deploys the same body to several groups.
    let provided: std::collections::HashSet<String> = admitted
        .values()
        .filter_map(|state| crate::deployment_identity(&state.current))
        .collect();
    let needed = |deployment: &DesiredDeployment| {
        observations.placed_anywhere(deployment)
            && !crate::deployment_identity(deployment).is_some_and(|id| provided.contains(&id))
    };
    for (name, state) in admitted.iter_mut() {
        // A deleted group's entry is a retained body, not a rollout: it selects no node, so every
        // staging question about it is vacuously true and answering them would discard the very
        // bodies `retire_deleted_groups` just kept.
        if !desired.contains_key(name) || state.previous.is_empty() {
            continue;
        }
        if observations.fully_handed(name, &state.current) {
            // Staging is over for the nodes this group selects NOW. A node relabelled away
            // mid-rollout is not one of them and is still running one of these bodies, so the ones
            // somebody is on are kept — as bodies only. `progress` asks `fully_handed` rather than
            // reading this list, so a retained body never reports the group as still rolling.
            state.previous.retain(|deployment| {
                let retained = needed(deployment);
                if retained {
                    tracing::debug!(
                        group = name,
                        deployment = deployment.deployment,
                        "predecessor retired for this group but kept as a body: a node elsewhere \
                         in the fleet is still placed on it"
                    );
                }
                retained
            });
            continue;
        }
        // The rollout is still staging, so retire only the individual predecessors no node is on
        // any more — what a retarget of an already-staging rollout accumulates, and what keeps the
        // list the size of the cohorts that actually exist.
        //
        // Never emptied here: a node that has been handed nothing at all (newly selected, never
        // published) is on no predecessor either, and an empty list means "nothing is staged",
        // which hands `current` to every node in one generation.
        let live: Vec<DesiredDeployment> = state
            .previous
            .iter()
            .filter(|deployment| needed(deployment))
            .cloned()
            .collect();
        if live.is_empty() {
            // No node is on ANY of them, so dropping all but the most recent strands no cohort —
            // and `assign_nodes` falls back to `previous[0]` and nothing else. Keeping the whole
            // list instead let a group that can never finish staging (its nodes sit on deployments
            // it does not name) accumulate one unretirable entry per retarget, growing the durable
            // ConfigMap until the apiserver refused the write and no generation published again.
            state.previous.truncate(1);
        } else {
            state.previous = live;
        }
    }
}

fn build_set_plans(
    sets: &[UpdateGroupSet],
    desired: &BTreeMap<String, DesiredDeployment>,
    group_labels: &BTreeMap<String, BTreeMap<String, String>>,
    admitted: &BTreeMap<String, AdmittedDeployment>,
    observations: &Observations<'_>,
    now: chrono::DateTime<chrono::Utc>,
) -> (Vec<SetPlan>, BTreeMap<String, Vec<usize>>) {
    let mut plans: Vec<SetPlan> = Vec::with_capacity(sets.len());
    let mut group_plans: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for set in sets {
        let mut members: Vec<String> = desired
            .keys()
            .filter(|name| {
                group_labels.get(*name).is_some_and(|labels| {
                    crate::selector_matches(&set.spec.selector.match_labels, labels)
                })
            })
            .cloned()
            .collect();
        members.sort();
        let max_concurrent = if members.is_empty() {
            0
        } else {
            set.spec.effective_max_concurrent(members.len())
        };
        // A member with no admitted entry has never been published, so it is not occupying a slot.
        // Neither does an UNOBSERVABLE one: it is not settled (settlement is evidence and it has
        // none) but nothing is in flight either, and counting it as rolling let one pre-enrollment,
        // decommissioned, or offline-provisioned group hold its set's only concurrency slot forever
        // and starve every sibling. A group holding SOME blind agents is judged on the agents that
        // can be observed, so one offline-provisioned machine never wedges its healthy siblings.
        let rolling_now = members
            .iter()
            .filter(|name| is_rolling(admitted, observations, name))
            .count();
        // A set is open only inside its schedule: both its recurring rollout windows and its
        // one-off dated calendar must admit `now` (each is "always open" when unset, so a set
        // using only one mechanism is gated by only that one). An exhausted calendar stops gating
        // (see `window::calendar_open`), so a stale one never wedges it.
        //
        // `frozen` is the ONLY representation of "this set is outside its schedule", and `slots`
        // counts ONLY concurrency. Folding the schedule into the slot count as well — freezing by
        // publishing zero free slots — expressed one condition twice, so `admit_pending`'s
        // emergency waiver lifted the `frozen` gate and was then refused by the slot gate for want
        // of a slot the freeze had taken away; the escape hatch worked only for a group that was
        // already mid-rollout (which bypasses slots for other reasons) and was inert for every
        // settled one. Two gates, two distinct conditions, one waiver that covers exactly one of
        // them.
        //
        // Deliberately not logged here: being frozen is a steady state that persists for days, and
        // this runs once per reconcile (one second), so an unconditional line here is ~600k lines a
        // week per set. It is reported on `SetStatus::frozen`, and `runtime` logs the TRANSITION.
        let open = crate::window::is_open(&set.spec.rollout_windows, now)
            && crate::window::calendar_open(&set.spec.calendar, now);
        let plan_idx = plans.len();
        for name in &members {
            group_plans.entry(name.clone()).or_default().push(plan_idx);
        }
        plans.push(SetPlan {
            members,
            max_concurrent,
            slots: max_concurrent.saturating_sub(rolling_now),
            frozen: !open,
        });
    }
    (plans, group_plans)
}

/// Whether this group currently occupies a concurrency slot: it has been published at least once
/// and the rollout it is ADMITTED to is genuinely in flight. The single definition, read both when
/// counting a set's used slots and when deciding whether a retarget needs to claim a new one.
///
/// Deliberately asked about `admitted.current` rather than about the operator's desire: a group
/// whose desire changed mid-rollout is [`GroupProgress::Held`] — the new deployment is not live —
/// while the rollout it is actually performing still occupies the slot it claimed.
fn is_rolling(
    admitted: &BTreeMap<String, AdmittedDeployment>,
    observations: &Observations<'_>,
    name: &str,
) -> bool {
    admitted
        .get(name)
        .is_some_and(|state| observations.progress(name, state) == Progress::Rolling)
}

fn admit_pending(
    groups: &BTreeMap<String, ResolvedGroup>,
    desired: &BTreeMap<String, DesiredDeployment>,
    group_plans: &BTreeMap<String, Vec<usize>>,
    plans: &mut [SetPlan],
    admitted: &mut BTreeMap<String, AdmittedDeployment>,
    observations: &Observations<'_>,
) {
    // Pending is decided on the whole desired deployment, not its identity string. `assign_nodes`
    // publishes the stored `current`, so a body change that keeps the same `deployment` name —
    // a corrected digest, changed args, or dependency inputs that only resolved once the producer
    // came up — is a real change nodes must receive. Comparing names alone dropped those silently
    // and forever, and no operator can name-bump a change the control plane itself resolved.
    let mut pending: Vec<String> = desired
        .keys()
        .filter(|name| {
            admitted
                .get(*name)
                .is_none_or(|state| state.current != desired[*name])
        })
        .cloned()
        .collect();
    pending.sort_by(|a, b| {
        let count = |n: &String| group_plans.get(n).map_or(0, Vec::len);
        count(b).cmp(&count(a)).then_with(|| a.cmp(b))
    });
    for name in pending {
        if !groups[&name].inputs_ready {
            continue;
        }
        // A prerequisite opens only once its desired deployment is admitted and every selected
        // node reports that exact deployment healthy. The graph itself is validated by the domain
        // planner before reaching this function. A dependency with no admitted entry at all has
        // not been published even once, so it cannot have settled.
        if !groups[&name].depends_on.iter().all(|dependency| {
            classify(dependency, desired, admitted, observations) == GroupProgress::Settled
        }) {
            continue;
        }
        // The predecessors a `maxUnavailable` batch stages away from are, in every case, the
        // deployments run by the nodes this admission has NOT yet moved: everything this group was
        // already admitted to, minus the deployment being admitted now. There is exactly one rule,
        // and it does not consult telemetry — staging is a property of what was published, so it
        // applies identically to a rollout, a rollback, and a group nothing can observe:
        //
        // * First admission — nothing has ever been published for this group, so there are none.
        // * An ordinary retarget — the deployment being replaced, which every node still runs.
        //   Note this stages EVERY change, including one that keeps the deployment's name:
        //   advancement is decided on the published configuration's digest, so a changed archive,
        //   argument, secret, or resolved input is as stageable as a rename.
        // * A retarget of a rollout that is still staging — the abandoned `current` AND the
        //   predecessor it was staging away from, because the group's nodes are spread across
        //   both. Dropping either one strands its cohort: `assign_nodes` can only leave a node
        //   where it is if the deployment it is on is still named here.
        // * A rollback onto the predecessor of a staging rollout — the target simply drops out of
        //   the list, leaving the half-rolled `current` the nodes that advanced are on. Keeping
        //   the (equal) predecessor instead made every node that had advanced revert in a single
        //   generation: `maxUnavailable` silently not applied to rollbacks.
        //
        // `finish_staged_rollouts` retires each entry as soon as no node is on it, and collapses
        // the list to one when no node is on any of them, so this grows only while cohorts
        // genuinely exist and a repeated retarget cannot accumulate entries.
        let rolling = is_rolling(admitted, observations, &name);
        // An EMERGENCY CORRECTION waives the SCHEDULE, and nothing else. A schedule governs when
        // new change is introduced into a fleet; it is not a promise to leave the fleet on a
        // release that is failing until Sunday. The set's concurrency limit still applies, so an
        // emergency retarget of a settled group still waits for a free slot: an emergency is a
        // reason to move now, never a reason to change every group in the fleet at once. Every
        // other gate — resolved inputs, settled prerequisites, `maxUnavailable` staging — applies
        // unchanged too.
        //
        // Which retarget is a correction is not something the control plane can see — it is the
        // operator's intent, so the operator states it (`spec.emergencyCorrection`) rather than the
        // planner guessing from telemetry. Guessing failed in both directions: a group carrying one
        // chronically unhealthy node was permanently window-exempt for ordinary forward changes,
        // and a release that bricks the agent itself emits no telemetry at all, so the one
        // emergency an operator most needs the escape hatch for was the one it could not detect.
        let emergency = groups[&name].emergency_correction;
        let mut previous: Vec<DesiredDeployment> = Vec::new();
        if let Some(state) = admitted.get(&name) {
            for deployment in std::iter::once(&state.current).chain(&state.previous) {
                if deployment != &desired[&name] && !previous.contains(deployment) {
                    previous.push(deployment.clone());
                }
            }
        }
        let admit = |admitted: &mut BTreeMap<String, AdmittedDeployment>| {
            admitted.insert(
                name.clone(),
                AdmittedDeployment {
                    current: desired[&name].clone(),
                    previous: previous.clone(),
                },
            );
        };
        // A group that has never been published has no predecessor to stage away from and nothing
        // for a slot or a schedule to protect.
        if !admitted.contains_key(&name) {
            admit(admitted);
            continue;
        }
        match group_plans.get(&name) {
            None => {
                admit(admitted);
            }
            Some(indices) => {
                // The SCHEDULE binds every admission of an already-published group — a rollout
                // window is the operator's statement about *when* this fleet may change at all, not
                // merely about how many groups may change at once, so a GitOps-driven spec change
                // to an in-flight member still waits for the window. An operator-declared emergency
                // correction is the single exception, because a window that also traps a fleet on a
                // release the operator is trying to escape is not a safety control.
                let frozen = indices.iter().any(|&i| plans[i].frozen);
                if frozen && !emergency {
                    continue;
                }
                // CONCURRENCY SLOTS are the second, independent gate, and an emergency does NOT
                // waive it. Only an in-flight group bypasses it: a group that is already rolling
                // holds its slot whatever it is rolling toward, so a retarget of it neither frees
                // nor needs one — and demanding a free slot there is what made a rollout onto a
                // release that is unhealthy on its first node unrecoverable: it can never settle,
                // so it holds its own slot against the very correction that would end it.
                // `previous` keeps the staging honest across the preemption.
                let admitted_now = if rolling {
                    warn_preempt(&name);
                    admit(admitted);
                    true
                } else if indices.iter().all(|&i| plans[i].slots > 0) {
                    admit(admitted);
                    for &i in indices {
                        plans[i].slots -= 1;
                    }
                    true
                } else {
                    false
                };
                // Logged where the bypass actually happens — once, on the pass that admits — not
                // once per reconcile for as long as the flag is set. The steady state is on the
                // set's `status.emergency`.
                if admitted_now && frozen {
                    tracing::warn!(
                        group = name,
                        "admitting this group's deployment OUTSIDE its set's rollout schedule: the \
                         operator declared spec.emergencyCorrection. Clear the flag once the \
                         emergency is over — it exempts every later change to this group too."
                    );
                }
            }
        }
    }
}

fn warn_preempt(group: &str) {
    tracing::warn!(
        group,
        "admitting a new desired deployment over this group's in-flight rollout; nodes that have \
         not advanced stay on its predecessor"
    );
}

fn build_statuses(
    sets: &[UpdateGroupSet],
    plans: &[SetPlan],
    group_plans: &BTreeMap<String, Vec<usize>>,
    group_progress: &BTreeMap<String, GroupProgress>,
    emergency: &BTreeSet<String>,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<SetStatus> {
    let shared: BTreeSet<String> = group_plans
        .iter()
        .filter(|(_, plans)| plans.len() > 1)
        .map(|(name, _)| name.clone())
        .collect();
    sets.iter()
        .zip(plans)
        .map(|(set, plan)| {
            let mut rolling = Vec::new();
            let mut settled_members = Vec::new();
            let mut shared_members = Vec::new();
            let mut unobservable_members = Vec::new();
            let mut emergency_members = Vec::new();
            for name in &plan.members {
                if shared.contains(name) {
                    shared_members.push(name.clone());
                }
                // Reported alongside, not instead of, the progress verdict: an emergency member is
                // still Rolling or Settled like any other. This list answers "which members are
                // currently exempt from my schedule", which is otherwise invisible.
                if emergency.contains(name) {
                    emergency_members.push(name.clone());
                }
                match group_progress.get(name) {
                    // Held back — neither rolling nor settled on its desire. A member with no
                    // admitted entry has not been published at all, which is the same story for a
                    // reader, and a member absent from the map is not planned this pass.
                    Some(GroupProgress::Held) | None => {}
                    Some(GroupProgress::Settled) => settled_members.push(name.clone()),
                    Some(GroupProgress::Rolling) => rolling.push(name.clone()),
                    // Reported on its own, never as rolling: this member consumes no slot and can
                    // never settle, so an operator needs to see WHY its dependents are waiting —
                    // it selects no agent, or every agent it selects is blind.
                    Some(GroupProgress::Unobservable) => unobservable_members.push(name.clone()),
                }
            }
            // Steady state, not an event: reported on the status and logged by `runtime` when it
            // CHANGES. Logged here it would emit one line per reconcile — a warn every second, for
            // as long as nobody adds a window, burying every real signal.
            let calendar_exhausted = crate::window::calendar_exhausted(&set.spec.calendar, now);
            SetStatus {
                name: set.metadata.name.clone().unwrap_or_default(),
                member_count: plan.members.len(),
                max_concurrent: plan.max_concurrent,
                rolling,
                settled: settled_members,
                unobservable: unobservable_members,
                shared: shared_members,
                emergency: emergency_members,
                frozen: plan.frozen,
                calendar_exhausted,
            }
        })
        .collect()
}

fn assign_nodes(
    groups: &BTreeMap<String, ResolvedGroup>,
    admitted: &BTreeMap<String, AdmittedDeployment>,
    held: &BTreeMap<String, HeldGroup>,
    observations: &Observations<'_>,
) -> BTreeMap<String, DesiredDeployment> {
    let mut node_deployments = BTreeMap::new();
    // Every deployment body the control plane still has, by identity. Group membership is a label,
    // so a node arrives in a group already running one of these; this is what lets the group it
    // arrived in republish that deployment verbatim instead of moving the node.
    //
    // Quarantined groups are in here too. They were pruned out of `admitted` above (they cannot be
    // planned) and are restored by `domain::plan_reconcile` only after this runs, so reading
    // `admitted` alone made the one node relabelling is FOR — a node moved out of a quarantined
    // group — the one node whose placement could not be recognized. So are the bodies of DELETED
    // groups and of retired predecessors that somebody is still on: `retire_deleted_groups` and
    // `finish_staged_rollouts` keep a body for exactly as long as a node is placed on it, so
    // "where is this node?" has an answer whenever the control plane ever published one.
    let running: HashMap<String, &DesiredDeployment> = admitted
        .values()
        .chain(held.values().map(|held| &held.state))
        .flat_map(|state| std::iter::once(&state.current).chain(state.previous.iter()))
        .filter_map(|deployment| Some((crate::deployment_identity(deployment)?, deployment)))
        .collect();
    for (name, group) in groups.iter() {
        // A group awaiting its first admission publishes nothing. Its nodes are left out of the
        // generation entirely (see `domain::plan_reconcile`) so they hold their last known
        // assignment rather than being handed something ungated.
        let Some(state) = admitted.get(name) else {
            continue;
        };
        let mut nodes = observations.nodes(name);
        nodes.sort();
        // There is ONE path here whether or not the group is mid-rollout. An empty `previous` means
        // no DEPLOYMENT change is in flight; it does not mean every selected node is already on
        // `current`. A node relabelled INTO a settled group arrives running whatever its old group
        // handed it, and short-circuiting on `previous.is_empty()` handed `current` to all of them
        // in one generation — a bulk relabel restarted every machine at once with no
        // `maxUnavailable` and no health gate. For the machine a membership change is the same move
        // as a deployment change, so it is staged the same way.
        //
        // Advancement is judged on the exact configuration each node reports acting on, so a
        // change that keeps the deployment's name still stages one batch at a time.
        let (Some(current_id), Some(previous_ids)) = (
            crate::deployment_identity(&state.current),
            state
                .previous
                .iter()
                .map(crate::deployment_identity)
                .collect::<Option<Vec<String>>>(),
        ) else {
            // Nothing can be shown to have advanced, so hold every node on the predecessor rather
            // than guess. With no predecessor there is nothing to hold on and `current` is all the
            // control plane has.
            let fallback = state.previous.first().unwrap_or(&state.current);
            for node in nodes {
                node_deployments.insert(node.clone(), fallback.clone());
            }
            continue;
        };
        let mut unavailable = 0usize;
        let mut held = Vec::new();
        // Whether any node of this group is positively observed healthy ON `current`. It is what
        // makes `current` a PROVEN target rather than an unproven one, which is the only condition
        // under which an already-broken node is moved out of turn below.
        let mut proven = false;
        for node in nodes {
            // A node has advanced once it either REPORTS `current` or was already PUBLISHED
            // `current` in the last generation. The published half is what makes a node's
            // assignment monotonic within a rollout: telemetry ages out after a minute, and a node
            // that reboots to apply the very update it was just handed is silent for longer than
            // that. Judging on live telemetry alone republished it under the PREDECESSOR — telling
            // the machine mid-update to go back — and then flipped it forward again on the next
            // report. Absence of evidence is not evidence of not having advanced; it still counts
            // against `maxUnavailable` below, which is what actually holds the rollout back.
            let on_current = observations.evidence(node, &current_id);
            proven |= on_current == NodeEvidence::Healthy;
            if observations.advanced(node, &current_id) {
                if on_current.unavailable() {
                    unavailable += 1;
                }
                node_deployments.insert(node.clone(), state.current.clone());
                continue;
            }
            // WHERE this node actually is, among the deployments the group is still holding. A
            // retarget of a staging rollout leaves nodes on the abandoned `current`, and judging
            // them against one nominated predecessor read every one of them as Silent — so they
            // each spent a slot of `maxUnavailable` they were not using, collapsing the budget to
            // zero, and were then handed that predecessor anyway: a healthy node reverted for
            // being in the wrong place. A node is held where it is, and only its own deployment
            // decides whether it is available.
            //
            // "Where it is" reaches past this group's own deployments, because a node relabelled in
            // from another group — healthy or quarantined — mid-roll is on neither `current` nor
            // any of them (see `running`, which spans both). Falling through
            // to the predecessor handed that machine a backward move — and the ONE move no budget
            // was ever checked against, since only the forward move is gated below. It is held on
            // exactly what it is already running instead, which is a no-op for it, and its own
            // deployment decides whether it is available: a node healthy somewhere is not spending
            // this group's `maxUnavailable` on a rollout it has not joined.
            //
            // ONE rule for a node whose placement this group does not recognize: it is HELD on
            // whatever it is actually running, and if it moves at all the move is spent from the
            // budget below. The fallbacks this replaced each assumed the opposite — that an
            // unrecognized placement means "safe to hand out `current`" — and each turned a bulk
            // relabel into a fleet-wide restart in a single signed generation: `hold == current`
            // makes the `moved < budget` throttle a no-op, so every such node moved at once.
            let (evidence, hold) = match previous_ids
                .iter()
                .position(|identity| observations.advanced(node, identity))
            {
                Some(position) => (
                    observations.evidence(node, &previous_ids[position]),
                    Some(&state.previous[position]),
                ),
                None => match observations.placement(node) {
                    // The node IS somewhere. `running` answers with the body whenever the control
                    // plane ever published it (bodies outlive their groups for exactly this). A
                    // `None` here means the body is genuinely gone, so there is nothing to hold it
                    // on — but moving it is still a move, so it waits for a budget slot like every
                    // other and is simply left out of the generation until it gets one.
                    Some(identity) => (
                        observations.evidence(node, &identity),
                        running.get(&identity).copied(),
                    ),
                    // Nothing has ever been published or reported for this node and this group has
                    // no rollout staged: this is its FIRST delivery, not a move. No machine is
                    // disrupted (none was ever handed anything) and there is no batch to take a
                    // turn in, so a freshly enrolled agent is published immediately rather than
                    // waiting a generation per sibling. It still counts against availability — it
                    // is not on the release yet — and it can discharge that by reporting, because
                    // it was published.
                    None if state.previous.is_empty() => {
                        if observations.evidence(node, &current_id).unavailable() {
                            unavailable += 1;
                        }
                        node_deployments.insert(node.clone(), state.current.clone());
                        continue;
                    }
                    // The same node while a rollout IS staged is part of the cohort being moved one
                    // batch at a time, so it takes its turn like every other member — with nothing
                    // to hold it on meanwhile, so it is simply left out until it gets a slot, which
                    // costs it nothing because nothing was ever published for it. Handing it
                    // `current` here instead delivered the in-flight release, unstaged, to every
                    // node the control plane cannot account for while its siblings were still
                    // moving one at a time.
                    //
                    // It is the ONE held node that does not spend a `maxUnavailable` slot, and that
                    // exemption is what keeps the group from deadlocking. Counting it made the two
                    // halves self-reinforcing: with no placement it reads `Silent`, taking a slot,
                    // and with nothing to hold it on it is dropped from the generation whenever the
                    // budget is spent — so it is never published, so it can never report, so it
                    // stays Silent and holds that slot forever. One autoscaler-enrolled agent
                    // joining a group with the default `maxUnavailable: 1` mid-rollout was enough
                    // to freeze that group, and every group sequenced behind it, permanently.
                    // Nothing is running on this node for its absence to disrupt, so there is
                    // nothing for the availability budget to be protecting; it waits for a movement
                    // slot, which the other nodes' convergence always frees.
                    None => {
                        held.push((node, NodeEvidence::Silent, None));
                        continue;
                    }
                },
            };
            if evidence.unavailable() {
                unavailable += 1;
            }
            held.push((node, evidence, hold));
        }
        // A node held on the predecessor that positively reports itself BROKEN there is moved out of
        // turn — it does not need FREE capacity — but only onto a `current` some sibling is already
        // observed healthy on. It is already unavailable, so moving it to a PROVEN release cannot
        // disrupt anything further, and refusing to move it is what left a rollback unable to
        // rescue the node the rollout broke: that one node's own unavailability consumed the entire
        // budget the rollback needed to reach it. Every half of the condition is load-bearing.
        // An UNPROVEN `current` never gets the exemption, so a degraded node still spends the
        // budget and holds a rollout back rather than being fed an untried release. And only a
        // positively verified unhealthy report qualifies: silence must not, or a telemetry outage
        // would read as "everything is already down" and move the whole fleet in one generation.
        //
        // What a rescue is exempt from is the SHORTFALL, not the batch size: it draws on the full
        // `maxUnavailable` instead of what is left of it, and still spends from the same
        // per-generation movement budget as every other node. Exempting it from the budget
        // entirely turned an app-level health blip — a downstream dependency, an expired licence,
        // one bad config every node reports on — into an unthrottled fleet-wide move in a single
        // signed generation. At least one node always moves, so the rollback that has to reach a
        // broken node still makes progress every pass.
        let capacity = group.max_unavailable.saturating_sub(unavailable);
        let rescue_budget = group.max_unavailable.max(1);
        let mut moved = 0usize;
        for (node, evidence, hold) in held {
            let budget = if proven && evidence == NodeEvidence::Broken {
                rescue_budget
            } else {
                capacity
            };
            // Out of budget means the node does not move — it is republished on exactly what it is
            // already running, which is a no-op for that machine. The alternative, publishing one
            // nominated predecessor to every held node, is a MOVE for anything not already on it,
            // and one that no budget was ever checked against.
            let deployment = if moved < budget {
                moved += 1;
                Some(&state.current)
            } else {
                hold
            };
            match deployment {
                Some(deployment) => {
                    node_deployments.insert(node.clone(), deployment.clone());
                }
                // Out of budget AND nothing to hold this node on. It is left out of the generation
                // rather than moved unbudgeted; `domain::plan_reconcile` republishes it under its
                // last routing, and it moves as soon as a slot frees.
                None => tracing::warn!(
                    node,
                    group = name,
                    "node is placed on a deployment the control plane no longer has a body for and \
                     this group has no free maxUnavailable slot; leaving it out of this generation \
                     rather than moving it unbudgeted"
                ),
            }
        }
    }
    node_deployments
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-formed running digest for report fixtures. Nothing in this module reads it; a report
    /// simply needs one to be well formed.
    const DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    // A fixed instant for tests whose sets carry no rollout windows (always open, so the
    // exact value is irrelevant). Window behaviour is unit-tested in `crate::window`.
    fn test_now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-07-20T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    /// A deployment as the planner only ever sees one: built from a `DeploymentSpec`, where
    /// `reportUrl` is required. The identity a report carries is derived from this same shape.
    fn deployment_named(id: &str) -> DesiredDeployment {
        DesiredDeployment {
            schema: updated_contracts::assignment::RepositoryAssignment::SCHEMA,
            deployment: id.into(),
            metadata_url: "https://cdn/m/".into(),
            targets_url: "https://cdn/t/".into(),
            report_url: Some("https://cdn".into()),
            application: crate::ExactTarget {
                path: "app".into(),
                sha256: "a".repeat(64),
            },
            ordered_install_fallback: false,
            provider_set: crate::ExactTarget {
                path: "prov".into(),
                sha256: "b".repeat(64),
            },
            release_root: serde_json::json!({"signed": {}, "signatures": []}),
            runtime: runtime(),
        }
    }

    fn runtime() -> updated_contracts::assignment::ManagedRuntime {
        updated_contracts::assignment::ManagedRuntime {
            mode: updated_contracts::assignment::RuntimeMode::Managed,
            product: "app".into(),
            channel: "stable".into(),
            install_root: "/opt/app".into(),
            args: vec![],
            secrets: vec![],
            inputs: BTreeMap::new(),
            repository: updated_contracts::assignment::ManagedRepositoryLimits {
                metadata_limit: 1,
                target_limit: 1,
                transport_timeout_seconds: 1,
            },
            storage: updated_contracts::assignment::ManagedStorage {
                inactive_releases: 1,
                inactive_providers: 1,
                inactive_supervisors: 1,
                inactive_bytes: 1,
                inactive_repository_caches: 1,
            },
            timeouts: updated_contracts::assignment::ManagedTimeouts {
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

    fn group(name: &str, deployment: DesiredDeployment) -> ResolvedGroup {
        ResolvedGroup {
            name: name.into(),
            match_labels: BTreeMap::from([("group".into(), name.into())]),
            depends_on: vec![],
            inputs: BTreeMap::new(),
            inputs_ready: true,
            deployment,
            max_unavailable: 1,
            emergency_correction: false,
        }
    }

    fn admitted(deployment: DesiredDeployment) -> AdmittedDeployment {
        AdmittedDeployment {
            current: deployment,
            previous: Vec::new(),
        }
    }

    fn pair_set() -> UpdateGroupSet {
        UpdateGroupSet::new(
            "pair-00",
            crate::UpdateGroupSetSpec {
                selector: crate::LabelSelector {
                    match_labels: BTreeMap::from([("set".into(), "pair-00".into())]),
                },
                max_concurrent: None,
                rollout_windows: vec![],
                calendar: vec![],
            },
        )
    }

    /// One shared signing key for the throttle tests (identity binding is proven in `join`/
    /// `telemetry`; here we only need every report to carry a signature that verifies against the
    /// pinned key). `.0` is the PKCS#8 signing key, `.1` the pinned public point.
    static TEST_KEY: std::sync::LazyLock<(Vec<u8>, Vec<u8>)> = std::sync::LazyLock::new(|| {
        let key_pem = updated::csr::generate_key().unwrap();
        let pkcs8 = updated::csr::key_pem_to_pkcs8_der(&key_pem).unwrap();
        let csr = updated::csr::csr_for(&key_pem, "throttle-test").unwrap();
        let public = crate::join::csr_public_key(&csr).unwrap();
        (pkcs8, public)
    });

    /// The pinned-key map the throttle needs: every node routed by `node_groups`, mapped to the
    /// shared test public key (so signed reports verify).
    fn pubkeys(node_groups: &BTreeMap<String, String>) -> HashMap<String, Vec<u8>> {
        node_groups
            .keys()
            .map(|node| (node.clone(), TEST_KEY.1.clone()))
            .collect()
    }

    /// A freshly-stamped report as of `now`. Throttling keys off (deployment, healthy); the running
    /// version is irrelevant here. Stamping against the same instant the pass is planned at is what
    /// a node reporting on every tick looks like — the freshness bound is exercised by its own
    /// tests (`a_stale_report_is_treated_as_not_settled` and the contract's gate tests) rather than
    /// by perturbing these.
    fn report_at(
        now: chrono::DateTime<chrono::Utc>,
        node: &str,
        deployment: &str,
        healthy: bool,
    ) -> (String, Envelope) {
        // A node reports the digest of the configuration it is acting on, so fixtures name the
        // deployment and derive the identity the planner will compare against.
        let identity = crate::deployment_identity(&deployment_named(deployment)).unwrap();
        let mut report = NodeReport::new(node, deployment, identity, deployment, DIGEST, healthy);
        report.reported_at_ms = now.timestamp_millis() as u64;
        let envelope = updated_contracts::telemetry::sign_report(&report, &TEST_KEY.0).unwrap();
        (node.into(), envelope)
    }

    fn report(node: &str, deployment: &str, healthy: bool) -> (String, Envelope) {
        report_at(test_now(), node, deployment, healthy)
    }

    /// A healthy report older than [`updated_contracts::telemetry::REPORT_FRESHNESS`], stamped relative to
    /// `test_now`.
    fn stale_report(node: &str, deployment: &str) -> (String, Envelope) {
        let identity = crate::deployment_identity(&deployment_named(deployment)).unwrap();
        let mut report = NodeReport::new(node, deployment, identity, deployment, DIGEST, true);
        let stale_ms = updated_contracts::telemetry::REPORT_FRESHNESS.as_millis() as u64 + 60_000;
        report.reported_at_ms = (test_now().timestamp_millis() as u64).saturating_sub(stale_ms);
        let envelope = updated_contracts::telemetry::sign_report(&report, &TEST_KEY.0).unwrap();
        (node.into(), envelope)
    }

    /// An admitted state with nothing staging left — the shape `Observations::progress` is asked
    /// about when the only question is what telemetry says.
    fn admitted_now(deployment: &DesiredDeployment) -> AdmittedDeployment {
        AdmittedDeployment {
            current: deployment.clone(),
            previous: Vec::new(),
        }
    }

    /// Group labels for a plain two-member `pair-00` set.
    fn pair_labels() -> BTreeMap<String, BTreeMap<String, String>> {
        BTreeMap::from([
            (
                "a".to_string(),
                BTreeMap::from([("set".to_string(), "pair-00".to_string())]),
            ),
            (
                "b".to_string(),
                BTreeMap::from([("set".to_string(), "pair-00".to_string())]),
            ),
        ])
    }

    /// Node → group routing for a two-member pair, one agent each.
    fn pair_node_groups() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("n-a".to_string(), "a".to_string()),
            ("n-b".to_string(), "b".to_string()),
        ])
    }

    type GroupFixture = (
        BTreeMap<String, ResolvedGroup>,
        BTreeMap<String, String>,
        BTreeMap<String, BTreeMap<String, String>>,
    );

    fn three_node_group() -> GroupFixture {
        let groups = BTreeMap::from([("g".into(), group("g", deployment_named("v0")))]);
        let node_groups = ["n0", "n1", "n2"]
            .into_iter()
            .map(|node| (node.into(), "g".into()))
            .collect();
        (groups, node_groups, BTreeMap::new())
    }

    #[test]
    fn stages_one_node_at_a_time_within_a_group() {
        let (mut groups, node_groups, labels) = three_node_group();
        let mut admitted = BTreeMap::new();
        let baseline = HashMap::from([
            report("n0", "v0", true),
            report("n1", "v0", true),
            report("n2", "v0", true),
        ]);
        plan_rollouts(
            &[],
            RolloutInputs {
                groups: &mut groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &baseline,
                public_keys: &pubkeys(&node_groups),
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
            },
            &mut admitted,
            test_now(),
        );
        groups.get_mut("g").unwrap().deployment = deployment_named("v1");
        let first = plan_rollouts(
            &[],
            RolloutInputs {
                groups: &mut groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &baseline,
                public_keys: &pubkeys(&node_groups),
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
            },
            &mut admitted,
            test_now(),
        );
        assert_eq!(first.node_deployments["n0"].deployment, "v1");
        assert_eq!(first.node_deployments["n1"].deployment, "v0");
        assert_eq!(first.node_deployments["n2"].deployment, "v0");

        let one_settled = HashMap::from([
            report("n0", "v1", true),
            report("n1", "v0", true),
            report("n2", "v0", true),
        ]);
        let second = plan_rollouts(
            &[],
            RolloutInputs {
                groups: &mut groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &one_settled,
                public_keys: &pubkeys(&node_groups),
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
            },
            &mut admitted,
            test_now(),
        );
        assert_eq!(second.node_deployments["n0"].deployment, "v1");
        assert_eq!(second.node_deployments["n1"].deployment, "v1");
        assert_eq!(second.node_deployments["n2"].deployment, "v0");
    }

    #[test]
    fn thousand_node_rollout_never_exceeds_the_group_budget_and_converges() {
        let mut groups = BTreeMap::from([("g".into(), group("g", deployment_named("v0")))]);
        groups.get_mut("g").unwrap().max_unavailable = 100;
        let node_groups: BTreeMap<String, String> = (0..1_000)
            .map(|index| (format!("node-{index:04}"), "g".into()))
            .collect();
        let keys = pubkeys(&node_groups);
        let mut reports: HashMap<String, Envelope> = node_groups
            .keys()
            .map(|node| report(node, "v0", true))
            .collect();
        let mut admitted = BTreeMap::new();
        let labels = BTreeMap::new();

        plan_rollouts(
            &[],
            RolloutInputs {
                groups: &groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &keys,
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
            },
            &mut admitted,
            test_now(),
        );
        groups.get_mut("g").unwrap().deployment = deployment_named("v1");

        for batch in 0..10 {
            let plan = plan_rollouts(
                &[],
                RolloutInputs {
                    groups: &groups,
                    group_labels: &labels,
                    node_groups: &node_groups,
                    reports: &reports,
                    public_keys: &keys,
                    published: &BTreeMap::new(),
                    held: &BTreeMap::new(),
                },
                &mut admitted,
                test_now(),
            );
            let selected: Vec<_> = plan
                .node_deployments
                .iter()
                .filter(|(_, deployment)| deployment.deployment == "v1")
                .map(|(node, _)| node.clone())
                .collect();
            assert_eq!(selected.len(), (batch + 1) * 100);
            // Each admitted member now reports itself settled on v1. Re-signing unconditionally is
            // idempotent — the report's contents are what matter, not how many times it was written —
            // and the envelope keeps its payload opaque, so there is no field to peek at first.
            for advancing in selected {
                reports.insert(advancing.clone(), report(&advancing, "v1", true).1);
            }
        }

        let converged = plan_rollouts(
            &[],
            RolloutInputs {
                groups: &groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &keys,
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
            },
            &mut admitted,
            test_now(),
        );
        assert!(converged
            .node_deployments
            .values()
            .all(|deployment| deployment.deployment == "v1"));
        assert!(admitted["g"].previous.is_empty());
    }

    #[test]
    fn a_degraded_held_node_consumes_the_unavailable_budget() {
        let (mut groups, node_groups, labels) = three_node_group();
        let mut admitted = BTreeMap::from([(
            "g".into(),
            AdmittedDeployment {
                current: deployment_named("v1"),
                previous: vec![deployment_named("v0")],
            },
        )]);
        let reports = HashMap::from([
            report("n0", "v0", true),
            report("n1", "v0", true),
            report("n2", "v0", false),
        ]);
        groups.get_mut("g").unwrap().deployment = deployment_named("v1");
        let outcome = plan_rollouts(
            &[],
            RolloutInputs {
                groups: &mut groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &pubkeys(&node_groups),
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
            },
            &mut admitted,
            test_now(),
        );
        assert!(outcome
            .node_deployments
            .values()
            .all(|deployment| deployment.deployment == "v0"));
    }

    /// A rollout onto a release that is unhealthy on its very first node must stay correctable.
    /// It can never settle, so gating the next desired deployment on it settling made the group
    /// permanently un-updatable — the operator could not even fix forward. The retarget is
    /// admitted; the predecessor the un-advanced nodes are running is preserved, so staging is
    /// unchanged and nothing jumps the `maxUnavailable` budget.
    #[test]
    fn a_mid_roll_retarget_preempts_without_losing_the_predecessor() {
        let (mut groups, node_groups, labels) = three_node_group();
        groups.get_mut("g").unwrap().deployment = deployment_named("v2");
        let mut admitted = BTreeMap::from([(
            "g".into(),
            AdmittedDeployment {
                current: deployment_named("v1"),
                previous: vec![deployment_named("v0")],
            },
        )]);
        let reports = HashMap::from([
            report("n0", "v1", false),
            report("n1", "v0", true),
            report("n2", "v0", true),
        ]);
        let outcome = plan_rollouts(
            &[],
            RolloutInputs {
                groups: &mut groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &pubkeys(&node_groups),
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
            },
            &mut admitted,
            test_now(),
        );
        assert_eq!(admitted["g"].current.deployment, "v2");
        assert_eq!(
            admitted["g"]
                .previous
                .iter()
                .map(|deployment| deployment.deployment.as_str())
                .collect::<Vec<_>>(),
            vec!["v1", "v0"],
            "both cohorts survive the preemption: the abandoned v1 that n0 is on and the v0 the \
             other two never left"
        );
        // `n0` is unhealthy on the abandoned v1, so it counts against `maxUnavailable` and no node
        // is advanced this pass: the preemption changes what is admitted, never the staging budget.
        // Every node is republished exactly where it already is — nothing moves in either
        // direction on a pass with no budget.
        assert_eq!(outcome.node_deployments["n0"].deployment, "v1");
        assert_eq!(outcome.node_deployments["n1"].deployment, "v0");
        assert_eq!(outcome.node_deployments["n2"].deployment, "v0");
    }

    /// The same preemption with the advanced cohort HEALTHY, which is the case that showed the
    /// budget was not applied backwards at all: ten nodes at `maxUnavailable: 1`, five of them
    /// published and healthy on v1 after five staged generations, retargeted to v2. Holding one
    /// nominated predecessor meant all five read as Silent against it (so the budget collapsed to
    /// zero) and were then handed it anyway — five healthy nodes downgraded in one signed
    /// generation, which is exactly what `maxUnavailable` exists to prevent.
    #[test]
    fn a_retarget_never_yanks_a_healthy_advanced_node_backwards() {
        let nodes: Vec<String> = (0..10).map(|index| format!("n{index}")).collect();
        let groups = BTreeMap::from([("g".into(), group("g", deployment_named("v2")))]);
        let node_groups: BTreeMap<String, String> = nodes
            .iter()
            .map(|node| (node.clone(), "g".to_string()))
            .collect();
        // Five nodes were staged onto v1 one generation at a time; the rest never left v0.
        let advanced = |index: usize| index < 5;
        let mut admitted = BTreeMap::from([(
            "g".into(),
            AdmittedDeployment {
                current: deployment_named("v1"),
                previous: vec![deployment_named("v0")],
            },
        )]);
        let published: BTreeMap<String, String> = nodes
            .iter()
            .enumerate()
            .map(|(index, node)| {
                let deployment = if advanced(index) { "v1" } else { "v0" };
                (
                    node.clone(),
                    crate::deployment_identity(&deployment_named(deployment)).unwrap(),
                )
            })
            .collect();
        let reports: HashMap<String, Envelope> = nodes
            .iter()
            .enumerate()
            .map(|(index, node)| report(node, if advanced(index) { "v1" } else { "v0" }, true))
            .collect();

        let outcome = plan_rollouts(
            &[],
            RolloutInputs {
                groups: &groups,
                group_labels: &BTreeMap::new(),
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &pubkeys(&node_groups),
                published: &published,
                held: &BTreeMap::new(),
            },
            &mut admitted,
            test_now(),
        );

        assert_eq!(admitted["g"].current.deployment, "v2");
        let moved: Vec<&String> = nodes
            .iter()
            .filter(|node| outcome.node_deployments[*node].deployment == "v2")
            .collect();
        assert_eq!(moved.len(), 1, "one node moves: maxUnavailable is 1");
        for (index, node) in nodes.iter().enumerate() {
            if moved.contains(&node) {
                continue;
            }
            assert_eq!(
                outcome.node_deployments[node].deployment,
                if advanced(index) { "v1" } else { "v0" },
                "{node} is healthy where it is and stays there until the budget reaches it"
            );
        }

        // And it converges: no cohort is stranded, and each pass moves exactly one node.
        let mut published = published_from(&outcome);
        let mut reports = reports;
        for node in outcome.node_deployments.keys() {
            let (node, envelope) = report(node, &outcome.node_deployments[node].deployment, true);
            reports.insert(node, envelope);
        }
        for _ in 0..12 {
            let plan = plan_rollouts(
                &[],
                RolloutInputs {
                    groups: &groups,
                    group_labels: &BTreeMap::new(),
                    node_groups: &node_groups,
                    reports: &reports,
                    public_keys: &pubkeys(&node_groups),
                    published: &published,
                    held: &BTreeMap::new(),
                },
                &mut admitted,
                test_now(),
            );
            let on_v2 = plan
                .node_deployments
                .values()
                .filter(|deployment| deployment.deployment == "v2")
                .count();
            assert!(
                on_v2 <= previously_on_v2(&published) + 1,
                "one node per pass"
            );
            published = published_from(&plan);
            for (node, deployment) in &plan.node_deployments {
                let (node, envelope) = report(node, &deployment.deployment, true);
                reports.insert(node, envelope);
            }
        }
        let target = crate::deployment_identity(&deployment_named("v2")).unwrap();
        assert!(
            published.values().all(|identity| *identity == target),
            "every node converges on the retarget"
        );
        assert!(
            admitted["g"].previous.is_empty(),
            "and the staging finishes: no cohort is left behind"
        );
    }

    /// The same rule for a node that arrives from OUTSIDE the group. Group membership is a label,
    /// so a node can be relabelled into a group mid-roll while running a deployment that group has
    /// never held — on neither its `current` nor any of its predecessors. That node fell through to
    /// "hold it on the most recent predecessor", which for it is a backward MOVE, and the only one
    /// the per-generation budget was never checked against.
    #[test]
    fn a_node_relabelled_in_mid_roll_is_not_yanked_onto_a_deployment_it_never_ran() {
        let nodes = ["n0", "n1", "n2", "z-arrival"];
        let groups = BTreeMap::from([
            ("g".into(), group("g", deployment_named("v2"))),
            ("other".into(), group("other", deployment_named("w1"))),
        ]);
        // `z-arrival` sorts last, so the single-node movement budget is spent before it is reached:
        // whatever it is assigned this pass is what "held where it is" has to mean.
        let node_groups: BTreeMap<String, String> = nodes
            .iter()
            .map(|node| ((*node).to_string(), "g".to_string()))
            .collect();
        let mut admitted = BTreeMap::from([
            (
                "g".into(),
                AdmittedDeployment {
                    current: deployment_named("v2"),
                    previous: vec![deployment_named("v1")],
                },
            ),
            ("other".into(), admitted(deployment_named("w1"))),
        ]);
        let running = |node: &str| if node == "z-arrival" { "w1" } else { "v1" };
        let published: BTreeMap<String, String> = nodes
            .iter()
            .map(|node| {
                (
                    (*node).to_string(),
                    crate::deployment_identity(&deployment_named(running(node))).unwrap(),
                )
            })
            .collect();
        let reports: HashMap<String, Envelope> = nodes
            .iter()
            .map(|node| report(node, running(node), true))
            .collect();

        let outcome = plan_rollouts(
            &[],
            RolloutInputs {
                groups: &groups,
                group_labels: &BTreeMap::new(),
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &pubkeys(&node_groups),
                published: &published,
                held: &BTreeMap::new(),
            },
            &mut admitted,
            test_now(),
        );

        assert_eq!(
            outcome.node_deployments["z-arrival"].deployment, "w1",
            "a node healthy on a deployment this group does not hold is republished on exactly \
             that, not reverted onto a predecessor it has never run"
        );
        assert_eq!(
            outcome
                .node_deployments
                .values()
                .filter(|deployment| deployment.deployment == "v2")
                .count(),
            1,
            "and the group's own staging is still one node per generation"
        );
    }

    /// How many nodes the last published generation had on v2 — the baseline the next pass may
    /// exceed by at most one.
    fn previously_on_v2(published: &BTreeMap<String, String>) -> usize {
        let v2 = crate::deployment_identity(&deployment_named("v2")).unwrap();
        published.values().filter(|id| **id == v2).count()
    }

    /// The rollback shape of the same case: reverting to exactly the deployment the group still
    /// holds as its predecessor. The rollback is itself a staged generation change — the nodes left
    /// to move are the ones already handed the half-rolled `current`, so THAT becomes the
    /// predecessor — and the node the rollout broke is rescued onto the release its siblings are
    /// observed healthy on.
    #[test]
    fn reverting_to_the_predecessor_ends_the_rollout() {
        let (mut groups, node_groups, labels) = three_node_group();
        groups.get_mut("g").unwrap().deployment = deployment_named("v0");
        let mut admitted = BTreeMap::from([(
            "g".into(),
            AdmittedDeployment {
                current: deployment_named("v1"),
                previous: vec![deployment_named("v0")],
            },
        )]);
        let reports = HashMap::from([
            report("n0", "v1", false),
            report("n1", "v0", true),
            report("n2", "v0", true),
        ]);
        let outcome = plan_rollouts(
            &[],
            RolloutInputs {
                groups: &mut groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &pubkeys(&node_groups),
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
            },
            &mut admitted,
            test_now(),
        );
        assert_eq!(admitted["g"].current.deployment, "v0");
        assert_eq!(
            admitted["g"].previous[0].deployment, "v1",
            "a rollback stages away from the half-rolled deployment, so THAT is the predecessor"
        );
        assert!(outcome
            .node_deployments
            .values()
            .all(|deployment| deployment.deployment == "v0"));
    }

    #[test]
    fn membership_reordering_never_demotes_an_advanced_node() {
        let mut groups = BTreeMap::from([("g".into(), group("g", deployment_named("v1")))]);
        let node_groups = ["a-new", "m-advanced", "z-held"]
            .into_iter()
            .map(|node| (node.into(), "g".into()))
            .collect();
        let labels = BTreeMap::new();
        let reports = HashMap::from([
            report("a-new", "v0", true),
            report("m-advanced", "v1", false),
            report("z-held", "v0", true),
        ]);
        let mut admitted = BTreeMap::from([(
            "g".into(),
            AdmittedDeployment {
                current: deployment_named("v1"),
                previous: vec![deployment_named("v0")],
            },
        )]);
        let outcome = plan_rollouts(
            &[],
            RolloutInputs {
                groups: &mut groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &pubkeys(&node_groups),
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
            },
            &mut admitted,
            test_now(),
        );
        assert_eq!(outcome.node_deployments["m-advanced"].deployment, "v1");
        assert_eq!(outcome.node_deployments["a-new"].deployment, "v0");
        assert_eq!(outcome.node_deployments["z-held"].deployment, "v0");
    }

    #[test]
    fn a_stale_report_is_treated_as_not_settled() {
        // A node that reported healthy once and then went silent must NOT keep a group "settled"
        // forever (the fail-open direction). One pair-member with only a stale report never
        // settles, so it stays `rolling` and its sibling is held — same as a missing report.
        let mut groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment_named("v1"))),
            ("b".to_string(), group("b", deployment_named("v1"))),
        ]);
        let group_labels = pair_labels();
        let node_groups = pair_node_groups();
        // "a" is admitted v1 but its only report is stale; "b" holds a fresh v1.
        let reports = HashMap::from([stale_report("n-a", "v1"), report("n-b", "v1", true)]);
        let mut admitted = BTreeMap::new();
        let statuses = plan_rollouts(
            &[pair_set()],
            RolloutInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
                reports: &reports,
            },
            &mut admitted,
            test_now(),
        );
        assert!(
            statuses.sets[0].rolling.contains(&"a".to_string()),
            "stale 'a' must be rolling, not settled"
        );
        assert!(
            statuses.sets[0].settled.contains(&"b".to_string()),
            "fresh 'b' is settled"
        );
    }

    #[test]
    fn holds_the_second_member_until_the_first_settles() {
        // Two members of a pair, both baseline "v0", one agent each.
        let mut groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment_named("v0"))),
            ("b".to_string(), group("b", deployment_named("v0"))),
        ]);
        let group_labels = pair_labels();
        let node_groups = pair_node_groups();
        // Seed baseline as admitted (first sight), both settled on v0.
        let reports_v0 = HashMap::from([report("n-a", "v0", true), report("n-b", "v0", true)]);
        let sets = [pair_set()];
        // The durable admitted set survives across passes just as the in-cluster ConfigMap does.
        let mut admitted = BTreeMap::new();
        plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
                reports: &reports_v0,
            },
            &mut admitted,
            test_now(),
        );

        // Now both want v1. Only one may roll.
        groups.get_mut("a").unwrap().deployment = deployment_named("v1");
        groups.get_mut("b").unwrap().deployment = deployment_named("v1");
        let statuses = plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
                reports: &reports_v0, // agents still on v0
            },
            &mut admitted,
            test_now(),
        );
        // Exactly one member (the first by name, "a") is admitted to v1; "b" is held at v0.
        assert_eq!(admitted["a"].current.deployment, "v1");
        assert_eq!(admitted["b"].current.deployment, "v0");
        assert_eq!(statuses.sets[0].rolling, vec!["a".to_string()]);
        assert!(statuses.sets[0].settled.is_empty());
        assert_eq!(statuses.sets[0].max_concurrent, 1);

        // "a" settles on v1; the slot frees and "b" is admitted.
        let reports_a_done = HashMap::from([report("n-a", "v1", true), report("n-b", "v0", true)]);
        let statuses = plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
                reports: &reports_a_done,
            },
            &mut admitted,
            test_now(),
        );
        assert_eq!(admitted["a"].current.deployment, "v1");
        assert_eq!(admitted["b"].current.deployment, "v1");
        assert_eq!(statuses.sets[0].settled, vec!["a".to_string()]);
        assert_eq!(statuses.sets[0].rolling, vec!["b".to_string()]);
    }

    #[test]
    fn leader_failover_with_fresh_local_state_still_respects_max_concurrent() {
        // Regression for the node-local-admitted-state HA bug: a rescheduled/second leader that
        // lost its PVC must NOT re-baseline every member to the current desired and admit the whole
        // set at once. With the admitted set carried in durable in-cluster storage, the new leader
        // loads the SAME map even though its local disk is empty, so the throttle holds.
        let group_labels = pair_labels();
        let node_groups = pair_node_groups();
        let reports_v0 = HashMap::from([report("n-a", "v0", true), report("n-b", "v0", true)]);
        let sets = [pair_set()];
        let all_v1 = || {
            BTreeMap::from([
                ("a".to_string(), group("a", deployment_named("v1"))),
                ("b".to_string(), group("b", deployment_named("v1"))),
            ])
        };

        // Leader 1: seed baseline v0, then admit exactly one of the pair toward v1.
        let mut admitted = BTreeMap::new();
        let mut groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment_named("v0"))),
            ("b".to_string(), group("b", deployment_named("v0"))),
        ]);
        plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
                reports: &reports_v0,
            },
            &mut admitted,
            test_now(),
        );
        let mut groups = all_v1();
        let statuses = plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
                reports: &reports_v0,
            },
            &mut admitted,
            test_now(),
        );
        assert_eq!(statuses.sets[0].rolling, vec!["a".to_string()]);
        assert_eq!(admitted["a"].current.deployment, "v1");
        assert_eq!(admitted["b"].current.deployment, "v0");

        // Failover: the durable admitted set survives in-cluster, so the new leader loads the SAME
        // map. Neither member has settled on v1 yet (agents still report v0).
        let mut failover_admitted = admitted.clone();
        let mut failover_groups = all_v1();
        let failover_statuses = plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &mut failover_groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
                reports: &reports_v0,
            },
            &mut failover_admitted,
            test_now(),
        );
        assert_eq!(
            failover_admitted["a"].current.deployment, "v1",
            "the in-flight member keeps rolling"
        );
        assert_eq!(
            failover_admitted["b"].current.deployment, "v0",
            "the held member is NOT mass-admitted across failover"
        );
        assert_eq!(
            failover_statuses.sets[0].rolling,
            vec!["a".to_string()],
            "max_concurrent held across the leader change"
        );

        // Contrast: a leader that lost the durable state too (empty admitted map — the old cold-PVC
        // bug) would re-seed both baselines to the current desired and admit BOTH at once. This is
        // exactly the breach the durable in-cluster store prevents.
        let mut cold_admitted = BTreeMap::new();
        let mut cold_groups = all_v1();
        plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &mut cold_groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
                reports: &reports_v0,
            },
            &mut cold_admitted,
            test_now(),
        );
        assert_eq!(cold_admitted["a"].current.deployment, "v1");
        assert_eq!(
            cold_admitted["b"].current.deployment, "v1",
            "empty-state reseed mass-admits both members — the very breach durable admitted state prevents"
        );
    }

    fn set_named(name: &str, label_key: &str, label_value: &str) -> UpdateGroupSet {
        UpdateGroupSet::new(
            name,
            crate::UpdateGroupSetSpec {
                selector: crate::LabelSelector {
                    match_labels: BTreeMap::from([(label_key.into(), label_value.into())]),
                },
                max_concurrent: None,
                rollout_windows: vec![],
                calendar: vec![],
            },
        )
    }

    #[test]
    fn a_shared_group_is_held_until_every_governing_set_has_a_slot() {
        // set-X = {a, b}, roll = {b, c}; b is shared by both (N=1 each). Labels:
        //   a: {set: X}          b: {set: X, roll: r}          c: {set: Y, roll: r}
        let mut groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment_named("v0"))),
            ("b".to_string(), group("b", deployment_named("v0"))),
            ("c".to_string(), group("c", deployment_named("v0"))),
        ]);
        let group_labels = BTreeMap::from([
            (
                "a".to_string(),
                BTreeMap::from([("set".to_string(), "X".to_string())]),
            ),
            (
                "b".to_string(),
                BTreeMap::from([
                    ("set".to_string(), "X".to_string()),
                    ("roll".to_string(), "r".to_string()),
                ]),
            ),
            (
                "c".to_string(),
                BTreeMap::from([
                    ("set".to_string(), "Y".to_string()),
                    ("roll".to_string(), "r".to_string()),
                ]),
            ),
        ]);
        let node_groups = BTreeMap::from([
            ("n-a".to_string(), "a".to_string()),
            ("n-b".to_string(), "b".to_string()),
            ("n-c".to_string(), "c".to_string()),
        ]);
        let sets = [set_named("X", "set", "X"), set_named("roll", "roll", "r")];
        let all_v0 = HashMap::from([
            report("n-a", "v0", true),
            report("n-b", "v0", true),
            report("n-c", "v0", true),
        ]);
        // Seed baseline.
        let mut admitted = BTreeMap::new();
        plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
                reports: &all_v0,
            },
            &mut admitted,
            test_now(),
        );

        // Everyone wants v1. In set X (N=1): a and b compete. In roll (N=1): b and c compete.
        // Most-constrained first admits the shared b, consuming X's and roll's only slot, so
        // a is held (X full) and c is held (roll full) — b rolls alone.
        for g in ["a", "b", "c"] {
            groups.get_mut(g).unwrap().deployment = deployment_named("v1");
        }
        let statuses = plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
                reports: &all_v0,
            },
            &mut admitted,
            test_now(),
        );
        assert_eq!(
            admitted["b"].current.deployment, "v1",
            "shared group b rolls first"
        );
        assert_eq!(
            admitted["a"].current.deployment, "v0",
            "a held: set X's slot taken by b"
        );
        assert_eq!(
            admitted["c"].current.deployment, "v0",
            "c held: roll's slot taken by b"
        );
        // b is reported as shared by both sets.
        assert!(statuses
            .sets
            .iter()
            .all(|s| s.shared == vec!["b".to_string()]));
    }

    #[test]
    fn a_forged_report_never_settles_a_member() {
        // Group `a`'s node presents a healthy, fresh report signed by the WRONG key (a forgery);
        // group `b`'s node presents a genuine one. The throttle must verify against each node's
        // pinned key: `a` must NOT settle (so a forged report can never free a concurrency slot and
        // advance the rollout over a node that never actually settled), while `b` does.
        let mut groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment_named("v1"))),
            ("b".to_string(), group("b", deployment_named("v1"))),
        ]);
        let group_labels = pair_labels();
        let node_groups = BTreeMap::from([
            ("n-a".to_string(), "a".to_string()),
            ("n-b".to_string(), "b".to_string()),
        ]);
        let identity = crate::deployment_identity(&deployment_named("v1")).unwrap();
        let mut report_a = NodeReport::new("n-a", "v1", identity, "v1", DIGEST, true);
        report_a.reported_at_ms = test_now().timestamp_millis() as u64;
        // Genuinely signed, but by a key the control plane never pinned for this node — the forgery a
        // bucket writer could mount without the node's own key.
        let wrong_key =
            updated::csr::key_pem_to_pkcs8_der(&updated::csr::generate_key().unwrap()).unwrap();
        let forged = updated_contracts::telemetry::sign_report(&report_a, &wrong_key).unwrap();
        let reports = HashMap::from([("n-a".to_string(), forged), report("n-b", "v1", true)]);
        let mut admitted = BTreeMap::from([
            ("a".to_string(), admitted(deployment_named("v1"))),
            ("b".to_string(), admitted(deployment_named("v1"))),
        ]);
        let statuses = plan_rollouts(
            &[pair_set()],
            RolloutInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &pubkeys(&node_groups),
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
            },
            &mut admitted,
            test_now(),
        );
        assert!(
            !statuses.sets[0].settled.contains(&"a".to_string()),
            "a forged report must not settle its member"
        );
        assert!(
            statuses.sets[0].rolling.contains(&"a".to_string()),
            "the unverified member is still rolling, not settled"
        );
        assert!(
            statuses.sets[0].settled.contains(&"b".to_string()),
            "a genuine report settles its member"
        );
    }

    fn windowed_set(windows: Vec<crate::window::RolloutWindow>) -> UpdateGroupSet {
        UpdateGroupSet::new(
            "pair-00",
            crate::UpdateGroupSetSpec {
                selector: crate::LabelSelector {
                    match_labels: BTreeMap::from([("set".into(), "pair-00".into())]),
                },
                max_concurrent: None,
                rollout_windows: windows,
                calendar: vec![],
            },
        )
    }

    fn at(rfc3339: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(rfc3339)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn a_closed_window_freezes_new_rollouts_then_opens() {
        let mut groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment_named("v0"))),
            ("b".to_string(), group("b", deployment_named("v0"))),
        ]);
        let group_labels = pair_labels();
        let node_groups = pair_node_groups();
        // Reports are stamped against the instant each pass is planned at, so a member is settled
        // on v0 whichever day the pass runs.
        let reports_v0 = |now| {
            HashMap::from([
                report_at(now, "n-a", "v0", true),
                report_at(now, "n-b", "v0", true),
            ])
        };
        // "Every Sunday" — closed on a Monday, open on the Sunday.
        let sets = [windowed_set(vec![crate::window::RolloutWindow {
            weekdays: vec![crate::window::Weekday::Sunday],
            ..Default::default()
        }])];
        let mut admitted = BTreeMap::new();

        // Seed baseline at v0 while closed (Monday). Baseline is never a throttled rollout,
        // so both seed regardless of the window.
        let monday = at("2026-07-20T12:00:00Z");
        plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
                reports: &reports_v0(monday),
            },
            &mut admitted,
            monday, // closed
        );

        // Both want v1 while closed: nothing new is admitted — the set is frozen.
        groups.get_mut("a").unwrap().deployment = deployment_named("v1");
        groups.get_mut("b").unwrap().deployment = deployment_named("v1");
        let statuses = plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
                reports: &reports_v0(monday),
            },
            &mut admitted,
            monday, // closed
        );
        assert_eq!(
            admitted["a"].current.deployment, "v0",
            "held: window closed"
        );
        assert_eq!(
            admitted["b"].current.deployment, "v0",
            "held: window closed"
        );
        assert!(statuses.sets[0].frozen);
        assert!(statuses.sets[0].rolling.is_empty());

        // Sunday arrives: the window opens and the set admits up to max_concurrent (1 here).
        groups.get_mut("a").unwrap().deployment = deployment_named("v1");
        groups.get_mut("b").unwrap().deployment = deployment_named("v1");
        let sunday = at("2026-07-26T12:00:00Z");
        let statuses = plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
                reports: &reports_v0(sunday),
            },
            &mut admitted,
            sunday, // open
        );
        assert_eq!(
            admitted["a"].current.deployment, "v1",
            "admitted: window open"
        );
        assert_eq!(
            admitted["b"].current.deployment, "v0",
            "held by concurrency, not the window"
        );
        assert!(!statuses.sets[0].frozen);
        assert_eq!(statuses.sets[0].rolling, vec!["a".to_string()]);
    }

    fn calendared_set(calendar: Vec<crate::window::CalendarEntry>) -> UpdateGroupSet {
        UpdateGroupSet::new(
            "pair-00",
            crate::UpdateGroupSetSpec {
                selector: crate::LabelSelector {
                    match_labels: BTreeMap::from([("set".into(), "pair-00".into())]),
                },
                max_concurrent: None,
                rollout_windows: vec![],
                calendar,
            },
        )
    }

    #[test]
    fn a_dated_calendar_gates_then_runs_out_and_falls_back_open() {
        let mut groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment_named("v0"))),
            ("b".to_string(), group("b", deployment_named("v0"))),
        ]);
        let group_labels = pair_labels();
        let node_groups = pair_node_groups();
        // The only approved window is 2026-08-25 06:00–09:00 UTC.
        let sets = [calendared_set(vec![crate::window::CalendarEntry {
            date: "2026-08-25".into(),
            start: "06:00".into(),
            end: "09:00".into(),
        }])];
        let mut admitted = BTreeMap::new();
        let seed = |groups: &mut BTreeMap<String, ResolvedGroup>,
                    admitted: &mut BTreeMap<String, AdmittedDeployment>,
                    now| {
            // Both members report themselves settled on v0 as of this pass.
            let reports_v0 = HashMap::from([
                report_at(now, "n-a", "v0", true),
                report_at(now, "n-b", "v0", true),
            ]);
            plan_rollouts(
                &sets,
                RolloutInputs {
                    groups,
                    group_labels: &group_labels,
                    node_groups: &node_groups,
                    public_keys: &pubkeys(&node_groups),
                    published: &BTreeMap::new(),
                    held: &BTreeMap::new(),
                    reports: &reports_v0,
                },
                admitted,
                now,
            )
        };

        // Baseline seeded before the window (baseline is never throttled).
        seed(&mut groups, &mut admitted, at("2026-08-25T05:00:00Z"));

        // Want v1 before the window: frozen (outside the dated window).
        groups.get_mut("a").unwrap().deployment = deployment_named("v1");
        groups.get_mut("b").unwrap().deployment = deployment_named("v1");
        let statuses = seed(&mut groups, &mut admitted, at("2026-08-25T05:30:00Z"));
        assert_eq!(
            admitted["a"].current.deployment, "v0",
            "held: before the window"
        );
        assert!(statuses.sets[0].frozen);

        // Inside the window: admits up to max_concurrent (1).
        groups.get_mut("a").unwrap().deployment = deployment_named("v1");
        groups.get_mut("b").unwrap().deployment = deployment_named("v1");
        let statuses = seed(&mut groups, &mut admitted, at("2026-08-25T07:00:00Z"));
        assert_eq!(
            admitted["a"].current.deployment, "v1",
            "admitted inside the window"
        );
        assert_eq!(
            admitted["b"].current.deployment, "v0",
            "held by concurrency"
        );
        assert!(!statuses.sets[0].frozen);

        // Long after the window: the calendar has run out, so it stops gating and the held
        // member is free to roll (fallback to open).
        groups.get_mut("a").unwrap().deployment = deployment_named("v1");
        groups.get_mut("b").unwrap().deployment = deployment_named("v1");
        // "a" settled on v1 so its slot is free; "b" now rolls because the calendar ran out.
        let later = at("2026-09-15T12:00:00Z");
        let reports_a_done = HashMap::from([
            report_at(later, "n-a", "v1", true),
            report_at(later, "n-b", "v0", true),
        ]);
        let statuses = plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
                reports: &reports_a_done,
            },
            &mut admitted,
            later,
        );
        assert_eq!(
            admitted["b"].current.deployment, "v1",
            "calendar ran out: b rolls"
        );
        assert!(!statuses.sets[0].frozen);
    }

    /// A whole-day calendar entry for `date`, so the exact wall-clock moment a test runs at
    /// never lands on a window boundary.
    fn full_day(date: chrono::NaiveDate) -> crate::window::CalendarEntry {
        crate::window::CalendarEntry {
            date: date.format("%Y-%m-%d").to_string(),
            start: "00:00".into(),
            end: "24:00".into(),
        }
    }

    /// Two members of one set, baseline v0, one agent each. Returns everything an
    /// `plan_rollouts` call needs plus the reports showing both settled on v0.
    #[allow(clippy::type_complexity)]
    fn two_member_pair(
        now: chrono::DateTime<chrono::Utc>,
    ) -> (
        BTreeMap<String, ResolvedGroup>,
        BTreeMap<String, BTreeMap<String, String>>,
        BTreeMap<String, String>,
        HashMap<String, Envelope>,
    ) {
        let groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment_named("v0"))),
            ("b".to_string(), group("b", deployment_named("v0"))),
        ]);
        let reports = HashMap::from([
            report_at(now, "n-a", "v0", true),
            report_at(now, "n-b", "v0", true),
        ]);
        (groups, pair_labels(), pair_node_groups(), reports)
    }

    // These two exercise the operator's real admission decision (`plan_rollouts`, the same
    // call `reconcile_once` makes) against calendars built from the actual current time —
    // one covering "now", one a year out — so the gating is validated end-to-end against the
    // wall clock rather than a hardcoded date. The whole-day windows keep the outcome
    // independent of the exact instant the test runs.

    #[test]
    fn calendar_window_covering_the_current_time_admits_the_rollout() {
        let now = chrono::Utc::now();
        // The only approved window is the whole of today (UTC), so `now` is inside it.
        let sets = [calendared_set(vec![full_day(now.date_naive())])];
        let (mut groups, group_labels, node_groups, reports) = two_member_pair(now);
        let mut admitted = BTreeMap::new();
        let mut run = |groups: &mut BTreeMap<String, ResolvedGroup>| {
            plan_rollouts(
                &sets,
                RolloutInputs {
                    groups,
                    group_labels: &group_labels,
                    node_groups: &node_groups,
                    public_keys: &pubkeys(&node_groups),
                    published: &BTreeMap::new(),
                    held: &BTreeMap::new(),
                    reports: &reports,
                },
                &mut admitted,
                now,
            )
        };

        run(&mut groups); // seed baseline v0
        groups.get_mut("a").unwrap().deployment = deployment_named("v1");
        groups.get_mut("b").unwrap().deployment = deployment_named("v1");
        let statuses = run(&mut groups);

        assert!(!statuses.sets[0].frozen, "the current-time window is open");
        assert_eq!(
            admitted["a"].current.deployment, "v1",
            "admitted: inside today's window"
        );
        assert_eq!(
            admitted["b"].current.deployment, "v0",
            "held by concurrency, not the calendar"
        );
        assert_eq!(statuses.sets[0].rolling, vec!["a".to_string()]);
    }

    #[test]
    fn calendar_window_a_year_from_today_freezes_the_rollout() {
        let now = chrono::Utc::now();
        // The only approved window is a year out — a pending future window, so the set is
        // frozen now (it has not run out; it has not yet begun).
        let next_year = now.date_naive() + chrono::Duration::days(365);
        let sets = [calendared_set(vec![full_day(next_year)])];
        let (mut groups, group_labels, node_groups, reports) = two_member_pair(now);
        let mut admitted = BTreeMap::new();
        let mut run = |groups: &mut BTreeMap<String, ResolvedGroup>| {
            plan_rollouts(
                &sets,
                RolloutInputs {
                    groups,
                    group_labels: &group_labels,
                    node_groups: &node_groups,
                    public_keys: &pubkeys(&node_groups),
                    published: &BTreeMap::new(),
                    held: &BTreeMap::new(),
                    reports: &reports,
                },
                &mut admitted,
                now,
            )
        };

        run(&mut groups); // seed baseline v0
        groups.get_mut("a").unwrap().deployment = deployment_named("v1");
        groups.get_mut("b").unwrap().deployment = deployment_named("v1");
        let statuses = run(&mut groups);

        assert!(
            statuses.sets[0].frozen,
            "a window a year out has not opened yet"
        );
        assert_eq!(
            admitted["a"].current.deployment, "v0",
            "held: outside the calendar"
        );
        assert_eq!(
            admitted["b"].current.deployment, "v0",
            "held: outside the calendar"
        );
        assert!(statuses.sets[0].rolling.is_empty());
    }

    #[test]
    fn dependency_edges_wait_for_authentic_prerequisite_settlement() {
        let mut groups = BTreeMap::from([
            (
                "initialize".into(),
                group("initialize", deployment_named("v0")),
            ),
            ("join".into(), group("join", deployment_named("v0"))),
        ]);
        groups.get_mut("join").unwrap().depends_on = vec!["initialize".into()];
        let node_groups = BTreeMap::from([
            ("node-init".into(), "initialize".into()),
            ("node-join".into(), "join".into()),
        ]);
        let keys = pubkeys(&node_groups);
        let labels = BTreeMap::new();
        let mut reports = HashMap::from([
            report("node-init", "v0", true),
            report("node-join", "v0", true),
        ]);
        let mut admitted = BTreeMap::new();
        let run = |groups: &BTreeMap<String, ResolvedGroup>,
                   reports: &HashMap<String, Envelope>,
                   admitted: &mut BTreeMap<String, AdmittedDeployment>| {
            plan_rollouts(
                &[],
                RolloutInputs {
                    groups,
                    group_labels: &labels,
                    node_groups: &node_groups,
                    reports,
                    public_keys: &keys,
                    published: &BTreeMap::new(),
                    held: &BTreeMap::new(),
                },
                admitted,
                test_now(),
            )
        };

        run(&groups, &reports, &mut admitted);
        groups.get_mut("initialize").unwrap().deployment = deployment_named("v1");
        groups.get_mut("join").unwrap().deployment = deployment_named("v1");
        run(&groups, &reports, &mut admitted);
        assert_eq!(admitted["initialize"].current.deployment, "v1");
        assert_eq!(admitted["join"].current.deployment, "v0");

        reports.insert("node-init".into(), report("node-init", "v1", true).1);
        run(&groups, &reports, &mut admitted);
        assert_eq!(admitted["join"].current.deployment, "v1");
    }

    #[test]
    fn an_operator_can_revert_a_rollout_that_never_settles() {
        // The first node takes v1 and never becomes healthy, so `previous` never clears. Without an
        // explicit revert path the group is stuck half-rolled forever: every new desired value is
        // refused while a predecessor is held — including the one that undoes the rollout.
        let (mut groups, node_groups, labels) = three_node_group();
        let keys = pubkeys(&node_groups);
        let mut admitted = BTreeMap::from([(
            "g".into(),
            AdmittedDeployment {
                current: deployment_named("v1"),
                previous: vec![deployment_named("v0")],
            },
        )]);
        groups.get_mut("g").unwrap().deployment = deployment_named("v0");
        let reports = HashMap::from([
            report("n0", "v1", false), // took the new deployment and is not healthy
            report("n1", "v0", true),
            report("n2", "v0", true),
        ]);
        let plan = plan_rollouts(
            &[],
            RolloutInputs {
                groups: &groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &keys,
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
            },
            &mut admitted,
            test_now(),
        );
        assert_eq!(
            admitted["g"].current.deployment, "v0",
            "the revert is admitted"
        );
        assert_eq!(
            admitted["g"].previous[0].deployment, "v1",
            "and it is staged like any other change: the nodes left to move are the ones already \
             handed the half-rolled v1"
        );
        assert!(
            plan.node_deployments
                .values()
                .all(|deployment| deployment.deployment == "v0"),
            "and every node is published back onto the predecessor"
        );
    }

    #[test]
    fn a_group_with_no_agents_never_holds_its_sets_concurrency_slot() {
        // A pre-enrollment (or decommissioned) member has no telemetry and so can never be
        // "settled" — but it is not rolling either, and treating it as in-flight starves every
        // sibling in the set forever.
        let mut groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment_named("v0"))),
            ("b".to_string(), group("b", deployment_named("v0"))),
        ]);
        let group_labels = pair_labels();
        // Only `b` has an agent; `a` selects nobody.
        let node_groups = BTreeMap::from([("n-b".to_string(), "b".to_string())]);
        let reports = HashMap::from([report("n-b", "v0", true)]);
        let sets = [pair_set()];
        let mut admitted = BTreeMap::new();
        let run = |groups: &BTreeMap<String, ResolvedGroup>,
                   admitted: &mut BTreeMap<String, AdmittedDeployment>| {
            plan_rollouts(
                &sets,
                RolloutInputs {
                    groups,
                    group_labels: &group_labels,
                    node_groups: &node_groups,
                    public_keys: &pubkeys(&node_groups),
                    published: &BTreeMap::new(),
                    held: &BTreeMap::new(),
                    reports: &reports,
                },
                admitted,
                test_now(),
            )
        };
        run(&groups, &mut admitted);

        groups.get_mut("b").unwrap().deployment = deployment_named("v1");
        let statuses = run(&groups, &mut admitted);
        assert_eq!(
            admitted["b"].current.deployment, "v1",
            "the empty member must not consume the set's only slot"
        );
        assert_eq!(statuses.sets[0].rolling, vec!["b".to_string()]);
        assert_eq!(statuses.sets[0].unobservable, vec!["a".to_string()]);

        // And it stays updatable itself: it holds no slot of its own, so once its sibling stops
        // rolling the set's slot is free for it. Nothing it can (never) report gates its retarget.
        groups.get_mut("b").unwrap().deployment = deployment_named("v0");
        groups.get_mut("a").unwrap().deployment = deployment_named("v1");
        run(&groups, &mut admitted);
        run(&groups, &mut admitted);
        assert_eq!(
            admitted["a"].current.deployment, "v1",
            "an agent-less member must not be pinned forever to its first admission"
        );
    }

    /// An offline-provisioned agent has no pinned public key, so nothing it writes can ever be
    /// verified and its group can never be seen as settled. That must make the group UNOBSERVABLE,
    /// not permanently rolling: it holds no concurrency slot, its predecessor retires, and the
    /// operator can still retarget it.
    #[test]
    fn a_group_holding_an_unverifiable_agent_stays_updatable() {
        let mut groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment_named("v0"))),
            ("b".to_string(), group("b", deployment_named("v0"))),
        ]);
        let group_labels = pair_labels();
        let node_groups = pair_node_groups();
        let reports = HashMap::from([report("n-a", "v0", true), report("n-b", "v0", true)]);
        // `n-b` was declared offline and never enrolled, so it has no pinned key.
        let keys: HashMap<String, Vec<u8>> =
            HashMap::from([("n-a".to_string(), TEST_KEY.1.clone())]);
        let sets = [pair_set()];
        let mut admitted = BTreeMap::new();
        let mut published = BTreeMap::new();
        // A real reconcile feeds the identities it just published back into the next pass; for a
        // blind node that map is the ONLY way its staging can be observed at all.
        let run = |groups: &BTreeMap<String, ResolvedGroup>,
                   admitted: &mut BTreeMap<String, AdmittedDeployment>,
                   published: &mut BTreeMap<String, String>| {
            let plan = plan_rollouts(
                &sets,
                RolloutInputs {
                    groups,
                    group_labels: &group_labels,
                    node_groups: &node_groups,
                    public_keys: &keys,
                    published,
                    reports: &reports,
                    held: &BTreeMap::new(),
                },
                admitted,
                test_now(),
            );
            *published = published_from(&plan);
            plan
        };
        run(&groups, &mut admitted, &mut published);

        groups.get_mut("b").unwrap().deployment = deployment_named("v1");
        let staging = run(&groups, &mut admitted, &mut published);
        assert_eq!(
            admitted["b"].current.deployment, "v1",
            "a group whose reports can never be verified must still be retargetable"
        );
        assert_eq!(
            staging.sets[0].rolling,
            vec!["b".to_string()],
            "while the blind node is still being handed the new deployment the rollout is in \
             flight, whatever telemetry can (never) say about it"
        );

        // One pass later every node has been handed it, so the staging is finished and the member
        // goes back to being unobservable rather than rolling forever.
        let statuses = run(&groups, &mut admitted, &mut published);
        assert!(admitted["b"].previous.is_empty());
        assert_eq!(statuses.sets[0].unobservable, vec!["b".to_string()]);
        assert!(statuses.sets[0].rolling.is_empty());

        // It holds no slot once it has stopped staging, so its verifiable sibling rolls next.
        groups.get_mut("a").unwrap().deployment = deployment_named("v1");
        run(&groups, &mut admitted, &mut published);
        assert_eq!(admitted["a"].current.deployment, "v1");
    }

    /// A group holding ONE unverifiable agent alongside verifiable ones keeps a real, stageable
    /// rollout, so it stays [`Progress::Rolling`] and never settles — but that must not make it
    /// un-updatable. The operator's retarget preempts the rollout it can never finish.
    #[test]
    fn a_group_that_can_never_settle_is_still_retargetable() {
        let (mut groups, node_groups, labels) = three_node_group();
        groups.get_mut("g").unwrap().deployment = deployment_named("v2");
        let mut keys = pubkeys(&node_groups);
        keys.remove("n2");
        let mut admitted = BTreeMap::from([("g".into(), admitted(deployment_named("v1")))]);
        let reports = HashMap::from([report("n0", "v1", true), report("n1", "v1", true)]);
        plan_rollouts(
            &[],
            RolloutInputs {
                groups: &groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &keys,
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
            },
            &mut admitted,
            test_now(),
        );
        assert_eq!(admitted["g"].current.deployment, "v2");
        assert_eq!(
            admitted["g"].previous[0].deployment, "v1",
            "the rollout still stages: the unverifiable node does not disable maxUnavailable"
        );
    }

    /// A node rebooting into the update it was just handed stops reporting for longer than the
    /// telemetry freshness bound. Judging solely on live telemetry republished it under the
    /// PREDECESSOR — telling a machine mid-update to go back — and then flipped it forward again
    /// once it reported. A node's assignment only ever moves forward within a rollout.
    #[test]
    fn a_node_that_goes_silent_mid_update_is_not_demoted() {
        let (mut groups, node_groups, labels) = three_node_group();
        groups.get_mut("g").unwrap().deployment = deployment_named("v1");
        let mut admitted = BTreeMap::from([(
            "g".into(),
            AdmittedDeployment {
                current: deployment_named("v1"),
                previous: vec![deployment_named("v0")],
            },
        )]);
        // `n0` was handed v1 last generation and is now rebooting: no fresh report at all.
        let published = BTreeMap::from([(
            "n0".to_string(),
            crate::deployment_identity(&deployment_named("v1")).unwrap(),
        )]);
        let reports = HashMap::from([report("n1", "v0", true), report("n2", "v0", true)]);
        let outcome = plan_rollouts(
            &[],
            RolloutInputs {
                groups: &groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &pubkeys(&node_groups),
                published: &published,
                held: &BTreeMap::new(),
            },
            &mut admitted,
            test_now(),
        );
        assert_eq!(outcome.node_deployments["n0"].deployment, "v1");
        // The silent node still spends the availability budget, so nothing else advances.
        assert_eq!(outcome.node_deployments["n1"].deployment, "v0");
        assert_eq!(outcome.node_deployments["n2"].deployment, "v0");
    }

    #[test]
    fn a_first_sighting_is_gated_like_every_later_admission() {
        // Cold cluster: nothing admitted, no telemetry yet. A consumer group must NOT be published
        // on first sight just because it has no admitted entry — its prerequisite has not settled
        // and its inputs are unresolved, so it would ship with an empty `runtime.inputs`. Its nodes
        // get no assignment at all this generation and hold whatever they already have.
        let mut groups = BTreeMap::from([
            (
                "initialize".into(),
                group("initialize", deployment_named("init-v1")),
            ),
            ("join".into(), group("join", deployment_named("join-v1"))),
        ]);
        groups.get_mut("join").unwrap().depends_on = vec!["initialize".into()];
        groups.get_mut("join").unwrap().inputs_ready = false;
        let node_groups = BTreeMap::from([
            ("node-init".into(), "initialize".into()),
            ("node-join".into(), "join".into()),
        ]);
        let keys = pubkeys(&node_groups);
        let labels = BTreeMap::new();
        let mut admitted = BTreeMap::new();
        let plan = plan_rollouts(
            &[],
            RolloutInputs {
                groups: &groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &HashMap::new(),
                public_keys: &keys,
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
            },
            &mut admitted,
            test_now(),
        );
        assert_eq!(admitted["initialize"].current.deployment, "init-v1");
        assert!(
            !admitted.contains_key("join"),
            "a consumer whose inputs are unresolved is not admitted on first sight"
        );
        assert!(
            !plan.node_deployments.contains_key("node-join"),
            "an unadmitted group publishes nothing for its nodes"
        );

        // The producer settles and the consumer's inputs resolve: now it is admitted.
        groups.get_mut("join").unwrap().inputs_ready = true;
        let reports = HashMap::from([report("node-init", "init-v1", true)]);
        let plan = plan_rollouts(
            &[],
            RolloutInputs {
                groups: &groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &keys,
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
            },
            &mut admitted,
            test_now(),
        );
        assert_eq!(admitted["join"].current.deployment, "join-v1");
        assert_eq!(plan.node_deployments["node-join"].deployment, "join-v1");
    }

    #[test]
    fn a_same_name_deployment_change_is_still_re_admitted_and_published() {
        // Dependency inputs resolve inside the control plane, so the deployment body changes with
        // no name to bump. Admission that compared only the name dropped this forever while
        // reporting the group Published.
        let (mut groups, node_groups, labels) = three_node_group();
        let keys = pubkeys(&node_groups);
        let reports = HashMap::from([
            report("n0", "v0", true),
            report("n1", "v0", true),
            report("n2", "v0", true),
        ]);
        let mut admitted = BTreeMap::new();
        let run = |groups: &BTreeMap<String, ResolvedGroup>,
                   admitted: &mut BTreeMap<String, AdmittedDeployment>| {
            plan_rollouts(
                &[],
                RolloutInputs {
                    groups,
                    group_labels: &labels,
                    node_groups: &node_groups,
                    reports: &reports,
                    public_keys: &keys,
                    published: &BTreeMap::new(),
                    held: &BTreeMap::new(),
                },
                admitted,
                test_now(),
            )
        };
        run(&groups, &mut admitted);

        // Same `deployment` identity, different body.
        let resolved = updated_contracts::telemetry::OutputValue::String {
            value: "https://leader-0:8200".into(),
        };
        groups
            .get_mut("g")
            .unwrap()
            .deployment
            .runtime
            .inputs
            .insert("leader".into(), resolved.clone());
        let plan = run(&groups, &mut admitted);

        assert_eq!(
            admitted["g"].current.runtime.inputs["leader"], resolved,
            "a body change under an unchanged name must be re-admitted"
        );
        assert!(
            !admitted["g"].previous.is_empty(),
            "and it must be STAGED: the predecessor is retained so the group rolls in batches"
        );
        // `max_unavailable` is 1 for this fixture, so exactly one of the three nodes receives the
        // new body this pass and the other two hold the old one.
        let advanced = plan
            .node_deployments
            .values()
            .filter(|deployment| deployment.runtime.inputs.get("leader") == Some(&resolved))
            .count();
        assert_eq!(
            advanced, 1,
            "an edit that renames nothing must still respect maxUnavailable"
        );
    }
    /// The durable "node → deployment identity we published for it" map, as the operator would
    /// persist it after signing this generation. Feeding it back into the next pass is what a real
    /// reconcile loop does, and it is the only way a blind node's staging can be observed at all.
    fn published_from(plan: &RolloutPlan) -> BTreeMap<String, String> {
        plan.node_deployments
            .iter()
            .filter_map(|(node, deployment)| {
                Some((node.clone(), crate::deployment_identity(deployment)?))
            })
            .collect()
    }

    /// An offline-provisioned agent (no pinned key, so nothing it writes is evidence) sitting in a
    /// group alongside enrolled ones must not wedge that group: the rollout stages through every
    /// node, one `maxUnavailable` batch per pass, and finishes. Judging the blind node as "not yet
    /// healthy" spent the whole availability budget on a node that could never release it, so the
    /// group re-published its predecessor to everyone forever while claiming to be rolling.
    #[test]
    fn a_blind_agent_never_wedges_its_groups_healthy_siblings() {
        let (mut groups, node_groups, labels) = three_node_group();
        // `n2` was declared offline and never enrolled.
        let mut keys = pubkeys(&node_groups);
        keys.remove("n2");
        let mut admitted = BTreeMap::from([("g".into(), admitted(deployment_named("v0")))]);
        let mut published = BTreeMap::new();
        let mut reports = HashMap::from([report("n0", "v0", true), report("n1", "v0", true)]);
        groups.get_mut("g").unwrap().deployment = deployment_named("v1");

        let mut advanced = Vec::new();
        for _ in 0..4 {
            let plan = plan_rollouts(
                &[],
                RolloutInputs {
                    groups: &groups,
                    group_labels: &labels,
                    node_groups: &node_groups,
                    reports: &reports,
                    public_keys: &keys,
                    published: &published,
                    held: &BTreeMap::new(),
                },
                &mut admitted,
                test_now(),
            );
            advanced.push(
                plan.node_deployments
                    .values()
                    .filter(|deployment| deployment.deployment == "v1")
                    .count(),
            );
            published = published_from(&plan);
            // Every observable node that was handed v1 reports it healthy on the next tick.
            for (node, deployment) in &plan.node_deployments {
                if keys.contains_key(node) {
                    let (node, envelope) = report(node, &deployment.deployment, true);
                    reports.insert(node, envelope);
                }
            }
        }
        assert_eq!(
            advanced,
            vec![1, 2, 3, 3],
            "one node per pass, blind node included, until the whole group has v1"
        );
        assert!(
            admitted["g"].previous.is_empty(),
            "and the rollout finishes: staging is judged on what was published, so a node that can \
             never report still completes it"
        );
    }

    /// A node enrolled INTO a group while that group's rollout is already staged must not freeze
    /// it. Such a node has no placement at all: nothing was ever published for it and it has never
    /// reported. Counting it against `maxUnavailable` was a deadlock, because with nothing to hold
    /// it on it is also left out of every generation it has no movement slot for — so it could
    /// never be published, never report, and never release the slot it was spending. The group
    /// stayed `Rolling` forever, holding its set's concurrency slot, and the new agent was never
    /// handed anything at all.
    #[test]
    fn an_agent_enrolled_mid_rollout_does_not_freeze_its_group() {
        let (mut groups, mut node_groups, labels) = three_node_group();
        // Two agents an autoscaler enrolled after the rollout to v1 was already staged: keyed, but
        // never published to and never heard from.
        node_groups.insert("n3".into(), "g".into());
        node_groups.insert("n4".into(), "g".into());
        let keys = pubkeys(&node_groups);
        let mut admitted = BTreeMap::from([("g".into(), admitted(deployment_named("v0")))]);
        let mut reports = HashMap::from([
            report("n0", "v0", true),
            report("n1", "v0", true),
            report("n2", "v0", true),
        ]);
        let mut published: BTreeMap<String, String> = ["n0", "n1", "n2"]
            .into_iter()
            .map(|node| {
                (
                    node.to_string(),
                    crate::deployment_identity(&deployment_named("v0")).unwrap(),
                )
            })
            .collect();
        groups.get_mut("g").unwrap().deployment = deployment_named("v1");

        let mut last = None;
        for _ in 0..12 {
            let plan = plan_rollouts(
                &[],
                RolloutInputs {
                    groups: &groups,
                    group_labels: &labels,
                    node_groups: &node_groups,
                    reports: &reports,
                    public_keys: &keys,
                    published: &published,
                    held: &BTreeMap::new(),
                },
                &mut admitted,
                test_now(),
            );
            published = published_from(&plan);
            for (node, deployment) in &plan.node_deployments {
                let (node, envelope) = report(node, &deployment.deployment, true);
                reports.insert(node, envelope);
            }
            last = Some(plan);
        }
        let plan = last.unwrap();
        assert_eq!(
            plan.node_deployments.len(),
            5,
            "every node of the group, the two new ones included, is in the generation"
        );
        assert!(
            plan.node_deployments
                .values()
                .all(|deployment| deployment.deployment == "v1"),
            "and the rollout reaches all of them: {:?}",
            plan.node_deployments
        );
        assert!(
            admitted["g"].previous.is_empty(),
            "so the rollout finishes and stops holding its set's concurrency slot"
        );
    }

    /// A blind node is never counted as healthy, only as unjudgeable: a group whose observable
    /// agents are all healthy on the desired deployment settles (so dependents are not blocked
    /// forever), while a group where NOTHING is observable is reported unobservable instead.
    #[test]
    fn settlement_excludes_blind_nodes_rather_than_assuming_them_healthy() {
        let (groups, node_groups, _) = three_node_group();
        let mut keys = pubkeys(&node_groups);
        keys.remove("n2");
        let reports = HashMap::from([report("n0", "v0", true), report("n1", "v0", true)]);
        let nothing_published = BTreeMap::new();
        let observations = Observations::new(
            &node_groups,
            &reports,
            &keys,
            &nothing_published,
            test_now().timestamp_millis() as u64,
        );
        assert_eq!(
            observations.progress("g", &admitted_now(&groups["g"].deployment)),
            Progress::Settled
        );
        assert_eq!(
            observations.evidence(
                "n2",
                &crate::deployment_identity(&groups["g"].deployment).unwrap()
            ),
            NodeEvidence::Blind,
            "the blind node is excluded from the verdict, never counted healthy"
        );

        let no_keys = HashMap::new();
        let blind_only = Observations::new(
            &node_groups,
            &reports,
            &no_keys,
            &nothing_published,
            test_now().timestamp_millis() as u64,
        );
        assert_eq!(
            blind_only.progress("g", &admitted_now(&groups["g"].deployment)),
            Progress::Unobservable,
            "a group nothing can be observed about is never claimed to be settled"
        );
    }

    /// Preemption of an in-flight rollout bypasses the set's concurrency SLOTS — it already holds
    /// one — but never its SCHEDULE. A rollout window is the operator's statement about when this
    /// fleet may change at all, so a spec change to an in-flight member waits for the window like
    /// every other change.
    #[test]
    fn preempting_an_in_flight_rollout_still_waits_for_the_rollout_window() {
        let (mut groups, node_groups, _) = three_node_group();
        let labels = BTreeMap::from([(
            "g".to_string(),
            BTreeMap::from([("set".to_string(), "pair-00".to_string())]),
        )]);
        let sets = [windowed_set(vec![crate::window::RolloutWindow {
            weekdays: vec![crate::window::Weekday::Sunday],
            ..Default::default()
        }])];
        let keys = pubkeys(&node_groups);
        // `g` is mid-rollout and rolling FORWARD: n0 has v1 and is healthy, n1/n2 still run v0.
        // Nothing reports the admitted deployment broken, so the retarget is ordinary new change.
        let mut admitted = BTreeMap::from([(
            "g".into(),
            AdmittedDeployment {
                current: deployment_named("v1"),
                previous: vec![deployment_named("v0")],
            },
        )]);
        let reports = HashMap::from([
            report_at(at("2026-07-19T01:30:00Z"), "n0", "v1", true),
            report_at(at("2026-07-19T01:30:00Z"), "n1", "v0", true),
            report_at(at("2026-07-19T01:30:00Z"), "n2", "v0", true),
        ]);
        groups.get_mut("g").unwrap().deployment = deployment_named("v2");
        let run = |now: chrono::DateTime<chrono::Utc>,
                   admitted: &mut BTreeMap<String, AdmittedDeployment>| {
            plan_rollouts(
                &sets,
                RolloutInputs {
                    groups: &groups,
                    group_labels: &labels,
                    node_groups: &node_groups,
                    reports: &reports,
                    public_keys: &keys,
                    published: &BTreeMap::new(),
                    held: &BTreeMap::new(),
                },
                admitted,
                now,
            )
        };
        // Tuesday afternoon: outside the Sunday window.
        let frozen = run(at("2026-07-21T14:00:00Z"), &mut admitted);
        assert_eq!(
            admitted["g"].current.deployment, "v1",
            "a frozen set admits nothing, preemption included"
        );
        assert!(frozen.sets[0].frozen);
        // Sunday, inside the window: the preemption goes through without needing a free slot.
        run(at("2026-07-19T01:30:00Z"), &mut admitted);
        assert_eq!(admitted["g"].current.deployment, "v2");
    }

    /// A rollback is a generation change like any other, so `maxUnavailable` applies to it.
    /// Clearing the predecessor on a rollback made `assign_nodes` take the no-predecessor path and
    /// downgrade every advanced machine in one signed generation.
    #[test]
    fn a_rollback_is_staged_one_node_at_a_time() {
        let node_groups: BTreeMap<String, String> = ["n0", "n1", "n2", "n3"]
            .into_iter()
            .map(|node| (node.to_string(), "g".to_string()))
            .collect();
        let groups = BTreeMap::from([("g".to_string(), group("g", deployment_named("v0")))]);
        let keys = pubkeys(&node_groups);
        // Half the group has already advanced to v1, healthily; the operator reverts to v0.
        let mut admitted = BTreeMap::from([(
            "g".into(),
            AdmittedDeployment {
                current: deployment_named("v1"),
                previous: vec![deployment_named("v0")],
            },
        )]);
        let reports = HashMap::from([
            report("n0", "v1", true),
            report("n1", "v1", true),
            report("n2", "v0", true),
            report("n3", "v0", true),
        ]);
        let plan = plan_rollouts(
            &[],
            RolloutInputs {
                groups: &groups,
                group_labels: &BTreeMap::new(),
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &keys,
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
            },
            &mut admitted,
            test_now(),
        );
        assert_eq!(admitted["g"].current.deployment, "v0");
        assert_eq!(
            admitted["g"].previous[0].deployment, "v1",
            "the nodes left to move are the ones already on v1, so v1 is what is staged away from"
        );
        let reverted = plan
            .node_deployments
            .values()
            .filter(|deployment| deployment.deployment == "v0")
            .count();
        assert_eq!(
            reverted, 3,
            "the two already-advanced nodes revert one at a time, not both at once"
        );
    }

    /// Losing every pinned key mid-rollout (the agents were deleted and re-created, or re-declared
    /// as `manual`) must not convert a throttled rollout into an unthrottled fleet-wide swap. The
    /// predecessor is retired on what was PUBLISHED, never on whether telemetry can be read, so the
    /// next change is still staged.
    #[test]
    fn a_group_that_loses_every_pinned_key_still_stages_its_next_change() {
        let (mut groups, node_groups, labels) = three_node_group();
        let mut admitted = BTreeMap::from([("g".into(), admitted(deployment_named("v0")))]);
        // Every node was published v0 by the last generation; none of them can be verified now.
        let published: BTreeMap<String, String> = node_groups
            .keys()
            .map(|node| {
                (
                    node.clone(),
                    crate::deployment_identity(&deployment_named("v0")).unwrap(),
                )
            })
            .collect();
        groups.get_mut("g").unwrap().deployment = deployment_named("v1");
        let plan = plan_rollouts(
            &[],
            RolloutInputs {
                groups: &groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &HashMap::new(),
                public_keys: &HashMap::new(),
                published: &published,
                held: &BTreeMap::new(),
            },
            &mut admitted,
            test_now(),
        );
        assert_eq!(
            admitted["g"].previous[0].deployment, "v0",
            "an unobservable group keeps its predecessor: staging is not an evidence question"
        );
        assert_eq!(
            plan.node_deployments
                .values()
                .filter(|deployment| deployment.deployment == "v1")
                .count(),
            1,
            "maxUnavailable still applies when nothing can be observed"
        );
    }

    type EscapeHatchFixture = (
        BTreeMap<String, ResolvedGroup>,
        BTreeMap<String, String>,
        BTreeMap<String, BTreeMap<String, String>>,
        [UpdateGroupSet; 1],
        BTreeMap<String, AdmittedDeployment>,
    );

    /// The windowed-set fixture the emergency-correction tests share: `g` governed by a
    /// Sunday-only set, already admitted to `v2` (rolled out inside the window) and now being
    /// retargeted on a Monday afternoon.
    fn escape_hatch_fixture() -> EscapeHatchFixture {
        let (groups, node_groups, _) = three_node_group();
        let labels = BTreeMap::from([(
            "g".to_string(),
            BTreeMap::from([("set".to_string(), "pair-00".to_string())]),
        )]);
        let sets = [windowed_set(vec![crate::window::RolloutWindow {
            weekdays: vec![crate::window::Weekday::Sunday],
            ..Default::default()
        }])];
        let admitted = BTreeMap::from([(
            "g".to_string(),
            AdmittedDeployment {
                current: deployment_named("v2"),
                previous: vec![deployment_named("v1")],
            },
        )]);
        (groups, node_groups, labels, sets, admitted)
    }

    /// Monday afternoon, far outside the Sunday window.
    fn monday() -> chrono::DateTime<chrono::Utc> {
        at("2026-07-20T14:00:00Z")
    }

    /// A schedule controls when NEW change is introduced; it must never trap a fleet on a release
    /// the operator is trying to escape. The hatch is the operator STATING the emergency
    /// (`spec.emergencyCorrection`), which is why it works in the case telemetry can never
    /// describe: a release that bricks the agent itself produces no reports at all, so every node
    /// is Silent and no amount of health evidence would ever have opened it.
    #[test]
    fn an_operator_declared_emergency_correction_is_admitted_outside_the_window() {
        let (mut groups, node_groups, labels, sets, mut admitted) = escape_hatch_fixture();
        let keys = pubkeys(&node_groups);
        // v2 bricked the agent: nothing reports anything, ever.
        let reports = HashMap::new();
        // The operator reverts to v1 and says so.
        groups.get_mut("g").unwrap().deployment = deployment_named("v1");
        groups.get_mut("g").unwrap().emergency_correction = true;
        let plan = plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &keys,
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
            },
            &mut admitted,
            monday(),
        );
        assert!(
            plan.sets[0].frozen,
            "the set really is outside its schedule; the declared emergency is what is exempt"
        );
        assert_eq!(
            admitted["g"].current.deployment, "v1",
            "a declared emergency correction must not wait six days for the next window, and \
             silence must not be able to refuse it"
        );
        assert_eq!(
            plan.sets[0].emergency,
            vec!["g".to_string()],
            "the set's status names the member that is bypassing its schedule"
        );
    }

    /// The converse, and the reason intent is stated rather than inferred: a group carrying a
    /// chronically unhealthy node (a failing downstream dependency, an expired licence) is NOT an
    /// emergency. Reading "some node reports unhealthy" as a correction silently exempted every
    /// later forward change to that group from the set's schedule.
    #[test]
    fn a_chronically_unhealthy_member_does_not_exempt_an_ordinary_change_from_the_window() {
        let (mut groups, node_groups, labels, sets, mut admitted) = escape_hatch_fixture();
        let keys = pubkeys(&node_groups);
        // Fully rolled out on v2 — and n0 has been reporting unhealthy for weeks for reasons that
        // have nothing to do with the rollout.
        admitted.get_mut("g").unwrap().previous.clear();
        let reports = HashMap::from([
            report_at(monday(), "n0", "v2", false),
            report_at(monday(), "n1", "v2", true),
            report_at(monday(), "n2", "v2", true),
        ]);
        // An ordinary GitOps forward change lands on a Monday afternoon. No emergency is declared.
        groups.get_mut("g").unwrap().deployment = deployment_named("v3");
        let plan = plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &keys,
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
            },
            &mut admitted,
            monday(),
        );
        assert!(plan.sets[0].frozen);
        assert_eq!(
            admitted["g"].current.deployment, "v2",
            "an unhealthy node is not a statement of intent; the change waits for the window"
        );
        assert!(
            plan.sets[0].emergency.is_empty(),
            "nothing was exempted, so nothing is reported as exempt"
        );
    }

    /// The case the hatch exists for and the one it used to miss: a group that is SETTLED, so it
    /// holds no in-flight slot of its own. When the schedule was expressed twice — as `frozen` AND
    /// as zero free slots — waiving `frozen` left the retarget refused by the slot the freeze had
    /// taken away, and the hatch worked only for a group that happened to be mid-rollout.
    #[test]
    fn an_emergency_correction_to_a_settled_group_is_admitted_outside_the_window() {
        let (mut groups, node_groups, labels, sets, mut admitted) = escape_hatch_fixture();
        let keys = pubkeys(&node_groups);
        // Fully rolled out on v2 and reporting healthy: nothing is in flight, so nothing about
        // this group bypasses a slot for any other reason.
        admitted.get_mut("g").unwrap().previous.clear();
        let reports = HashMap::from([
            report_at(monday(), "n0", "v2", true),
            report_at(monday(), "n1", "v2", true),
            report_at(monday(), "n2", "v2", true),
        ]);
        groups.get_mut("g").unwrap().deployment = deployment_named("v3");
        groups.get_mut("g").unwrap().emergency_correction = true;
        let plan = plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &keys,
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
            },
            &mut admitted,
            monday(),
        );
        assert!(
            plan.sets[0].frozen,
            "the set really is outside its schedule; the declared emergency is what is exempt"
        );
        assert_eq!(
            admitted["g"].current.deployment, "v3",
            "a settled group's declared emergency correction must be admitted outside the window"
        );
        assert_eq!(
            plan.sets[0].emergency,
            vec!["g".to_string()],
            "the set's status names the member that is bypassing its schedule"
        );
    }

    /// The control: the identical retarget of the identical settled group, without the operator's
    /// statement, still waits for the window.
    #[test]
    fn an_ordinary_retarget_of_a_settled_group_is_refused_outside_the_window() {
        let (mut groups, node_groups, labels, sets, mut admitted) = escape_hatch_fixture();
        let keys = pubkeys(&node_groups);
        admitted.get_mut("g").unwrap().previous.clear();
        let reports = HashMap::from([
            report_at(monday(), "n0", "v2", true),
            report_at(monday(), "n1", "v2", true),
            report_at(monday(), "n2", "v2", true),
        ]);
        groups.get_mut("g").unwrap().deployment = deployment_named("v3");
        let plan = plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &keys,
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
            },
            &mut admitted,
            monday(),
        );
        assert!(plan.sets[0].frozen);
        assert_eq!(
            admitted["g"].current.deployment, "v2",
            "without a declared emergency the schedule binds an already-published group"
        );
        assert!(plan.sets[0].emergency.is_empty());
    }

    /// The schedule is waived; the blast radius is not. A declared emergency still claims one of
    /// the set's `maxConcurrent` slots, so declaring one across a fleet rolls it a slot at a time
    /// rather than changing every group at once.
    #[test]
    fn an_emergency_correction_still_waits_for_a_free_concurrency_slot() {
        // Two members, so `maxConcurrent` defaults to one. `a` is mid-rollout and holds it.
        let mut groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment_named("v1"))),
            ("b".to_string(), group("b", deployment_named("v2"))),
        ]);
        // `a` has two nodes so its rollout can be genuinely half-staged: with only one node it
        // would be fully handed `v1` on the first pass and settle immediately.
        let node_groups = BTreeMap::from([
            ("n-a0".to_string(), "a".to_string()),
            ("n-a1".to_string(), "a".to_string()),
            ("n-b".to_string(), "b".to_string()),
        ]);
        let keys = pubkeys(&node_groups);
        let sets = [windowed_set(vec![crate::window::RolloutWindow {
            weekdays: vec![crate::window::Weekday::Sunday],
            ..Default::default()
        }])];
        let mut admitted = BTreeMap::from([
            (
                "a".to_string(),
                AdmittedDeployment {
                    current: deployment_named("v1"),
                    previous: vec![deployment_named("v0")],
                },
            ),
            ("b".to_string(), admitted(deployment_named("v2"))),
        ]);
        // `a` is half-staged (n-a1 still on v0), so it genuinely occupies the set's only slot.
        // `b` is settled on v2, and the operator declares an emergency correction back to v1.
        let reports = HashMap::from([
            report_at(monday(), "n-a0", "v1", true),
            report_at(monday(), "n-a1", "v0", true),
            report_at(monday(), "n-b", "v2", true),
        ]);
        groups.get_mut("b").unwrap().deployment = deployment_named("v1");
        groups.get_mut("b").unwrap().emergency_correction = true;
        let run = |groups: &BTreeMap<String, ResolvedGroup>,
                   reports: &HashMap<String, Envelope>,
                   admitted: &mut BTreeMap<String, AdmittedDeployment>| {
            plan_rollouts(
                &sets,
                RolloutInputs {
                    groups,
                    group_labels: &pair_labels(),
                    node_groups: &node_groups,
                    reports,
                    public_keys: &keys,
                    published: &BTreeMap::new(),
                    held: &BTreeMap::new(),
                },
                admitted,
                monday(),
            )
        };
        let plan = run(&groups, &reports, &mut admitted);
        assert!(plan.sets[0].frozen);
        assert_eq!(
            plan.sets[0].max_concurrent, 1,
            "two members, so one group may change at a time"
        );
        assert_eq!(
            admitted["b"].current.deployment, "v2",
            "the emergency waives the schedule, not the set's concurrency limit"
        );
        // `a` finishes staging and settles, freeing the slot; the emergency then goes through, still
        // outside the window.
        let settled_reports = HashMap::from([
            report_at(monday(), "n-a0", "v1", true),
            report_at(monday(), "n-a1", "v1", true),
            report_at(monday(), "n-b", "v2", true),
        ]);
        let plan = run(&groups, &settled_reports, &mut admitted);
        assert!(plan.sets[0].frozen);
        assert_eq!(
            admitted["b"].current.deployment, "v1",
            "once a slot frees, the declared emergency is admitted without waiting for the window"
        );
        assert_eq!(plan.sets[0].emergency, vec!["b".to_string()]);
    }

    /// The rescue exemption is from the availability SHORTFALL, not from the batch size. An
    /// app-level dependency outage that makes most of a group report unhealthy must not move the
    /// whole fleet in one signed generation.
    #[test]
    fn a_rescue_is_bounded_per_generation_like_every_other_movement() {
        let node_groups: BTreeMap<String, String> = (0..100)
            .map(|index| (format!("n{index:03}"), "g".to_string()))
            .collect();
        let groups = BTreeMap::from([("g".to_string(), group("g", deployment_named("v2")))]);
        let keys = pubkeys(&node_groups);
        let mut admitted = BTreeMap::from([(
            "g".into(),
            AdmittedDeployment {
                current: deployment_named("v2"),
                previous: vec![deployment_named("v1")],
            },
        )]);
        // n000 already advanced and is healthy on v2, so v2 is PROVEN. Every other node reports
        // itself unhealthy on v1 — a downstream dependency the application health-checks, not a
        // property of the rollout at all.
        let mut reports = HashMap::from([report("n000", "v2", true)]);
        for index in 1..100 {
            let (node, envelope) = report(&format!("n{index:03}"), "v1", false);
            reports.insert(node, envelope);
        }
        let plan = plan_rollouts(
            &[],
            RolloutInputs {
                groups: &groups,
                group_labels: &BTreeMap::new(),
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &keys,
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
            },
            &mut admitted,
            test_now(),
        );
        let on_current = plan
            .node_deployments
            .values()
            .filter(|deployment| deployment.deployment == "v2")
            .count();
        assert_eq!(
            on_current, 2,
            "the node already on v2 plus at most maxUnavailable rescued nodes — never all 99"
        );
    }

    /// Every consumer reads ONE verdict per group. A change to a deployment's body that keeps its
    /// name is a real change the nodes have not received, so while the set has no free slot for it
    /// the group is `Held` — the deployment NAME comparison the status path used reported it fully
    /// admitted and `Ready`.
    #[test]
    fn a_body_change_that_keeps_the_deployment_name_is_reported_held() {
        // Two members of `pair-00`, so its effective concurrency is one. `sibling` is mid-rollout
        // and holds that slot, which is what makes `g`'s body change wait.
        let mut groups = BTreeMap::from([
            ("g".to_string(), group("g", deployment_named("v0"))),
            (
                "sibling".to_string(),
                group("sibling", deployment_named("s1")),
            ),
        ]);
        let mut node_groups: BTreeMap<String, String> = ["n0", "n1", "n2"]
            .into_iter()
            .map(|node| (node.to_string(), "g".to_string()))
            .collect();
        node_groups.insert("n-sibling".to_string(), "sibling".to_string());
        let labels = BTreeMap::from([
            (
                "g".to_string(),
                BTreeMap::from([("set".to_string(), "pair-00".to_string())]),
            ),
            (
                "sibling".to_string(),
                BTreeMap::from([("set".to_string(), "pair-00".to_string())]),
            ),
        ]);
        let keys = pubkeys(&node_groups);
        let reports = HashMap::from([
            report("n0", "v0", true),
            report("n1", "v0", true),
            report("n2", "v0", true),
            report("n-sibling", "s0", true),
        ]);
        let sets = [pair_set()];
        let mut admitted = BTreeMap::from([
            ("g".to_string(), admitted(deployment_named("v0"))),
            (
                "sibling".to_string(),
                AdmittedDeployment {
                    current: deployment_named("s1"),
                    previous: vec![deployment_named("s0")],
                },
            ),
        ]);
        // Same deployment NAME, different resolved body.
        let mut changed = deployment_named("v0");
        changed.runtime.args = vec!["--flag".into()];
        groups.get_mut("g").unwrap().deployment = changed.clone();
        let plan = plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &keys,
                published: &BTreeMap::new(),
                held: &BTreeMap::new(),
            },
            &mut admitted,
            test_now(),
        );
        assert_eq!(
            admitted["g"].current,
            deployment_named("v0"),
            "the set's only slot is taken, so the body change is not admitted this pass"
        );
        assert_eq!(
            plan.groups["g"],
            GroupProgress::Held,
            "a body change that keeps the deployment name is still an unadmitted change"
        );
        assert!(
            !plan.sets[0].settled.contains(&"g".to_string())
                && !plan.sets[0].rolling.contains(&"g".to_string()),
            "and the set reports it as neither settled nor rolling"
        );
    }

    /// A group with SOME blind agents is still staging while `assign_nodes` moves them one batch
    /// per generation, so it is `Rolling` and keeps its set's concurrency slot until every node has
    /// been handed the deployment. Judging it on telemetry alone declared it settled — freeing the
    /// slot and reporting the rollout finished — as soon as its observable node converged, while
    /// dozens of blind ones had not been moved at all.
    #[test]
    fn a_mixed_group_holds_its_slot_until_its_blind_nodes_are_staged() {
        let mut groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment_named("v0"))),
            ("b".to_string(), group("b", deployment_named("v0"))),
        ]);
        let group_labels = pair_labels();
        let mut node_groups = pair_node_groups();
        // `b` also holds three offline-provisioned agents.
        for index in 0..3 {
            node_groups.insert(format!("blind{index}"), "b".to_string());
        }
        let keys: HashMap<String, Vec<u8>> = ["n-a", "n-b"]
            .into_iter()
            .map(|node| (node.to_string(), TEST_KEY.1.clone()))
            .collect();
        let sets = [pair_set()];
        let mut admitted = BTreeMap::from([
            ("a".to_string(), admitted(deployment_named("v0"))),
            ("b".to_string(), admitted(deployment_named("v0"))),
        ]);
        let mut published = BTreeMap::new();
        let mut reports = HashMap::from([report("n-a", "v0", true), report("n-b", "v0", true)]);
        groups.get_mut("b").unwrap().deployment = deployment_named("v1");
        // `b` is retargeted; from the next pass its observable node reports v1 healthy, while the
        // blind ones can only be staged one per generation — four passes for four nodes.
        for pass in 0..4 {
            let plan = plan_rollouts(
                &sets,
                RolloutInputs {
                    groups: &groups,
                    group_labels: &group_labels,
                    node_groups: &node_groups,
                    reports: &reports,
                    public_keys: &keys,
                    published: &published,
                    held: &BTreeMap::new(),
                },
                &mut admitted,
                test_now(),
            );
            assert_eq!(
                plan.groups["b"],
                GroupProgress::Rolling,
                "pass {pass}: blind nodes are still being handed v1, so the rollout is in flight"
            );
            assert_eq!(plan.sets[0].rolling, vec!["b".to_string()]);
            assert_eq!(
                plan.sets[0].settled,
                vec!["a".to_string()],
                "pass {pass}: only the untouched sibling is settled"
            );
            // And the slot it holds is real: a sibling retarget cannot claim one.
            let mut contending = groups.clone();
            contending.get_mut("a").unwrap().deployment = deployment_named("v9");
            let contended = plan_rollouts(
                &sets,
                RolloutInputs {
                    groups: &contending,
                    group_labels: &group_labels,
                    node_groups: &node_groups,
                    reports: &reports,
                    public_keys: &keys,
                    published: &published,
                    held: &BTreeMap::new(),
                },
                &mut admitted.clone(),
                test_now(),
            );
            assert_eq!(
                contended.groups["a"],
                GroupProgress::Held,
                "pass {pass}: the set's only slot is still occupied"
            );
            // Only now does the generation this pass planned become the published one.
            published = published_from(&plan);
            for (node, deployment) in &plan.node_deployments {
                if keys.contains_key(node) {
                    let (node, envelope) = report(node, &deployment.deployment, true);
                    reports.insert(node, envelope);
                }
            }
        }
        // The next pass sees every node handed v1, so the staging is finished.
        let plan = plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &keys,
                published: &published,
                held: &BTreeMap::new(),
            },
            &mut admitted,
            test_now(),
        );
        assert!(admitted["b"].previous.is_empty());
        assert_eq!(plan.groups["b"], GroupProgress::Settled);
    }

    /// A rollout whose nodes sit on a deployment the group does not name can never finish staging:
    /// nothing is ever handed `current`, and no predecessor is ever retired because no node is on
    /// one either. Retargeting such a group prepends the abandoned `current` every time, so keeping
    /// the whole un-retirable list grew the durable ConfigMap by one deployment per retarget —
    /// forever, until the apiserver refused the write at 1 MiB and no generation could publish
    /// again. It collapses to the single entry `assign_nodes` actually falls back to instead.
    #[test]
    fn repeated_retargets_that_can_never_finish_staging_keep_the_state_bounded() {
        let mut groups = BTreeMap::from([("g".into(), group("g", deployment_named("v0")))]);
        let node_groups = BTreeMap::from([("n0".to_string(), "g".to_string())]);
        let keys = pubkeys(&node_groups);
        // The node was published a deployment no group here holds (its own group was deleted), and
        // it is silent, so it spends the whole `maxUnavailable` budget and never moves.
        let published = BTreeMap::from([(
            "n0".to_string(),
            crate::deployment_identity(&deployment_named("elsewhere")).unwrap(),
        )]);
        let mut admitted = BTreeMap::from([("g".to_string(), admitted(deployment_named("v0")))]);
        for version in 1..=8 {
            let target = format!("v{version}");
            groups.get_mut("g").unwrap().deployment = deployment_named(&target);
            let plan = plan_rollouts(
                &[],
                RolloutInputs {
                    groups: &groups,
                    group_labels: &BTreeMap::new(),
                    node_groups: &node_groups,
                    reports: &HashMap::new(),
                    public_keys: &keys,
                    published: &published,
                    held: &BTreeMap::new(),
                },
                &mut admitted,
                test_now(),
            );
            assert!(
                admitted["g"].previous.len() <= 2,
                "retarget {version} left {} staged deployments in the durable state: {:?}",
                admitted["g"].previous.len(),
                admitted["g"]
                    .previous
                    .iter()
                    .map(|deployment| deployment.deployment.clone())
                    .collect::<Vec<_>>()
            );
            // The bound costs the node nothing, because the node is not moved either way: the
            // control plane has no body for where it actually is, so it is left OUT of the
            // generation until a `maxUnavailable` slot frees (`domain::plan_reconcile` republishes
            // its last routing meanwhile). Publishing it `previous[0]` instead — a deployment it
            // was never on — was a move, and the one move no budget was ever checked against.
            assert!(
                !plan.node_deployments.contains_key("n0"),
                "retarget {version}: a node the control plane cannot place is never moved unbudgeted"
            );
        }
    }

    /// Relabelling a node OUT of a quarantined group is the documented remediation for one, so the
    /// group it lands in must recognize where it is. A quarantined group is pruned from `admitted`
    /// before `assign_nodes` runs and restored only afterwards, so reading `admitted` alone left
    /// the node's deployment unrecognized and published it on the new group's predecessor — a
    /// backward move, and the one move no `maxUnavailable` budget is ever checked against.
    #[test]
    fn a_node_relabelled_off_a_quarantined_group_is_never_moved_backward() {
        let groups = BTreeMap::from([("core".into(), group("core", deployment_named("core-v2")))]);
        let node_groups = BTreeMap::from([
            ("n-moved".to_string(), "core".to_string()),
            ("n-stuck".to_string(), "core".to_string()),
        ]);
        let keys = pubkeys(&node_groups);
        // `core` is mid-rollout from core-v1 to core-v2: `n-stuck` was handed core-v2 and has gone
        // quiet, which spends the group's single `maxUnavailable` slot.
        let mut admitted = BTreeMap::from([(
            "core".to_string(),
            AdmittedDeployment {
                current: deployment_named("core-v2"),
                previous: vec![deployment_named("core-v1")],
            },
        )]);
        // `edge` is quarantined: it is absent from the planned groups and its nodes are pinned.
        let held = BTreeMap::from([(
            "edge".to_string(),
            HeldGroup {
                state: AdmittedDeployment {
                    current: deployment_named("edge-v1"),
                    previous: Vec::new(),
                },
                match_labels: BTreeMap::from([("group".to_string(), "edge".to_string())]),
            },
        )]);
        let published = BTreeMap::from([
            (
                "n-moved".to_string(),
                crate::deployment_identity(&deployment_named("edge-v1")).unwrap(),
            ),
            (
                "n-stuck".to_string(),
                crate::deployment_identity(&deployment_named("core-v2")).unwrap(),
            ),
        ]);
        let plan = plan_rollouts(
            &[],
            RolloutInputs {
                groups: &groups,
                group_labels: &BTreeMap::new(),
                node_groups: &node_groups,
                reports: &HashMap::new(),
                public_keys: &keys,
                published: &published,
                held: &held,
            },
            &mut admitted,
            test_now(),
        );
        assert_eq!(
            plan.node_deployments["n-moved"],
            deployment_named("edge-v1"),
            "the relabelled node is republished on exactly what it is running, which is a no-op"
        );
        assert_eq!(
            plan.node_deployments["n-stuck"],
            deployment_named("core-v2")
        );
    }

    /// A bulk relabel INTO a group that is not mid-rollout is still a move for every machine that
    /// arrives, so it is staged against `maxUnavailable` like any other. The group's `previous` is
    /// empty (no deployment change is in flight) and short-circuiting on that handed `current` to
    /// all of them in one signed generation: three machines relabelled from `a` to `b` restarted at
    /// once, with no budget and no health gate.
    #[test]
    fn nodes_relabelled_into_a_settled_group_are_staged_against_max_unavailable() {
        // `b` is settled on v2; `a` is settled on v1 and still exists (it keeps a node of its own).
        let groups = BTreeMap::from([
            ("a".into(), group("a", deployment_named("v1"))),
            ("b".into(), group("b", deployment_named("v2"))),
        ]);
        let node_groups = BTreeMap::from([
            ("a-keeper".to_string(), "a".to_string()),
            ("n0".to_string(), "b".to_string()),
            // n1..n3 were just relabelled out of `a`, so they are still running v1.
            ("n1".to_string(), "b".to_string()),
            ("n2".to_string(), "b".to_string()),
            ("n3".to_string(), "b".to_string()),
        ]);
        let mut admitted = BTreeMap::from([
            ("a".to_string(), admitted(deployment_named("v1"))),
            ("b".to_string(), admitted(deployment_named("v2"))),
        ]);
        let v1 = crate::deployment_identity(&deployment_named("v1")).unwrap();
        let v2 = crate::deployment_identity(&deployment_named("v2")).unwrap();
        let published = BTreeMap::from([
            ("a-keeper".to_string(), v1.clone()),
            ("n0".to_string(), v2),
            ("n1".to_string(), v1.clone()),
            ("n2".to_string(), v1.clone()),
            ("n3".to_string(), v1),
        ]);
        let reports: HashMap<String, Envelope> = ["a-keeper", "n1", "n2", "n3"]
            .iter()
            .map(|node| report(node, "v1", true))
            .chain(std::iter::once(report("n0", "v2", true)))
            .collect();

        let plan = plan_rollouts(
            &[],
            RolloutInputs {
                groups: &groups,
                group_labels: &BTreeMap::new(),
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &pubkeys(&node_groups),
                published: &published,
                held: &BTreeMap::new(),
            },
            &mut admitted,
            test_now(),
        );

        assert_eq!(
            ["n1", "n2", "n3"]
                .iter()
                .filter(|node| plan.node_deployments[**node].deployment == "v2")
                .count(),
            1,
            "one relabelled node per generation moves; maxUnavailable is 1"
        );
        assert_eq!(
            plan.node_deployments["n0"],
            deployment_named("v2"),
            "the node already on the group's deployment is republished on it"
        );
        assert_eq!(
            plan.node_deployments["a-keeper"],
            deployment_named("v1"),
            "the source group is untouched"
        );
    }

    /// The same bulk relabel with the source group DELETED in the same commit. Nothing in the
    /// desired state holds v1 any more, so a group that answered "where is this node?" from the
    /// planned groups alone could not place any of the arrivals and handed all of them `current` at
    /// once: `hold == current` makes the `moved < budget` throttle a no-op, so every machine
    /// restarted in one signed generation with no `maxUnavailable` and no health gate. The body of
    /// a deleted group is retained for exactly as long as a node is placed on it, so the arrivals
    /// are recognized and staged one per generation — and the relabel still converges.
    #[test]
    fn nodes_relabelled_in_from_a_deleted_group_are_staged_against_max_unavailable() {
        // `a` is gone from desired state; only its retained admitted body says where its nodes are.
        let groups = BTreeMap::from([("b".into(), group("b", deployment_named("v2")))]);
        let node_groups: BTreeMap<String, String> = ["n1", "n2", "n3"]
            .iter()
            .map(|node| (node.to_string(), "b".to_string()))
            .collect();
        let mut admitted = BTreeMap::from([
            ("a".to_string(), admitted(deployment_named("v1"))),
            ("b".to_string(), admitted(deployment_named("v2"))),
        ]);
        let v1 = crate::deployment_identity(&deployment_named("v1")).unwrap();
        let keys = pubkeys(&node_groups);
        let mut published: BTreeMap<String, String> = node_groups
            .keys()
            .map(|node| (node.clone(), v1.clone()))
            .collect();
        let mut reports: HashMap<String, Envelope> = ["n1", "n2", "n3"]
            .iter()
            .map(|node| report(node, "v1", true))
            .collect();

        let mut moved = Vec::new();
        for _ in 0..4 {
            let plan = plan_rollouts(
                &[],
                RolloutInputs {
                    groups: &groups,
                    group_labels: &BTreeMap::new(),
                    node_groups: &node_groups,
                    reports: &reports,
                    public_keys: &keys,
                    published: &published,
                    held: &BTreeMap::new(),
                },
                &mut admitted,
                test_now(),
            );
            moved.push(
                plan.node_deployments
                    .values()
                    .filter(|deployment| deployment.deployment == "v2")
                    .count(),
            );
            published = published_from(&plan);
            for (node, deployment) in &plan.node_deployments {
                let (node, envelope) = report(node, &deployment.deployment, true);
                reports.insert(node, envelope);
            }
        }
        assert_eq!(
            moved,
            vec![1, 2, 3, 3],
            "one relabelled machine per generation; maxUnavailable is 1"
        );
        assert!(
            !admitted.contains_key("a"),
            "and the deleted group's body is dropped the moment nobody is on it"
        );
    }
}
