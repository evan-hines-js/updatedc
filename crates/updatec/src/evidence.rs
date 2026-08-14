//! Cross-pass observation memory: the [`ObservationLog`].
//!
//! Split out of the per-pass planner deliberately. The planner is PURE — every verdict recomputed
//! from this pass's inputs — and this module is the one place anything about the past is
//! remembered, so the boundary between the two models is a module boundary and not a habit.
//!
//! Two facts live here, and both are here for the same reason: a single pass's store read cannot
//! establish either. Whether a node has EVER uploaded a report, and which releases a node has told
//! us it durably REJECTED. Everything else the planner judges — settlement, availability, the
//! fleet-wide regression halt's threshold, whether a rollout has failed — is recomputed from this
//! pass's reports.
//!
//! Both remembered facts are MONOTONE claims about the past, with no lifecycle rules at all: a
//! claim is added when it is seen and dropped only when what it is about leaves the system. That is
//! deliberate. This module used to infer a rejection from a report SEQUENCE, and every deep defect
//! of it was a lifecycle bug in the remembering — a health blip read as an attempt, a merely-fetched
//! tick read as a rollback, a committed movement's record resurrected by a retarget later — and,
//! fatally, a proof that could be MISSED for ever, because a node never retries bytes it has
//! rejected. The node now states the fact itself (`NodeReport::rejected`), so what is left to
//! remember is only "we have seen it said", which cannot be wrong in the direction that matters:
//! it never invents a rejection, and it does not lose one to a store that failed to answer for a
//! second.

use std::collections::HashSet;

/// Which nodes have ever been heard from.
///
/// "Has ever reported" cannot be derived from one pass: re-deriving it from the reports readable
/// RIGHT NOW made an object store that stopped answering drive every group's `observable` count to
/// zero, which CLEARS `ReportsStale` — the alert resolving itself exactly when the whole fleet goes
/// dark. Remembered, a store outage leaves the count where it was while `fresh` falls, so the
/// condition fires.
///
/// Losing it (a restart, a leader change) is the fail-safe direction and self-healing: every live
/// node re-enters on its next uploaded report, and until then it counts as "has not started yet"
/// rather than "stopped reporting", which is the reading that does not page.
#[derive(Clone, Debug, Default)]
pub struct ObservationLog {
    /// Nodes whose report envelope has been seen in the store at least once, at any age and
    /// whether or not it verified ([`ObservationLog::has_reported`]).
    reported: HashSet<String>,
    /// `(node, assignment identity)` pairs a node's own authentic report has claimed a DURABLE
    /// REJECTION for. Remembered so one unreadable object does not un-halt a proven-bad release:
    /// reports are read best-effort per node, and a single failed read would otherwise drop the
    /// fleet's evidence below `maxRegressions` for that pass and admit another `maxUnavailable`
    /// batch onto the body — one blip at a time.
    ///
    /// Losing it costs nothing and heals itself: the claim is in the node's standing report, so a
    /// fresh process re-reads it on its next pass. That is why it is not durable state, unlike the
    /// admitted set — and why a restart can no longer un-decide a rollout the way losing an
    /// inferred sequence could.
    rejections: HashSet<(String, String)>,
}

impl ObservationLog {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Remember every node whose report envelope was readable in the store this pass, at any age.
    ///
    /// Called with the raw store read rather than the verified reports: the question this answers
    /// is "would this node's silence be news", which a node settles the first time it uploads
    /// anything at all.
    pub(crate) fn note_reported<'a>(&mut self, nodes: impl Iterator<Item = &'a String>) {
        for node in nodes {
            if !self.reported.contains(node) {
                self.reported.insert(node.clone());
            }
        }
    }

    /// Whether this node has EVER been seen with a report envelope in the store — at any age, and
    /// whether or not it verified. Observability accounting only, never a trust decision (that
    /// stays `Observations::report`): it exists so "has not reported yet" can be told apart from
    /// "stopped reporting". A node's key is pinned at enrollment, generations before it can fetch
    /// an assignment and upload anything, so counting a keyed-but-silent node as observable made
    /// every mass enrollment and every scale-out past `maxUnavailable` raise `ReportsStale` and
    /// then clear it — the alert-on-a-healthy-rollout the condition is tuned to avoid.
    pub(crate) fn has_reported(&self, node: &str) -> bool {
        self.reported.contains(node)
    }

    /// Record what `node`'s own authentic report says about the release its assignment names: that
    /// it durably rejected it, or that it does not claim so.
    ///
    /// Remembering is what a missing report must not undo; a report that ARRIVES and says otherwise
    /// is the node itself withdrawing the claim, and it is honoured. The node has one way to do
    /// that — an operator's break-glass override of its rejection record — and refusing to hear it
    /// would leave the deployment halted fleet-wide with no exit but a new digest, after the
    /// operator had deliberately cleared the very record the halt rests on.
    pub(crate) fn note_rejection(&mut self, node: &str, identity: &str, rejected: bool) {
        let claim = (node.to_string(), identity.to_string());
        if rejected {
            self.rejections.insert(claim);
        } else {
            self.rejections.remove(&claim);
        }
    }

    /// Whether this node has claimed a durable rejection of `identity` — now or in an earlier pass.
    pub(crate) fn rejected(&self, node: &str, identity: &str) -> bool {
        self.rejections
            .contains(&(node.to_string(), identity.to_string()))
    }

    /// Forget rejection claims about assignment identities no generation still names, so the memory
    /// is bounded by the live deployments. Owned by the planner, which computes that set each pass.
    pub(crate) fn prune_identities(&mut self, live: &HashSet<String>) {
        self.rejections
            .retain(|(_, identity)| live.contains(identity));
    }

    /// Forget nodes that left the FLEET — the apiserver's full agent list, not the planned subset.
    /// Pruning on the planned nodes would forget a QUARANTINED agent, which has not departed: it is
    /// carrying a status condition, and a node dropped from memory over one reads as "never
    /// reported", which silences the staleness alert for exactly the machine an operator is already
    /// worried about. The caller is `reconcile_once`, the one place the full fleet is known.
    pub(crate) fn prune_nodes(&mut self, fleet: impl Fn(&str) -> bool) {
        self.reported.retain(|node| fleet(node));
        self.rejections.retain(|(node, _)| fleet(node));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_is_remembered_from_its_first_envelope_until_it_leaves_the_fleet() {
        let mut log = ObservationLog::new();
        let node = "n".to_string();
        assert!(
            !log.has_reported(&node),
            "a keyed but never-heard-from node is UNOBSERVED, not stale"
        );
        log.note_reported(std::iter::once(&node));
        assert!(log.has_reported(&node));
        // A pass whose store read returned nothing (an outage) must not un-remember it: that is
        // exactly when `ReportsStale` has to fire rather than resolve itself.
        log.note_reported(std::iter::empty());
        assert!(log.has_reported(&node));
        // Departure is the one thing that forgets, so a machine re-created under the same name
        // starts from nothing.
        log.prune_nodes(|_| false);
        assert!(!log.has_reported(&node));
    }

    #[test]
    fn a_rejection_claim_is_kept_until_its_node_or_its_deployment_leaves() {
        let identity = "a".repeat(64);
        let other = "b".repeat(64);
        let mut log = ObservationLog::new();
        assert!(!log.rejected("n", &identity));
        log.note_rejection("n", &identity, true);
        assert!(log.rejected("n", &identity));
        assert!(
            !log.rejected("n", &other),
            "a claim is about the exact bytes an assignment names, never about the node at large"
        );
        // A pass that could not read this node's report must not un-halt what it proved bad.
        log.prune_identities(&HashSet::from([identity.clone()]));
        assert!(log.rejected("n", &identity));
        // The operator publishes corrected bytes: the old identity leaves every generation and the
        // claim goes with it, so the fleet is not halted by evidence about a body nobody names.
        log.prune_identities(&HashSet::from([other]));
        assert!(!log.rejected("n", &identity));

        // The node itself withdrawing the claim — the operator break-glassed its rejection record
        // — is heard, because the alternative is a halt with no exit but a new digest after the
        // operator has already cleared what the halt rests on.
        log.note_rejection("n", &identity, true);
        log.note_rejection("n", &identity, false);
        assert!(!log.rejected("n", &identity));

        log.note_rejection("n", &identity, true);
        log.prune_nodes(|_| false);
        assert!(
            !log.rejected("n", &identity),
            "a decommissioned machine's claim leaves with it, so a same-name replacement starts \
             from nothing"
        );
    }
}
