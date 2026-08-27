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

use std::collections::HashMap;
use std::collections::{BTreeSet, HashSet};
use updated_contracts::key::P256PublicKey;
use updated_contracts::telemetry::{AuthenticReport, Envelope, NodeReport};

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

/// Authenticity verdicts that outlive a pass.
///
/// Verifying a node report is the most expensive thing a pass does: at the 10,000-agent enrollment
/// ceiling it is ~28 us per node, ~280 ms per pass, and it dominates everything else the pass spends
/// — nine times the cost of decoding the whole fleet from the apiserver.
///
/// Almost all of it is repeated work. A node re-reports on its own check interval, so between two
/// passes seconds apart its envelope is usually the SAME BYTES, and re-verifying identical bytes
/// under an identical key can only reach the identical verdict. `ReportCache` already refuses to
/// re-download an unchanged report; this refuses to re-verify one.
///
/// The entry is keyed on everything the verdict depends on, so it cannot outlive its own premises:
///
/// * the exact envelope, compared by value — a node that re-reports gets re-verified;
/// * the pinned key, compared by value — a key rotation invalidates every verdict made under the
///   old one, which is what stops a rotated-away key from certifying a report forever;
/// * the node name, which is the map key — attribution is part of what verification proves, so a
///   verdict never migrates to another node.
///
/// Freshness is deliberately NOT cached and never could be: it is a clock comparison applied to the
/// verdict afterwards, so a cached authentic report still ages out on exactly the same schedule.
#[derive(Clone, Debug, Default)]
pub struct VerifiedReports {
    entries: HashMap<String, VerifiedEntry>,
    /// How many ECDSA verifications have actually been performed.
    ///
    /// A cache that never hit would be invisible: every verdict would still be correct and every
    /// test would still pass, while the pass quietly paid full price. This is what makes the hit
    /// observable, and what [`VerifiedReports::verifications`] lets a test assert on.
    verifications: u64,
}

#[derive(Clone, Debug)]
struct VerifiedEntry {
    key: P256PublicKey,
    envelope: Envelope,
    report: Option<AuthenticReport>,
}

impl VerifiedReports {
    /// The authenticated capability for this node, or `None` when there is none to read.
    ///
    /// A pure lookup: it cannot verify. [`VerifiedReports::verify_fleet`] is the single place an
    /// ECDSA verification happens, and it runs over the whole fleet before any of this is read, so
    /// a node that has both a report and a pinned key is already warm by the time the planner asks.
    ///
    /// The envelope and key are still compared, and a mismatch reads as `None`. That cannot happen
    /// after a warm-up over the same inputs; it is here so that if it somehow did, the planner would
    /// treat the node as unverifiable rather than act on a verdict reached from other bytes.
    fn authentic(
        &self,
        node: &str,
        envelope: &Envelope,
        key: &P256PublicKey,
    ) -> Option<&AuthenticReport> {
        let entry = self.entries.get(node)?;
        (&entry.envelope == envelope && &entry.key == key)
            .then_some(entry.report.as_ref())
            .flatten()
    }

    /// This node's full report, only after both cached authenticity and the shared freshness gate.
    pub(crate) fn fresh(
        &self,
        node: &str,
        envelope: &Envelope,
        key: &P256PublicKey,
        now_ms: u64,
    ) -> Option<NodeReport> {
        self.authentic(node, envelope, key)
            .and_then(|report| report.fresh(now_ms))
    }

    /// This node's one nonperishable positive claim, without exposing stale machine state or a
    /// negative/retraction representation.
    pub(crate) fn rejected_assignment(
        &self,
        node: &str,
        envelope: &Envelope,
        key: &P256PublicKey,
    ) -> Option<String> {
        self.authentic(node, envelope, key)
            .and_then(AuthenticReport::rejected_assignment)
            .map(str::to_string)
    }

    /// Verify the whole fleet up front, across every available core.
    ///
    /// Each node's verification is independent and pure — one ECDSA check over that node's own
    /// bytes under that node's own key — so there is nothing to serialize them for. Done lazily one
    /// node at a time from inside the planner, 10,000 nodes cost ~300 ms of wall clock on one core
    /// while the rest of the machine sat idle.
    ///
    /// This warms [`VerifiedReports::authentic`] for every node the planner can ask about: exactly
    /// the nodes that have both a report and a pinned key, which is the same set the lazy path
    /// would have verified. The planner therefore sees identical verdicts and keeps its lazy
    /// fallback; this only decides WHEN and on how many cores the work happens.
    ///
    /// Ordering is irrelevant to the result — verification is a pure function of (node, bytes, key)
    /// — so the parallel pass is deterministic in exactly the way the serial one was.
    // THE door: the only place this control plane checks a report's signature.
    //
    // That was true of the planner from the start and quietly false everywhere else — status
    // projection verified once per agent per pass, and so did dataflow producer health. Each was a
    // second full ECDSA pass over bytes the planner had just verified, the most expensive work the
    // controller does, paid twice and invisibly.
    //
    pub(crate) fn verify_fleet(
        &mut self,
        reports: &HashMap<String, Envelope>,
        public_keys: &HashMap<String, P256PublicKey>,
    ) {
        // Only what this pass does not already know. After a quiet interval this is empty and the
        // whole step costs one hash lookup per node.
        let pending: Vec<(&String, &Envelope, &P256PublicKey)> = reports
            .iter()
            .filter_map(|(node, envelope)| Some((node, envelope, public_keys.get(node)?)))
            .filter(|(node, envelope, key)| {
                !self
                    .entries
                    .get(node.as_str())
                    .is_some_and(|entry| &&entry.envelope == envelope && &&entry.key == key)
            })
            .collect();
        if pending.is_empty() {
            return;
        }
        let lanes = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
            .min(pending.len());
        let verdicts: Vec<(String, Option<AuthenticReport>)> = if lanes <= 1 {
            pending
                .iter()
                .map(|(node, envelope, key)| {
                    (
                        (*node).clone(),
                        updated_contracts::telemetry::authenticate_report(envelope, node, key),
                    )
                })
                .collect()
        } else {
            let chunk = pending.len().div_ceil(lanes);
            std::thread::scope(|scope| {
                let handles: Vec<_> = pending
                    .chunks(chunk)
                    .map(|lane| {
                        scope.spawn(move || {
                            lane.iter()
                                .map(|(node, envelope, key)| {
                                    (
                                        (*node).clone(),
                                        updated_contracts::telemetry::authenticate_report(
                                            envelope, node, key,
                                        ),
                                    )
                                })
                                .collect::<Vec<_>>()
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .flat_map(|handle| handle.join().expect("a verification lane cannot panic"))
                    .collect()
            })
        };
        self.verifications += verdicts.len() as u64;
        for ((node, report), (_, envelope, key)) in verdicts.into_iter().zip(pending) {
            self.entries.insert(
                node,
                VerifiedEntry {
                    key: key.clone(),
                    envelope: envelope.clone(),
                    report,
                },
            );
        }
    }

    /// How many verifications have been performed since this cache was created.
    pub fn verifications(&self) -> u64 {
        self.verifications
    }

    /// Forget nodes that have left the fleet, so a controller running for months does not keep a
    /// verdict for every node that ever enrolled. Called from the same per-pass pruning that bounds
    /// [`ObservationLog`], because it is bounded by exactly the same membership.
    pub(crate) fn prune_nodes(&mut self, fleet: impl Fn(&str) -> bool) {
        self.entries.retain(|node, _| fleet(node));
    }
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
        self.reported.extend(nodes.cloned());
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

    /// Record `node`'s authenticated proof that it durably rejected `identity`.
    ///
    /// This is monotone for the live `(node, identity)` pair, exactly like the node's append-only
    /// rejection ledger. Missing reports and later negative statements cannot erase safety
    /// evidence. Normal remediation publishes corrected bytes with a new identity; node and
    /// identity departure are the two explicit pruning paths below.
    pub(crate) fn note_rejection(&mut self, node: &str, identity: &str) {
        self.rejections
            .insert((node.to_string(), identity.to_string()));
    }

    /// Every node that has claimed a durable rejection of `identity` — now or in an earlier pass.
    ///
    /// Asked of the CLAIM alone, never of group membership, because a claim is about BYTES: the
    /// machine that proved them bad may since have been relabelled into another group, had its
    /// group quarantined (its nodes then resolve to the pseudo-group `default`), or have matched
    /// no group in the first place. Scoping the count to the groups PLANNED this pass let a bad
    /// `dependsOn` edit withdraw a proven-bad body's evidence and re-open it to every sibling
    /// group, and left the unmatched cohort's rejections recorded but never counted.
    ///
    /// Bounded on both axes by the pruning above: a claim lives until its identity leaves every
    /// generation or its node leaves the fleet.
    pub(crate) fn provers(&self, identity: &str) -> BTreeSet<String> {
        self.rejections
            .iter()
            .filter(|(_, claimed)| claimed == identity)
            .map(|(node, _)| node.clone())
            .collect()
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

    /// A real node key: the PKCS#8 signing half and the pinned public half.
    fn node_key() -> (Vec<u8>, P256PublicKey) {
        use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_ASN1_SIGNING};
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref()).unwrap();
        let public = P256PublicKey::from_point(pair.public_key().as_ref()).unwrap();
        (document.as_ref().to_vec(), public)
    }

    /// A report `node` genuinely signed with `pkcs8`.
    fn signed(pkcs8: &[u8], node: &str, healthy: bool) -> Envelope {
        const DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let mut report =
            NodeReport::new(node, "deploy-1", DIGEST, "1.0.0", DIGEST, DIGEST, healthy);
        crate::test_support::sign_report(&mut report, pkcs8)
    }

    /// Fleet inputs as a pass presents them.
    fn fleet(
        pkcs8: &[u8],
        key: &P256PublicKey,
        nodes: &[&str],
        healthy: bool,
    ) -> (HashMap<String, Envelope>, HashMap<String, P256PublicKey>) {
        (
            nodes
                .iter()
                .map(|n| (n.to_string(), signed(pkcs8, n, healthy)))
                .collect(),
            nodes.iter().map(|n| (n.to_string(), key.clone())).collect(),
        )
    }

    /// Verification happens in exactly one place. A reader that has not been warmed reports
    /// nothing — it cannot fall back to verifying, which is what keeps `verify_fleet` the only
    /// route to a verdict rather than merely the usual one.
    #[test]
    fn a_cold_cache_reads_as_nothing_rather_than_verifying() {
        let (pkcs8, key) = node_key();
        let (reports, _) = fleet(&pkcs8, &key, &["n1"], true);
        let cache = VerifiedReports::default();
        assert_eq!(cache.authentic("n1", &reports["n1"], &key), None);
        assert_eq!(cache.verifications(), 0);
    }

    /// The whole point of the cache: a pass that sees the same bytes under the same key must not
    /// pay for the verification again. Without this, a cache that never hit would still return
    /// correct verdicts and still pass every other test in this crate.
    #[test]
    fn an_unchanged_fleet_is_verified_once() {
        let (pkcs8, key) = node_key();
        let (reports, keys) = fleet(&pkcs8, &key, &["n1", "n2", "n3"], true);
        let mut cache = VerifiedReports::default();

        cache.verify_fleet(&reports, &keys);
        assert_eq!(cache.verifications(), 3);
        assert!(cache.authentic("n1", &reports["n1"], &key).is_some());

        for _ in 0..10 {
            cache.verify_fleet(&reports, &keys);
        }
        assert_eq!(
            cache.verifications(),
            3,
            "ten further passes over identical bytes must not re-verify"
        );
        assert!(cache.authentic("n2", &reports["n2"], &key).is_some());
    }

    /// Every premise a verdict rests on has to invalidate it.
    #[test]
    fn a_new_report_or_a_rotated_key_is_verified_again() {
        let (pkcs8, key) = node_key();
        let (mut reports, mut keys) = fleet(&pkcs8, &key, &["n1"], true);
        let mut cache = VerifiedReports::default();
        cache.verify_fleet(&reports, &keys);
        assert_eq!(cache.verifications(), 1);

        // The node re-reports under the SAME key: different bytes, so the old verdict cannot stand
        // in for the new one.
        let newer = signed(&pkcs8, "n1", false);
        assert_ne!(newer, reports["n1"]);
        reports.insert("n1".into(), newer.clone());
        cache.verify_fleet(&reports, &keys);
        assert_eq!(cache.verifications(), 2);
        assert!(cache.authentic("n1", &newer, &key).is_some());

        // The pin rotates. The cached verdict was reached under the OLD key, so serving it would
        // let a key the control plane has stopped trusting keep certifying this node's report.
        let (_, rotated) = node_key();
        assert_ne!(rotated, key);
        keys.insert("n1".into(), rotated.clone());
        cache.verify_fleet(&reports, &keys);
        assert_eq!(cache.verifications(), 3);
        assert_eq!(
            cache.authentic("n1", &newer, &rotated),
            None,
            "the report does not verify under a key that did not sign it"
        );
    }

    /// A node with no pinned key cannot be verified, so the warm-up must skip it rather than
    /// caching a `None` the planner would read as "checked, and unusable".
    #[test]
    fn a_node_without_a_pinned_key_is_not_warmed() {
        let (pkcs8, key) = node_key();
        let (reports, _) = fleet(&pkcs8, &key, &["n1"], true);
        let mut cache = VerifiedReports::default();
        cache.verify_fleet(&reports, &HashMap::new());
        assert_eq!(cache.verifications(), 0);
        assert_eq!(cache.authentic("n1", &reports["n1"], &key), None);
    }

    /// Splitting the fleet across cores must not change a single verdict: verification is a pure
    /// function of (node, bytes, key), so the parallel warm-up has to agree with a one-at-a-time
    /// one for every node, including the ones it refuses.
    #[test]
    fn warming_across_cores_agrees_with_warming_one_node_at_a_time() {
        let (pkcs8, key) = node_key();
        let nodes: Vec<String> = (0..64).map(|i| format!("agent-{i:02}")).collect();
        let refs: Vec<&str> = nodes.iter().map(String::as_str).collect();
        let (mut reports, keys) = fleet(&pkcs8, &key, &refs, true);
        // One node's report is signed by a key that is not its pin, so it must come back refused.
        let (other_pkcs8, _) = node_key();
        reports.insert(nodes[7].clone(), signed(&other_pkcs8, &nodes[7], true));

        let mut parallel = VerifiedReports::default();
        parallel.verify_fleet(&reports, &keys);

        for node in &nodes {
            let mut one = VerifiedReports::default();
            one.verify_fleet(
                &HashMap::from([(node.clone(), reports[node].clone())]),
                &HashMap::from([(node.clone(), key.clone())]),
            );
            assert_eq!(
                parallel.authentic(node, &reports[node], &key),
                one.authentic(node, &reports[node], &key),
                "{node} must reach the same verdict however the work was split"
            );
        }
        assert_eq!(
            parallel.authentic(&nodes[7], &reports[&nodes[7]], &key),
            None,
            "a report signed by another key is refused, in parallel as serially"
        );
    }

    /// A node that leaves the fleet must not leave its verdict behind for ever.
    #[test]
    fn a_departed_node_is_forgotten() {
        let (pkcs8, key) = node_key();
        let (reports, keys) = fleet(&pkcs8, &key, &["n1"], true);
        let mut cache = VerifiedReports::default();
        cache.verify_fleet(&reports, &keys);
        cache.prune_nodes(|node| node != "n1");
        assert_eq!(cache.authentic("n1", &reports["n1"], &key), None);
        cache.verify_fleet(&reports, &keys);
        assert_eq!(
            cache.verifications(),
            2,
            "the pruned entry is gone, so the next pass is a fresh verification"
        );
    }

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
        let provers = |log: &ObservationLog, id: &str| -> Vec<String> {
            log.provers(id).into_iter().collect()
        };
        let mut log = ObservationLog::new();
        assert!(provers(&log, &identity).is_empty());
        log.note_rejection("n", &identity);
        assert_eq!(provers(&log, &identity), vec!["n".to_string()]);
        assert!(
            provers(&log, &other).is_empty(),
            "a claim is about the exact bytes an assignment names, never about the node at large"
        );
        // A pass that could not read this node's report must not un-halt what it proved bad.
        log.prune_identities(&HashSet::from([identity.clone()]));
        assert_eq!(provers(&log, &identity), vec!["n".to_string()]);
        // The operator publishes corrected bytes: the old identity leaves every generation and the
        // claim goes with it, so the fleet is not halted by evidence about a body nobody names.
        log.prune_identities(&HashSet::from([other]));
        assert!(provers(&log, &identity).is_empty());

        log.note_rejection("n", &identity);
        log.prune_nodes(|_| false);
        assert!(
            provers(&log, &identity).is_empty(),
            "a decommissioned machine's claim leaves with it, so a same-name replacement starts \
             from nothing"
        );
    }

    /// The evidence behind a fleet-wide halt is every machine that proved the bytes bad, whatever
    /// group each one is in now — the count is per IDENTITY, so a relabelled, quarantined, or
    /// unmatched prover is still a prover.
    #[test]
    fn provers_are_counted_per_identity_across_the_whole_fleet() {
        let identity = "a".repeat(64);
        let other = "b".repeat(64);
        let mut log = ObservationLog::new();
        log.note_rejection("grouped", &identity);
        log.note_rejection("unmatched", &identity);
        log.note_rejection("elsewhere", &other);
        assert_eq!(
            log.provers(&identity),
            BTreeSet::from(["grouped".to_string(), "unmatched".to_string()])
        );
        assert_eq!(
            log.provers(&other),
            BTreeSet::from(["elsewhere".to_string()])
        );
    }
}
