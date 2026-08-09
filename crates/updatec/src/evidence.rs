//! Cross-pass observation memory for the regression verdict: the [`ObservationLog`].
//!
//! Split out of the per-pass planner deliberately. The planner is pure — every verdict recomputed
//! from this pass's inputs — while rollback evidence is inherently a SEQUENCE of reports, and the
//! boundary between those two models is where every deep defect of this feature lived: a health
//! blip read as an attempt, a merely-fetched tick read as a rollback, a stale record from a
//! committed movement resurrected a retarget later. Everything that remembers the past lives in
//! this module, its lifecycle rules (open / upgrade / close / prune) are stated on `observe`, and
//! the module's test is a MODEL-BASED FUZZ: an independent declarative specification over whole
//! report histories that the incremental log must agree with on every step of every random
//! sequence — so the next lifecycle bug is caught by the model disagreeing, not by a reviewer
//! rediscovering it in production shape.

use std::collections::{HashMap, HashSet};

use updated_contracts::telemetry::NodeReport;

/// Cross-pass observation memory about the FLEET's nodes: which assignments each node has been
/// SEEN attempting (what it was running before the attempt began), and which nodes have ever
/// uploaded a report at all.
///
/// The evidence a rollback leaves behind is a report SEQUENCE — an update transaction in flight on
/// the new assignment, then settled again on the pre-attempt archive — and no single snapshot can
/// carry it: a fleet that rolled back FROM a bad deployment and a fleet the operator retargeted TO
/// the predecessor look identical in one pass, and deriving the verdict from one snapshot halted
/// the documented recovery path itself. This log is observational memory only, never a stored
/// verdict: the halt remains recomputed from the reports each pass, and losing the log (a leader
/// change, a restart) merely re-derives the evidence from the fresh attempt sequences the
/// still-contained nodes keep producing.
///
/// "Has ever reported" lives here for the same reason and not one of its own: it is a fact about
/// the past that a single pass's store read cannot establish. Re-deriving it from the reports
/// readable RIGHT NOW made an object store that stopped answering drive every group's `observable`
/// count to zero, which clears `ReportsStale` — the alert resolves itself exactly when the whole
/// fleet goes dark. Remembered, a store outage leaves the count where it was while `fresh` falls,
/// so the condition fires.
#[derive(Clone, Debug, Default)]
pub struct ObservationLog {
    /// node → target assignment identity → the movement record ([`AttemptSeed`]) opened when the
    /// node was first seen naming that assignment after being settled on a different one.
    attempts: HashMap<String, HashMap<String, AttemptSeed>>,
    /// node → the (assignment, archive) of its most recent settled healthy report.
    settled: HashMap<String, (String, String)>,
    /// Nodes whose report envelope has been seen in the store at least once, at any age and
    /// whether or not it verified ([`ObservationLog::has_reported`]).
    reported: HashSet<String>,
}

/// One observed movement of a node toward a new assignment: where it came from, and whether the
/// transaction itself was ever seen in flight.
#[derive(Clone, Debug)]
pub(crate) struct AttemptSeed {
    /// The assignment identity the node was settled on before the movement.
    pub(crate) from: String,
    /// The archive it was settled on before the movement — what a rollback returns it to.
    pub(crate) archive: String,
    /// Whether a report with an update TRANSACTION in flight on the target was observed
    /// ([`NodeReport::updating`]): the transaction genuinely ran.
    ///
    /// Two shapes are rejected by this flag, and both mint a fleet-wide halt without it. A node
    /// that merely FETCHED the assignment reports settled on it while running the old archive —
    /// the supervisor stamps the assignment it resolved even on a tick that installed nothing.
    /// And a node whose install never started still fails an ordinary readiness probe now and
    /// then; `healthy == false` alone cannot tell that blip from a transaction, which is why the
    /// node reports the two separately.
    attempted: bool,
}

impl ObservationLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one node's fresh, verified report into the log.
    ///
    /// A movement record opens at the TRANSITION of the reported assignment — in either report
    /// shape. The transaction's own tick is the definitive one (it marks the record `attempted`),
    /// but a settled report naming a NEW assignment must open the record too: the supervisor
    /// reports the assignment it RESOLVED, so a tick that fetched the new assignment but could not
    /// yet install (a transient archive-download failure) reports settled on it while still running
    /// the old archive — and keying the seed off that report alone erased the movement's origin, so
    /// the later genuine rollback produced no evidence. A report on the assignment the node is
    /// already settled on — an ordinary health blip — opens nothing.
    ///
    /// A record is CLOSED when the node settles somewhere else, because the movement it describes
    /// is over. Records only ever being dropped by [`prune`](Self::prune) — which keeps every
    /// identity some group still names — left a node that had moved toward an identity, committed,
    /// and later moved away carrying that first movement's state for ever: the next movement
    /// toward the same identity reused the stale record, so a single merely-fetched tick inherited
    /// an `attempted` flag and a pre-movement archive from a transaction that had SUCCEEDED, and
    /// halted a healthy deployment fleet-wide. The same staleness silences genuine evidence in the
    /// other direction, by remembering an archive the node has long left.
    pub(crate) fn observe(&mut self, node: &str, report: &NodeReport) {
        if !updated_contracts::is_sha256_hex(&report.assignment_sha256) {
            return;
        }
        match self.settled.get(node) {
            Some((from, archive)) if from != &report.assignment_sha256 => {
                let seed = AttemptSeed {
                    from: from.clone(),
                    archive: archive.clone(),
                    attempted: report.updating,
                };
                match self
                    .attempts
                    .entry(node.to_string())
                    .or_default()
                    .entry(report.assignment_sha256.clone())
                {
                    // A record already open for this target keeps its origin (the earliest settled
                    // state of this movement) and only upgrades to `attempted` — the merely-fetched
                    // tick must not downgrade a transaction already seen in flight.
                    std::collections::hash_map::Entry::Occupied(mut open) => {
                        open.get_mut().attempted |= report.updating;
                    }
                    std::collections::hash_map::Entry::Vacant(vacant) => {
                        vacant.insert(seed);
                    }
                }
            }
            // NOT a transition — the merely-fetched tick already moved `settled` onto the target —
            // but the transaction arriving now still proves the movement ran: upgrade the record
            // opened at the transition. A readiness blip with NO transaction in flight upgrades
            // nothing and opens nothing.
            Some(_) if report.updating => {
                if let Some(open) = self
                    .attempts
                    .get_mut(node)
                    .and_then(|attempts| attempts.get_mut(&report.assignment_sha256))
                {
                    open.attempted = true;
                }
            }
            // A node never seen settled proves nothing about where a movement started, so no
            // record is opened for it — the conservative direction.
            _ => {}
        }
        if report.healthy && updated_contracts::is_sha256_hex(&report.archive_sha256) {
            self.settled.insert(
                node.to_string(),
                (
                    report.assignment_sha256.clone(),
                    report.archive_sha256.clone(),
                ),
            );
            // Settling is what closes every movement this node is no longer performing — including
            // the one it just completed toward some earlier identity. The record for the identity
            // it settled ON is kept: that is the movement still in progress or just finished, and
            // the rollback verdict is read from exactly it.
            if let Some(attempts) = self.attempts.get_mut(node) {
                attempts.retain(|identity, _| identity == &report.assignment_sha256);
                if attempts.is_empty() {
                    self.attempts.remove(node);
                }
            }
        }
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
    /// stays [`Observations::report`]): it exists so "has not reported yet" can be told apart from
    /// "stopped reporting". A node's key is pinned at enrollment, generations before it can fetch
    /// an assignment and upload anything, so counting a keyed-but-silent node as observable made
    /// every mass enrollment and every scale-out past `maxUnavailable` raise `ReportsStale` and
    /// then clear it — the alert-on-a-healthy-rollout the condition is tuned to avoid.
    pub(crate) fn has_reported(&self, node: &str) -> bool {
        self.reported.contains(node)
    }

    /// The movement record proving `node`, now settled on `identity` running `archive`, ROLLED
    /// BACK: its transaction toward exactly this assignment was seen in flight, and it is back on
    /// the archive it was settled on before the movement. `None` when nothing is proven: the node
    /// committed successfully (a different archive), was never seen moving, or only ever fetched
    /// the assignment without a transaction running.
    pub(crate) fn rolled_back(
        &self,
        node: &str,
        identity: &str,
        archive: &str,
    ) -> Option<&AttemptSeed> {
        if !updated_contracts::is_sha256_hex(archive) {
            return None;
        }
        self.attempts
            .get(node)
            .and_then(|attempts| attempts.get(identity))
            .filter(|seed| seed.attempted && seed.archive == archive)
    }

    /// Drop memory about nodes that left the fleet, and attempt records for assignment identities
    /// no generation still names — so the log stays bounded by the fleet and its live deployments
    /// rather than growing with history.
    pub(crate) fn prune(
        &mut self,
        nodes: impl Fn(&str) -> bool,
        live_identities: &HashSet<String>,
    ) {
        self.settled.retain(|node, _| nodes(node));
        self.reported.retain(|node| nodes(node));
        self.attempts.retain(|node, attempts| {
            if !nodes(node) {
                return false;
            }
            attempts.retain(|identity, _| live_identities.contains(identity));
            !attempts.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Identities and archives in the report grammar every gate upstream enforces.
    fn hex(c: char) -> String {
        c.to_string().repeat(64)
    }

    /// The report shapes a node can legally emit, as the trust gate admits them. `healthy` and
    /// `updating` are never both true (`is_wellformed` refuses the combination), and an archive is
    /// hex or empty (pre-first-install).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    struct Shape {
        assignment: char,
        archive: Option<char>,
        healthy: bool,
        updating: bool,
    }

    fn report_of(shape: Shape) -> NodeReport {
        let mut report = NodeReport::new(
            "n",
            "d",
            hex(shape.assignment),
            "1.0.0",
            shape.archive.map(hex).unwrap_or_default(),
            shape.healthy,
        );
        report.updating = shape.updating;
        report
    }

    /// The INDEPENDENT specification of a proven rollback, stated declaratively over a node's
    /// whole report history rather than as an incremental state machine — so the log and the model
    /// can only agree by both being right.
    ///
    /// `rolled_back(T, archive)` holds exactly when:
    /// 1. there is a "departure point" `i`: the LAST report that was settled-healthy with a usable
    ///    archive on an assignment other than `T` (the state the movement left from);
    /// 2. after `i`, some report names `T` with an update transaction in flight (`updating`) —
    ///    the movement genuinely ran, not merely fetched, not a readiness blip;
    /// 3. the queried `archive` is exactly the departure point's archive — the node is back on
    ///    what it ran before the movement, so it did not commit.
    fn model_rolled_back(history: &[Shape], target: char, archive: char) -> bool {
        let departure = history
            .iter()
            .enumerate()
            .filter(|(_, shape)| {
                shape.healthy && shape.archive.is_some() && shape.assignment != target
            })
            .next_back();
        let Some((index, departed_from)) = departure else {
            return false;
        };
        let attempted = history[index + 1..]
            .iter()
            .any(|shape| shape.assignment == target && shape.updating);
        attempted && departed_from.archive == Some(archive)
    }

    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
        fn pick(&mut self, n: usize) -> usize {
            (self.next() >> 33) as usize % n
        }
    }

    /// Every lifecycle defect this machinery has had was a divergence between the incremental log
    /// and the sequence semantics its documentation promises: a readiness blip minting an attempt,
    /// a merely-fetched tick erasing an origin, a committed movement's record resurrected a
    /// retarget later. This fuzz drives random legal report sequences through the log and asserts
    /// it agrees with the declarative model at EVERY step for EVERY (target, archive) pair, then
    /// asserts coverage: every shape kind was emitted and both verdict directions (a rollback
    /// proven, and a proof closed by a later settle) actually occurred — so "all sequences" is
    /// proven exercised, not hoped.
    #[test]
    fn the_log_agrees_with_the_declarative_model_on_every_step_of_every_sequence() {
        let identities = ['a', 'b', 'c'];
        let archives = ['1', '2', '3'];
        // The legal alphabet: settled (commit or steady state), settled-with-empty-archive
        // (pre-first-install), merely-fetched (settled on a new assignment, old archive),
        // transaction in flight, and a plain readiness failure. Healthy+updating is unrepresentable.
        let mut alphabet: Vec<Shape> = Vec::new();
        for assignment in identities {
            for archive in archives {
                alphabet.push(Shape {
                    assignment,
                    archive: Some(archive),
                    healthy: true,
                    updating: false,
                });
                alphabet.push(Shape {
                    assignment,
                    archive: Some(archive),
                    healthy: false,
                    updating: true,
                });
                alphabet.push(Shape {
                    assignment,
                    archive: Some(archive),
                    healthy: false,
                    updating: false,
                });
            }
            alphabet.push(Shape {
                assignment,
                archive: None,
                healthy: true,
                updating: false,
            });
        }

        let mut shapes_seen: HashSet<Shape> = HashSet::new();
        let mut proofs_seen = 0usize;
        let mut closures_seen = 0usize;
        let live: HashSet<String> = identities.iter().map(|&c| hex(c)).collect();

        for seed in 0..64u64 {
            let mut rng = Lcg(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1));
            let mut log = ObservationLog::new();
            let mut history: Vec<Shape> = Vec::new();
            let mut previous: HashMap<(char, char), bool> = HashMap::new();
            for _ in 0..200 {
                let shape = alphabet[rng.pick(alphabet.len())];
                shapes_seen.insert(shape);
                history.push(shape);
                log.observe("n", &report_of(shape));
                // Pruning with every identity live must be a no-op on the verdicts: it is the
                // fleet/lineage bound, never part of the evidence rule.
                log.prune(|_| true, &live);
                for &target in &identities {
                    for &archive in &archives {
                        let expected = model_rolled_back(&history, target, archive);
                        let actual = log.rolled_back("n", &hex(target), &hex(archive)).is_some();
                        assert_eq!(
                            actual, expected,
                            "seed {seed}: history {history:?} target {target} archive {archive}"
                        );
                        let prior = previous.insert((target, archive), actual);
                        match (prior, actual) {
                            (Some(false) | None, true) => proofs_seen += 1,
                            (Some(true), false) => closures_seen += 1,
                            _ => {}
                        }
                    }
                }
            }
        }
        for shape in &alphabet {
            assert!(
                shapes_seen.contains(shape),
                "shape {shape:?} was never fuzzed"
            );
        }
        assert!(proofs_seen > 0, "no sequence ever proved a rollback");
        assert!(
            closures_seen > 0,
            "no proof was ever closed by a later settle — the stale-record class is untested"
        );
    }

    /// A node that left the fleet, and identities no generation still names, are forgotten — the
    /// two bounds that keep the log's memory proportional to the live system. (The fuzz above
    /// proves pruning with everything live changes no verdict.)
    #[test]
    fn pruning_forgets_departed_nodes_and_retired_identities() {
        let mut log = ObservationLog::new();
        let settled = report_of(Shape {
            assignment: 'a',
            archive: Some('1'),
            healthy: true,
            updating: false,
        });
        let moving = report_of(Shape {
            assignment: 'b',
            archive: Some('1'),
            healthy: false,
            updating: true,
        });
        log.observe("n", &settled);
        log.observe("n", &moving);
        let node = "n".to_string();
        log.note_reported(std::iter::once(&node));
        let back = report_of(Shape {
            assignment: 'b',
            archive: Some('1'),
            healthy: true,
            updating: false,
        });
        log.observe("n", &back);
        assert!(log.rolled_back("n", &hex('b'), &hex('1')).is_some());

        // The identity leaves every generation: the record goes with it.
        let only_a: HashSet<String> = [hex('a')].into();
        log.prune(|_| true, &only_a);
        assert!(log.rolled_back("n", &hex('b'), &hex('1')).is_none());

        // The node leaves the fleet: everything about it goes.
        log.observe("n", &settled);
        log.observe("n", &moving);
        log.prune(|_| false, &only_a);
        assert!(!log.has_reported("n"));
        assert!(log.rolled_back("n", &hex('b'), &hex('1')).is_none());
    }
}
