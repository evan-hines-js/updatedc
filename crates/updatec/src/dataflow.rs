//! Private repository dataflow objects.
//!
//! Every application payload uses the repository's object store under private internal namespaces.
//! This is the only object-layout implementation for assignment-bound inputs, producer outputs,
//! raw node reports, and the repository-private generation key.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use futures::StreamExt as _;
use object_store::path::Path as ObjectPath;
use object_store::{ObjectStore, ObjectStoreExt as _, PutMode, PutOptions, PutPayload};
#[cfg(test)]
use updated_contracts::dataflow::FileSnapshot;
use updated_contracts::dataflow::{
    InputPublication, InputSelection, OutputPublication, MAX_DATAFLOW_BODY_BYTES,
};
use updated_contracts::telemetry::{
    accept_stored_report, AcceptedReport, Envelope, ReportStoredAt,
};

const GENERATION_KEY_OBJECT: &str = "internal/dataflow/generation.key";
pub(crate) const INPUT_ROOT: &str = "internal/dataflow/inputs";
pub(crate) const OUTPUT_ROOT: &str = "internal/dataflow/outputs";
pub(crate) const REPORT_ROOT: &str = "internal/telemetry/nodes";
const GENERATION_KEY_BYTES: usize = 32;

fn observe_private_namespace_entry(
    count: &mut usize,
    limit: usize,
    kind: &str,
) -> object_store::Result<()> {
    *count = count.saturating_add(1);
    if *count > limit {
        return Err(invalid(format!(
            "the private {kind} namespace exceeds its {limit}-object fleet bound"
        )));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> object_store::Error {
    object_store::Error::Generic {
        store: "updatec-dataflow",
        source: message.into().into(),
    }
}

#[derive(Clone)]
pub(crate) struct RepositoryDataflow {
    store: Arc<dyn ObjectStore>,
    prefix: Arc<str>,
}

impl RepositoryDataflow {
    pub(crate) fn new(store: Arc<dyn ObjectStore>, prefix: impl Into<Arc<str>>) -> Self {
        Self {
            store,
            prefix: prefix.into(),
        }
    }

    fn key(&self, relative: &str) -> ObjectPath {
        crate::object_key(&self.prefix, relative)
    }

    pub(crate) fn output_key(&self, node: &str) -> ObjectPath {
        let digest = updated_contracts::telemetry::node_object_digest(node);
        self.key(&format!("{OUTPUT_ROOT}/{digest}.json"))
    }

    pub(crate) fn input_key(&self, assignment_sha256: &str) -> ObjectPath {
        self.key(&format!("{INPUT_ROOT}/{assignment_sha256}.json"))
    }

    pub(crate) fn report_key(&self, node: &str) -> ObjectPath {
        let digest = updated_contracts::telemetry::node_object_digest(node);
        self.key(&format!("{REPORT_ROOT}/{digest}.json"))
    }

    pub(crate) async fn generation_key(&self) -> object_store::Result<[u8; 32]> {
        let object = self.key(GENERATION_KEY_OBJECT);
        match crate::read_object_bounded(self.store.as_ref(), &object, GENERATION_KEY_BYTES as u64)
            .await
        {
            Ok(bytes) => return decode_generation_key(&bytes),
            Err(object_store::Error::NotFound { .. }) => {}
            Err(error) => return Err(error),
        }

        use aws_lc_rs::rand::SecureRandom as _;
        let mut generated = [0u8; GENERATION_KEY_BYTES];
        aws_lc_rs::rand::SystemRandom::new()
            .fill(&mut generated)
            .map_err(|_| invalid("secure randomness is unavailable"))?;
        match self
            .store
            .put_opts(
                &object,
                PutPayload::from(generated.to_vec()),
                PutOptions {
                    mode: PutMode::Create,
                    ..Default::default()
                },
            )
            .await
        {
            Ok(_) => Ok(generated),
            Err(
                object_store::Error::Precondition { .. }
                | object_store::Error::AlreadyExists { .. },
            ) => {
                let bytes = crate::read_object_bounded(
                    self.store.as_ref(),
                    &object,
                    GENERATION_KEY_BYTES as u64,
                )
                .await?;
                decode_generation_key(&bytes)
            }
            Err(error) => Err(error),
        }
    }

    /// Publish the complete file snapshot for one exact signed assignment. Objects are immutable:
    /// an assignment digest can never resolve to different bytes after a node has acted on it.
    pub(crate) async fn put_inputs(
        &self,
        assignment_sha256: &str,
        publication: &InputPublication,
        selection: &InputSelection,
    ) -> object_store::Result<()> {
        if !updated_contracts::is_canonical_sha256(assignment_sha256) {
            return Err(invalid("input object key is not a SHA-256 digest"));
        }
        let body = publication.to_bounded_body().map_err(invalid)?;
        InputPublication::from_bounded_body(&body, selection).map_err(invalid)?;
        let object = self.input_key(assignment_sha256);
        match self
            .store
            .put_opts(
                &object,
                PutPayload::from(body.clone()),
                PutOptions {
                    mode: PutMode::Create,
                    ..Default::default()
                },
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(
                object_store::Error::Precondition { .. }
                | object_store::Error::AlreadyExists { .. },
            ) => {
                let existing = crate::read_object_bounded(
                    self.store.as_ref(),
                    &object,
                    MAX_DATAFLOW_BODY_BYTES as u64,
                )
                .await?;
                if existing == body {
                    Ok(())
                } else {
                    Err(invalid(format!(
                        "assignment {assignment_sha256} already names different input bytes"
                    )))
                }
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) async fn inputs(
        &self,
        assignment_sha256: &str,
        selection: &InputSelection,
    ) -> object_store::Result<InputPublication> {
        if !updated_contracts::is_canonical_sha256(assignment_sha256) {
            return Err(invalid("input object key is not a SHA-256 digest"));
        }
        let object = self.input_key(assignment_sha256);
        let body = crate::read_object_bounded(
            self.store.as_ref(),
            &object,
            MAX_DATAFLOW_BODY_BYTES as u64,
        )
        .await?;
        InputPublication::from_bounded_body(&body, selection).map_err(invalid)
    }

    fn output_root(&self) -> ObjectPath {
        self.key(OUTPUT_ROOT)
    }

    fn input_root(&self) -> ObjectPath {
        self.key(INPUT_ROOT)
    }

    fn report_root(&self) -> ObjectPath {
        self.key(REPORT_ROOT)
    }

    /// Retire immutable input publications no live assignment names, after every capability that
    /// could have been minted for the old assignment has expired.
    ///
    /// The caller invokes this only after the replacement TUF generation is durably live. Active
    /// assignment objects are exact-path protected regardless of age; a grace cutoff handles a GET
    /// capability minted immediately before the generation changed. Unknown old entries in this
    /// controller-owned namespace are garbage as well, so interrupted writes cannot accumulate.
    pub(crate) async fn sweep_inputs_before(
        &self,
        active_assignment_sha256: impl IntoIterator<Item = String>,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> object_store::Result<usize> {
        let mut active = BTreeSet::new();
        for digest in active_assignment_sha256 {
            if !updated_contracts::is_canonical_sha256(&digest) {
                return Err(invalid("active input assignment is not a SHA-256 digest"));
            }
            active.insert(self.input_key(&digest));
        }
        let root = self.input_root();
        let mut objects = self.store.list(Some(&root));
        let sweep = async {
            let mut removed = 0usize;
            let mut count = 0usize;
            while let Some(next) = objects.next().await {
                let metadata = next?;
                observe_private_namespace_entry(
                    &mut count,
                    updated_contracts::backend::MAX_BACKEND_INVENTORY_MEMBERS,
                    "input",
                )?;
                if !crate::object_in_namespace(&root, &metadata.location) {
                    continue;
                }
                if metadata.last_modified <= cutoff && !active.contains(&metadata.location) {
                    match self.store.delete(&metadata.location).await {
                        Ok(()) | Err(object_store::Error::NotFound { .. }) => {
                            removed = removed.saturating_add(1);
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
            Ok(removed)
        };
        tokio::time::timeout(crate::OBJECT_STORE_MAINTENANCE_TIMEOUT, sweep)
            .await
            .map_err(|_| invalid("sweeping obsolete input snapshots timed out"))?
    }
}

fn decode_generation_key(bytes: &[u8]) -> object_store::Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| invalid("the repository dataflow generation key is not exactly 32 bytes"))
}

/// An absent ETag is no cache validator. Some object-store implementations legitimately omit it;
/// treating `None == None` as unchanged would pin the first body forever.
fn same_etag(cached: &Option<String>, current: &Option<String>) -> bool {
    matches!((cached, current), (Some(cached), Some(current)) if cached == current)
}

async fn retire_stale_object(store: &dyn ObjectStore, object: &ObjectPath, kind: &str) {
    match store.delete(object).await {
        Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
        Err(error) => {
            tracing::warn!(%object, %error, "retiring stale {kind} failed");
        }
    }
}

/// ETag-aware view of current producer outputs. One prefix listing per reconcile discovers every
/// change; only changed objects cross the wire. Objects for deleted nodes are removed so the
/// namespace remains bounded by the current inventory rather than historical churn.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExactOutputPublication {
    /// SHA-256 of the exact bytes read from storage, not of a reserialized document.
    sha256: String,
    publication: OutputPublication,
}

impl ExactOutputPublication {
    pub(crate) fn decode(body: &[u8], node: &str) -> Result<Self, String> {
        if body.len() > MAX_DATAFLOW_BODY_BYTES {
            return Err(format!(
                "dataflow output publication is {} bytes, past the {MAX_DATAFLOW_BODY_BYTES}-byte limit",
                body.len()
            ));
        }
        let publication: OutputPublication = serde_json::from_slice(body)
            .map_err(|error| format!("decoding dataflow output publication: {error}"))?;
        publication.validate(node)?;
        Ok(Self {
            sha256: updated_contracts::digest::sha256_bytes(body),
            publication,
        })
    }

    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }

    pub(crate) fn publication(&self) -> &OutputPublication {
        &self.publication
    }
}

#[derive(Default)]
pub(crate) struct OutputCache {
    entries: HashMap<ObjectPath, (Option<String>, ExactOutputPublication)>,
}

impl OutputCache {
    pub(crate) async fn refresh(
        &mut self,
        dataflow: &RepositoryDataflow,
        nodes: impl IntoIterator<Item = String>,
    ) -> object_store::Result<HashMap<String, ExactOutputPublication>> {
        let wanted: BTreeMap<ObjectPath, String> = nodes
            .into_iter()
            .map(|node| (dataflow.output_key(&node), node))
            .collect();
        let mut seen = BTreeSet::new();
        let root = dataflow.output_root();
        let mut listing = dataflow.store.list(Some(&root));
        let scan = async {
            let mut count = 0usize;
            while let Some(item) = listing.next().await {
                let meta = item?;
                observe_private_namespace_entry(
                    &mut count,
                    updated_contracts::backend::MAX_BACKEND_INVENTORY_MEMBERS,
                    "output",
                )?;
                if !crate::object_in_namespace(&root, &meta.location) {
                    continue;
                }
                let Some(node) = wanted.get(&meta.location) else {
                    retire_stale_object(dataflow.store.as_ref(), &meta.location, "node output")
                        .await;
                    self.entries.remove(&meta.location);
                    continue;
                };
                seen.insert(meta.location.clone());
                let unchanged = self
                    .entries
                    .get(&meta.location)
                    .is_some_and(|(etag, _)| same_etag(etag, &meta.e_tag));
                if unchanged {
                    continue;
                }
                let body = match crate::read_object_bounded(
                    dataflow.store.as_ref(),
                    &meta.location,
                    MAX_DATAFLOW_BODY_BYTES as u64,
                )
                .await
                {
                    Ok(body) => body,
                    Err(error) => {
                        tracing::warn!(%node, %error, "ignoring unreadable node output object");
                        self.entries.remove(&meta.location);
                        continue;
                    }
                };
                let publication = match ExactOutputPublication::decode(&body, node) {
                    Ok(publication) => publication,
                    Err(error) => {
                        tracing::warn!(%node, %error, "ignoring malformed node output object");
                        self.entries.remove(&meta.location);
                        continue;
                    }
                };
                self.entries
                    .insert(meta.location, (meta.e_tag, publication));
            }
            Ok::<(), object_store::Error>(())
        };
        tokio::time::timeout(crate::OBJECT_STORE_MAINTENANCE_TIMEOUT, scan)
            .await
            .map_err(|_| invalid("scanning the private output namespace timed out"))??;
        self.entries.retain(|object, _| seen.contains(object));
        Ok(self
            .entries
            .values()
            .map(|(_, output)| (output.publication().node.clone(), output.clone()))
            .collect())
    }
}

/// ETag-aware view of raw per-node report objects. One prefix listing discovers changes; malformed
/// or oversized bytes silence only their own node and can never fail the fleet reconcile.
#[derive(Default)]
pub(crate) struct ReportCache {
    /// The gate's own verdict is what is cached, not just the envelope it produced.
    ///
    /// An entry survives a pass untouched only while both its content ETag and durable storage
    /// instant are unchanged. Some stores reuse a content-derived ETag when identical bytes are
    /// written again; ignoring `last_modified` there would make a running controller retain the
    /// old order while a restarted controller observed the new one.
    entries: HashMap<ObjectPath, CachedReport>,
    initialized: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CachedReport {
    etag: Option<String>,
    stored_at: ReportStoredAt,
    accepted: AcceptedReport,
}

impl CachedReport {
    fn matches(&self, etag: &Option<String>, stored_at: ReportStoredAt) -> bool {
        same_etag(&self.etag, etag) && self.stored_at == stored_at
    }
}

pub(crate) struct ReportSnapshot {
    /// This pass's accepted reports, keyed by node.
    pub accepted: HashMap<String, AcceptedReport>,
    pub changed: bool,
}

impl ReportSnapshot {
    /// The envelopes alone, for the planner, which has no use for the acceptance proof.
    ///
    /// Consuming: the envelopes move out rather than being cloned a second time.
    pub(crate) fn into_envelopes(self) -> HashMap<String, Envelope> {
        self.accepted
            .into_iter()
            .map(|(node, accepted)| (node, accepted.into_envelope()))
            .collect()
    }
}

impl ReportCache {
    pub(crate) async fn refresh(
        &mut self,
        dataflow: &RepositoryDataflow,
        nodes: impl IntoIterator<Item = String>,
    ) -> object_store::Result<ReportSnapshot> {
        let wanted: BTreeMap<ObjectPath, String> = nodes
            .into_iter()
            .map(|node| (dataflow.report_key(&node), node))
            .collect();
        let previous = self.entries.clone();
        let mut seen = BTreeSet::new();
        let root = dataflow.report_root();
        let mut listing = dataflow.store.list(Some(&root));
        let scan = async {
            let mut count = 0usize;
            while let Some(item) = listing.next().await {
                let meta = item?;
                observe_private_namespace_entry(
                    &mut count,
                    updated_contracts::backend::MAX_BACKEND_INVENTORY_MEMBERS,
                    "report",
                )?;
                if !crate::object_in_namespace(&root, &meta.location) {
                    continue;
                }
                let Some(node) = wanted.get(&meta.location) else {
                    retire_stale_object(dataflow.store.as_ref(), &meta.location, "raw node report")
                        .await;
                    self.entries.remove(&meta.location);
                    continue;
                };
                seen.insert(meta.location.clone());
                let Some(stored_at) =
                    ReportStoredAt::from_unix_millis(meta.last_modified.timestamp_millis())
                else {
                    tracing::warn!(%node, "ignoring raw node report with pre-epoch metadata");
                    self.entries.remove(&meta.location);
                    continue;
                };
                if self
                    .entries
                    .get(&meta.location)
                    .is_some_and(|entry| entry.matches(&meta.e_tag, stored_at))
                {
                    continue;
                }
                let body = match crate::read_object_bounded(
                    dataflow.store.as_ref(),
                    &meta.location,
                    updated_contracts::telemetry::MAX_REPORT_ENVELOPE_BYTES as u64,
                )
                .await
                {
                    Ok(body) => body,
                    Err(error) => {
                        tracing::warn!(%node, %error, "ignoring unreadable raw node report");
                        self.entries.remove(&meta.location);
                        continue;
                    }
                };
                // THE acceptance point: the only place raw report bytes enter this control
                // plane. The store's durable timestamp survives controller restarts; stamping
                // `now` here would make every cached object equally new after a restart and turn
                // bounded eviction into node-name order.
                let accepted = accept_stored_report(&body, node, stored_at);
                let Some(accepted) = accepted else {
                    tracing::warn!(%node, "ignoring malformed raw node report");
                    self.entries.remove(&meta.location);
                    continue;
                };
                self.entries.insert(
                    meta.location,
                    CachedReport {
                        etag: meta.e_tag,
                        stored_at,
                        accepted,
                    },
                );
            }
            Ok::<(), object_store::Error>(())
        };
        tokio::time::timeout(crate::OBJECT_STORE_MAINTENANCE_TIMEOUT, scan)
            .await
            .map_err(|_| invalid("scanning the private report namespace timed out"))??;
        self.entries.retain(|object, _| seen.contains(object));
        let changed = !self.initialized || self.entries != previous;
        self.initialized = true;
        let accepted = wanted
            .into_iter()
            .filter_map(|(object, node)| {
                self.entries
                    .get(&object)
                    .map(|entry| (node, entry.accepted.clone()))
            })
            .collect();
        Ok(ReportSnapshot { accepted, changed })
    }
}

/// Publish the healthproxy-compatible fleet projection from the raw node objects the controller
/// just read. Shards land first and the small index last, so every visible index names a complete
/// generation. The raw objects remain the durable source; this projection is replaceable.
pub(crate) async fn publish_report_projection(
    store: &dyn ObjectStore,
    prefix: &str,
    accepted: &HashMap<String, AcceptedReport>,
    max_shards: updated_contracts::telemetry::FleetShardLimit,
) -> object_store::Result<()> {
    let mut fleet = updated_contracts::telemetry::FleetReports::default();
    for accepted in accepted.values() {
        fleet.record(accepted.clone());
    }
    let generation = fleet.rebalance(max_shards).map_err(invalid)?;
    let (_index, index_body, shards, evicted) = generation.into_parts();
    if evicted > 0 {
        tracing::warn!(
            evicted,
            "fleet report projection evicted its oldest entries"
        );
    }
    for (location, body) in shards {
        let key = crate::object_key(prefix, &location.object_key());
        store.put(&key, PutPayload::from(body)).await?;
    }
    let index = crate::object_key(prefix, updated_contracts::telemetry::FLEET_INDEX_OBJECT_KEY);
    store
        .put(&index, PutPayload::from(index_body))
        .await
        .map(|_| ())
}

/// Delete expired projection generations not named by the current index. The controller owns both
/// projection publication and retirement; the gateway never reads or mutates payload bytes.
pub(crate) async fn sweep_report_projections_before(
    store: &dyn ObjectStore,
    prefix: &str,
    cutoff: chrono::DateTime<chrono::Utc>,
) -> object_store::Result<()> {
    let index_key = crate::object_key(prefix, updated_contracts::telemetry::FLEET_INDEX_OBJECT_KEY);
    let body = match crate::read_object_bounded(
        store,
        &index_key,
        updated_contracts::telemetry::MAX_FLEET_INDEX_BYTES as u64,
    )
    .await
    {
        Ok(body) => body,
        Err(object_store::Error::NotFound { .. }) => return Ok(()),
        Err(error) => return Err(error),
    };
    let index = updated_contracts::telemetry::FleetIndex::parse(&body)
        .ok_or_else(|| invalid("the fleet report projection index is malformed"))?;
    let active: BTreeSet<ObjectPath> = index
        .shard_locations()
        .map(|location| crate::object_key(prefix, &location.object_key()))
        .collect();
    let fleet_prefix = crate::object_key(prefix, "telemetry/fleet");
    let shard_prefix = format!("{fleet_prefix}/");
    let mut objects = store.list(Some(&fleet_prefix));
    let sweep = async {
        while let Some(next) = objects.next().await {
            let metadata = next?;
            if metadata.location.as_ref().starts_with(&shard_prefix)
                && metadata.last_modified <= cutoff
                && !active.contains(&metadata.location)
            {
                match store.delete(&metadata.location).await {
                    Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    };
    tokio::time::timeout(crate::OBJECT_STORE_MAINTENANCE_TIMEOUT, sweep)
        .await
        .map_err(|_| invalid("sweeping obsolete fleet report projections timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(value: &[u8]) -> updated_contracts::dataflow::FileValue {
        updated_contracts::dataflow::FileValue::from_bytes(value).unwrap()
    }

    #[test]
    fn only_present_equal_etags_are_cache_validators() {
        assert!(same_etag(&Some("v1".into()), &Some("v1".into())));
        assert!(!same_etag(&Some("v1".into()), &Some("v2".into())));
        assert!(!same_etag(&None, &None));
        assert!(!same_etag(&Some("v1".into()), &None));
    }

    #[test]
    fn private_namespace_scan_budget_counts_every_listed_object() {
        let mut count = 0;
        observe_private_namespace_entry(&mut count, 1, "test").unwrap();
        assert!(observe_private_namespace_entry(&mut count, 1, "test").is_err());
    }

    fn publication(node: &str, value: &[u8]) -> OutputPublication {
        OutputPublication {
            schema: OutputPublication::SCHEMA,
            node: node.into(),
            deployment: "database".into(),
            assignment_sha256: "a".repeat(64),
            archive_sha256: "b".repeat(64),
            snapshot: FileSnapshot {
                files: BTreeMap::from([("endpoint".into(), file(value))]),
            },
        }
    }

    fn private_input(value: &[u8]) -> (InputPublication, InputSelection) {
        let publication = InputPublication::from_snapshot(
            FileSnapshot {
                files: BTreeMap::from([("password".into(), file(value))]),
            },
            &[7u8; 32],
        )
        .unwrap();
        let selection = publication.selection().unwrap();
        (publication, selection)
    }

    fn signed_report(node: &str) -> Envelope {
        use aws_lc_rs::rand::SecureRandom as _;
        use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

        let rng = aws_lc_rs::rand::SystemRandom::new();
        let key = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let mut report = updated_contracts::telemetry::NodeReport::new(
            node,
            "database",
            "a".repeat(64),
            "1.0.0",
            "b".repeat(64),
            "b".repeat(64),
            true,
        );
        report.output_sha256 = Some("c".repeat(64));
        // Prove the test key really came from the production randomness source rather than a
        // fixed fixture that could accidentally make signature handling deterministic.
        let mut entropy = [0u8; 1];
        rng.fill(&mut entropy).unwrap();
        crate::test_support::sign_report(&mut report, key.as_ref())
    }

    /// A signed report carried through the one acceptance gate, the way the scanner produces one.
    fn accepted_report(node: &str) -> AcceptedReport {
        let envelope = signed_report(node);
        accept_stored_report(
            &serde_json::to_vec(&envelope).unwrap(),
            node,
            ReportStoredAt::from_unix_millis(1).unwrap(),
        )
        .expect("a freshly signed report is acceptable")
    }

    #[test]
    fn report_cache_identity_includes_durable_storage_time() {
        let entry = CachedReport {
            etag: Some("same-content".into()),
            stored_at: ReportStoredAt::from_unix_millis(1).unwrap(),
            accepted: accepted_report("database-0"),
        };

        assert!(entry.matches(
            &Some("same-content".into()),
            ReportStoredAt::from_unix_millis(1).unwrap()
        ));
        assert!(
            !entry.matches(
                &Some("same-content".into()),
                ReportStoredAt::from_unix_millis(2).unwrap()
            ),
            "rewriting identical bytes is still a new durable storage event"
        );
    }

    #[tokio::test]
    async fn input_objects_are_assignment_bound_and_the_generation_key_is_stable() {
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let dataflow = RepositoryDataflow::new(store, "repository");
        assert_eq!(
            dataflow.generation_key().await.unwrap(),
            dataflow.generation_key().await.unwrap()
        );

        let (publication, selection) = private_input(b"secret");
        let assignment = "a".repeat(64);
        dataflow
            .put_inputs(&assignment, &publication, &selection)
            .await
            .unwrap();
        dataflow
            .put_inputs(&assignment, &publication, &selection)
            .await
            .unwrap();
        assert_eq!(
            dataflow.inputs(&assignment, &selection).await.unwrap(),
            publication
        );
        let (different, different_selection) = private_input(b"different");
        assert!(
            dataflow
                .put_inputs(&assignment, &different, &different_selection)
                .await
                .is_err(),
            "one signed assignment digest must never resolve to different input bytes"
        );
        assert!(dataflow
            .put_inputs("not-a-digest", &publication, &selection)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn input_gc_keeps_live_assignments_and_outlives_every_minted_capability() {
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let dataflow = RepositoryDataflow::new(store.clone(), "repository");
        let active = "a".repeat(64);
        let retired = "b".repeat(64);
        let (publication, selection) = private_input(b"secret");
        dataflow
            .put_inputs(&active, &publication, &selection)
            .await
            .unwrap();
        dataflow
            .put_inputs(&retired, &publication, &selection)
            .await
            .unwrap();
        let retired_key = dataflow.input_key(&retired);

        assert_eq!(
            dataflow
                .sweep_inputs_before(
                    [active.clone()],
                    chrono::Utc::now() - chrono::Duration::seconds(1),
                )
                .await
                .unwrap(),
            0,
            "a fresh abandoned object may still have a live bearer URL"
        );
        store
            .get(&retired_key)
            .await
            .expect("the capability grace retains the object");

        assert_eq!(
            dataflow
                .sweep_inputs_before(
                    [active.clone()],
                    chrono::Utc::now() + chrono::Duration::seconds(1),
                )
                .await
                .unwrap(),
            1
        );
        dataflow
            .inputs(&active, &selection)
            .await
            .expect("a live assignment is protected regardless of age");
        assert!(matches!(
            store.get(&retired_key).await,
            Err(object_store::Error::NotFound { .. })
        ));
    }

    #[test]
    fn per_node_object_keys_hide_and_confine_node_names() {
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let dataflow = RepositoryDataflow::new(store, "repository");
        let output = dataflow.output_key("rack-1.database-0").to_string();
        let report = dataflow.report_key("rack-1.database-0").to_string();
        assert!(!output.contains("rack-1.database-0"));
        assert!(!report.contains("rack-1.database-0"));
        assert_ne!(output, report, "object types have separate namespaces");
    }

    #[tokio::test]
    async fn one_bad_output_object_cannot_poison_other_nodes() {
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let dataflow = RepositoryDataflow::new(store.clone(), "repository");
        let good = publication("database-0", b"db.internal:5432");
        let good_body = serde_json::to_vec(&good).unwrap();
        store
            .put(
                &dataflow.output_key("database-0"),
                PutPayload::from(good_body.clone()),
            )
            .await
            .unwrap();
        store
            .put(
                &dataflow.output_key("database-1"),
                PutPayload::from(vec![b'x'; MAX_DATAFLOW_BODY_BYTES + 1]),
            )
            .await
            .unwrap();

        let outputs = OutputCache::default()
            .refresh(
                &dataflow,
                ["database-0".to_string(), "database-1".to_string()],
            )
            .await
            .unwrap();
        let output = outputs.get("database-0").unwrap();
        assert_eq!(output.publication(), &good);
        assert_eq!(
            output.sha256(),
            updated_contracts::digest::sha256_bytes(&good_body)
        );
        assert!(!outputs.contains_key("database-1"));
    }

    #[tokio::test]
    async fn raw_report_cache_isolates_malformed_nodes_and_tracks_changes() {
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let dataflow = RepositoryDataflow::new(store.clone(), "repository");
        let envelope = signed_report("database-0");
        store
            .put(
                &dataflow.report_key("database-0"),
                PutPayload::from(serde_json::to_vec(&envelope).unwrap()),
            )
            .await
            .unwrap();
        store
            .put(
                &dataflow.report_key("database-1"),
                PutPayload::from(b"not json".to_vec()),
            )
            .await
            .unwrap();

        let nodes = ["database-0".to_string(), "database-1".to_string()];
        let mut cache = ReportCache::default();
        let first = cache.refresh(&dataflow, nodes.clone()).await.unwrap();
        assert!(first.changed);
        assert_eq!(
            first
                .accepted
                .get("database-0")
                .cloned()
                .map(AcceptedReport::into_envelope),
            Some(envelope)
        );
        assert!(!first.accepted.contains_key("database-1"));
        assert!(!cache.refresh(&dataflow, nodes).await.unwrap().changed);
    }

    #[tokio::test]
    async fn objects_for_absent_nodes_are_retired_from_private_namespaces() {
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let dataflow = RepositoryDataflow::new(store.clone(), "repository");
        let departed = dataflow.output_key("departed-0");
        store
            .put(
                &departed,
                PutPayload::from(serde_json::to_vec(&publication("departed-0", b"old")).unwrap()),
            )
            .await
            .unwrap();
        // Deliberately a byte-prefix *sibling* of the output namespace, derived from it so the
        // test keeps testing that if the namespace is ever renamed.
        let sibling = crate::object_key("repository", &format!("{OUTPUT_ROOT}-old/foreign.json"));
        store
            .put(&sibling, PutPayload::from(b"foreign".to_vec()))
            .await
            .unwrap();

        OutputCache::default()
            .refresh(&dataflow, std::iter::empty())
            .await
            .unwrap();
        assert!(matches!(
            store.get(&departed).await,
            Err(object_store::Error::NotFound { .. })
        ));
        store
            .get(&sibling)
            .await
            .expect("a byte-prefix sibling is outside the output namespace");
    }

    #[tokio::test]
    async fn projection_sweep_preserves_the_indexed_generation() {
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let prefix = "repository";
        publish_report_projection(
            store.as_ref(),
            prefix,
            &HashMap::from([("database-0".into(), accepted_report("database-0"))]),
            updated_contracts::telemetry::FleetShardLimit::new(8).unwrap(),
        )
        .await
        .unwrap();
        let index_key =
            crate::object_key(prefix, updated_contracts::telemetry::FLEET_INDEX_OBJECT_KEY);
        let index_body = crate::read_object_bounded(
            store.as_ref(),
            &index_key,
            updated_contracts::telemetry::MAX_FLEET_INDEX_BYTES as u64,
        )
        .await
        .unwrap();
        let index = updated_contracts::telemetry::FleetIndex::parse(&index_body).unwrap();
        let active: Vec<ObjectPath> = index
            .shard_locations()
            .map(|location| crate::object_key(prefix, &location.object_key()))
            .collect();
        assert!(!active.is_empty());

        let stale = crate::object_key(prefix, "telemetry/fleet/obsolete/shard-00000000.json");
        store
            .put(&stale, PutPayload::from(b"obsolete".to_vec()))
            .await
            .unwrap();
        sweep_report_projections_before(
            store.as_ref(),
            prefix,
            chrono::Utc::now() + chrono::Duration::seconds(1),
        )
        .await
        .unwrap();

        assert!(matches!(
            store.get(&stale).await,
            Err(object_store::Error::NotFound { .. })
        ));
        for object in active {
            store
                .get(&object)
                .await
                .expect("the current index protects every active shard");
        }
    }
}
