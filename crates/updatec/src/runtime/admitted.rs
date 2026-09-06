//! The admitted rollout state: what the planner committed to, sharded across ConfigMaps so it
//! survives a restart, plus the pending-publication journal that makes a half-finished publish
//! recoverable rather than ambiguous.

use super::*;

/// Base name for the durable-state index and its deterministic shard ConfigMaps.
///
/// Shards add `-a-00`/`-b-00`, so the base is capped at 248 characters. A repository name may use
/// Kubernetes' full 253-character DNS-subdomain allowance; [`bounded_child_name`] hashes the
/// truncated tail so every derived name stays valid without a second naming path.
pub(crate) fn admitted_configmap_name(repository_name: &str) -> String {
    const MAX_BASE_BYTES: usize = 248;
    bounded_child_name("updatec-admitted-", repository_name, MAX_BASE_BYTES)
}

/// A repository's validated durable-state width.
///
/// The CRD carries a `u8`, storage indexes carry a `u8`, and collection APIs need a `usize`.
/// Keeping both conversions behind this type means code that writes an index cannot accidentally
/// consume an unvalidated integer or re-state the absolute bound with a fallible conversion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AdmittedShardLimit(u8);

impl AdmittedShardLimit {
    pub(crate) fn new(configured: u8) -> Result<Self, StorageError> {
        if !(1..=MAX_ADMITTED_STATE_SHARDS).contains(&usize::from(configured)) {
            return Err(StorageError::Operation(format!(
                "stateMaxShards must be between 1 and {MAX_ADMITTED_STATE_SHARDS}"
            )));
        }
        Ok(Self(configured))
    }

    pub(crate) fn stored(self) -> u8 {
        self.0
    }

    pub(crate) fn count(self) -> usize {
        usize::from(self.0)
    }
}

pub(crate) fn admitted_state_shard_name(
    base: &str,
    slot: AdmittedStateSlot,
    index: usize,
) -> String {
    debug_assert!(index < MAX_ADMITTED_STATE_SHARDS);
    format!("{base}-{}-{index:02}", slot.name())
}

/// What an operator must do about an admitted-state document this controller cannot read. Nothing
/// in the loop can repair one — every reconcile fails on it, forever — so the error has to name the
/// remedy or it is an outage with no exit. It is a last resort and not automatic because it throws
/// the rollout history away, which is exactly what the durable state exists to keep.
pub(crate) const ADMITTED_STATE_REMEDY: &str =
    "delete this index and its -a-NN/-b-NN shard ConfigMaps to re-seed every group from its \
     current desired deployment (the \
     rollout is rebaselined: in-flight staging is forgotten and each set's concurrency is counted \
     afresh)";

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum AdmittedStateSlot {
    A,
    B,
}

impl AdmittedStateSlot {
    pub(crate) fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::B => "b",
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmittedStateIndex {
    pub(crate) format: u8,
    #[serde(deserialize_with = "updated_contracts::required_option")]
    pub(crate) active: Option<AdmittedStateSlot>,
    #[serde(deserialize_with = "updated_contracts::required_option")]
    pub(crate) revision_sha256: Option<String>,
    pub(crate) max_shards: u8,
    pub(crate) a_shards: u8,
    pub(crate) b_shards: u8,
}

impl Default for AdmittedStateIndex {
    fn default() -> Self {
        Self {
            format: ADMITTED_STATE_FORMAT,
            active: None,
            revision_sha256: None,
            max_shards: 0,
            a_shards: 0,
            b_shards: 0,
        }
    }
}

impl AdmittedStateIndex {
    pub(crate) fn shards(&self, slot: AdmittedStateSlot) -> u8 {
        match slot {
            AdmittedStateSlot::A => self.a_shards,
            AdmittedStateSlot::B => self.b_shards,
        }
    }

    pub(crate) fn set_shards(&mut self, slot: AdmittedStateSlot, shards: u8) {
        match slot {
            AdmittedStateSlot::A => self.a_shards = shards,
            AdmittedStateSlot::B => self.b_shards = shards,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.format != ADMITTED_STATE_FORMAT {
            return Err(format!("unsupported format {}", self.format));
        }
        for count in [self.a_shards, self.b_shards] {
            if usize::from(count) > MAX_ADMITTED_STATE_SHARDS {
                return Err(format!(
                    "slot declares {count} shards, over the absolute limit"
                ));
            }
        }
        match self.active {
            Some(active) => {
                if !(1..=MAX_ADMITTED_STATE_SHARDS).contains(&usize::from(self.max_shards)) {
                    return Err(format!("invalid maxShards {}", self.max_shards));
                }
                if self.shards(active) != self.max_shards {
                    return Err("active slot width does not match maxShards".into());
                }
                if !self
                    .revision_sha256
                    .as_deref()
                    .is_some_and(updated_contracts::is_canonical_sha256)
                {
                    return Err("active slot has no valid revisionSha256".into());
                }
            }
            None => {
                if self.revision_sha256.is_some() || self.max_shards != 0 {
                    return Err("an empty index declares an active revision".into());
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct AdmittedStateVersion {
    pub(crate) resource_version: String,
    pub(crate) index: AdmittedStateIndex,
}

/// The exact stored shape of the durable rollout baseline. Every field is REQUIRED on the way in —
/// no `#[serde(default)]` anywhere — and that is the choice, not an oversight. This document has
/// exactly one writer and one reader, the same build: there is no reader window and no migration
/// path here, which is why [`ADMITTED_STATE_FORMAT`] refuses a shard it did not write outright and
/// [`ADMITTED_STATE_REMEDY`] names the only exit. A `default` would not rescue a shape change; it
/// would hide one, reading a document this build never wrote as a valid baseline and silently
/// re-admitting from it. Changing this shape means the stored state is re-seeded, which is what the
/// remedy says and what the format byte is for.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredDurableRolloutState {
    pub(crate) admitted: BTreeMap<String, crate::rollout::AdmittedDeployment>,
    pub(crate) vetoed: BTreeMap<String, crate::VetoedDeployment>,
    pub(crate) routing: BTreeMap<String, String>,
    pub(crate) assignments: BTreeMap<String, Vec<String>>,
}

pub(crate) struct PreparedAdmittedState {
    pub(crate) encoded: Vec<u8>,
    pub(crate) revision_sha256: String,
    pub(crate) max_shards: AdmittedShardLimit,
}

/// Encode the durable rollout state and check it fits the shards the operator allowed.
///
/// `max_shards` is always [`AdmittedShardLimit::new`]'s answer — `reconcile_once` computes it
/// once per pass and threads it here and through [`AdmittedRecord`] — so the knob is bounded in
/// exactly one place and this function only spends it. Repeating the range check here restated the
/// bound at a layer that cannot disagree with the first.
pub(crate) fn prepare_admitted_state(
    state: &DurableRolloutState,
    max_shards: AdmittedShardLimit,
) -> Result<PreparedAdmittedState, Box<dyn std::error::Error>> {
    state.validate().map_err(StorageError::Operation)?;
    let encoded = serde_json::to_vec(&StoredDurableRolloutState::from(state))?;
    let capacity = max_shards.count() * ADMITTED_STATE_SHARD_MAX_BYTES;
    if encoded.len() > capacity {
        return Err(Box::new(StorageError::Operation(format!(
            "StateCapacityExceeded: durable rollout state is {} bytes but stateMaxShards={} \
             permits exactly {} bytes; raise spec.stateMaxShards before publishing this fleet",
            encoded.len(),
            max_shards.count(),
            capacity
        ))));
    }
    let revision_sha256 = updated_contracts::digest::sha256_bytes(&encoded);
    Ok(PreparedAdmittedState {
        encoded,
        revision_sha256,
        max_shards,
    })
}

impl From<&DurableRolloutState> for StoredDurableRolloutState {
    fn from(state: &DurableRolloutState) -> Self {
        Self {
            admitted: state.admitted.clone(),
            vetoed: state.vetoed.clone(),
            routing: state.routing.clone(),
            assignments: encode_assignments(&state.assignments),
        }
    }
}

impl TryFrom<StoredDurableRolloutState> for DurableRolloutState {
    type Error = String;

    fn try_from(stored: StoredDurableRolloutState) -> Result<Self, Self::Error> {
        let state = Self {
            admitted: stored.admitted,
            vetoed: stored.vetoed,
            routing: stored.routing,
            assignments: decode_assignments(stored.assignments)?,
        };
        state.validate()?;
        Ok(state)
    }
}

/// Load one atomically indexed durable-state generation. Every shard must agree with the index and
/// the complete byte stream's digest; partial/mixed projections fail closed rather than silently
/// rebaselining rollout concurrency.
pub(crate) async fn load_admitted_state(
    configmaps: &Api<ConfigMap>,
    name: &str,
) -> Result<(DurableRolloutState, Option<AdmittedStateVersion>), Box<dyn std::error::Error>> {
    let Some(configmap) = configmaps.get_opt(name).await? else {
        return Ok((DurableRolloutState::default(), None));
    };
    let resource_version = configmap.metadata.resource_version.clone().ok_or_else(|| {
        StorageError::Operation(format!(
            "admitted-state index {name} has no resourceVersion"
        ))
    })?;
    let encoded = configmap
        .data
        .as_ref()
        .and_then(|data| data.get("index.json"))
        .ok_or_else(|| {
            StorageError::Operation(format!(
                "admitted-state index {name} has no index.json; {ADMITTED_STATE_REMEDY}"
            ))
        })?;
    let index: AdmittedStateIndex = serde_json::from_str(encoded).map_err(|error| {
        StorageError::Operation(format!(
            "invalid admitted-state index {name}: {error}; {ADMITTED_STATE_REMEDY}"
        ))
    })?;
    index.validate().map_err(|error| {
        StorageError::Operation(format!(
            "invalid admitted-state index {name}: {error}; {ADMITTED_STATE_REMEDY}"
        ))
    })?;
    let mut version = AdmittedStateVersion {
        resource_version,
        index,
    };
    let stale_slots: Vec<AdmittedStateSlot> = match version.index.active {
        Some(active) => vec![active.other()],
        None => vec![AdmittedStateSlot::A, AdmittedStateSlot::B],
    };
    let mut cleaned = false;
    for slot in stale_slots {
        let count = usize::from(version.index.shards(slot));
        if count == 0 {
            continue;
        }
        delete_admitted_state_shards(configmaps, name, slot, 0, count).await?;
        version.index.set_shards(slot, 0);
        cleaned = true;
    }
    if cleaned {
        let namespace = configmap.metadata.namespace.as_deref().ok_or_else(|| {
            StorageError::Operation(format!("admitted-state index {name} has no namespace"))
        })?;
        let owner = configmap
            .metadata
            .owner_references
            .as_ref()
            .and_then(|owners| owners.iter().find(|owner| owner.controller == Some(true)))
            .cloned();
        version = write_admitted_state_index(
            configmaps,
            name,
            namespace,
            version.index,
            Some(version.resource_version),
            owner,
        )
        .await?;
    }
    let Some(active) = version.index.active else {
        return Ok((DurableRolloutState::default(), Some(version)));
    };
    let total = usize::from(version.index.shards(active));
    let revision = version
        .index
        .revision_sha256
        .as_deref()
        .expect("a validated active index has a revision");
    let mut encoded = Vec::new();
    for shard_index in 0..total {
        let shard_name = admitted_state_shard_name(name, active, shard_index);
        let shard = configmaps.get(&shard_name).await.map_err(|error| {
            StorageError::Operation(format!(
                "cannot read admitted-state shard {shard_name}: {error}; {ADMITTED_STATE_REMEDY}"
            ))
        })?;
        validate_admitted_state_shard(&shard, revision, active, shard_index, total).map_err(
            |error| {
                StorageError::Operation(format!(
                    "invalid admitted-state shard {shard_name}: {error}; {ADMITTED_STATE_REMEDY}"
                ))
            },
        )?;
        let bytes = &shard
            .binary_data
            .as_ref()
            .and_then(|data| data.get("state.bin"))
            .expect("validation requires state.bin")
            .0;
        encoded.extend_from_slice(bytes);
    }
    if !updated_contracts::digest::digests_match(
        &updated_contracts::digest::sha256_bytes(&encoded),
        revision,
    ) {
        return Err(Box::new(StorageError::Operation(format!(
            "admitted-state shards for {name} do not match index revision {revision}; \
             {ADMITTED_STATE_REMEDY}"
        ))));
    }
    let stored: StoredDurableRolloutState = serde_json::from_slice(&encoded).map_err(|error| {
        StorageError::Operation(format!(
            "invalid admitted-state document for {name}: {error}; {ADMITTED_STATE_REMEDY}"
        ))
    })?;
    let state = DurableRolloutState::try_from(stored).map_err(|error| {
        StorageError::Operation(format!(
            "invalid admitted-state document for {name}: {error}; {ADMITTED_STATE_REMEDY}"
        ))
    })?;
    Ok((state, Some(version)))
}

/// The local journal of the generation this replica is publishing, written between signing and
/// upload and cleared once the durable state that describes it has been recorded in-cluster.
///
/// `version` — the `timestamp.json` version this upload carries — is what decides whether the
/// generation reached the store, because the STORE is the only thing that knows: it serves `version`
/// iff this upload landed. `marker` is journalled beside it purely so the marker file can be
/// FINISHED (it is written after `publish_repository` returns, so a process death in that gap — an
/// OOM kill, an evicted pod — leaves the store serving this generation while the marker still names
/// its predecessor); it is never read as evidence of the upload. Marker equality is neither
/// necessary (that same gap) nor sufficient: the marker covers the content and the signed metadata,
/// so a pass triggered by neither journals a marker already on disk before the upload was attempted.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingPublication {
    pub(crate) marker: PublicationMarker,
    pub(crate) version: u64,
    /// The same exact stored rollout-state shape used by the in-cluster baseline. A local journal
    /// is a different atomicity mechanism, not a second serialization contract.
    pub(crate) state: StoredDurableRolloutState,
}

/// The journal file, alongside the publication marker it is compared against.
pub(crate) const PENDING_STATE_FILE: &str = "pending-state.json";

/// Remove the publication journal through one fail-closed path. Absence means there was no
/// interrupted publication; any other failure leaves a document that could be replayed on a later
/// pass, so planning must stop until the state volume is writable again.
pub(crate) async fn remove_pending_publication_journal(path: &Path) -> Result<(), StorageError> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(StorageError::Operation(format!(
            "cannot remove pending publication journal {}: {error}; refusing to continue with replayable rollout state",
            path.display()
        ))),
    }
}

/// Where the durable rollout state is recorded: its index/shards, owner, and configured bound.
pub(crate) struct AdmittedRecord<'a> {
    pub(crate) configmaps: &'a Api<ConfigMap>,
    pub(crate) name: &'a str,
    pub(crate) namespace: &'a str,
    pub(crate) owner: Option<OwnerReference>,
    pub(crate) max_shards: AdmittedShardLimit,
}

/// Record the state a generation published but never got to store in-cluster.
///
/// The durable state is written AFTER the upload, because writing it first turned a failed publish
/// into a record that nodes had been handed a deployment nobody served. The reverse gap is not
/// harmless: reconcile is dropped at any await when the publisher lease renewal fails (a rolling
/// restart), and losing the write after a successful publish leaves `assignments` naming the
/// PREDECESSOR for a node the generation already advanced. If the group's admission gates have
/// since closed, the next pass replans with `current` = the predecessor, reads that node as
/// advanced on it, and publishes it backward — one signed generation, no `maxUnavailable`, no
/// health gate.
///
/// So the state is journalled locally before the upload and adopted here on the next pass. The
/// journal is evaluated at most once — it is removed whatever the verdict — so it can never
/// re-apply itself over a later in-cluster write.
pub(crate) async fn recover_pending_publication(
    record: AdmittedRecord<'_>,
    state_dir: &Path,
    store: &dyn ObjectStore,
    destination: &S3Destination,
    durable: DurableRolloutState,
    resource_version: Option<AdmittedStateVersion>,
) -> Result<(DurableRolloutState, Option<AdmittedStateVersion>), Box<dyn std::error::Error>> {
    let AdmittedRecord {
        configmaps,
        name,
        namespace,
        owner,
        max_shards,
    } = record;
    let path = state_dir.join(PENDING_STATE_FILE);
    let bytes = match read_local_bounded(&path, PENDING_STATE_MAX_BYTES).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((durable, resource_version));
        }
        Err(error) => {
            return Err(Box::new(StorageError::Operation(format!(
                "cannot read pending publication journal {}: {error}; refusing to plan from a possibly stale rollout baseline",
                path.display()
            ))));
        }
    };
    let pending: PendingPublication = serde_json::from_slice(&bytes).map_err(|error| {
        StorageError::Operation(format!(
            "invalid pending publication journal {}: {error}; refusing to plan from a possibly stale rollout baseline",
            path.display()
        ))
    })?;
    if pending.version == 0 || pending.marker.validate().is_err() {
        return Err(Box::new(StorageError::Operation(format!(
            "invalid pending publication identity in {}; refusing to plan from a possibly stale rollout baseline",
            path.display()
        ))));
    }
    let pending_state = DurableRolloutState::try_from(pending.state).map_err(|error| {
        StorageError::Operation(format!(
            "invalid pending rollout state in {}: {error}; refusing to plan from a possibly stale rollout baseline",
            path.display()
        ))
    })?;
    let mut recovered = None;
    // The STORE is the ONE authority on whether the journalled generation was uploaded: it serves
    // `version` iff this upload landed. The publication marker is neither necessary nor sufficient.
    if store_published_version(store, destination).await? == Some(pending.version) {
        let marker_path = state_dir.join(PUBLISHED_GENERATION_FILE);
        if read_publication_marker(&marker_path).await.ok().flatten()
            != Some(pending.marker.clone())
        {
            // The upload landed and the process died before the marker write. Finish it, so the
            // local record and the store agree again instead of the next pass republishing
            // identical content under a new version.
            tracing::warn!(
                version = pending.version,
                "the object store serves a generation whose local publication marker was never \
                 written (the process died between the upload and the marker); adopting the \
                 journalled state rather than discarding a live generation's rollout state"
            );
            foundation::durable::atomic_write(
                &marker_path,
                ".published-",
                &pending.marker.to_bounded_json()?,
            )?;
        }
        recovered = Some(pending_state);
    }
    // Otherwise the upload never completed: the store does not serve this generation, so nothing
    // was ever handed to a node and there is nothing to record.
    let outcome = match recovered {
        Some(state) if state != durable => {
            tracing::warn!(
                configmap = name,
                "a published generation was never recorded in-cluster (the reconcile was cancelled \
                 or the process restarted between the upload and the write); adopting it from the \
                 local journal so no already-advanced node is republished on its predecessor"
            );
            let prepared = prepare_admitted_state(&state, max_shards)?;
            let version = store_admitted_state(
                configmaps,
                name,
                namespace,
                prepared,
                resource_version,
                owner,
            )
            .await?;
            (state, version)
        }
        _ => (durable, resource_version),
    };
    remove_pending_publication_journal(&path).await?;
    Ok(outcome)
}

/// The control plane's durable rollout state: what each group is pinned to, and which group each
/// node was routed to in the last published generation.
///
/// Every field is a claim about a generation that WAS published, so it is written only after the
/// signing and upload of that generation succeed (see `reconcile_once`). Recording it first left a
/// record saying nodes had been handed a deployment that a failed publish never served — and for a
/// blind node, `assignments` is the only staging signal there is.
///
/// The routing half exists because publication REPLACES the whole target set: a node left out of a
/// generation does not keep its old assignment, its `agents/<node>.json` target simply stops
/// existing. Knowing what a node was last published under is what lets a group that cannot be
/// planned this pass (quarantined, or waiting on its inputs) leave that node exactly where it was.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct DurableRolloutState {
    pub admitted: BTreeMap<String, crate::rollout::AdmittedDeployment>,
    /// Deployment identities an `onRegression: rollback` response has consumed the evidence for
    /// (`crate::VetoedDeployment`). Durable for the same reason `admitted` is: the response
    /// reassigns the rejecting nodes, so the live reports the halt is recomputed from stop naming
    /// the proven-bad body, and only this record keeps it refused across a leader change.
    pub vetoed: BTreeMap<String, crate::VetoedDeployment>,
    pub routing: BTreeMap<String, String>,
    /// Node → the deployment identity the last generation published for it. A staged rollout reads
    /// it to tell a node it has already advanced from one it has not, so a node that goes quiet
    /// while rebooting into its update is never republished under the predecessor.
    ///
    /// Rebuilt from each publication, so it holds exactly the nodes of the current generation and
    /// never accumulates. It is stored INVERTED (see [`encode_assignments`]) so the configured
    /// shard budget is spent on node names rather than repeating one group identity per node.
    pub assignments: BTreeMap<String, String>,
}

impl DurableRolloutState {
    /// Validate the one durable rollout-state contract on both sides of persistence.
    pub(crate) fn validate(&self) -> Result<(), String> {
        for (group, admitted) in &self.admitted {
            if updated_contracts::identity::ResourceName::new(group).is_err() {
                return Err(format!("durable admitted-state group {group:?} is invalid"));
            }
            admitted
                .current
                .validate()
                .map_err(|error| format!("durable group {group} current deployment: {error}"))?;
            for previous in &admitted.previous {
                previous.validate().map_err(|error| {
                    format!("durable group {group} previous deployment: {error}")
                })?;
            }
        }
        for (identity, veto) in &self.vetoed {
            if !updated_contracts::is_canonical_sha256(identity)
                || !updated_contracts::identity::is_segment(&veto.deployment)
                || veto.evidence == 0
            {
                return Err(format!("durable veto {identity:?} is invalid"));
            }
        }
        for (node, group) in &self.routing {
            if updated_contracts::identity::ResourceName::new(node).is_err()
                || updated_contracts::identity::ResourceName::new(group).is_err()
            {
                return Err(format!(
                    "durable route {node:?} -> {group:?} has an invalid identity"
                ));
            }
        }
        for (node, identity) in &self.assignments {
            if updated_contracts::identity::ResourceName::new(node).is_err()
                || !updated_contracts::is_canonical_sha256(identity)
            {
                return Err(format!(
                    "durable assignment for {node:?} has an invalid identity"
                ));
            }
        }
        Ok(())
    }
}

/// The stored form of the published assignments: deployment identity → the nodes it was published
/// to. Inverted from the in-memory node → identity map deliberately. Identities are per-GROUP — a
/// fleet has at most two live ones per group — so writing a 64-character digest against every node
/// name needlessly doubles the per-node cost of the bounded sharded document.
pub(crate) fn encode_assignments(
    assignments: &BTreeMap<String, String>,
) -> BTreeMap<String, Vec<String>> {
    let mut inverted: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (node, identity) in assignments {
        inverted
            .entry(identity.clone())
            .or_default()
            .push(node.clone());
    }
    inverted
}

pub(crate) fn decode_assignments(
    stored: BTreeMap<String, Vec<String>>,
) -> Result<BTreeMap<String, String>, String> {
    let mut assignments = BTreeMap::new();
    for (identity, nodes) in stored {
        if !updated_contracts::is_canonical_sha256(&identity) {
            return Err(format!(
                "stored assignment identity {identity:?} is not a SHA-256"
            ));
        }
        for node in nodes {
            if updated_contracts::identity::ResourceName::new(&node).is_err() {
                return Err(format!("stored assignment node {node:?} is invalid"));
            }
            if assignments.insert(node.clone(), identity.clone()).is_some() {
                return Err(format!(
                    "node {node} appears under more than one assignment"
                ));
            }
        }
    }
    Ok(assignments)
}

/// Persist the admitted set through an atomic double-buffered projection. The inactive slot is
/// fully written and digest-addressed before the small index is CAS-swapped to it; the old active
/// slot remains readable throughout and is reclaimed only after the pointer moves.
pub(crate) async fn store_admitted_state(
    configmaps: &Api<ConfigMap>,
    name: &str,
    namespace: &str,
    prepared: PreparedAdmittedState,
    version: Option<AdmittedStateVersion>,
    owner: Option<OwnerReference>,
) -> Result<Option<AdmittedStateVersion>, Box<dyn std::error::Error>> {
    let PreparedAdmittedState {
        encoded,
        revision_sha256: revision,
        max_shards,
    } = prepared;
    let old_index = version
        .as_ref()
        .map(|version| version.index.clone())
        .unwrap_or_default();
    let target = old_index
        .active
        .map(AdmittedStateSlot::other)
        .unwrap_or(AdmittedStateSlot::A);
    let shard_count = max_shards.count();
    let target_previous = usize::from(old_index.shards(target));
    if target_previous > shard_count {
        delete_admitted_state_shards(configmaps, name, target, shard_count, target_previous)
            .await?;
    }

    // Record the allocation before writing it. If the process dies mid-slot, the next load knows
    // the exact inactive range to reclaim; unindexed partial shards can therefore never leak.
    let mut allocating = old_index.clone();
    allocating.set_shards(target, max_shards.stored());
    let mut version = write_admitted_state_index(
        configmaps,
        name,
        namespace,
        allocating,
        version.map(|version| version.resource_version),
        owner.clone(),
    )
    .await?;

    let projection = AdmittedStateProjection {
        configmaps,
        base: name,
        namespace,
        owner: owner.clone(),
    };
    for shard_index in 0..shard_count {
        let start = encoded.len() * shard_index / shard_count;
        let end = encoded.len() * (shard_index + 1) / shard_count;
        projection
            .write_shard(
                target,
                shard_index,
                shard_count,
                &revision,
                &encoded[start..end],
            )
            .await?;
    }

    let old_active = version.index.active;
    version.index.active = Some(target);
    version.index.revision_sha256 = Some(revision);
    version.index.max_shards = max_shards.stored();
    version = write_admitted_state_index(
        configmaps,
        name,
        namespace,
        version.index,
        Some(version.resource_version),
        owner.clone(),
    )
    .await?;

    if let Some(old_active) = old_active {
        let old_count = usize::from(version.index.shards(old_active));
        delete_admitted_state_shards(configmaps, name, old_active, 0, old_count).await?;
        version.index.set_shards(old_active, 0);
        version = write_admitted_state_index(
            configmaps,
            name,
            namespace,
            version.index,
            Some(version.resource_version),
            owner,
        )
        .await?;
    }
    Ok(Some(version))
}

pub(crate) fn admitted_state_labels() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "app.kubernetes.io/component".into(),
            "controller-state".into(),
        ),
        ("app.kubernetes.io/managed-by".into(), "updatec".into()),
    ])
}

pub(crate) async fn write_admitted_state_index(
    configmaps: &Api<ConfigMap>,
    name: &str,
    namespace: &str,
    index: AdmittedStateIndex,
    resource_version: Option<String>,
    owner: Option<OwnerReference>,
) -> Result<AdmittedStateVersion, Box<dyn std::error::Error>> {
    index.validate().map_err(|error| {
        StorageError::Operation(format!("refusing to write invalid state index: {error}"))
    })?;
    let configmap = ConfigMap {
        metadata: kube::api::ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            resource_version: resource_version.clone(),
            owner_references: owner.map(|owner| vec![owner]),
            labels: Some(admitted_state_labels()),
            ..Default::default()
        },
        data: Some(BTreeMap::from([(
            "index.json".into(),
            serde_json::to_string(&index)?,
        )])),
        ..Default::default()
    };
    let written = if resource_version.is_some() {
        configmaps
            .replace(name, &PostParams::default(), &configmap)
            .await?
    } else {
        configmaps
            .create(&PostParams::default(), &configmap)
            .await?
    };
    let resource_version = written.metadata.resource_version.ok_or_else(|| {
        StorageError::Operation(format!(
            "apiserver returned state index {name} without resourceVersion"
        ))
    })?;
    Ok(AdmittedStateVersion {
        resource_version,
        index,
    })
}

pub(crate) struct AdmittedStateProjection<'a> {
    pub(crate) configmaps: &'a Api<ConfigMap>,
    pub(crate) base: &'a str,
    pub(crate) namespace: &'a str,
    pub(crate) owner: Option<OwnerReference>,
}

impl AdmittedStateProjection<'_> {
    pub(crate) async fn write_shard(
        &self,
        slot: AdmittedStateSlot,
        index: usize,
        total: usize,
        revision: &str,
        bytes: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        if bytes.len() > ADMITTED_STATE_SHARD_MAX_BYTES {
            return Err(Box::new(StorageError::Operation(format!(
                "state shard {index} is {} bytes, over the {}-byte ceiling",
                bytes.len(),
                ADMITTED_STATE_SHARD_MAX_BYTES
            ))));
        }
        let name = admitted_state_shard_name(self.base, slot, index);
        let current = self.configmaps.get_opt(&name).await?;
        let configmap = ConfigMap {
            metadata: kube::api::ObjectMeta {
                name: Some(name.clone()),
                namespace: Some(self.namespace.to_string()),
                resource_version: current
                    .as_ref()
                    .and_then(|current| current.metadata.resource_version.clone()),
                owner_references: self.owner.clone().map(|owner| vec![owner]),
                labels: Some(admitted_state_labels()),
                ..Default::default()
            },
            data: Some(BTreeMap::from([
                ("format".into(), ADMITTED_STATE_FORMAT.to_string()),
                ("revisionSha256".into(), revision.to_string()),
                ("slot".into(), slot.name().to_string()),
                ("index".into(), index.to_string()),
                ("total".into(), total.to_string()),
            ])),
            binary_data: Some(BTreeMap::from([(
                "state.bin".into(),
                ByteString(bytes.to_vec()),
            )])),
            ..Default::default()
        };
        if current.is_some() {
            self.configmaps
                .replace(&name, &PostParams::default(), &configmap)
                .await?;
        } else {
            self.configmaps
                .create(&PostParams::default(), &configmap)
                .await?;
        }
        Ok(())
    }
}

pub(crate) fn validate_admitted_state_shard(
    shard: &ConfigMap,
    revision: &str,
    slot: AdmittedStateSlot,
    index: usize,
    total: usize,
) -> Result<(), String> {
    let data = shard
        .data
        .as_ref()
        .ok_or_else(|| "missing metadata data".to_string())?;
    let expected = [
        ("format", ADMITTED_STATE_FORMAT.to_string()),
        ("revisionSha256", revision.to_string()),
        ("slot", slot.name().to_string()),
        ("index", index.to_string()),
        ("total", total.to_string()),
    ];
    for (key, value) in expected {
        if data.get(key) != Some(&value) {
            return Err(format!("{key} does not match the active index"));
        }
    }
    let bytes = shard
        .binary_data
        .as_ref()
        .and_then(|data| data.get("state.bin"))
        .ok_or_else(|| "missing state.bin".to_string())?;
    if bytes.0.len() > ADMITTED_STATE_SHARD_MAX_BYTES {
        return Err(format!(
            "state.bin is {} bytes, over the {}-byte ceiling",
            bytes.0.len(),
            ADMITTED_STATE_SHARD_MAX_BYTES
        ));
    }
    Ok(())
}

pub(crate) async fn delete_admitted_state_shards(
    configmaps: &Api<ConfigMap>,
    base: &str,
    slot: AdmittedStateSlot,
    start: usize,
    end: usize,
) -> Result<(), kube::Error> {
    for index in start..end {
        let name = admitted_state_shard_name(base, slot, index);
        match configmaps.delete(&name, &DeleteParams::default()).await {
            Ok(_) => {}
            Err(kube::Error::Api(error)) if error.code == 404 => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
