//! One reconcile pass, and the cross-pass state it threads through: acquire the lease, read the
//! fleet once, converge backends, plan and publish a generation, write statuses, deliver
//! subscriptions. The stages it calls live in the sibling modules.

use super::*;

/// Cross-pass controller state the reconcile loop owns and threads through every pass: the alert
/// sink and the in-memory progress marks the `RolloutStuck` condition derives from, plus the
/// consecutive-failure count `ReconcileFailing` reports. Lives in the main loop, not in
/// `reconcile_once`, because all three must survive individual passes.
pub struct ReconcileHooks {
    pub alerts: Option<Arc<crate::alerts::AlertSink>>,
    pub progress: crate::alerts::ProgressTracker,
    /// Cross-pass memory about the fleet's nodes (`evidence::ObservationLog`): which nodes have
    /// ever reported at all. Nothing else the planner decides is remembered — the regression
    /// verdict and every settlement verdict are functions of the reports readable this pass — so
    /// losing this costs one staleness alert's baseline until each node reports again.
    pub observation_log: crate::evidence::ObservationLog,
    /// Authenticity verdicts for node reports already verified, kept across passes.
    ///
    /// Beside [`Self::observation_log`] rather than inside it: the planner holds `&mut` on the log
    /// while it verifies, so the cache has to be reachable through a separate borrow.
    pub verified_reports: crate::evidence::VerifiedReports,
    /// The last authoritative Draupnir decision set. It is repository-scoped because one
    /// controller process reconciles one repository, and bounded to one referenced policy.
    pub(crate) admission_cache: crate::admission::AdmissionCache,
    /// Failed passes in a row WITHIN one leadership epoch. Reset by a successful publish, and by
    /// the loop whenever this replica stops being the leader — a streak that spanned the gap let
    /// one ordinary transient after a handover reach the `ReconcileFailing` threshold on its own.
    pub consecutive_failures: u32,
    /// The object store this process publishes and reads through. See [`StoreCache`].
    pub(crate) store: Option<StoreCache>,
    /// Raw per-node S3 reports, refreshed by prefix listing and ETag.
    pub(crate) raw_reports: crate::dataflow::ReportCache,
    pub(crate) report_shards: updated_contracts::telemetry::FleetShardLimit,
    pub(crate) projected_report_shards: Option<updated_contracts::telemetry::FleetShardLimit>,
    pub(crate) last_report_projection_sweep: Option<std::time::Instant>,
    /// Current private producer objects, discovered by one S3 prefix listing and refreshed by
    /// ETag. Kept beside the report cache because the pure planner joins the two snapshots.
    pub(crate) output_data: crate::dataflow::OutputCache,
}

/// How long a built object store — and the credentials Secret behind it — is reused before it is
/// rebuilt from scratch. The gateway reloads the same material on the same period for the same
/// reason (`MATERIAL_RELOAD_INTERVAL`): temporary credentials (STS, IRSA) expire, and a controller
/// that never rebuilt would keep a dead key pair until someone restarted the pod.
pub(crate) const STORE_RELOAD_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// The object store built for one repository destination, kept across passes.
///
/// Building one is not free: it reads the credentials Secret from the apiserver and constructs an
/// `AmazonS3` with its own HTTP client and TLS connection pool. Reconcile runs once a second, so
/// building it per pass dropped that pool a second later — every store request the pass made (the
/// fleet index, each shard, the rollback guard's `timestamp.json`, and every
/// publish upload) paid a fresh TCP+TLS handshake, and every pass paid one Secret read. Rebuilt
/// only when the repository's destination actually changes or the credentials age out.
pub(crate) struct StoreCache {
    pub(crate) destination: S3Destination,
    pub(crate) store: Arc<dyn ObjectStore>,
    pub(crate) built: std::time::Instant,
}

impl StoreCache {
    /// Whether this cached store still answers for `destination` at `now`.
    pub(crate) fn is_current(&self, destination: &S3Destination, now: std::time::Instant) -> bool {
        self.destination == *destination && now.duration_since(self.built) < STORE_RELOAD_INTERVAL
    }
}

impl ReconcileHooks {
    pub fn new(alerts: Option<Arc<crate::alerts::AlertSink>>) -> Self {
        Self {
            alerts,
            progress: crate::alerts::ProgressTracker::new(),
            observation_log: crate::evidence::ObservationLog::new(),
            verified_reports: Default::default(),
            admission_cache: crate::admission::AdmissionCache::default(),
            consecutive_failures: 0,
            store: None,
            raw_reports: crate::dataflow::ReportCache::default(),
            report_shards: updated_contracts::telemetry::DEFAULT_FLEET_REPORT_MAX_SHARDS,
            projected_report_shards: None,
            last_report_projection_sweep: None,
            output_data: crate::dataflow::OutputCache::default(),
        }
    }

    pub fn with_report_shards(
        mut self,
        report_shards: updated_contracts::telemetry::FleetShardLimit,
    ) -> Self {
        self.report_shards = report_shards;
        self
    }

    /// The object store for `destination`, built once and reused while it is still current (see
    /// [`StoreCache`]). A rebuild re-reads the credentials Secret, so a rotated key pair is picked
    /// up within [`STORE_RELOAD_INTERVAL`] without a restart, and a repository edited to point at
    /// another bucket takes effect on the very next pass.
    pub(crate) async fn store(
        &mut self,
        secrets: &Api<Secret>,
        destination: &S3Destination,
    ) -> Result<Arc<dyn ObjectStore>, Box<dyn std::error::Error>> {
        let now = std::time::Instant::now();
        if let Some(cached) = self
            .store
            .as_ref()
            .filter(|cached| cached.is_current(destination, now))
        {
            return Ok(cached.store.clone());
        }
        let store = build_store(secrets, destination).await?.objects;
        self.store = Some(StoreCache {
            destination: destination.clone(),
            store: store.clone(),
            built: now,
        });
        Ok(store)
    }

    /// This replica has stopped being the leader (or never was this round), so the epoch-scoped
    /// consecutive-failure streak `ReconcileFailing` counts ends with it: carrying it across the gap
    /// let one ordinary transient after a handover reach the threshold on its own, while another
    /// replica had meanwhile reconciled cleanly and cleared the condition on every set.
    pub fn end_leadership_epoch(&mut self) {
        self.consecutive_failures = 0;
        self.admission_cache.clear();
    }

    /// Forget every cross-pass fact owned by a deleted repository incarnation while preserving
    /// process-level configuration. A same-name replacement must begin from its CRs, object store
    /// and reports, never from the predecessor's caches or alert clocks.
    pub(crate) fn reset_repository_epoch(&mut self) {
        let replacement = Self::new(self.alerts.clone()).with_report_shards(self.report_shards);
        *self = replacement;
    }
}

/// The controller loop's explicit states. Repository absence is normal during installation and
/// after deletion, not a failed reconcile with a status object to patch.
#[derive(Debug)]
pub enum ReconcileOutcome {
    Reconciled {
        digest: String,
        /// `None` during repository finalization — the caller keeps the last snapshot until the
        /// next pass observes that the resource is gone and enters `WaitingForRepository`.
        snapshot: Option<crate::metrics::FleetSnapshot>,
    },
    WaitingForRepository,
}

/// The one process-level setting needed to materialize an [`UpdateBackend`]. Backend topology and
/// behavior live in the CRD; the operator's own chart supplies the immutable executable image.
#[derive(Clone, Debug)]
pub struct BackendRuntimeConfig {
    pub image: String,
    pub image_pull_policy: String,
}

/// This repository's fleet, kept current by a watch instead of re-read on every pass.
///
/// Both halves of a pass need the same set: backend materialization selects from it, and
/// publication plans over it. It used to be a full unpaginated LIST every tick — and because the
/// request set no `resourceVersion`, the apiserver could not serve it from its watch cache, so each
/// tick meant a quorum read from etcd and ~10 MiB on the wire at the 10,000-agent enrollment
/// ceiling. That cost is per replica and never falls, however quiet the fleet is.
///
/// A reflector pays it once. The initial LIST fills the store, and from then on only deltas cross
/// the wire; a pass reads from memory. Two properties of `kube`'s store make this safe to plan a
/// rollout against:
///
/// * A re-list buffers into a separate map and swaps it in atomically at `InitDone`, so the store
///   is never briefly empty or half-populated. A pass can never mistake a resync for "the fleet
///   vanished" and cordon everything.
/// * [`FleetWatch::start`] awaits the first sync, so the first pass sees a complete fleet rather
///   than an empty one.
///
/// What a watch cannot promise is freshness, and this is deliberately eventually consistent: an
/// agent enrolled a moment ago may land one tick later. That is the same guarantee the loop already
/// had — it is level-triggered and re-runs every five seconds — and a rollout decision made from a
/// view that is one tick behind is corrected on the next pass.
pub struct FleetWatch {
    pub(crate) store: kube::runtime::reflector::Store<UpdateAgent>,
    pub(crate) pump: tokio::task::JoinHandle<()>,
    pub(crate) repository: String,
}

impl FleetWatch {
    /// Begin watching, returning only once the store holds a complete fleet.
    pub async fn start(
        client: Client,
        namespace: &str,
        repository: &str,
    ) -> Result<Self, kube::runtime::reflector::store::WriterDropped> {
        let api: Api<UpdateAgent> = Api::namespaced(client, namespace);
        let (store, writer) = kube::runtime::reflector::store();
        let stream = kube::runtime::reflector(
            writer,
            kube::runtime::watcher(api, kube::runtime::watcher::Config::default()),
        );
        let pump = tokio::spawn(async move {
            let mut stream = std::pin::pin!(stream);
            while let Some(event) = stream.next().await {
                // `watcher` retries internally with backoff, re-listing when its resourceVersion
                // is too old, so an error here is a transient the stream recovers from on its own.
                if let Err(error) = event {
                    tracing::warn!(%error, "fleet watch error; re-listing");
                }
            }
            // The stream is infinite by construction, so reaching this is unrecoverable: the store
            // would silently freeze and every later pass would plan against a view that stopped
            // advancing. [`FleetWatch::is_live`] turns that into a refusal to reconcile.
            tracing::error!("fleet watch ended; this replica can no longer see the fleet");
        });
        store.wait_until_ready().await?;
        Ok(Self {
            store,
            pump,
            repository: repository.to_string(),
        })
    }

    /// Whether the watch is still advancing. A frozen store must never be planned against: it looks
    /// exactly like a fleet that has stopped changing.
    pub fn is_live(&self) -> bool {
        !self.pump.is_finished()
    }

    /// This repository's agents, in the stable order a pass expects.
    pub fn agents(&self) -> Vec<Arc<UpdateAgent>> {
        select_repository_agents(self.store.state(), &self.repository)
    }
}

/// Which agents belong to a pass, and in what order.
///
/// The filter is by `spec.repositoryRef`, which is a spec field and so not expressible as a
/// Kubernetes field selector; the watch is therefore namespace-wide and narrowed here. The sort is
/// what makes a pass deterministic — planning, status writes and inventory projection all walk this
/// order. Shared with the tests, so a pass under test selects its fleet by the same rule production
/// does rather than by whatever order a fixture happened to be written in.
pub fn select_repository_agents(
    all: impl IntoIterator<Item = Arc<UpdateAgent>>,
    repository: &str,
) -> Vec<Arc<UpdateAgent>> {
    let mut agents: Vec<Arc<UpdateAgent>> = all
        .into_iter()
        .filter(|agent| agent.spec.repository_ref.name == repository)
        .collect();
    agents.sort_by_key(|agent| agent.name_any());
    agents
}

/// Which group sets this repository owns, in the stable order every planner and status projection
/// uses. Repository ownership is an explicit identity boundary: label selectors are evaluated only
/// after this filter, so identical labels in sibling repositories cannot share a concurrency gate
/// that neither controller could enforce globally.
pub fn select_repository_group_sets(
    all: impl IntoIterator<Item = UpdateGroupSet>,
    repository: &str,
) -> Vec<UpdateGroupSet> {
    let mut sets: Vec<UpdateGroupSet> = all
        .into_iter()
        .filter(|set| set.spec.repository_ref.name == repository)
        .collect();
    sets.sort_by_key(|set| set.name_any());
    sets
}

impl Drop for FleetWatch {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

/// Plan and publish one generation. `agents` is this repository's fleet as
/// [`list_repository_agents`] read it for this pass — the same list the backend half was given.
///
/// These inputs are one reconcile identity, not independent knobs. Carrying them as a value keeps
/// every phase on the same namespace, repository, storage root, public origin and lease holder;
/// adding a phase cannot accidentally grow a second, partially-threaded spelling of the pass.
pub struct ReconcileRequest<'a> {
    pub client: Client,
    pub namespace: &'a str,
    pub repository_name: &'a str,
    pub state_dir: &'a Path,
    pub public_url: &'a str,
    pub identity: &'a str,
    pub agents: Vec<Arc<UpdateAgent>>,
}

/// The one cutoff policy for private objects superseded by a published generation.
///
/// Both input snapshots and enrollment objects are bearer-capability targets. They must therefore
/// use the same shared grace from the wire contract; accepting a duration at either call site would
/// reopen the possibility that one object kind is retired while a capability remains spendable.
fn private_object_retirement_cutoff(
    now: chrono::DateTime<chrono::Utc>,
) -> Result<chrono::DateTime<chrono::Utc>, StorageError> {
    let grace =
        chrono::Duration::from_std(updated_contracts::dataflow::PRIVATE_OBJECT_RETIREMENT_GRACE)
            .map_err(|_| {
                StorageError("private-object retirement grace is not representable".into())
            })?;
    now.checked_sub_signed(grace)
        .ok_or_else(|| StorageError("private-object retirement cutoff is not representable".into()))
}

/// The irreversible half of a planned generation.
///
/// Construction requires every preflighted input, and `commit` consumes the value. This is the one
/// path from a pure plan to a projection-ready generation: private inputs exist before signed
/// metadata can name them, the publisher lease is rechecked immediately before the external write,
/// and durable rollout state is recorded only after that write is known to have landed.
struct PublicationTransaction<'a> {
    client: &'a Client,
    namespace: &'a str,
    identity: &'a str,
    state_dir: &'a Path,
    repository: &'a UpdateRepository,
    destination: &'a S3Destination,
    store: &'a Arc<dyn ObjectStore>,
    secrets: &'a Api<Secret>,
    configmaps: &'a Api<ConfigMap>,
    admitted_name: &'a str,
    admitted_version: Option<AdmittedStateVersion>,
    dataflow: &'a crate::dataflow::RepositoryDataflow,
    dataflow_key: &'a [u8; 32],
    plan: &'a crate::PublicationPlan,
    input_snapshots: &'a BTreeMap<String, updated_contracts::dataflow::FileSnapshot>,
    planned: &'a DurableRolloutState,
    prepared_state: Option<PreparedAdmittedState>,
    desired_digest: &'a str,
    reconcile_now: chrono::DateTime<chrono::Utc>,
}

/// Proof that publication and its durable rollout-state record completed, carrying the only values
/// the projection phase may learn from that transaction.
struct PublishedGeneration {
    repo_dir: std::path::PathBuf,
    root_renewal_failure: Option<String>,
}

impl PublicationTransaction<'_> {
    async fn commit(self) -> Result<PublishedGeneration, Box<dyn std::error::Error>> {
        let Self {
            client,
            namespace,
            identity,
            state_dir,
            repository,
            destination,
            store,
            secrets,
            configmaps,
            admitted_name,
            admitted_version,
            dataflow,
            dataflow_key,
            plan,
            input_snapshots,
            planned,
            prepared_state,
            desired_digest,
            reconcile_now,
        } = self;

        // Every assignment's complete keyed-blinded input publication must exist in private S3
        // before the TUF generation can commit to its exact bytes. Construction happens only after
        // deterministic publication and durable-state preflights, so a generation that cannot
        // possibly commit never uploads sensitive input objects no generation can reference.
        crate::input_data::publish(
            dataflow,
            plan,
            &repository.spec.assignment_prefix,
            input_snapshots,
            dataflow_key,
        )
        .await?;

        let published_marker = state_dir.join(PUBLISHED_GENERATION_FILE);
        let local_marker = publication_marker(state_dir, desired_digest).await?;
        let recorded_marker = match read_publication_marker(&published_marker).await {
            Ok(marker) => marker,
            Err(error) => {
                // This file is only a republication optimization, never generation authority. A bad
                // copy safely means "publish again" after the rollback guard verifies the store.
                tracing::warn!(%error, "the local publication marker is unusable; forcing republication");
                None
            }
        };
        let content_unchanged = local_marker.is_some() && local_marker == recorded_marker;
        let repo_dir = state_dir.join("repository");
        // Re-signing well before expiry is the standard TUF discipline (timestamp exists to prove
        // freshness), and it is ONE mechanism: the same check renews the root, which
        // `replace_release` never touches.
        let mut renewals = expiring_metadata(&repo_dir, reconcile_now).await;
        let initialized =
            foundation::file::path_entry_exists(&repo_dir.join("metadata/root.json"))?;
        // Root renewal happens before the pass commits to signing a generation. A renewal that
        // cannot be performed drops out of `renewals` and must not itself cause a generation sign.
        let mut root_renewal_failure = None;
        if publication_required(content_unchanged, &renewals) {
            refuse_generation_rollback(store.as_ref(), destination, &repo_dir).await?;
            let signing = secrets
                .get(&repository.spec.signing_secret_ref.name)
                .await?;
            let keys_dir = state_dir.join("keys");
            materialize_signing_keys(&signing, &keys_dir).await?;
            if !initialized {
                let keys = updated_tuf::repo::Keys::in_dir(&keys_dir)?;
                updated_tuf::repo::init(&repo_dir, &keys, METADATA_EXPIRY_DAYS).await?;
            } else {
                root_renewal_failure = renew_expiring_root(
                    &repo_dir,
                    &keys_dir,
                    &repository.name_any(),
                    &mut renewals,
                )
                .await;
            }
            if publication_required(content_unchanged, &renewals) {
                crate::publisher::sign_plan(&repo_dir, &keys_dir, plan, METADATA_EXPIRY_DAYS)
                    .await?;

                // Signing can starve lease renewal. Recheck immediately before the irreversible
                // external write; object-version CAS fences the remaining network gap.
                if !holds_lease(client, namespace, "updatec-publisher", identity).await? {
                    return Err(Box::new(StorageError(
                        "publisher lease lost during reconcile; skipping publish to avoid a split-brain write"
                            .into(),
                    )));
                }

                let marker = publication_marker(state_dir, desired_digest)
                    .await?
                    .ok_or_else(|| {
                        StorageError(
                            "signed repository has no root/timestamp generation after signing"
                                .into(),
                        )
                    })?;
                // Journal before upload. If the process dies after the upload but before the state
                // CAS, recovery adopts exactly the state the store-served generation implies.
                let pending_bytes = serde_json::to_vec(&PendingPublication {
                    marker: marker.clone(),
                    version: updated_tuf::repo::current_version(&repo_dir).await?,
                    state: StoredDurableRolloutState::from(planned),
                })?;
                if pending_bytes.len() > PENDING_STATE_MAX_BYTES {
                    return Err(Box::new(StorageError(format!(
                        "pending publication state is {} bytes, over the {} byte durable-state limit",
                        pending_bytes.len(),
                        PENDING_STATE_MAX_BYTES
                    ))));
                }
                foundation::durable::atomic_write(
                    &state_dir.join(PENDING_STATE_FILE),
                    ".pending-",
                    &pending_bytes,
                )?;

                publish_repository(store.as_ref(), destination, &repo_dir).await?;
                foundation::durable::atomic_write(
                    &published_marker,
                    ".published-",
                    &marker.to_bounded_json()?,
                )?;
            }
        }

        // Immutable input objects may contain credentials. The generation is now live (or was
        // already live), so retire only objects it no longer names and only after the shared
        // capability grace. Cleanup remains best-effort; it cannot roll back a committed publish.
        if let Err(error) = dataflow
            .sweep_inputs_before(
                plan.node_assignments.values().cloned(),
                private_object_retirement_cutoff(chrono::Utc::now())?,
            )
            .await
        {
            tracing::warn!(%error, "retiring obsolete private input snapshots failed");
        }

        // Durable state is a claim about what was published, so this CAS is necessarily after the
        // object-store commit. The journal above covers cancellation in this final gap.
        if let Some(prepared_state) = prepared_state {
            let _ = store_admitted_state(
                configmaps,
                admitted_name,
                namespace,
                prepared_state,
                admitted_version,
                repository.controller_owner_ref(&()),
            )
            .await?;
        }
        remove_pending_publication_journal(&state_dir.join(PENDING_STATE_FILE)).await?;

        Ok(PublishedGeneration {
            repo_dir,
            root_renewal_failure,
        })
    }
}

/// Quarantine one invalid group and preserve every safety fact the rest of this pass needs.
///
/// A quarantined group always has two coupled effects: its status records the refusal, and its
/// agents remain associated with it (and with its last admitted deployment, when one exists).
/// Keeping those effects in one operation prevents a new validation branch from accidentally
/// routing the group's agents through the ungated default deployment.
async fn quarantine_invalid_group(
    groups_api: &Api<UpdateGroup>,
    group: &UpdateGroup,
    reason: &str,
    message: &str,
    durable: &DurableRolloutState,
    quarantined: &mut BTreeMap<String, BTreeMap<String, String>>,
    held: &mut BTreeMap<String, crate::rollout::AdmittedDeployment>,
) -> Result<(), kube::Error> {
    quarantine_group(groups_api, group, reason, message).await?;
    let name = group.name_any();
    if let Some(state) = durable.admitted.get(&name) {
        held.insert(name.clone(), state.clone());
    }
    quarantined.insert(name, group.spec.selector.match_labels.clone());
    Ok(())
}

pub async fn reconcile_once(
    request: ReconcileRequest<'_>,
    hooks: &mut ReconcileHooks,
) -> Result<ReconcileOutcome, Box<dyn std::error::Error>> {
    let ReconcileRequest {
        client,
        namespace,
        repository_name,
        state_dir,
        public_url,
        identity,
        agents,
    } = request;
    let pass_started = std::time::Instant::now();
    let repositories: Api<UpdateRepository> = Api::namespaced(client.clone(), namespace);
    let Some(repository) = repositories.get_opt(repository_name).await? else {
        // This is the ordinary install/delete boundary. Clear both sides of the repository epoch:
        // durable local bytes that outlive the CR, and in-memory verdicts/caches that outlive a
        // pass. A same-name replacement therefore has exactly the same clean start as a first CR.
        clear_local_repository_state(state_dir).await?;
        hooks.reset_repository_epoch();
        return Ok(ReconcileOutcome::WaitingForRepository);
    };
    let groups_api: Api<UpdateGroup> = Api::namespaced(client.clone(), namespace);
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let nodes_api: Api<UpdateAgent> = Api::namespaced(client.clone(), namespace);
    let sets_api: Api<UpdateGroupSet> = Api::namespaced(client.clone(), namespace);
    let admission_policies: Api<UpdateAdmissionPolicy> = Api::namespaced(client.clone(), namespace);
    let configmaps: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);

    // Finalizer gate. A repository incarnation owns three durable projections: its S3 prefix,
    // fixed-name admitted-state ConfigMaps, and node-local TUF state. The finalizer holds a deleted
    // UpdateRepository in `Terminating` until all three are empty, and is placed on a live one so
    // the guarantee is in effect before anything is ever published.
    if repository.metadata.deletion_timestamp.is_some() {
        finalize_repository(&repositories, &secrets, &configmaps, &repository, state_dir).await?;
        hooks.reset_repository_epoch();
        return Ok(ReconcileOutcome::Reconciled {
            digest: format!("finalized repository {repository_name}"),
            snapshot: None,
        });
    }
    // Bind the exact external key space before the finalizer exists. If deletion races this first
    // pass before the status patch, no object has been published and no finalizer needs to clean
    // one; after this succeeds, deletion no longer trusts a potentially retargeted spec.
    let destination = managed_repository_destination(&repository)?;
    // Keep the object returned by the status subresource. A successful first bind changes the
    // resourceVersion; using the object read above for the guarded finalizer patch would make every
    // repository's first reconcile fail with a guaranteed 409 before retrying the exact same path.
    let repository =
        ensure_repository_storage_ownership(&repositories, &repository, &destination).await?;
    ensure_repository_finalizer(&repositories, &repository).await?;

    // The object store is needed every reconcile — to recover an interrupted publication, to read
    // the node telemetry that drives rollout planning, and to publish — so it is resolved up front.
    // Built once and reused across passes (see `StoreCache`): its connection pool is what makes
    // every request in the pass cheap, and dropping it each second made every one of them pay a
    // fresh handshake.
    let store = hooks.store(&secrets, &destination).await?;

    // The agents of this repository, handed in by the caller's single LIST for this pass. Backend
    // reconciliation has already projected their complete topology (including cordons) through
    // its independent Kubernetes path; this half owns rollout publication only.
    let mut agent_resources = agents;
    // The FULL fleet — quarantined agents included — is what the observation log's node memory is
    // bounded by: pruning on the planned subset destroyed a quarantined agent's rollback proof
    // over a status condition, and the pre-movement state a record carries is unrecoverable from
    // any later report. This is the one place the full list is known, so the node half of the
    // prune lives here; the planner prunes the identity half, whose set it owns.
    let fleet: HashSet<String> = agent_resources
        .iter()
        .map(|agent| agent.name_any())
        .collect();
    hooks
        .observation_log
        .prune_nodes(|node| fleet.contains(node));
    hooks
        .verified_reports
        .prune_nodes(|node| fleet.contains(node));
    // Rollout accounting needs the same cordoned set the backend reconciler already projected.
    // Collect it before quarantine: a quarantined node is still deliberately absent from rollout
    // cohorts, even though its malformed control-plane identity cannot participate otherwise.
    let cordons: BTreeSet<String> = agent_resources
        .iter()
        .filter(|agent| agent.spec.cordon)
        .map(|agent| agent.name_any())
        .collect();

    // The rollout state (each group's currently-pinned deployment, and the routing the last
    // generation published) lives durably in-cluster as one atomically indexed, bounded ConfigMap
    // projection — NOT on the node-local PVC. That is what survives an HA leader change or a
    // cold/rescheduled PVC: a fresh leader loads the real admitted baseline from etcd instead of
    // re-seeding every group to the current desired and admitting a whole set at once (the
    // `max_concurrent` breach that node-local state allowed).
    // The single publisher lease keeps this a single writer; the write below is a resourceVersion
    // compare-and-swap as a second guard. It is loaded here, before groups are validated, because
    // quarantining a group needs the deployment that group is still pinned to.
    let admitted_name = admitted_configmap_name(repository_name);
    let state_max_shards = AdmittedShardLimit::new(repository.spec.state_max_shards)?;
    let (durable, admitted_version) = load_admitted_state(&configmaps, &admitted_name).await?;
    // A generation this replica published but never recorded is adopted before anything is planned
    // from the loaded state — planning on a baseline that predates the live generation is what
    // republishes an already-advanced node on its predecessor.
    let (durable, admitted_version) = recover_pending_publication(
        AdmittedRecord {
            configmaps: &configmaps,
            name: &admitted_name,
            namespace,
            owner: repository.controller_owner_ref(&()),
            max_shards: state_max_shards,
        },
        state_dir,
        store.as_ref(),
        &destination,
        durable,
        admitted_version,
    )
    .await?;

    let mut group_resources = groups_api.list(&ListParams::default()).await?;
    group_resources
        .items
        .retain(|group| group.spec.repository_ref.name == repository_name);
    // Desired groups keyed by name, plus each group's own metadata labels for set
    // membership matching. A single malformed group (empty selector or an unparseable
    // deployment) is quarantined — its own status carries the failure and it is dropped from
    // this generation — rather than aborting publication for every other resource.
    let mut groups = BTreeMap::new();
    let mut group_labels = BTreeMap::new();
    // Every group quarantined this pass, mapped to the selector that says which agents are its
    // agents. The selector travels with the quarantine — not only with the pin below — because a
    // group quarantined BEFORE it was ever admitted has no pin at all, and its agents must still be
    // recognized as belonging to it: otherwise they resolve to the unmatched-node pseudo-group and
    // are handed the repository's fleet-wide default deployment, the exact ungated swap quarantine
    // exists to prevent. An unusable selector is carried as EMPTY, which selects nothing — the
    // group's membership is genuinely unknown, and reading an empty selector as "every agent" would
    // withhold the whole fleet over one broken group.
    let mut quarantined_groups: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    // What each quarantined group is still pinned to. Its nodes must keep exactly that: routing
    // them to the unmatched-node pseudo-group would turn a typo'd digest or a bad `maxUnavailable`
    // into a fleet-wide, unthrottled, ungated deployment swap, and leaving them out of the
    // generation would delete their assignments outright (publication replaces every target).
    let mut held_groups: BTreeMap<String, crate::rollout::AdmittedDeployment> = BTreeMap::new();
    // Only a group that has been admitted at least once has a pin, so this is a SUBSET of
    // `quarantined_groups`; membership — which agents are a quarantined group's agents — is
    // answered from `quarantined_groups` above, which covers the never-admitted ones too.
    for group in group_resources.iter() {
        let name = group.name_any();
        if name == crate::DEFAULT_GROUP {
            quarantine_invalid_group(
                &groups_api,
                group,
                "ReservedName",
                "`default` is reserved for agents that match no group; rename this UpdateGroup.",
                &durable,
                &mut quarantined_groups,
                &mut held_groups,
            )
            .await?;
            continue;
        }
        if group.spec.selector.match_labels.is_empty() {
            quarantine_invalid_group(
                &groups_api,
                group,
                "EmptySelector",
                "This group's selector has no matchLabels; an empty selector would match every agent and is refused.",
                &durable,
                &mut quarantined_groups,
                &mut held_groups,
            )
            .await?;
            continue;
        }
        let deployment = match group.spec.deployment.clone().try_into() {
            Ok(deployment) => deployment,
            Err(error) => {
                quarantine_invalid_group(
                    &groups_api,
                    group,
                    "InvalidDeployment",
                    &format!("This group's deployment is invalid: {error}"),
                    &durable,
                    &mut quarantined_groups,
                    &mut held_groups,
                )
                .await?;
                continue;
            }
        };
        let max_unavailable = match group.spec.max_unavailable {
            Some(0) => {
                quarantine_invalid_group(
                    &groups_api,
                    group,
                    "InvalidMaxUnavailable",
                    "maxUnavailable must be at least one",
                    &durable,
                    &mut quarantined_groups,
                    &mut held_groups,
                )
                .await?;
                continue;
            }
            value => value.unwrap_or(1),
        };
        groups.insert(
            name.clone(),
            ResolvedGroup {
                name: name.clone(),
                match_labels: group.spec.selector.match_labels.clone(),
                depends_on: group.spec.depends_on.clone(),
                inputs: group.spec.inputs.clone(),
                input_snapshot: None,
                deployment,
                max_unavailable,
                emergency_correction: group.spec.emergency_correction,
            },
        );
        group_labels.insert(name, group.labels().clone());
    }
    // Dependency wiring is validated over the WHOLE admitted map, per group, and answered the
    // same way every other invalid spec is: quarantine the groups it names and keep planning the
    // rest. Left to the pure planner, one group's bad edit — an input outside its dependsOn, a
    // dangling dependency, a cycle — failed every reconcile for the whole repository.
    let quarantined_names: BTreeSet<String> = quarantined_groups.keys().cloned().collect();
    for (name, message) in crate::dependency_violations(&groups, &quarantined_names) {
        let Some(group) = group_resources
            .iter()
            .find(|group| group.name_any() == name)
        else {
            continue;
        };
        quarantine_invalid_group(
            &groups_api,
            group,
            "InvalidDependencies",
            &message,
            &durable,
            &mut quarantined_groups,
            &mut held_groups,
        )
        .await?;
        groups.remove(&name);
        group_labels.remove(&name);
    }
    group_resources
        .items
        .retain(|group| !quarantined_groups.contains_key(&group.name_any()));

    // Quarantine a malformed-identity agent — never the whole reconcile — and drop it from this
    // generation: a bad identity never resolved to an assignment, so there is nothing to preserve.
    // Overlapping selectors are deliberately NOT handled here. An ambiguous node must hold the last
    // known-good routing (fail safe, never fail open), so we leave it in
    // the plan and let `build_publication_plan` fault the whole generation closed with
    // `AmbiguousNode`; `reconcile_once` returns that error and the previous publication stays live.
    let mut quarantined_agents: HashSet<String> = HashSet::new();
    for agent in &agent_resources {
        let node = agent.name_any();
        let identity = &agent.spec.identity;
        let invalid = if !identity.is_well_formed_for(&node) {
            Some((
                "InvalidIdentity",
                "This agent's identity is malformed (its registration digest or pinned key does \
                 not match its kind).",
            ))
        } else if updated_contracts::identity::ResourceName::new(&node).is_err() {
            // Apply the shared identity grammar before a node enters assignment, raw-report, or
            // backend projections. Every one of those structures keys by this exact name.
            Some((
                "InvalidName",
                "This agent's name is not a lowercase Kubernetes DNS subdomain, so it cannot be \
                 used consistently as a node identity. Recreate it with a valid name.",
            ))
        } else {
            None
        };
        if let Some((reason, message)) = invalid {
            quarantine_agent(&nodes_api, agent, reason, message).await?;
            quarantined_agents.insert(node);
        }
    }
    agent_resources.retain(|agent| !quarantined_agents.contains(&agent.name_any()));

    // Every agent stays in the plan. Nodes whose group is quarantined are held on that group's
    // pinned deployment by the planner (`DesiredState::held`) — they are neither re-routed to the
    // ungated default nor dropped from the signed generation.
    let resolved_nodes: Vec<ResolvedNode> = agent_resources
        .iter()
        .map(|node| ResolvedNode {
            name: node.name_any(),
            labels: node.spec.labels.clone(),
        })
        .collect();
    // The other per-node operational control, straight from each agent's spec (the cordoned set is
    // collected above, before quarantine). Both are pure planner inputs: a hold changes only what
    // is published FOR the node (its recorded body, verbatim); the independent backend reconcile
    // already projected the cordon into trusted load-balancer topology. Nothing reaches into a
    // machine. A hold on a quarantined agent needs no such care: that agent is out of the plan
    // entirely, so there is nothing to hold it on.
    let holds: BTreeSet<String> = agent_resources
        .iter()
        .filter(|agent| agent.spec.hold)
        .map(|agent| agent.name_any())
        .collect();

    // An ABSENT admitted-state index/active projection reads as "no group has ever been admitted",
    // so every group
    // takes the first-admission branch and every group's staging baseline is lost: `previous` is
    // empty for all of them, so nothing is staged away from, and the rollout history each set's
    // concurrency accounting depends on is gone. On a fleet that HAS published, that is the entire
    // inventory re-admitted from a blank baseline in one generation. Deleting (or failing to
    // restore) that projection must not be a fleet-wide rebaseline, so this fails closed exactly like
    // the analogous "local publisher state is empty but the store has a generation" guard.
    if admitted_version
        .as_ref()
        .is_none_or(|version| version.index.active.is_none())
        && durable.admitted.is_empty()
        && store_published_version(store.as_ref(), &destination)
            .await?
            .is_some()
    {
        return Err(Box::new(StorageError(format!(
            "the durable admitted-state index {admitted_name} has no active state while a published \
             generation exists; refusing to re-admit every group ungated (restore it, or delete \
             the published generation to start over)"
        ))));
    }

    let agent_names: Vec<String> = resolved_nodes
        .iter()
        .map(|node| node.name.clone())
        .collect();
    let dataflow =
        crate::dataflow::RepositoryDataflow::new(store.clone(), destination.prefix.clone());
    let report_snapshot = hooks
        .raw_reports
        .refresh(&dataflow, agent_names.clone())
        .await?;
    if report_snapshot.changed || hooks.projected_report_shards != Some(hooks.report_shards) {
        crate::dataflow::publish_report_projection(
            store.as_ref(),
            &destination.prefix,
            &report_snapshot.accepted,
            hooks.report_shards,
        )
        .await?;
        hooks.projected_report_shards = Some(hooks.report_shards);
    }
    let should_sweep = hooks.last_report_projection_sweep.is_none_or(|last| {
        last.elapsed() >= updated_contracts::telemetry::FLEET_GENERATION_RETENTION
    });
    if should_sweep {
        let retention =
            chrono::Duration::from_std(updated_contracts::telemetry::FLEET_GENERATION_RETENTION)
                .map_err(|_| {
                    StorageError("fleet-generation retention is not representable".into())
                })?;
        let cutoff = chrono::Utc::now() - retention;
        if let Err(error) = crate::dataflow::sweep_report_projections_before(
            store.as_ref(),
            &destination.prefix,
            cutoff,
        )
        .await
        {
            tracing::warn!(%error, "sweeping obsolete fleet report projections failed");
        }
        hooks.last_report_projection_sweep = Some(std::time::Instant::now());
    }
    let reports = report_snapshot.into_envelopes();
    // Node → pinned public key, admitted from each agent's enrollment identity through the one
    // gate that admits one. The planner verifies every report's signature against it, so only
    // health it can cryptographically attribute to the node itself advances a rollout — a forged or
    // tampered report is ignored. A key that does not parse yields no entry, and a node with no
    // entry is unverifiable rather than trusted.
    let public_keys: HashMap<String, P256PublicKey> = agent_resources
        .iter()
        .filter_map(|agent| {
            let encoded = agent.spec.identity.public_key.as_ref()?;
            Some((agent.name_any(), P256PublicKey::parse_hex(encoded).ok()?))
        })
        .collect();
    let mut set_resources = sets_api.list(&ListParams::default()).await?;
    set_resources.items = select_repository_group_sets(set_resources.items, repository_name);
    // Surface misconfigured schedule entries in the controller log. An invalid window or
    // calendar entry still fails safe (it never opens), so this is observability, not a gate.
    for set in &set_resources.items {
        for window in &set.spec.rollout_windows {
            if let Err(error) = window.validate() {
                tracing::warn!(
                    set = set.name_any(),
                    %error,
                    "UpdateGroupSet rollout window is invalid; it will never open"
                );
            }
        }
        for entry in &set.spec.calendar {
            if let Err(error) = entry.validate() {
                tracing::warn!(
                    set = set.name_any(),
                    %error,
                    "UpdateGroupSet calendar entry is invalid; it will never open"
                );
            }
        }
    }
    let reconcile_now = chrono::Utc::now();
    // Draupnir sees the complete active release set: every desired group/default plus every body
    // retained by durable rollout state for machines that may still run it. The request itself is
    // the event notification. Decisions are cached for 30 seconds, while an unseen subject forces
    // an immediate refresh so a newly requested upgrade is never admitted from an older set.
    let mut active_deployments: Vec<crate::DesiredDeployment> = groups
        .values()
        .map(|group| group.deployment.clone())
        .chain(durable.admitted.values().flat_map(|state| {
            std::iter::once(state.current.clone()).chain(state.previous.iter().cloned())
        }))
        .collect();
    if let Ok(default) =
        crate::DesiredDeployment::try_from(repository.spec.default_deployment.clone())
    {
        active_deployments.push(default);
    }
    let admission = crate::admission::evaluate(
        &mut hooks.admission_cache,
        &admission_policies,
        &secrets,
        repository
            .spec
            .admission_policy_ref
            .as_ref()
            .map(|reference| reference.name.as_str()),
        namespace,
        repository_name,
        active_deployments.iter(),
    )
    .await;
    if let Some(error) = admission.error.as_deref() {
        tracing::warn!(
            repository = repository_name,
            policy = admission.policy_name.as_deref().unwrap_or("unknown"),
            %error,
            "release admission is unavailable; holding every subject without a fresh authoritative decision"
        );
    }
    let blocked_deployments: BTreeSet<String> = active_deployments
        .iter()
        .filter(|deployment| {
            admission
                .status(deployment)
                .is_some_and(|status| !status.allowed)
        })
        .filter_map(crate::deployment_identity)
        .collect();
    let dataflow_key = dataflow.generation_key().await?;
    let outputs = hooks
        .output_data
        .refresh(
            &dataflow,
            resolved_nodes.iter().map(|node| node.name.clone()),
        )
        .await?;
    let outcome = crate::domain::plan_reconcile(
        crate::domain::DesiredState {
            repository: &repository.spec,
            groups: &groups,
            group_labels: &group_labels,
            sets: &set_resources.items,
            nodes: &resolved_nodes,
            quarantined: &quarantined_groups,
            held: &held_groups,
            holds: &holds,
            cordons: &cordons,
            blocked_deployments: &blocked_deployments,
        },
        crate::domain::ObservedState {
            reports: &reports,
            outputs: &outputs,
            dataflow_key: &dataflow_key,
            public_keys: &public_keys,
            admitted: &durable.admitted,
            vetoed: &durable.vetoed,
            routing: &durable.routing,
            assignments: &durable.assignments,
            now: reconcile_now,
        },
        &mut hooks.observation_log,
        &mut hooks.verified_reports,
    )?;
    let crate::domain::ReconcilePlan {
        publication: plan,
        input_snapshots,
        admitted: planned_admitted,
        vetoed: planned_vetoed,
        routing: planned_routing,
        assignments: planned_assignments,
        set_statuses,
        groups: group_progress,
        node_counts,
        halted_groups,
    } = outcome;
    let planned = DurableRolloutState {
        admitted: planned_admitted,
        vetoed: planned_vetoed,
        routing: planned_routing,
        assignments: planned_assignments,
    };
    let state_needs_rebalance = admitted_version
        .as_ref()
        .is_none_or(|version| version.index.max_shards != state_max_shards.stored());
    // Preflight the exact bytes before signing or uploading anything. Discovering an undersized
    // stateMaxShards after the object store advanced would leave the live generation ahead of its
    // rollout baseline until the knob was repaired.
    let prepared_state = (durable != planned || state_needs_rebalance)
        .then(|| prepare_admitted_state(&planned, state_max_shards))
        .transpose()?;

    let desired_digest = desired_publication_digest(&repository.spec, &plan.digest)?;
    let PublishedGeneration {
        repo_dir,
        root_renewal_failure,
    } = PublicationTransaction {
        client: &client,
        namespace,
        identity,
        state_dir,
        repository: &repository,
        destination: &destination,
        store: &store,
        secrets: &secrets,
        configmaps: &configmaps,
        admitted_name: &admitted_name,
        admitted_version,
        dataflow: &dataflow,
        dataflow_key: &dataflow_key,
        plan: &plan,
        input_snapshots: &input_snapshots,
        planned: &planned,
        prepared_state,
        desired_digest: &desired_digest,
        reconcile_now,
    }
    .commit()
    .await?;

    // ONE projection path for both outcomes — a reconcile that reused an unchanged generation and
    // one that just signed a new one reach this same sequence, so both expose identical enrollment,
    // status, and subscription state. Everything below runs on every pass; nothing above may return
    // early past it.
    //
    // The trust anchor is read HERE, after any repository init or re-sign in this same pass, and
    // never before: it is the digest that enrollment and node capability authorization pin the
    // store-served root against, and by this point the store already serves the new root. Reading it earlier
    // recorded the pre-rewrite digest, so every enrollment failed for a full reconcile tick after
    // the initial publish or a root re-sign.
    //
    // It is resolved ONCE — the anchor this pass recorded, else whatever the repository's status
    // already carries — because the same value is WRITTEN into that status and HANDED to enrollment
    // as the pinning anchor. Two spellings of one rule that must never disagree is how they do.
    let published_root_sha256 = local_routing_root_sha256(state_dir).await.or_else(|| {
        repository
            .status
            .as_ref()
            .and_then(|status| status.routing_root_sha256.clone())
    });
    // Enrollment objects change only when their own inputs change: desired configuration, pinned
    // root, or public repository location. Routine timestamp/snapshot renewal must not mint one new
    // object per fleet member when none of those bootstrap bytes changed.
    let enrollment_generation_sha256 = enrollment_generation_sha256(
        &desired_digest,
        published_root_sha256.as_deref().unwrap_or_default(),
        public_url,
    );
    let enrollment_objects = publish_enrollment_objects(
        &repository,
        &agent_resources,
        store.as_ref(),
        &destination.prefix,
        public_url,
        published_root_sha256.as_deref(),
        &enrollment_generation_sha256,
    )
    .await?;
    publish_resource_statuses(
        ResourceApis {
            repositories: &repositories,
            groups: &groups_api,
            agents: &nodes_api,
        },
        StatusSnapshot {
            repository: &repository,
            storage_ownership: RepositoryStorageOwnership::from(&destination),
            routing_root_sha256: published_root_sha256.clone(),
            root_renewal_failure,
            groups: &group_resources.items,
            agents: &agent_resources,
            plan: &plan,
            reports: &reports,
            group_progress: &group_progress,
            public_keys: &public_keys,
            verified: &hooks.verified_reports,
            node_counts: &node_counts,
            halted_groups: &halted_groups,
            admission: &admission,
            enrollment_objects: &enrollment_objects,
            now: reconcile_now,
        },
        &set_resources.items,
        &mut hooks.progress,
        hooks.alerts.as_ref(),
    )
    .await?;
    // The status pointer is durable before retirement begins. Keep superseded bytes through two
    // capability lifetimes as well: an operator may have read the old pointer immediately before
    // this status update and be in the middle of copying it out of band.
    if let Err(error) = sweep_enrollment_objects(
        store.as_ref(),
        &destination.prefix,
        &enrollment_objects,
        private_object_retirement_cutoff(chrono::Utc::now())?,
    )
    .await
    {
        tracing::warn!(%error, "retiring obsolete enrollment objects failed");
    }
    publish_group_set_statuses(
        &sets_api,
        &set_resources.items,
        &set_statuses,
        hooks.alerts.as_ref(),
    )
    .await?;
    deliver_subscriptions(
        &client,
        namespace,
        &repository,
        &destination.prefix,
        state_dir,
        public_url,
    )
    .await;
    // Everything fallible has now succeeded, so the failure streak resets here — never earlier:
    // resetting before the projection made `ReconcileFailing` blind to any failure inside the
    // projection stage itself, the last third of every pass.
    hooks.consecutive_failures = 0;

    // The metrics snapshot: pure projection of what this pass already computed, handed to the
    // scrape listener by the main loop. The fleet-wide freshness counts are SUMS of the planner's
    // per-group accounting — the one definition of "fresh", not a second derivation — and the
    // deployment labels come from the admitted map, which carries every group's current plus the
    // repository default under its reserved name.
    let mut deployments: Vec<String> = planned
        .admitted
        .values()
        .map(|state| state.current.deployment.clone())
        .collect();
    deployments.sort();
    deployments.dedup();
    let (reports_fresh, reports_observable) = node_counts
        .values()
        .fold((0, 0), |(fresh, observable), counts| {
            (fresh + counts.fresh, observable + counts.observable)
        });
    let snapshot = crate::metrics::FleetSnapshot {
        // Read HERE, not from `reconcile_now`: that instant is the start of planning, before
        // admission, signing, the upload, the durable write and the whole status projection, and a
        // staleness alert of the form `time() - updatec_reconcile_timestamp_seconds` would read the
        // fleet as a full pass-duration staler than it is. Both gauges below are now anchored to the
        // same instant — the end of the pass, which is what the metric says it reports.
        reconcile_timestamp_seconds: chrono::Utc::now().timestamp().max(0) as u64,
        reconcile_duration_seconds: pass_started.elapsed().as_secs_f64(),
        generation: updated_tuf::repo::current_version(&repo_dir).await.ok(),
        deployments,
        groups: group_progress
            .iter()
            .map(|(name, progress)| {
                (
                    name.clone(),
                    (
                        *progress,
                        node_counts.get(name).cloned().unwrap_or_default(),
                    ),
                )
            })
            .collect(),
        reports_fresh,
        reports_stale: reports_observable.saturating_sub(reports_fresh),
        quarantined_groups: quarantined_groups.len(),
    };
    Ok(ReconcileOutcome::Reconciled {
        digest: plan.digest,
        snapshot: Some(snapshot),
    })
}

/// Push change-tracking events to every [`UpdateSubscription`](crate::UpdateSubscription) covering
/// this repository, catching each subscriber up to the currently published generation. Runs on every
/// reconcile — including the no-change path — so a subscription created (or a webhook recovered)
/// after a publish is still caught up on the next tick. Best-effort: a delivery or status-write
/// failure is logged and retried, never allowed to block publication.
pub(crate) async fn deliver_subscriptions(
    client: &Client,
    namespace: &str,
    repository: &UpdateRepository,
    repository_prefix: &str,
    state_dir: &Path,
    public_url: &str,
) {
    let repo_dir = state_dir.join("repository");
    match foundation::file::path_entry_exists(&repo_dir.join("metadata/timestamp.json")) {
        Ok(true) => {}
        Ok(false) => return, // nothing has been published yet — no generation to announce.
        Err(error) => {
            tracing::warn!(%error, "checking for published metadata before delivering subscriptions");
            return;
        }
    }
    let outcome = async {
        let version = updated_tuf::repo::current_version(&repo_dir).await?;
        let subscriptions: Api<UpdateSubscription> = Api::namespaced(client.clone(), namespace);
        let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
        let repository_name = repository.name_any();
        let now = chrono::Utc::now().to_rfc3339();
        crate::subscription::deliver_updates(
            &subscriptions,
            &secrets,
            crate::subscription::DeliveryContext {
                repository: &repository_name,
                namespace,
                prefix: repository_prefix,
                public_url,
                version,
                now: &now,
            },
        )
        .await
    }
    .await;
    if let Err(error) = outcome {
        tracing::warn!(error = %error, "delivering update subscriptions");
    }
}

/// The digest of the `root.json` this publisher signs with, from its own local repository state.
///
/// Read from disk rather than from the object store: this is the value enrollment pins the
/// store-served root AGAINST, so taking it from the store would compare a document with itself.
/// `None` before this replica has ever signed a generation.
pub(crate) async fn local_routing_root_sha256(state_dir: &Path) -> Option<String> {
    file_sha256(&state_dir.join("repository/metadata/root.json")).await
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::disallowed_methods)] // In-memory signer fixtures need synthetic URL values.
pub(crate) mod wiring_tests {
    use super::*;
    use axum::body::Bytes;
    use axum::http::{Method, StatusCode, Uri};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex as StdMutex;

    const TEST_MANAGED_PREFIX: &str = "routing/default/default";

    #[test]
    fn private_object_retirement_uses_the_contracts_shared_grace() {
        let now = chrono::Utc::now();
        let cutoff = private_object_retirement_cutoff(now).unwrap();
        assert_eq!(
            now - cutoff,
            chrono::Duration::from_std(
                updated_contracts::dataflow::PRIVATE_OBJECT_RETIREMENT_GRACE
            )
            .unwrap()
        );
    }

    #[test]
    fn group_set_ownership_is_filtered_before_label_selection() {
        let group_set = |name: &str, repository: &str| {
            UpdateGroupSet::new(
                name,
                crate::UpdateGroupSetSpec {
                    repository_ref: crate::LocalObjectReference {
                        name: repository.into(),
                    },
                    selector: crate::LabelSelector::default(),
                    max_concurrent: None,
                    rollout_windows: Vec::new(),
                    calendar: Vec::new(),
                    max_regressions: None,
                    on_regression: crate::RegressionResponse::Halt,
                    stuck_after_seconds: None,
                },
            )
        };

        let selected = select_repository_group_sets(
            [
                group_set("z-local", "default"),
                group_set("foreign", "other"),
                group_set("a-local", "default"),
            ],
            "default",
        );
        assert_eq!(
            selected
                .iter()
                .map(kube::ResourceExt::name_any)
                .collect::<Vec<_>>(),
            ["a-local", "z-local"]
        );
    }

    #[derive(Debug)]
    struct RecordingMultipartUpload {
        parts: Arc<StdMutex<Vec<Vec<u8>>>>,
        aborted: Arc<AtomicBool>,
        completed: Arc<AtomicBool>,
        fail_part: bool,
        fail_complete: bool,
    }

    impl RecordingMultipartUpload {
        fn healthy() -> Self {
            Self {
                parts: Arc::default(),
                aborted: Arc::default(),
                completed: Arc::default(),
                fail_part: false,
                fail_complete: false,
            }
        }
    }

    fn upload_error(message: &'static str) -> object_store::Error {
        object_store::Error::Generic {
            store: "multipart-test",
            source: Box::new(std::io::Error::other(message)),
        }
    }

    #[async_trait::async_trait]
    impl object_store::MultipartUpload for RecordingMultipartUpload {
        fn put_part(&mut self, data: PutPayload) -> object_store::UploadPart {
            if self.fail_part {
                return Box::pin(async { Err(upload_error("part failed")) });
            }
            let parts = Arc::clone(&self.parts);
            Box::pin(async move {
                let mut bytes = Vec::with_capacity(data.content_length());
                for chunk in data {
                    bytes.extend_from_slice(&chunk);
                }
                parts.lock().expect("parts").push(bytes);
                Ok(())
            })
        }

        async fn complete(&mut self) -> object_store::Result<object_store::PutResult> {
            self.completed.store(true, Ordering::SeqCst);
            if self.fail_complete {
                Err(upload_error("completion failed"))
            } else {
                Ok(object_store::PutResult {
                    e_tag: None,
                    version: None,
                    extensions: Default::default(),
                })
            }
        }

        async fn abort(&mut self) -> object_store::Result<()> {
            self.aborted.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn multipart_publication_has_one_bounded_success_path_including_empty_files() {
        const PART_BYTES: usize = 5 * 1024 * 1024;
        let bytes = vec![7_u8; PART_BYTES + 17];
        let mut source = std::io::Cursor::new(bytes.clone());
        let mut upload = RecordingMultipartUpload::healthy();
        upload_repository_parts(&mut source, &mut upload, Path::new("large-target"))
            .await
            .unwrap();
        assert!(upload.completed.load(Ordering::SeqCst));
        assert!(!upload.aborted.load(Ordering::SeqCst));
        {
            let parts = upload.parts.lock().expect("parts");
            assert_eq!(
                parts.iter().map(Vec::len).collect::<Vec<_>>(),
                [PART_BYTES, 17]
            );
            assert_eq!(parts.concat(), bytes);
        }

        let mut empty = std::io::Cursor::new(Vec::<u8>::new());
        let mut upload = RecordingMultipartUpload::healthy();
        upload_repository_parts(&mut empty, &mut upload, Path::new("empty-target"))
            .await
            .unwrap();
        assert_eq!(
            upload.parts.lock().expect("parts").as_slice(),
            &[Vec::<u8>::new()]
        );
        assert!(upload.completed.load(Ordering::SeqCst));
        assert!(!upload.aborted.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn every_observable_multipart_failure_is_aborted() {
        let mut source = std::io::Cursor::new(b"target".to_vec());
        let mut part_failure = RecordingMultipartUpload {
            fail_part: true,
            ..RecordingMultipartUpload::healthy()
        };
        let error =
            upload_repository_parts(&mut source, &mut part_failure, Path::new("part-failure"))
                .await
                .unwrap_err();
        assert!(error.to_string().contains("uploading a part"));
        assert!(part_failure.aborted.load(Ordering::SeqCst));
        assert!(!part_failure.completed.load(Ordering::SeqCst));

        let mut source = std::io::Cursor::new(b"target".to_vec());
        let mut completion_failure = RecordingMultipartUpload {
            fail_complete: true,
            ..RecordingMultipartUpload::healthy()
        };
        let error = upload_repository_parts(
            &mut source,
            &mut completion_failure,
            Path::new("completion-failure"),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("completing the upload"));
        assert!(completion_failure.aborted.load(Ordering::SeqCst));
        assert!(completion_failure.completed.load(Ordering::SeqCst));
    }

    /// The in-process store's contents: object key → bytes.
    type Objects = Arc<StdMutex<BTreeMap<String, Vec<u8>>>>;

    /// One in-process S3-compatible store: path-style `/{bucket}/{key}`, exact object operations,
    /// and ListObjectsV2. The dataflow caches discover raw per-node objects by prefix, so a fixture
    /// without listing would test a storage protocol production never uses.
    async fn s3_endpoint(objects: Objects) -> std::net::SocketAddr {
        async fn handle(
            axum::extract::State(objects): axum::extract::State<Objects>,
            method: Method,
            uri: Uri,
            headers: axum::http::HeaderMap,
            body: Bytes,
        ) -> axum::response::Response {
            let parsed =
                reqwest::Url::parse(&format!("http://s3.test{uri}")).expect("fixture request URI");
            if method == Method::GET
                && parsed
                    .query_pairs()
                    .any(|(name, value)| name == "list-type" && value == "2")
            {
                let prefix = parsed
                    .query_pairs()
                    .find_map(|(name, value)| (name == "prefix").then(|| value.into_owned()))
                    .unwrap_or_default();
                let escape = |value: &str| {
                    value
                        .replace('&', "&amp;")
                        .replace('<', "&lt;")
                        .replace('>', "&gt;")
                };
                let contents = objects
                    .lock()
                    .expect("s3")
                    .iter()
                    .filter(|(key, _)| key.starts_with(&prefix))
                    .map(|(key, bytes)| {
                        format!(
                            "<Contents><Key>{}</Key><LastModified>2026-08-08T00:00:00Z</LastModified><ETag>\"{}\"</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Contents>",
                            escape(key),
                            updated_contracts::digest::sha256_bytes(bytes),
                            bytes.len()
                        )
                    })
                    .collect::<String>();
                let count = contents.matches("<Contents>").count();
                let response = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>updates</Name><Prefix>{}</Prefix><KeyCount>{count}</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>{contents}</ListBucketResult>",
                    escape(&prefix)
                );
                return axum::response::Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/xml")
                    .body(axum::body::Body::from(response))
                    .expect("list response");
            }
            let key = uri.path().trim_start_matches('/');
            let key = key.strip_prefix("updates/").unwrap_or(key).to_string();
            let respond = |status: StatusCode, body: Vec<u8>| {
                let etag = updated_contracts::digest::sha256_bytes(&body);
                axum::response::Response::builder()
                    .status(status)
                    .header("etag", format!("\"{etag}\""))
                    .header("last-modified", "Sat, 08 Aug 2026 00:00:00 GMT")
                    .body(axum::body::Body::from(body))
                    .expect("response")
            };
            let respond_to_head = |status: StatusCode, body: &[u8]| {
                let etag = updated_contracts::digest::sha256_bytes(body);
                axum::response::Response::builder()
                    .status(status)
                    .header("etag", format!("\"{etag}\""))
                    .header("content-length", body.len())
                    .header("last-modified", "Sat, 08 Aug 2026 00:00:00 GMT")
                    .body(axum::body::Body::empty())
                    .expect("HEAD response")
            };

            // The production publisher has one upload path: bounded multipart streaming for
            // metadata and large targets alike. Model the three S3 operations instead of teaching
            // production a fixture-only single-PUT fallback.
            let upload_id = parsed
                .query_pairs()
                .find_map(|(name, value)| (name == "uploadId").then(|| value.into_owned()));
            if method == Method::POST && parsed.query_pairs().any(|(name, _)| name == "uploads") {
                let id = updated_contracts::digest::sha256_bytes(key.as_bytes());
                return respond(
                    StatusCode::OK,
                    format!(
                        "<InitiateMultipartUploadResult><UploadId>{id}</UploadId></InitiateMultipartUploadResult>"
                    )
                    .into_bytes(),
                );
            }
            if method == Method::PUT {
                if let (Some(id), Some(part)) = (
                    upload_id.as_deref(),
                    parsed.query_pairs().find_map(|(name, value)| {
                        (name == "partNumber").then(|| value.into_owned())
                    }),
                ) {
                    let part = part.parse::<u32>().expect("numeric multipart part");
                    objects
                        .lock()
                        .expect("s3")
                        .insert(format!("\0multipart/{id}/{part:010}"), body.to_vec());
                    return respond(StatusCode::OK, Vec::new());
                }
            }
            if method == Method::POST {
                if let Some(id) = upload_id.as_deref() {
                    let part_prefix = format!("\0multipart/{id}/");
                    let mut guard = objects.lock().expect("s3");
                    let parts = guard
                        .range(part_prefix.clone()..)
                        .take_while(|(part, _)| part.starts_with(&part_prefix))
                        .map(|(part, bytes)| (part.clone(), bytes.clone()))
                        .collect::<Vec<_>>();
                    let mut complete = Vec::new();
                    for (part, bytes) in parts {
                        guard.remove(&part);
                        complete.extend_from_slice(&bytes);
                    }
                    let etag = updated_contracts::digest::sha256_bytes(&complete);
                    guard.insert(key, complete);
                    return respond(
                        StatusCode::OK,
                        format!(
                            "<CompleteMultipartUploadResult><ETag>\"{etag}\"</ETag></CompleteMultipartUploadResult>"
                        )
                        .into_bytes(),
                    );
                }
            }
            if method == Method::DELETE {
                if let Some(id) = upload_id.as_deref() {
                    let part_prefix = format!("\0multipart/{id}/");
                    objects
                        .lock()
                        .expect("s3")
                        .retain(|part, _| !part.starts_with(&part_prefix));
                    return respond(StatusCode::NO_CONTENT, Vec::new());
                }
            }
            match method {
                Method::GET => match objects.lock().expect("s3").get(&key) {
                    Some(bytes) => respond(StatusCode::OK, bytes.clone()),
                    None => respond(StatusCode::NOT_FOUND, Vec::new()),
                },
                Method::HEAD => match objects.lock().expect("s3").get(&key) {
                    Some(bytes) => respond_to_head(StatusCode::OK, bytes),
                    None => respond_to_head(StatusCode::NOT_FOUND, &[]),
                },
                Method::PUT => {
                    let mut objects = objects.lock().expect("s3");
                    if headers
                        .get(axum::http::header::IF_NONE_MATCH)
                        .is_some_and(|value| value == "*")
                        && objects.contains_key(&key)
                    {
                        return respond(StatusCode::PRECONDITION_FAILED, Vec::new());
                    }
                    if let Some(expected) = headers.get(axum::http::header::IF_MATCH) {
                        let actual = objects.get(&key).map(|current| {
                            format!("\"{}\"", updated_contracts::digest::sha256_bytes(current))
                        });
                        if actual
                            .as_deref()
                            .is_none_or(|actual| actual.as_bytes() != expected)
                        {
                            return respond(StatusCode::PRECONDITION_FAILED, Vec::new());
                        }
                    }
                    objects.insert(key, body.to_vec());
                    respond(StatusCode::OK, body.to_vec())
                }
                Method::DELETE => {
                    objects.lock().expect("s3").remove(&key);
                    respond(StatusCode::NO_CONTENT, Vec::new())
                }
                _ => respond(StatusCode::METHOD_NOT_ALLOWED, Vec::new()),
            }
        }
        let app = axum::Router::new()
            .fallback(axum::routing::any(handle))
            .with_state(objects);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        addr
    }

    /// The cluster the mock apiserver serves: fixtures in, status patches out.
    #[derive(Default)]
    struct Cluster {
        repository: Option<UpdateRepository>,
        groups: Vec<UpdateGroup>,
        sets: Vec<UpdateGroupSet>,
        agents: Vec<UpdateAgent>,
        secrets: BTreeMap<String, Secret>,
        configmaps: BTreeMap<String, ConfigMap>,
        /// Every `PATCH .../status`, as (request path, body) in arrival order.
        status_patches: Vec<(String, serde_json::Value)>,
    }

    fn kube_list(items: Vec<serde_json::Value>) -> serde_json::Value {
        serde_json::json!({ "metadata": { "resourceVersion": "1" }, "items": items })
    }

    /// One pass exactly as the controller loop runs it. Production reads the fleet from the
    /// reflector store; a mock apiserver has no watch to reflect, so the fixture LISTs instead and
    /// then narrows through [`select_repository_agents`] — the same rule `FleetWatch::agents` uses,
    /// so a pass under test sees the fleet the same way and in the same order a real pass does.
    async fn reconcile_pass(
        client: Client,
        state: &Path,
        hooks: &mut ReconcileHooks,
    ) -> Result<ReconcileOutcome, Box<dyn std::error::Error>> {
        let listed: Api<UpdateAgent> = Api::namespaced(client.clone(), "default");
        let agents = select_repository_agents(
            listed
                .list(&ListParams::default())
                .await?
                .items
                .into_iter()
                .map(Arc::new),
            "default",
        );
        reconcile_once(
            ReconcileRequest {
                client,
                namespace: "default",
                repository_name: "default",
                state_dir: state,
                public_url: "https://public",
                identity: "wiring-test",
                agents,
            },
            hooks,
        )
        .await
    }

    fn apiserver_for(cluster: Arc<StdMutex<Cluster>>, identity: &str) -> Client {
        let identity = identity.to_string();
        crate::tests::apiserver(move |method, path, body| {
            let mut cluster = cluster.lock().expect("cluster");
            let not_found = || {
                (
                    StatusCode::NOT_FOUND,
                    serde_json::json!({
                        "kind": "Status", "apiVersion": "v1", "metadata": {},
                        "status": "Failure", "reason": "NotFound", "code": 404
                    }),
                )
            };
            if method == Method::PATCH && path.ends_with("/status") {
                cluster.status_patches.push((
                    path.to_string(),
                    serde_json::from_slice(&body).expect("status patch body"),
                ));
                // kube deserializes the response as the patched resource, so answer with the
                // fixture the path names.
                let mut parts = path.trim_end_matches("/status").rsplit('/');
                let name = parts.next().unwrap_or_default().to_string();
                let plural = parts.next().unwrap_or_default();
                let patched = match plural {
                    "updaterepositories" => {
                        serde_json::to_value(cluster.repository.as_ref().expect("repo")).unwrap()
                    }
                    "updategroups" => serde_json::to_value(
                        cluster
                            .groups
                            .iter()
                            .find(|group| group.metadata.name.as_deref() == Some(&name))
                            .expect("patched group exists"),
                    )
                    .unwrap(),
                    "updateagents" => serde_json::to_value(
                        cluster
                            .agents
                            .iter()
                            .find(|agent| agent.metadata.name.as_deref() == Some(&name))
                            .expect("patched agent exists"),
                    )
                    .unwrap(),
                    "updategroupsets" => serde_json::to_value(
                        cluster
                            .sets
                            .iter()
                            .find(|set| set.metadata.name.as_deref() == Some(&name))
                            .expect("patched set exists"),
                    )
                    .unwrap(),
                    other => panic!("status patch for unmodeled plural {other}"),
                };
                return (StatusCode::OK, patched);
            }
            let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
            match (method.clone(), segments.as_slice()) {
                (Method::GET, [.., "updaterepositories", _name]) => cluster
                    .repository
                    .as_ref()
                    .map(|repository| (StatusCode::OK, serde_json::to_value(repository).unwrap()))
                    .unwrap_or_else(not_found),
                // The finalizer merge patch: acknowledged, not modeled.
                (Method::PATCH, [.., "updaterepositories", _name]) => (
                    StatusCode::OK,
                    serde_json::to_value(cluster.repository.as_ref().expect("repo fixture"))
                        .unwrap(),
                ),
                (Method::GET, [.., "updategroups"]) => (
                    StatusCode::OK,
                    kube_list(
                        cluster
                            .groups
                            .iter()
                            .map(|group| serde_json::to_value(group).unwrap())
                            .collect(),
                    ),
                ),
                (Method::GET, [.., "updateagents"]) => (
                    StatusCode::OK,
                    kube_list(
                        cluster
                            .agents
                            .iter()
                            .map(|agent| serde_json::to_value(agent).unwrap())
                            .collect(),
                    ),
                ),
                (Method::GET, [.., "updategroupsets"]) => (
                    StatusCode::OK,
                    kube_list(
                        cluster
                            .sets
                            .iter()
                            .map(|set| serde_json::to_value(set).unwrap())
                            .collect(),
                    ),
                ),
                // No subscription fixture: delivery is a side channel with its own tests, and an
                // empty list is what every case here needs.
                (Method::GET, [.., "updatesubscriptions"]) => {
                    (StatusCode::OK, kube_list(Vec::new()))
                }
                (Method::GET, [.., "leases", "updatec-publisher"]) => {
                    let lease = Lease {
                        metadata: kube::api::ObjectMeta {
                            name: Some("updatec-publisher".into()),
                            namespace: Some("default".into()),
                            ..Default::default()
                        },
                        spec: Some(new_lease_spec(&identity, chrono::Utc::now(), 0)),
                    };
                    (StatusCode::OK, serde_json::to_value(&lease).unwrap())
                }
                (Method::GET, [.., "secrets", name]) => match cluster.secrets.get(*name) {
                    Some(secret) => (StatusCode::OK, serde_json::to_value(secret).unwrap()),
                    None => not_found(),
                },
                (Method::GET, [.., "configmaps", name]) => match cluster.configmaps.get(*name) {
                    Some(map) => (StatusCode::OK, serde_json::to_value(map).unwrap()),
                    None => not_found(),
                },
                (Method::POST, [.., "configmaps"]) => {
                    let mut map: ConfigMap = serde_json::from_slice(&body).expect("configmap");
                    map.metadata.resource_version = Some("1".into());
                    let name = map.metadata.name.clone().expect("configmap name");
                    let value = serde_json::to_value(&map).unwrap();
                    cluster.configmaps.insert(name, map);
                    (StatusCode::CREATED, value)
                }
                (Method::PUT, [.., "configmaps", name]) => {
                    let mut map: ConfigMap = serde_json::from_slice(&body).expect("configmap");
                    map.metadata.resource_version = Some("2".into());
                    let value = serde_json::to_value(&map).unwrap();
                    cluster.configmaps.insert((*name).to_string(), map);
                    (StatusCode::OK, value)
                }
                _ => {
                    eprintln!("apiserver mock: unhandled {method} {path}");
                    not_found()
                }
            }
        })
    }

    /// A signing Secret holding REAL freshly generated TUF keys, so the pass signs and publishes
    /// exactly as production does.
    async fn signing_secret(dir: &Path) -> Secret {
        updated_tuf::repo::generate_keys(dir).await.expect("keys");
        let mut data = BTreeMap::new();
        for name in updated_tuf::repo::KEY_FILE_NAMES {
            data.insert(
                name.to_string(),
                ByteString(std::fs::read(dir.join(name)).expect(name)),
            );
        }
        Secret {
            metadata: kube::api::ObjectMeta {
                name: Some("tuf-signing-keys".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            data: Some(data),
            ..Default::default()
        }
    }

    fn s3_credentials() -> Secret {
        Secret {
            metadata: kube::api::ObjectMeta {
                name: Some("s3-creds".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            data: Some(BTreeMap::from([
                (
                    "AWS_ACCESS_KEY_ID".to_string(),
                    ByteString(b"wiring".to_vec()),
                ),
                (
                    "AWS_SECRET_ACCESS_KEY".to_string(),
                    ByteString(b"wiring-secret".to_vec()),
                ),
            ])),
            ..Default::default()
        }
    }

    fn agent(name: &str, kind: crate::AgentIdentityKind, cordon: bool) -> UpdateAgent {
        UpdateAgent::new(
            name,
            crate::UpdateAgentSpec {
                repository_ref: crate::LocalObjectReference {
                    name: "default".into(),
                },
                identity: crate::AgentIdentity {
                    kind,
                    // Enrolled with no registration digest is a MALFORMED identity: the shape
                    // `reconcile_once` quarantines. Reserved with none is the ordinary fixture.
                    registration_sha256: None,
                    public_key: None,
                },
                labels: BTreeMap::from([("role".to_string(), "edge".to_string())]),
                backend_address: None,
                hold: false,
                cordon,
            },
        )
    }

    /// A node key pair for the wiring tests: `.0` is the PKCS#8 signing key, `.1` the pinned public
    /// point an `UpdateAgent` carries as hex. One pair for the module — identity binding is proven
    /// in `join`/`telemetry`; here a report only has to verify against the pin.
    static NODE_KEY: std::sync::LazyLock<(Vec<u8>, P256PublicKey)> =
        std::sync::LazyLock::new(|| {
            let key_pem = updated::csr::generate_key().unwrap();
            let pkcs8 = updated::csr::key_pem_to_pkcs8_der(&key_pem).unwrap();
            let csr = updated::csr::csr_for(&key_pem, "wiring-test").unwrap();
            let public = crate::join::csr_public_key(&csr).unwrap();
            (pkcs8, public)
        });

    fn enroll_test_agent(agent: &mut UpdateAgent) {
        let node = agent.name_any();
        agent.spec.identity = crate::AgentIdentity {
            kind: crate::AgentIdentityKind::Enrolled,
            registration_sha256: Some(updated_contracts::telemetry::node_object_digest(&node)),
            public_key: Some(NODE_KEY.1.to_hex()),
        };
    }

    /// Put a node's signed report into the exact private raw-object namespace the agent's capability
    /// names and the controller reads. The controller, and only the controller, derives the
    /// healthproxy fleet index from these raw objects.
    fn publish_report(
        objects: &StdMutex<BTreeMap<String, Vec<u8>>>,
        node: &str,
        deployment: &str,
        identity: &str,
        mutate: impl FnOnce(&mut updated_contracts::telemetry::NodeReport),
    ) {
        let mut report = updated_contracts::telemetry::NodeReport::new(
            node,
            deployment,
            identity,
            "1.0.0",
            "1".repeat(64),
            "1".repeat(64),
            true,
        )
        .unwrap();
        mutate(&mut report);
        let envelope = crate::test_support::sign_report(&mut report, &NODE_KEY.0);
        let body = serde_json::to_vec(&envelope).expect("encoded report");
        updated_contracts::telemetry::accept_stored_report(
            &body,
            node,
            updated_contracts::telemetry::ReportStoredAt::from_unix_millis(1).unwrap(),
        )
        .expect("the fixture produces an acceptable report");
        // Through the production key builder, not a second spelling of the layout: a fixture that
        // knows independently where reports live is a fixture that can keep passing after the real
        // namespace moves out from under it.
        let key = crate::dataflow::RepositoryDataflow::new(
            std::sync::Arc::new(object_store::memory::InMemory::new()),
            TEST_MANAGED_PREFIX,
        )
        .report_key(node);
        objects.lock().expect("s3").insert(key.to_string(), body);
    }

    /// The full fixture: repository pointed at the in-process S3, one healthy group over one
    /// agent, plus whatever `mutate` adds. Returns everything a test asserts against.
    async fn fleet(
        tmp: &Path,
        endpoint: std::net::SocketAddr,
        mutate: impl FnOnce(&mut Cluster),
    ) -> Arc<StdMutex<Cluster>> {
        let mut spec = crate::tests::repository();
        spec.s3.credentials_secret_ref = Some(crate::LocalSecretReference {
            name: "s3-creds".into(),
        });
        spec.s3.endpoint = Some(format!("http://{endpoint}"));
        // The in-process store is the controller's private endpoint. Capabilities are always
        // signed against a distinct HTTPS origin, even though these wiring tests never spend one.
        spec.s3.public_endpoint = Some(format!("https://{endpoint}"));
        let mut repository = UpdateRepository::new("default", spec);
        repository.metadata.namespace = Some("default".into());
        let mut group = UpdateGroup::new(
            "edge",
            crate::UpdateGroupSpec {
                repository_ref: crate::LocalObjectReference {
                    name: "default".into(),
                },
                selector: crate::LabelSelector {
                    match_labels: BTreeMap::from([("role".to_string(), "edge".to_string())]),
                },
                depends_on: Vec::new(),
                inputs: BTreeMap::new(),
                deployment: crate::tests::deployment_spec("edge-v1"),
                max_unavailable: None,
                emergency_correction: false,
            },
        );
        group.metadata.namespace = Some("default".into());
        let mut cluster = Cluster {
            repository: Some(repository),
            groups: vec![group],
            agents: vec![agent("n1", crate::AgentIdentityKind::Reserved, false)],
            ..Default::default()
        };
        cluster
            .secrets
            .insert("tuf-signing-keys".into(), signing_secret(tmp).await);
        cluster.secrets.insert("s3-creds".into(), s3_credentials());
        mutate(&mut cluster);
        Arc::new(StdMutex::new(cluster))
    }

    #[tokio::test]
    async fn an_absent_repository_is_a_clean_waiting_epoch() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        std::fs::create_dir_all(state.join("repository/metadata")).unwrap();
        std::fs::create_dir_all(state.join("keys")).unwrap();
        std::fs::write(state.join("repository/metadata/root.json"), b"stale root").unwrap();
        std::fs::write(state.join("keys/root.pk8"), b"stale key").unwrap();
        std::fs::write(state.join(PUBLISHED_GENERATION_FILE), b"stale marker").unwrap();
        std::fs::write(state.join(PENDING_STATE_FILE), b"stale journal").unwrap();

        let cluster = Arc::new(StdMutex::new(Cluster::default()));
        let mut hooks = ReconcileHooks::new(None);
        hooks.consecutive_failures = 7;
        hooks.projected_report_shards = Some(hooks.report_shards);
        hooks.last_report_projection_sweep = Some(std::time::Instant::now());

        let outcome = reconcile_pass(
            apiserver_for(cluster.clone(), "wiring-test"),
            &state,
            &mut hooks,
        )
        .await
        .expect("repository absence is not an error");

        assert!(matches!(outcome, ReconcileOutcome::WaitingForRepository));
        for owned in [
            "repository",
            "keys",
            PUBLISHED_GENERATION_FILE,
            PENDING_STATE_FILE,
        ] {
            assert!(
                !state.join(owned).exists(),
                "the deleted repository must not leave {owned} for a same-name replacement"
            );
        }
        assert_eq!(hooks.consecutive_failures, 0);
        assert_eq!(hooks.projected_report_shards, None);
        assert_eq!(hooks.last_report_projection_sweep, None);
        assert!(
            cluster.lock().expect("cluster").status_patches.is_empty(),
            "a missing object has no status endpoint to patch"
        );
    }

    /// The happy pass, end to end: a generation is signed and uploaded (the store serves
    /// `timestamp.json`), the durable rollout state is created, and the statuses carry the alert
    /// conditions beside Ready — the whole wiring the planner tests cannot see.
    #[tokio::test]
    async fn a_full_pass_signs_publishes_and_projects_statuses() {
        let tmp = tempfile::tempdir().unwrap();
        let objects = Arc::new(StdMutex::new(BTreeMap::new()));
        let endpoint = s3_endpoint(objects.clone()).await;
        let cluster = fleet(tmp.path(), endpoint, |_| {}).await;
        let client = apiserver_for(cluster.clone(), "wiring-test");
        let mut hooks = ReconcileHooks::new(None);

        let outcome = reconcile_pass(client, &tmp.path().join("state"), &mut hooks)
            .await
            .expect("the pass succeeds");
        assert!(matches!(
            outcome,
            ReconcileOutcome::Reconciled {
                snapshot: Some(_),
                ..
            }
        ));

        let objects_now = objects.lock().expect("s3");
        assert!(
            objects_now.contains_key(&format!("{TEST_MANAGED_PREFIX}/metadata/timestamp.json")),
            "the generation was uploaded: {:?}",
            objects_now.keys().collect::<Vec<_>>()
        );
        assert!(
            objects_now.keys().any(|key| key.contains("agents/n1.json")),
            "the agent's assignment target was published (TUF names targets by hash): {:?}",
            objects_now.keys().collect::<Vec<_>>()
        );
        assert!(
            objects_now
                .keys()
                .any(|key| key.starts_with(&format!("{TEST_MANAGED_PREFIX}/enrollments/"))),
            "the reserved agent's bundle was published through the universal S3 path: {:?}",
            objects_now.keys().collect::<Vec<_>>()
        );
        let (enrollment_object_key, enrollment_bytes) = objects_now
            .iter()
            .find(|(key, _)| key.starts_with(&format!("{TEST_MANAGED_PREFIX}/enrollments/")))
            .expect("one enrollment object");
        assert!(
            enrollment_bytes.len() < updated_contracts::enrollment::MAX_CONTROL_DOCUMENT_BYTES,
            "the bootstrap stays small rather than embedding fleet-wide TUF metadata"
        );
        let enrollment =
            updated_contracts::enrollment::EnrollmentBundle::from_bounded_json(enrollment_bytes)
                .expect("published enrollment object");
        assert_eq!(enrollment.agent_id, "n1");
        assert_eq!(enrollment.install_root, std::path::Path::new("/opt/app"));
        assert!(
            enrollment_object_key.ends_with(&format!(
                "{}.json",
                updated_contracts::digest::sha256_bytes(enrollment_bytes)
            )),
            "the status capability digest must authenticate these exact bytes"
        );
        assert!(
            objects_now.keys().all(|key| !key.starts_with(&format!(
                "{TEST_MANAGED_PREFIX}/{}/",
                crate::dataflow::INPUT_ROOT
            ))),
            "an assignment with no inputs has no pointless private payload object"
        );
        drop(objects_now);

        let cluster = cluster.lock().expect("cluster");
        assert!(
            cluster.configmaps.contains_key("updatec-admitted-default"),
            "the durable rollout state was recorded"
        );
        let group_patch = cluster
            .status_patches
            .iter()
            .find(|(path, _)| path.ends_with("/updategroups/edge/status"))
            .expect("the group's status was written");
        let conditions: Vec<&str> = group_patch.1["status"]["conditions"]
            .as_array()
            .expect("conditions")
            .iter()
            .map(|condition| condition["type"].as_str().unwrap())
            .collect();
        for expected in ["Ready", "RolloutStuck", "ReportsStale", "DeploymentHalted"] {
            assert!(
                conditions.contains(&expected),
                "group conditions missing {expected}: {conditions:?}"
            );
        }
        let agent_patch = cluster
            .status_patches
            .iter()
            .find(|(path, _)| path.ends_with("/updateagents/n1/status"))
            .expect("the agent's status was written");
        let enrollment_key = agent_patch.1["status"]["enrollmentObjectKey"]
            .as_str()
            .expect("every eligible agent status points at its S3 bundle");
        assert!(enrollment_object_sha256_for_node(enrollment_key, "n1").is_some());
        assert!(
            agent_patch.1["status"]["assignmentSha256"]
                .as_str()
                .is_some_and(updated_contracts::is_canonical_sha256),
            "status may expose only the non-secret signed assignment identity"
        );
        assert!(
            agent_patch.1["status"].get("inputSha256").is_none(),
            "a low-entropy secret digest must never be projected into Kubernetes status"
        );
    }

    #[test]
    fn enrollment_generation_changes_only_with_bootstrap_inputs() {
        let baseline = enrollment_generation_sha256(
            &"a".repeat(64),
            &"b".repeat(64),
            "https://objects.example/routing/",
        );
        assert_eq!(
            baseline,
            enrollment_generation_sha256(
                &"a".repeat(64),
                &"b".repeat(64),
                "https://objects.example/routing/"
            ),
            "a metadata renewal has no input with which to churn every node's object"
        );
        assert_ne!(
            baseline,
            enrollment_generation_sha256(
                &"c".repeat(64),
                &"b".repeat(64),
                "https://objects.example/routing/"
            )
        );
        assert_ne!(
            baseline,
            enrollment_generation_sha256(
                &"a".repeat(64),
                &"c".repeat(64),
                "https://objects.example/routing/"
            )
        );
        assert_ne!(
            baseline,
            enrollment_generation_sha256(
                &"a".repeat(64),
                &"b".repeat(64),
                "https://other.example/routing/"
            )
        );
    }

    /// The mock apiserver records status patches rather than applying them, so a test that needs
    /// the NEXT pass to see the cluster this one left behind applies them by hand. Returns how many
    /// were applied.
    fn apply_status_patches(cluster: &StdMutex<Cluster>) -> usize {
        let mut cluster = cluster.lock().expect("cluster");
        let patches = std::mem::take(&mut cluster.status_patches);
        for (path, body) in &patches {
            let status = body["status"].clone();
            let mut parts = path.trim_end_matches("/status").rsplit('/');
            let name = parts.next().unwrap_or_default().to_string();
            match parts.next().unwrap_or_default() {
                "updaterepositories" => {
                    cluster.repository.as_mut().expect("repo").status =
                        Some(serde_json::from_value(status).expect("repository status"));
                }
                "updategroups" => {
                    let group = cluster
                        .groups
                        .iter_mut()
                        .find(|group| group.name_any() == name)
                        .expect("patched group");
                    group.status = Some(serde_json::from_value(status).expect("group status"));
                }
                "updateagents" => {
                    let agent = cluster
                        .agents
                        .iter_mut()
                        .find(|agent| agent.name_any() == name)
                        .expect("patched agent");
                    agent.status = Some(serde_json::from_value(status).expect("agent status"));
                }
                other => panic!("unmodeled plural {other}"),
            }
        }
        patches.len()
    }

    /// A pass over a fleet that has stopped changing writes NOTHING. The loop runs once a second
    /// over every custom resource, so a status document that differs pass to pass — which is what a
    /// freshly stamped `lastTransitionTime` on Ready made every one of them — is an etcd write and a
    /// watch event per resource per second on a completely idle fleet, at the documented ceiling of
    /// ten thousand agents.
    #[tokio::test]
    async fn an_idle_pass_rewrites_no_status() {
        let tmp = tempfile::tempdir().unwrap();
        let objects = Arc::new(StdMutex::new(BTreeMap::new()));
        let endpoint = s3_endpoint(objects.clone()).await;
        let cluster = fleet(tmp.path(), endpoint, |_| {}).await;
        let client = apiserver_for(cluster.clone(), "wiring-test");
        let mut hooks = ReconcileHooks::new(None);
        let state = tmp.path().join("state");
        // Two passes to reach the fixed point: the first publishes the generation, the second
        // observes an enrolled node settled on it. Both are genuine changes and both must be
        // written. Seed the authentic report only after its assignment exists, as a real node does.
        let edge = crate::deployment_identity(
            &crate::DesiredDeployment::try_from(crate::tests::deployment_spec("edge-v1")).unwrap(),
        )
        .unwrap();
        for pass in 1..=2 {
            reconcile_pass(client.clone(), &state, &mut hooks)
                .await
                .expect("the pass succeeds");
            assert!(
                apply_status_patches(&cluster) > 0,
                "pass {pass} changed the fleet, so it must write"
            );
            if pass == 1 {
                enroll_test_agent(&mut cluster.lock().expect("cluster").agents[0]);
                publish_report(&objects, "n1", "edge-v1", &edge, |_| {});
            }
        }

        // Nothing has happened since. Not one patch may leave the controller.
        //
        // Nor one signature verification: the nodes' report bytes and pinned keys are exactly what
        // the previous pass already verified, and re-verifying identical bytes under an identical
        // key can only reach the identical verdict. This is the end-to-end proof that the
        // cross-pass cache actually engages in a real pass — an isolated unit test of the cache
        // would still pass if nothing ever reached it.
        let verified_before = hooks.verified_reports.verifications();
        assert!(
            verified_before > 0,
            "the settled passes must have verified the fleet's reports at least once"
        );
        reconcile_pass(client, &state, &mut hooks)
            .await
            .expect("the idle pass succeeds");
        assert_eq!(
            hooks.verified_reports.verifications(),
            verified_before,
            "an idle pass re-reads the same reports under the same keys, so it must not re-verify"
        );
        let cluster = cluster.lock().expect("cluster");
        assert!(
            cluster.status_patches.is_empty(),
            "an unchanged fleet must produce no status write at all, got {:?}",
            cluster
                .status_patches
                .iter()
                .map(|(path, body)| (path, body.to_string()))
                .collect::<Vec<_>>()
        );
    }

    /// The `UpdateGroupSet` layer, end to end: the set's own status — member accounting, schedule
    /// flags, and the alertable conditions — is written by a real pass. The planner tests decide
    /// the numbers; this locks the wiring that carries them to the resource.
    #[tokio::test]
    async fn a_set_status_is_published_with_its_members_and_conditions() {
        let tmp = tempfile::tempdir().unwrap();
        let objects = Arc::new(StdMutex::new(BTreeMap::new()));
        let endpoint = s3_endpoint(objects.clone()).await;
        let cluster = fleet(tmp.path(), endpoint, |cluster| {
            cluster.groups[0].metadata.labels =
                Some(BTreeMap::from([("tier".to_string(), "edge".to_string())]));
            let mut set = UpdateGroupSet::new(
                "edge-set",
                crate::UpdateGroupSetSpec {
                    repository_ref: crate::LocalObjectReference {
                        name: "default".into(),
                    },
                    selector: crate::LabelSelector {
                        match_labels: BTreeMap::from([("tier".to_string(), "edge".to_string())]),
                    },
                    max_concurrent: None,
                    rollout_windows: Vec::new(),
                    calendar: Vec::new(),
                    on_regression: crate::RegressionResponse::Halt,
                    max_regressions: Some(3),
                    stuck_after_seconds: Some(90),
                },
            );
            set.metadata.namespace = Some("default".into());
            cluster.sets.push(set);
        })
        .await;
        let client = apiserver_for(cluster.clone(), "wiring-test");
        let mut hooks = ReconcileHooks::new(None);
        reconcile_pass(client, &tmp.path().join("state"), &mut hooks)
            .await
            .expect("the pass succeeds with a set governing the group");

        let cluster = cluster.lock().expect("cluster");
        let set_patch = cluster
            .status_patches
            .iter()
            .find(|(path, _)| path.ends_with("/updategroupsets/edge-set/status"))
            .expect("the set's status was written");
        let status = &set_patch.1["status"];
        assert_eq!(status["memberCount"], 1, "{status}");
        assert_eq!(
            status["frozen"], false,
            "a set with neither windows nor a calendar is never frozen: {status}"
        );
        let conditions: Vec<&str> = status["conditions"]
            .as_array()
            .expect("conditions")
            .iter()
            .map(|condition| condition["type"].as_str().unwrap())
            .collect();
        for expected in ["Ready", "DeploymentHalted", "ReconcileFailing"] {
            assert!(
                conditions.contains(&expected),
                "set conditions missing {expected}: {conditions:?}"
            );
        }
    }

    /// `reconcile_once` bounds the observation log to the LIVE FLEET, and nothing asserted that it
    /// still calls `prune_nodes` at all: `evidence.rs` proves the routine correct in isolation, and
    /// the only wiring test touching the log asserts that evidence SURVIVES a pass — which deleting
    /// the call satisfies too. Unbound, the log grows for the lifetime of a leader reconciling once
    /// a second across a churning fleet, and a machine returning under a departed name inherits its
    /// predecessor's observability history.
    #[tokio::test]
    async fn a_departed_agents_memory_is_pruned_by_the_pass_that_stops_selecting_it() {
        let tmp = tempfile::tempdir().unwrap();
        let objects = Arc::new(StdMutex::new(BTreeMap::new()));
        let endpoint = s3_endpoint(objects.clone()).await;
        let cluster = fleet(tmp.path(), endpoint, |cluster| {
            cluster
                .agents
                .push(agent("n2", crate::AgentIdentityKind::Reserved, false));
        })
        .await;
        let state = tmp.path().join("state");
        let mut hooks = ReconcileHooks::new(None);
        // n2 carries a "has uploaded something" mark into the pass — the baseline `ReportsStale`
        // measures freshness against.
        hooks
            .observation_log
            .note_reported(std::iter::once(&"n2".to_string()));

        reconcile_pass(
            apiserver_for(cluster.clone(), "wiring-test"),
            &state,
            &mut hooks,
        )
        .await
        .expect("the first pass succeeds");
        assert!(
            hooks.observation_log.has_reported("n2"),
            "a member of the fleet keeps its memory"
        );

        // The machine is decommissioned: its UpdateAgent is deleted. Nothing else changes.
        cluster
            .lock()
            .expect("cluster")
            .agents
            .retain(|agent| agent.name_any() != "n2");
        reconcile_pass(
            apiserver_for(cluster.clone(), "wiring-test"),
            &state,
            &mut hooks,
        )
        .await
        .expect("the second pass succeeds");
        assert!(
            !hooks.observation_log.has_reported("n2"),
            "the pass that stopped selecting the node forgot it, so a machine returning under the \
             same name is counted as one that has never reported rather than one gone quiet"
        );
    }

    /// The halt's whole PROJECTION was unreached by the wiring harness: the set fixture's
    /// `maxRegressions` was inert (no pinned key, no telemetry object), so `plan_rollouts` always
    /// took the `halts.is_empty()` fast path — the set test only ever proved a `DeploymentHalted`
    /// of status False. A fleet-wide freeze could therefore be published as invisible on every CR,
    /// with a rollout silently stopped and nothing naming the cause.
    ///
    /// Driven the way production drives it: a real signed report in the store, carrying the node's
    /// own durable rejection of the release it was assigned.
    #[tokio::test]
    async fn a_fleet_wide_halt_reaches_both_the_set_and_the_group_status() {
        let tmp = tempfile::tempdir().unwrap();
        let objects = Arc::new(StdMutex::new(BTreeMap::new()));
        let endpoint = s3_endpoint(objects.clone()).await;
        let cluster = fleet(tmp.path(), endpoint, |cluster| {
            enroll_test_agent(&mut cluster.agents[0]);
            cluster.groups[0].metadata.labels =
                Some(BTreeMap::from([("tier".to_string(), "edge".to_string())]));
            let mut set = UpdateGroupSet::new(
                "edge-set",
                crate::UpdateGroupSetSpec {
                    repository_ref: crate::LocalObjectReference {
                        name: "default".into(),
                    },
                    selector: crate::LabelSelector {
                        match_labels: BTreeMap::from([("tier".to_string(), "edge".to_string())]),
                    },
                    max_concurrent: None,
                    rollout_windows: Vec::new(),
                    calendar: Vec::new(),
                    on_regression: crate::RegressionResponse::Halt,
                    // One rejecting node is a fleet verdict here.
                    max_regressions: Some(1),
                    stuck_after_seconds: Some(90),
                },
            );
            set.metadata.namespace = Some("default".into());
            cluster.sets.push(set);
        })
        .await;
        let state = tmp.path().join("state");
        let mut hooks = ReconcileHooks::new(None);
        // Pass one admits edge-v1 and publishes it to n1.
        reconcile_pass(
            apiserver_for(cluster.clone(), "wiring-test"),
            &state,
            &mut hooks,
        )
        .await
        .expect("the first pass admits the group's deployment");

        // n1 attempted edge-v1 and durably refused those bytes: healthy, on that assignment, still
        // executing what it had before. This is the whole evidence — no sequence to catch, and
        // nothing the control plane has to have been watching for.
        let v1 = crate::deployment_identity(
            &crate::DesiredDeployment::try_from(crate::tests::deployment_spec("edge-v1")).unwrap(),
        )
        .unwrap();
        publish_report(&objects, "n1", "edge-v1", &v1, |report| {
            report.rejected = true;
            report.healthy = false;
        });
        reconcile_pass(
            apiserver_for(cluster.clone(), "wiring-test"),
            &state,
            &mut hooks,
        )
        .await
        .expect("the second pass succeeds with the deployment halted");

        let condition = |patch: &serde_json::Value, name: &str| -> serde_json::Value {
            patch["status"]["conditions"]
                .as_array()
                .expect("conditions")
                .iter()
                .find(|condition| condition["type"] == name)
                .expect("the condition is published")
                .clone()
        };
        let published = |cluster: &Arc<StdMutex<Cluster>>, path: &str| -> serde_json::Value {
            cluster
                .lock()
                .expect("cluster")
                .status_patches
                .iter()
                .rev()
                .find(|(written, _)| written.ends_with(path))
                .unwrap_or_else(|| panic!("{path} was written"))
                .1
                .clone()
        };
        let set_patch = published(&cluster, "/updategroupsets/edge-set/status");
        assert_eq!(
            set_patch["status"]["halted"],
            serde_json::json!([{"deployment": "edge-v1", "evidence": 1, "rolledBack": false}]),
            "the set names the halted body and its evidence: {set_patch}"
        );
        assert_eq!(
            condition(&set_patch, "DeploymentHalted")["status"],
            "True",
            "{set_patch}"
        );
        let group_patch = published(&cluster, "/updategroups/edge/status");
        assert_eq!(
            condition(&group_patch, "DeploymentHalted")["status"],
            "True",
            "a set-less group learns of a halt the same way, so this is the one place it is ever \
             visible: {group_patch}"
        );
        // The group's own rollout verdict is the second, independent reading of the same evidence:
        // every node it selects has rejected the release, so the rollout is OVER — not eternally
        // "rolling", which is what held its set's concurrency slot against every sibling.
        assert_eq!(
            condition(&group_patch, "Ready")["reason"],
            "Rejected",
            "{group_patch}"
        );
        assert_eq!(set_patch["status"]["failed"], serde_json::json!(["edge"]));
        assert_eq!(set_patch["status"]["rollingCount"], 0);

        // A controller CRASH must not un-decide any of it. The node never attempts rejected bytes
        // again, so a verdict that depended on having WATCHED the rollback would be lost for ever
        // here; this one is recomputed from the standing report, so a brand-new process publishes
        // exactly the same thing.
        cluster.lock().expect("cluster").status_patches.clear();
        let mut restarted = ReconcileHooks::new(None);
        reconcile_pass(
            apiserver_for(cluster.clone(), "wiring-test"),
            &state,
            &mut restarted,
        )
        .await
        .expect("the pass after the restart succeeds");
        let set_patch = published(&cluster, "/updategroupsets/edge-set/status");
        assert_eq!(
            set_patch["status"]["halted"],
            serde_json::json!([{"deployment": "edge-v1", "evidence": 1, "rolledBack": false}]),
            "the halt stands across the restart rather than silently reopening the proven-bad body \
             to the rest of the fleet: {set_patch}"
        );
    }

    /// The repository default is a cohort like any other, and a halt on it freezes the fleet-wide
    /// switch just as hard — but its machines match no `UpdateGroup` and belong to no
    /// `UpdateGroupSet`, so neither of the two statuses that normally carry a halt exists. The
    /// planner keys that cohort's halt under the reserved `default` name; the repository's own
    /// status is where it has to surface, or the switch freezes with the repository still reporting
    /// `Ready`/`Published` and nothing anywhere naming the body or its evidence.
    #[tokio::test]
    async fn a_halted_default_deployment_is_named_on_the_repositorys_own_status() {
        let tmp = tempfile::tempdir().unwrap();
        let objects = Arc::new(StdMutex::new(BTreeMap::new()));
        let endpoint = s3_endpoint(objects.clone()).await;
        let cluster = fleet(tmp.path(), endpoint, |cluster| {
            enroll_test_agent(&mut cluster.agents[0]);
            // Matches no group, so it is the repository default's cohort.
            cluster.agents[0].spec.labels =
                BTreeMap::from([("role".to_string(), "unmatched".to_string())]);
        })
        .await;
        let state = tmp.path().join("state");
        let mut hooks = ReconcileHooks::new(None);
        reconcile_pass(
            apiserver_for(cluster.clone(), "wiring-test"),
            &state,
            &mut hooks,
        )
        .await
        .expect("the first pass publishes the default deployment to the unmatched machine");

        let default = crate::deployment_identity(
            &crate::DesiredDeployment::try_from(crate::tests::deployment_spec("default")).unwrap(),
        )
        .unwrap();
        publish_report(&objects, "n1", "default", &default, |report| {
            report.rejected = true;
            report.healthy = false;
        });
        reconcile_pass(
            apiserver_for(cluster.clone(), "wiring-test"),
            &state,
            &mut hooks,
        )
        .await
        .expect("the second pass succeeds with the default deployment halted");

        let repository_patch = cluster
            .lock()
            .expect("cluster")
            .status_patches
            .iter()
            .rev()
            .find(|(written, _)| written.ends_with("/updaterepositories/default/status"))
            .expect("the repository status was written")
            .1
            .clone();
        let halted = repository_patch["status"]["conditions"]
            .as_array()
            .expect("conditions")
            .iter()
            .find(|condition| condition["type"] == "DeploymentHalted")
            .expect("the repository names the halt")
            .clone();
        assert_eq!(halted["status"], "True", "{repository_patch}");
        assert!(
            halted["message"]
                .as_str()
                .expect("message")
                .contains("default"),
            "the halted body is named: {halted}"
        );
    }

    /// A hold is accounted to the group the node's LABELS select, not to the group its last
    /// published routing names. A held node is skipped by `assign_nodes` and carried forward on its
    /// previous routing, so keying `heldAgents` on the publication reported the hold against a group
    /// that no longer selects the machine while the group whose rollout the hold actually wedges
    /// reported zero — a freeze with nothing naming its cause.
    #[tokio::test]
    async fn a_hold_is_counted_by_the_group_the_labels_select_not_the_published_routing() {
        let tmp = tempfile::tempdir().unwrap();
        let objects = Arc::new(StdMutex::new(BTreeMap::new()));
        let endpoint = s3_endpoint(objects.clone()).await;
        let cluster = fleet(tmp.path(), endpoint, |cluster| {
            let mut core = cluster.groups[0].clone();
            core.metadata.name = Some("core".into());
            core.spec.selector.match_labels =
                BTreeMap::from([("role".to_string(), "core".to_string())]);
            core.spec.deployment = crate::tests::deployment_spec("core-v1");
            cluster.groups.push(core);
        })
        .await;
        let state = tmp.path().join("state");
        let mut hooks = ReconcileHooks::new(None);
        // Pass one: an ordinary `edge` node, published under `edge`.
        reconcile_pass(
            apiserver_for(cluster.clone(), "wiring-test"),
            &state,
            &mut hooks,
        )
        .await
        .expect("pass one publishes the fleet");
        // The operator moves the machine to `core` and freezes it there.
        {
            let mut cluster = cluster.lock().expect("cluster");
            cluster.status_patches.clear();
            let agent = &mut cluster.agents[0];
            agent.spec.labels = BTreeMap::from([("role".to_string(), "core".to_string())]);
            agent.spec.hold = true;
        }
        reconcile_pass(
            apiserver_for(cluster.clone(), "wiring-test"),
            &state,
            &mut hooks,
        )
        .await
        .expect("pass two plans around the hold");

        let cluster = cluster.lock().expect("cluster");
        let field = |group: &str, field: &str| -> u64 {
            cluster
                .status_patches
                .iter()
                .find(|(path, _)| path.ends_with(&format!("/updategroups/{group}/status")))
                .unwrap_or_else(|| panic!("{group} status was written"))
                .1["status"][field]
                .as_u64()
                .unwrap_or_else(|| panic!("{group} status has no {field}"))
        };
        let held_in = |group: &str| field(group, "heldAgents");
        // The premise, from the publication itself: the held node is still ROUTED to `edge` —
        // `matchedAgents` is the published routing's count — while the planner selects it into
        // `core`. Keying the hold count on the routing is what reported it against `edge`.
        assert_eq!(field("edge", "matchedAgents"), 1);
        assert_eq!(field("core", "matchedAgents"), 0);
        assert_eq!(
            held_in("core"),
            1,
            "the group the labels select carries the hold"
        );
        assert_eq!(
            held_in("edge"),
            0,
            "the group the stale routing names must not"
        );
    }

    /// Round 2's wholesale-replacement bug, locked at the wiring: quarantining a group must carry
    /// every condition it does not speak for — deleting the alert conditions lost their transition
    /// times and re-fired their webhooks when the group healed.
    #[tokio::test]
    async fn quarantining_a_group_carries_its_foreign_conditions_forward() {
        let tmp = tempfile::tempdir().unwrap();
        let objects = Arc::new(StdMutex::new(BTreeMap::new()));
        let endpoint = s3_endpoint(objects.clone()).await;
        let cluster = fleet(tmp.path(), endpoint, |cluster| {
            let mut broken = cluster.groups[0].clone();
            broken.metadata.name = Some("broken".into());
            broken.spec.selector.match_labels.clear(); // EmptySelector: quarantined on sight.
            broken.status = Some(crate::UpdateGroupStatus {
                observed_generation: Some(1),
                matched_agents: None,
                published_digest: None,
                held_agents: None,
                conditions: vec![ResourceCondition {
                    condition_type: "RolloutStuck".into(),
                    status: "True".into(),
                    reason: "NoNewSettledNode".into(),
                    message: "carried".into(),
                    observed_generation: Some(1),
                    last_transition_time: "2026-08-08T00:00:00Z".into(),
                }],
            });
            cluster.groups.push(broken);
        })
        .await;
        let client = apiserver_for(cluster.clone(), "wiring-test");
        let mut hooks = ReconcileHooks::new(None);
        reconcile_pass(client, &tmp.path().join("state"), &mut hooks)
            .await
            .expect("one broken group never faults the repository");
        let cluster = cluster.lock().expect("cluster");
        let quarantine_patch = cluster
            .status_patches
            .iter()
            .find(|(path, _)| path.ends_with("/updategroups/broken/status"))
            .expect("the quarantined group's status was written");
        let conditions = quarantine_patch.1["status"]["conditions"]
            .as_array()
            .expect("conditions");
        assert!(
            conditions.iter().any(|condition| {
                condition["type"] == "RolloutStuck" && condition["message"] == "carried"
            }),
            "the foreign condition must survive the quarantine write: {conditions:?}"
        );
    }
}
