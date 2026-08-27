//! Reconciling the `UpdateBackend` children this controller owns — Deployment, Role, RoleBinding,
//! access Secret and the sharded inventory projection — and draining them on delete.

use super::*;

// The healthproxy image, its pod-level credential group, and its container identity are one
// invariant. Keep the numeric ownership decision here once; CI pins it to the image USER shared by
// every first-party runtime image.
const HEALTHPROXY_RUNTIME_UID: i64 = 65_532;

/// Reconcile every backend belonging to this controller's repository. Each backend receives one
/// workload identity and, for EndpointSlice targets, one Role pinned to its two family-specific
/// slices. Resources are ordered so permission exists before startup and survives until shutdown.
///
/// `agents` is this repository's fleet as [`list_repository_agents`] read it — the pass's ONE
/// full-fleet LIST, shared with [`reconcile_once`]. This half only needs each agent's labels and
/// address, a strict subset of what publication already has in hand, so listing them again here
/// bought nothing and cost a second unpaginated read of every agent object in the namespace on a
/// loop that ticks once a second. `runtime` is validated at startup by `main`, where the
/// environment it comes from is read; nothing about it can change while the process runs.
pub async fn reconcile_backends(
    client: Client,
    namespace: &str,
    repository_name: &str,
    runtime: &BackendRuntimeConfig,
    agents: &[Arc<UpdateAgent>],
) -> Result<(), Box<dyn std::error::Error>> {
    let apis = BackendApis {
        backends: Api::namespaced(client.clone(), namespace),
        deployments: Api::namespaced(client.clone(), namespace),
        service_accounts: Api::namespaced(client.clone(), namespace),
        configmaps: Api::namespaced(client.clone(), namespace),
        roles: Api::namespaced(client.clone(), namespace),
        role_bindings: Api::namespaced(client, namespace),
    };
    let backend_resources = apis.backends.list(&ListParams::default()).await?;
    let conflicts = backend_target_conflicts(
        backend_resources
            .iter()
            .filter(|backend| backend.spec.repository_ref.name == repository_name),
    );

    for backend in backend_resources {
        if backend.spec.repository_ref.name != repository_name {
            continue;
        }
        let resource_name = backend_resource_name(&backend.name_any());
        if backend.metadata.deletion_timestamp.is_some() {
            finalize_backend(&apis, &backend, &resource_name).await?;
            continue;
        }
        ensure_backend_finalizer(&apis.backends, &backend).await?;

        // Already this repository's agents: the shared LIST is filtered once, by the caller.
        let selected: Vec<&UpdateAgent> = agents
            .iter()
            .map(Arc::as_ref)
            .filter(|agent| {
                crate::selector_matches(&backend.spec.selector.match_labels, &agent.spec.labels)
            })
            .collect();
        let generation = backend.metadata.generation;
        let validation = conflicts.get(&backend.name_any()).map_or_else(
            || validate_backend(&backend, &selected),
            |target| {
                Err((
                    "TargetConflict",
                    format!("Another UpdateBackend already owns {target}."),
                ))
            },
        );
        let status = match validation {
            Err((reason, message)) => {
                // Invalid desired state must never preserve valid-looking old routing authority.
                // Rewrite the last complete inventory as cordoned identities, so even a freshly
                // restarted HAProxy programmer can name and drain every server it previously
                // owned. Then terminate the workload in every failure case: its shutdown path
                // repeats the in-memory drain, and invalid desired state cannot keep or recreate a
                // balancer writer. Once it is gone, remove its exact access and projection too.
                let inventory_drained = match drain_backend_projection(
                    &apis.configmaps,
                    &backend,
                    &resource_name,
                )
                .await
                {
                    Ok(drained) => drained,
                    Err(error) => {
                        // The projection rewrite is defense in depth. A transient ConfigMap read
                        // or write failure must not return before the primary fail-closed action
                        // below gets its independent chance to terminate the balancer writer.
                        tracing::warn!(
                            backend = %backend.name_any(),
                            error = %error,
                            "could not cordon the existing backend inventory before shutdown"
                        );
                        false
                    }
                };
                let draining = delete_deployment(&apis.deployments, &resource_name).await?;
                if !draining {
                    delete_backend_access(&apis, &resource_name).await?;
                }
                UpdateBackendStatus {
                    observed_generation: generation,
                    matched_agents: Some(selected.len().min(u32::MAX as usize) as u32),
                    workload: draining.then(|| resource_name.clone()),
                    conditions: vec![failed_condition(
                        generation,
                        reason,
                        &format!(
                            "{message} {}",
                            if inventory_drained {
                                "The existing routing inventory is explicitly cordoned and the workload is terminating."
                            } else {
                                "No complete routing inventory was recoverable; the workload is terminating."
                            }
                        ),
                    )],
                }
            }
            Ok((inventory, _)) if inventory.is_empty() => {
                let draining = delete_deployment(&apis.deployments, &resource_name).await?;
                if !draining {
                    delete_backend_access(&apis, &resource_name).await?;
                }
                UpdateBackendStatus {
                    observed_generation: generation,
                    matched_agents: Some(0),
                    workload: draining.then(|| resource_name.clone()),
                    conditions: vec![condition(
                        crate::status_contract::READY_CONDITION,
                        !draining,
                        generation,
                        if draining { "Draining" } else { "Idle" },
                        if draining {
                            "The last selected agent was removed; the old workload is draining before its access is removed."
                        } else {
                            "No agents are selected; no healthproxy workload or access exists."
                        },
                    )],
                }
            }
            Ok((inventory, invalid_active)) => {
                let desired_access = backend_access_key(&backend.spec.target);
                if deployment_access_changed(&apis.deployments, &resource_name, &desired_access)
                    .await?
                {
                    delete_deployment(&apis.deployments, &resource_name).await?;
                    UpdateBackendStatus {
                        observed_generation: generation,
                        matched_agents: Some(inventory.len().min(u32::MAX as usize) as u32),
                        workload: Some(resource_name.clone()),
                        conditions: vec![condition(
                            crate::status_contract::READY_CONDITION,
                            false,
                            generation,
                            "Draining",
                            "The load-balancer target changed; the old workload is draining before access is replaced.",
                        )],
                    }
                } else {
                    apply_backend_inventory(&apis.configmaps, &backend, &resource_name, &inventory)
                        .await?;
                    reconcile_backend_access(&apis, &backend, &resource_name).await?;
                    let deployment = apply_backend_deployment(
                        &apis.deployments,
                        &backend,
                        &resource_name,
                        runtime,
                    )
                    .await?;
                    let available = deployment.status.as_ref().is_some_and(|status| {
                        status.observed_generation == deployment.metadata.generation
                            && status.available_replicas.unwrap_or_default() >= 1
                    });
                    let (ready, reason, message) = if invalid_active > 0 {
                        (
                            false,
                            "InvalidAgentEndpoints",
                            format!(
                                "{invalid_active} selected agent(s) have no valid address and pinned key; they are explicitly drained in the active inventory."
                            ),
                        )
                    } else if available {
                        (
                            true,
                            "Available",
                            "The healthproxy workload is available with its exact access."
                                .to_string(),
                        )
                    } else {
                        (
                            false,
                            "Starting",
                            "The healthproxy workload and exact access are configured; the pod is starting."
                                .to_string(),
                        )
                    };
                    UpdateBackendStatus {
                        observed_generation: generation,
                        matched_agents: Some(inventory.len().min(u32::MAX as usize) as u32),
                        workload: Some(resource_name.clone()),
                        conditions: vec![condition(
                            crate::status_contract::READY_CONDITION,
                            ready,
                            generation,
                            reason,
                            &message,
                        )],
                    }
                }
            }
        };
        patch_backend_status(&apis.backends, &backend, &status).await?;
    }
    Ok(())
}

pub(crate) fn backend_target_conflicts<'a>(
    backends: impl Iterator<Item = &'a UpdateBackend>,
) -> HashMap<String, String> {
    let mut owners: HashMap<String, Vec<String>> = HashMap::new();
    for backend in backends {
        for target in backend_target_keys(backend) {
            owners.entry(target).or_default().push(backend.name_any());
        }
    }
    let mut conflicts = HashMap::new();
    for (target, names) in owners {
        if names.len() > 1 {
            for name in names {
                conflicts.insert(name, target.clone());
            }
        }
    }
    conflicts
}

pub(crate) fn backend_target_keys(backend: &UpdateBackend) -> Vec<String> {
    match backend.spec.target.kind {
        BackendTargetKind::EndpointSlice => backend
            .spec
            .target
            .service
            .as_deref()
            .filter(|service| !service.is_empty())
            .map(|service| {
                vec![format!(
                    "EndpointSlice {}/{service}",
                    backend.namespace().unwrap_or_default()
                )]
            })
            .unwrap_or_default(),
        BackendTargetKind::HAProxy => {
            let Some(backend_name) = backend.spec.target.backend.as_deref() else {
                return Vec::new();
            };
            backend
                .spec
                .target
                .endpoints
                .iter()
                .filter(|endpoint| !endpoint.is_empty())
                .map(|endpoint| format!("HAProxy {endpoint}/{backend_name}"))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        }
    }
}

/// Check the process-level backend settings, at the one moment they can still be reported: startup,
/// where `main` reads them out of the environment and a failure exits the process the way
/// `UPDATED_PUBLIC_URL` and `UPDATED_ALERT_URL` already do.
///
/// These are chart values, not CRD fields, so there is no object to fail. Running the check at the
/// top of [`reconcile_backends`] instead meant a lowercase `pullPolicy` returned from the first
/// line of every pass, before a single [`UpdateBackend`] was listed or its status patched: the pod
/// came up healthy, every backend kept whatever status it last had (an empty one, for a new
/// object), and the only signal was one `tracing::error!` per second, forever.
pub fn validate_backend_runtime(runtime: &BackendRuntimeConfig) -> Result<(), &'static str> {
    if runtime.image.trim().is_empty() {
        return Err("UPDATED_HEALTHPROXY_IMAGE must not be empty");
    }
    if !matches!(
        runtime.image_pull_policy.as_str(),
        "Always" | "IfNotPresent" | "Never"
    ) {
        return Err("UPDATED_HEALTHPROXY_PULL_POLICY must be Always, IfNotPresent, or Never");
    }
    Ok(())
}

pub(crate) fn validate_backend(
    backend: &UpdateBackend,
    agents: &[&UpdateAgent],
) -> Result<
    (
        Vec<updated_contracts::backend::BackendInventoryMember>,
        usize,
    ),
    (&'static str, String),
> {
    if backend.spec.selector.match_labels.is_empty() {
        return Err((
            "EmptySelector",
            "spec.selector.matchLabels must select an explicit subset of agents.".into(),
        ));
    }
    if updated::http::network_endpoint(
        backend.spec.health_base.trim(),
        updated::http::EndpointTransport::HttpOrHttps,
        "spec.healthBase",
    )
    .is_err()
    {
        return Err((
            "InvalidHealthBase",
            "spec.healthBase must be an absolute HTTP(S) URL with no credentials, query, or fragment."
                .into(),
        ));
    }
    // The same bounds the CRD schema publishes, read from the same constants: an apiserver that
    // accepts a value this refuses (an older CRD in the cluster, a widened schema) is a CR that
    // fails every reconcile, so the two statements of the rule cannot be allowed to drift apart.
    if !(crate::BACKEND_POLL_SECONDS_MIN..=crate::BACKEND_INTERVAL_SECONDS_MAX)
        .contains(&backend.spec.interval_seconds)
        || !(crate::BACKEND_POLL_SECONDS_MIN..=crate::BACKEND_HEALTH_TIMEOUT_SECONDS_MAX)
            .contains(&backend.spec.health_timeout_seconds)
    {
        return Err((
            "InvalidPollPlan",
            format!(
                "intervalSeconds must be {min}..={interval_max} and healthTimeoutSeconds must be \
                 {min}..={timeout_max}.",
                min = crate::BACKEND_POLL_SECONDS_MIN,
                interval_max = crate::BACKEND_INTERVAL_SECONDS_MAX,
                timeout_max = crate::BACKEND_HEALTH_TIMEOUT_SECONDS_MAX,
            ),
        ));
    }
    let target = &backend.spec.target;
    match target.kind {
        BackendTargetKind::EndpointSlice => {
            if !target.endpoints.is_empty()
                || target.backend.is_some()
                || !target.service.as_deref().is_some_and(is_dns_label)
                || target.port.is_none_or(|port| port == 0)
                || !target.port_name.as_deref().is_some_and(is_dns_label)
            {
                return Err((
                    "InvalidEndpointSliceTarget",
                    "An EndpointSlice target requires only service, port, and portName; both names must be DNS labels and port must be nonzero.".into(),
                ));
            }
        }
        BackendTargetKind::HAProxy => {
            let backend_name = target.backend.as_deref().unwrap_or_default();
            if target.service.is_some()
                || target.port.is_some()
                || target.port_name.is_some()
                || target.endpoints.is_empty()
                || target.endpoints.iter().collect::<BTreeSet<_>>().len() != target.endpoints.len()
                || target
                    .endpoints
                    .iter()
                    .any(|endpoint| !updated_contracts::backend::is_tcp_endpoint(endpoint))
                || !updated_contracts::backend::is_balancer_safe(backend_name)
            {
                return Err((
                    "InvalidHAProxyTarget",
                    "HAProxy needs at least one delimiter-free endpoint and a safe backend name."
                        .into(),
                ));
            }
        }
    }

    let mut inventory = Vec::with_capacity(agents.len());
    let mut invalid_active = 0usize;
    for agent in agents {
        let node = agent.name_any();
        // A cordon is an operational safety instruction, not a partially configured route. It
        // needs only the balancer-safe identity HAProxy must explicitly drain; requiring the
        // address or report key here lets a simultaneous malformed edit preserve the old ACTIVE
        // projection and defeat the cordon.
        if agent.spec.cordon {
            let member = updated_contracts::backend::BackendInventoryMember::cordoned(node)
                .map_err(|message| ("InvalidAgentEndpoint", message))?;
            inventory.push(member);
            continue;
        }
        let active = if agent.spec.identity.is_well_formed_for(&node) {
            agent
                .spec
                .backend_address
                .as_deref()
                .zip(agent.spec.identity.public_key.as_deref())
                .and_then(|(address, public_key)| {
                    updated_contracts::backend::BackendInventoryMember::active(
                        node.clone(),
                        address,
                        public_key,
                    )
                    .ok()
                })
        } else {
            None
        };
        match active {
            Some(member) => inventory.push(member),
            None => {
                // Failing the WHOLE projection here preserved its last valid revision. That old
                // revision may still route this node and, worse, blocks an unrelated new cordon.
                // The complete next revision instead makes this identity explicitly non-routable
                // and reports the degradation on the UpdateBackend status.
                invalid_active += 1;
                inventory.push(
                    updated_contracts::backend::BackendInventoryMember::cordoned(node)
                        .map_err(|message| ("InvalidAgentEndpoint", message))?,
                );
            }
        }
    }
    inventory.sort_by(|left, right| left.node().cmp(right.node()));
    if let Err(message) = encode_backend_inventory(&inventory) {
        return Err(("InventoryCapacityExceeded", message));
    }
    Ok((inventory, invalid_active))
}

/// A Kubernetes DNS label: the bound the apiserver puts on the two names an `UpdateBackend` hands
/// it, the generated Service's name and the EndpointSlice port name.
///
/// Deliberately distinct from the shared fleet-node grammar: a node is a DNS *subdomain* of up to
/// 253 bytes, while each Kubernetes object name here is one DNS *label* of at most 63. A 200-byte
/// multi-label node name is legal and a 200-byte Service name is not; publishing this operator-side
/// Kubernetes constraint as part of the node protocol would conflate the two subjects.
pub(crate) fn is_dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value.as_bytes().first() != Some(&b'-')
        && value.as_bytes().last() != Some(&b'-')
}

/// Hex characters of the digest a truncated child name carries: enough that two names sharing a
/// truncated prefix still cannot collide.
pub(crate) const CHILD_NAME_DIGEST_CHARS: usize = 12;

/// A generated child object's name: `prefix` followed by the custom resource's `name`, bounded to
/// `max_bytes` by truncating the name and appending a hyphen plus [`CHILD_NAME_DIGEST_CHARS`] of its
/// SHA-256.
///
/// The BOUND differs per family and is the caller's — a DNS *label* budget for the backend's
/// ConfigMaps, the DNS *subdomain* budget for the durable state's — but the truncate-and-hash rule
/// is one rule, written here once. Two spellings of it (with two different digest APIs) is how a
/// change to one, such as widening the digest, silently leaves the other behind.
pub(crate) fn bounded_child_name(prefix: &str, name: &str, max_bytes: usize) -> String {
    if prefix.len() + name.len() <= max_bytes {
        return format!("{prefix}{name}");
    }
    let digest = updated_contracts::telemetry::node_object_digest(name);
    let retained = max_bytes - prefix.len() - 1 - CHILD_NAME_DIGEST_CHARS;
    format!(
        "{prefix}{}-{}",
        &name[..retained],
        &digest[..CHILD_NAME_DIGEST_CHARS]
    )
}

pub(crate) fn backend_resource_name(name: &str) -> String {
    // Reserve room for `-inventory-00`: every generated object shares this base and therefore one
    // deterministic naming rule, while all eight ConfigMaps remain valid DNS-label names.
    const MAX_BASE_BYTES: usize = 63 - "-inventory-00".len();
    bounded_child_name("updated-backend-", name, MAX_BASE_BYTES)
}

pub(crate) fn backend_inventory_name(base: &str, index: usize) -> String {
    debug_assert!(index < updated_contracts::backend::BACKEND_INVENTORY_SHARDS);
    format!("{base}-inventory-{index:02}")
}

pub(crate) fn backend_access_key(target: &BackendTarget) -> String {
    match target.kind {
        BackendTargetKind::EndpointSlice => format!(
            "endpointslice:{}",
            target.service.as_deref().unwrap_or_default()
        ),
        BackendTargetKind::HAProxy => "haproxy".into(),
    }
}

pub(crate) fn backend_labels(resource_name: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("app".into(), resource_name.into()),
        ("app.kubernetes.io/component".into(), "healthproxy".into()),
        ("app.kubernetes.io/managed-by".into(), "updatec".into()),
    ])
}

pub(crate) fn backend_owner(backend: &UpdateBackend) -> OwnerReference {
    backend
        .controller_owner_ref(&())
        .expect("UpdateBackend returned by the apiserver has a UID")
}

pub(crate) async fn ensure_backend_finalizer(
    api: &Api<UpdateBackend>,
    backend: &UpdateBackend,
) -> Result<(), kube::Error> {
    let Some(finalizers) = finalizers_with(backend.finalizers(), BACKEND_FINALIZER) else {
        return Ok(());
    };
    api.patch(
        &backend.name_any(),
        &PatchParams::default(),
        &Patch::Merge(finalizer_patch(backend, finalizers)),
    )
    .await?;
    Ok(())
}

/// The one writer of an `UpdateBackend` status, so the conditions array is merged over the observed
/// one — and the write skipped when nothing changed — in a single place, whichever of
/// `reconcile_backends`' branches computed the status.
pub(crate) async fn patch_backend_status(
    api: &Api<UpdateBackend>,
    backend: &UpdateBackend,
    status: &UpdateBackendStatus,
) -> Result<(), kube::Error> {
    let observed = backend.status.as_ref();
    let status = UpdateBackendStatus {
        conditions: crate::alerts::merge_conditions(
            observed
                .map(|status| status.conditions.as_slice())
                .unwrap_or_default(),
            status.conditions.clone(),
        ),
        ..status.clone()
    };
    if status_unchanged(&status, observed) {
        return Ok(());
    }
    api.patch_status(
        &backend.name_any(),
        &PatchParams::default(),
        &Patch::Merge(serde_json::json!({"status": status})),
    )
    .await?;
    Ok(())
}

pub(crate) async fn deployment_access_changed(
    deployments: &Api<Deployment>,
    name: &str,
    desired: &str,
) -> Result<bool, kube::Error> {
    Ok(deployments.get_opt(name).await?.is_some_and(|deployment| {
        deployment
            .spec
            .and_then(|spec| spec.template.metadata)
            .and_then(|metadata| metadata.annotations)
            .and_then(|annotations| annotations.get("updated.dev/backend-access").cloned())
            .as_deref()
            != Some(desired)
    }))
}

pub(crate) async fn reconcile_backend_access(
    apis: &BackendApis,
    backend: &UpdateBackend,
    name: &str,
) -> Result<(), kube::Error> {
    let service_accounts = &apis.service_accounts;
    let roles = &apis.roles;
    let role_bindings = &apis.role_bindings;
    let labels = backend_labels(name);
    let owner = backend_owner(backend);
    let service_account = ServiceAccount {
        metadata: kube::api::ObjectMeta {
            name: Some(name.into()),
            namespace: backend.namespace(),
            labels: Some(labels.clone()),
            owner_references: Some(vec![owner.clone()]),
            ..Default::default()
        },
        automount_service_account_token: Some(matches!(
            backend.spec.target.kind,
            BackendTargetKind::EndpointSlice
        )),
        ..Default::default()
    };
    apply(service_accounts, name, &service_account).await?;

    if backend.spec.target.kind == BackendTargetKind::HAProxy {
        delete_named(role_bindings, name).await?;
        delete_named(roles, name).await?;
        return Ok(());
    }
    let role = backend_role(backend, name, labels.clone(), owner.clone());
    apply(roles, name, &role).await?;
    let role_binding = RoleBinding {
        metadata: kube::api::ObjectMeta {
            name: Some(name.into()),
            namespace: backend.namespace(),
            labels: Some(labels),
            owner_references: Some(vec![owner]),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".into(),
            kind: "Role".into(),
            name: name.into(),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".into(),
            name: name.into(),
            namespace: backend.namespace(),
            ..Default::default()
        }]),
    };
    apply(role_bindings, name, &role_binding).await
}

pub(crate) async fn apply_backend_inventory(
    configmaps: &Api<ConfigMap>,
    backend: &UpdateBackend,
    name: &str,
    inventory: &[updated_contracts::backend::BackendInventoryMember],
) -> Result<(), Box<dyn std::error::Error>> {
    for (index, encoded) in encode_backend_inventory(inventory)? {
        let shard_name = backend_inventory_name(name, index);
        let configmap = ConfigMap {
            metadata: kube::api::ObjectMeta {
                name: Some(shard_name.clone()),
                namespace: backend.namespace(),
                labels: Some(backend_labels(name)),
                owner_references: Some(vec![backend_owner(backend)]),
                ..Default::default()
            },
            data: Some(BTreeMap::from([("inventory.json".into(), encoded)])),
            ..Default::default()
        };
        apply(configmaps, &shard_name, &configmap).await?;
    }
    Ok(())
}

/// Read the one fixed inventory projection without adopting a partial or mixed revision.
/// `None` means the projection cannot safely name the servers the workload currently owns.
pub(crate) async fn read_backend_inventory(
    configmaps: &Api<ConfigMap>,
    name: &str,
) -> Result<Option<Vec<updated_contracts::backend::BackendInventoryMember>>, kube::Error> {
    let mut shards = Vec::with_capacity(updated_contracts::backend::BACKEND_INVENTORY_SHARDS);
    for index in 0..updated_contracts::backend::BACKEND_INVENTORY_SHARDS {
        let Some(configmap) = configmaps
            .get_opt(&backend_inventory_name(name, index))
            .await?
        else {
            return Ok(None);
        };
        let Some(encoded) = configmap
            .data
            .as_ref()
            .and_then(|data| data.get("inventory.json"))
        else {
            return Ok(None);
        };
        if encoded.len() > updated_contracts::backend::BACKEND_INVENTORY_SHARD_MAX_BYTES {
            return Ok(None);
        }
        let Ok(shard) = serde_json::from_str(encoded) else {
            return Ok(None);
        };
        shards.push(shard);
    }
    Ok(updated_contracts::backend::assemble_backend_inventory(shards).ok())
}

/// Replace an existing complete projection with the same identities, all explicitly cordoned.
/// This is the one fail-closed path for every invalid backend configuration and ownership conflict.
pub(crate) async fn drain_backend_projection(
    configmaps: &Api<ConfigMap>,
    backend: &UpdateBackend,
    name: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let Some(current) = read_backend_inventory(configmaps, name).await? else {
        return Ok(false);
    };
    let drained = cordon_backend_inventory(current)?;
    apply_backend_inventory(configmaps, backend, name, &drained).await?;
    Ok(true)
}

pub(crate) fn cordon_backend_inventory(
    current: Vec<updated_contracts::backend::BackendInventoryMember>,
) -> Result<Vec<updated_contracts::backend::BackendInventoryMember>, String> {
    current
        .into_iter()
        .map(|member| updated_contracts::backend::BackendInventoryMember::cordoned(member.node()))
        .collect()
}

pub(crate) fn encode_backend_inventory(
    inventory: &[updated_contracts::backend::BackendInventoryMember],
) -> Result<Vec<(usize, String)>, String> {
    updated_contracts::backend::shard_backend_inventory(inventory)?
        .into_iter()
        .map(|shard| {
            let index = usize::from(shard.index);
            let encoded = serde_json::to_string(&shard)
                .map_err(|error| format!("encoding inventory shard {index}: {error}"))?;
            Ok((index, encoded))
        })
        .collect()
}

pub(crate) fn backend_role(
    backend: &UpdateBackend,
    name: &str,
    labels: BTreeMap<String, String>,
    owner: OwnerReference,
) -> Role {
    let service = backend.spec.target.service.as_deref().unwrap_or_default();
    Role {
        metadata: kube::api::ObjectMeta {
            name: Some(name.into()),
            namespace: backend.namespace(),
            labels: Some(labels),
            owner_references: Some(vec![owner]),
            ..Default::default()
        },
        rules: Some(vec![
            // The healthproxy materializes its slice through the same server-side apply it
            // reconciles it with, and Kubernetes authorizes an apply that creates the missing
            // object as CREATE — which RBAC cannot constrain by resourceName, because
            // authorization runs before a create request has one. So `create` is granted bare
            // here, and the OBJECT-level bound stays real through the named rule below: every
            // ongoing write (each reconcile's patch, and the delete that replaces a slice whose
            // address family flipped) is pinned to this backend's two family-specific names.
            PolicyRule {
                api_groups: Some(vec!["discovery.k8s.io".into()]),
                resources: Some(vec!["endpointslices".into()]),
                verbs: vec!["create".into()],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec!["discovery.k8s.io".into()]),
                resources: Some(vec!["endpointslices".into()]),
                resource_names: Some(vec![
                    format!("{service}-updated-ipv4"),
                    format!("{service}-updated-ipv6"),
                ]),
                verbs: vec!["get".into(), "patch".into(), "delete".into()],
                ..Default::default()
            },
        ]),
    }
}

/// The fixed port every operator-managed healthproxy serves `GET /metrics` on.
pub const BACKEND_METRICS_PORT: u16 = 9090;

pub(crate) async fn apply_backend_deployment(
    deployments: &Api<Deployment>,
    backend: &UpdateBackend,
    name: &str,
    runtime: &BackendRuntimeConfig,
) -> Result<Deployment, kube::Error> {
    let labels = backend_labels(name);
    let access = backend_access_key(&backend.spec.target);
    let mut env = vec![
        EnvVar {
            name: updated_contracts::backend::HEALTHPROXY_HEALTH_BASE_ENV.into(),
            value: Some(backend.spec.health_base.clone()),
            ..Default::default()
        },
        EnvVar {
            name: updated_contracts::backend::HEALTHPROXY_INVENTORY_DIR_ENV.into(),
            value: Some("/etc/healthproxy/inventory".into()),
            ..Default::default()
        },
        EnvVar {
            name: updated_contracts::backend::HEALTHPROXY_INTERVAL_SECS_ENV.into(),
            value: Some(backend.spec.interval_seconds.to_string()),
            ..Default::default()
        },
        EnvVar {
            name: updated_contracts::backend::HEALTHPROXY_HEALTH_TIMEOUT_SECS_ENV.into(),
            value: Some(backend.spec.health_timeout_seconds.to_string()),
            ..Default::default()
        },
        // Always on for an operator-managed checker: the exposition is plain-HTTP, read-only and
        // cluster-internal, and this deployment is the ONE observer of out-of-cluster nodes —
        // running it dark means the freshness of the signed reports that govern those machines is
        // unobservable exactly where it matters.
        // A fixed port rather than a spec knob: the operator owns this pod wholesale, and there
        // is nothing else on its network namespace to collide with.
        EnvVar {
            name: updated_contracts::backend::HEALTHPROXY_METRICS_ADDRESS_ENV.into(),
            value: Some(format!("0.0.0.0:{BACKEND_METRICS_PORT}")),
            ..Default::default()
        },
    ];
    match backend.spec.target.kind {
        BackendTargetKind::EndpointSlice => env.extend([
            EnvVar {
                name: updated_contracts::backend::HEALTHPROXY_SERVICE_ENV.into(),
                value: backend.spec.target.service.clone(),
                ..Default::default()
            },
            EnvVar {
                name: updated_contracts::backend::HEALTHPROXY_NAMESPACE_ENV.into(),
                value: backend.namespace(),
                ..Default::default()
            },
            EnvVar {
                name: updated_contracts::backend::HEALTHPROXY_PORT_ENV.into(),
                value: backend.spec.target.port.map(|port| port.to_string()),
                ..Default::default()
            },
            EnvVar {
                name: updated_contracts::backend::HEALTHPROXY_PORT_NAME_ENV.into(),
                value: backend.spec.target.port_name.clone(),
                ..Default::default()
            },
        ]),
        BackendTargetKind::HAProxy => env.extend([
            EnvVar {
                name: updated_contracts::backend::HEALTHPROXY_HAPROXY_ENDPOINTS_ENV.into(),
                value: Some(backend.spec.target.endpoints.join(",")),
                ..Default::default()
            },
            EnvVar {
                name: updated_contracts::backend::HEALTHPROXY_HAPROXY_BACKEND_ENV.into(),
                value: backend.spec.target.backend.clone(),
                ..Default::default()
            },
        ]),
    }
    let resources = ResourceRequirements {
        requests: Some(BTreeMap::from([
            ("cpu".into(), Quantity("10m".into())),
            ("memory".into(), Quantity("32Mi".into())),
        ])),
        limits: Some(BTreeMap::from([
            ("cpu".into(), Quantity("250m".into())),
            ("memory".into(), Quantity("128Mi".into())),
        ])),
        ..Default::default()
    };
    let deployment = Deployment {
        metadata: kube::api::ObjectMeta {
            name: Some(name.into()),
            namespace: backend.namespace(),
            labels: Some(labels.clone()),
            owner_references: Some(vec![backend_owner(backend)]),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(1),
            revision_history_limit: Some(2),
            selector: KubernetesLabelSelector {
                match_labels: Some(BTreeMap::from([("app".into(), name.into())])),
                ..Default::default()
            },
            strategy: Some(DeploymentStrategy {
                type_: Some("Recreate".into()),
                rolling_update: None,
            }),
            template: PodTemplateSpec {
                metadata: Some(kube::api::ObjectMeta {
                    labels: Some(labels),
                    annotations: Some(BTreeMap::from([(
                        "updated.dev/backend-access".into(),
                        access,
                    )])),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    automount_service_account_token: Some(matches!(
                        backend.spec.target.kind,
                        BackendTargetKind::EndpointSlice
                    )),
                    service_account_name: Some(name.into()),
                    termination_grace_period_seconds: Some(30),
                    security_context: Some(PodSecurityContext {
                        run_as_non_root: Some(true),
                        run_as_user: Some(HEALTHPROXY_RUNTIME_UID),
                        run_as_group: Some(HEALTHPROXY_RUNTIME_UID),
                        // The inventory projection is mounted 0440 (owner root, group readable),
                        // so the group is what the checker reads it through: without fsGroup the
                        // projected files stay root:root and the non-root process cannot open
                        // the very inventory it exists to serve — a crash loop on first boot.
                        fs_group: Some(HEALTHPROXY_RUNTIME_UID),
                        seccomp_profile: Some(SeccompProfile {
                            type_: "RuntimeDefault".into(),
                            localhost_profile: None,
                        }),
                        ..Default::default()
                    }),
                    containers: vec![Container {
                        name: "healthproxy".into(),
                        image: Some(runtime.image.clone()),
                        image_pull_policy: Some(runtime.image_pull_policy.clone()),
                        env: Some(env),
                        volume_mounts: Some(vec![VolumeMount {
                            name: "inventory".into(),
                            mount_path: "/etc/healthproxy/inventory".into(),
                            read_only: Some(true),
                            ..Default::default()
                        }]),
                        resources: Some(resources),
                        security_context: Some(SecurityContext {
                            allow_privilege_escalation: Some(false),
                            read_only_root_filesystem: Some(true),
                            run_as_non_root: Some(true),
                            run_as_user: Some(HEALTHPROXY_RUNTIME_UID),
                            run_as_group: Some(HEALTHPROXY_RUNTIME_UID),
                            capabilities: Some(Capabilities {
                                add: None,
                                drop: Some(vec!["ALL".into()]),
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }],
                    volumes: Some(vec![Volume {
                        name: "inventory".into(),
                        projected: Some(ProjectedVolumeSource {
                            sources: Some(
                                (0..updated_contracts::backend::BACKEND_INVENTORY_SHARDS)
                                    .map(|index| VolumeProjection {
                                        config_map: Some(ConfigMapProjection {
                                            name: backend_inventory_name(name, index),
                                            items: Some(vec![KeyToPath {
                                                key: "inventory.json".into(),
                                                path: format!("inventory-{index:02}.json"),
                                                ..Default::default()
                                            }]),
                                            optional: Some(false),
                                        }),
                                        ..Default::default()
                                    })
                                    .collect(),
                            ),
                            default_mode: Some(0o440),
                        }),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        status: None,
    };
    deployments
        .patch(
            name,
            &PatchParams::apply(BACKEND_FIELD_MANAGER).force(),
            &Patch::Apply(&deployment),
        )
        .await
}

pub(crate) async fn apply<K>(api: &Api<K>, name: &str, value: &K) -> Result<(), kube::Error>
where
    K: Clone
        + serde::Serialize
        + serde::de::DeserializeOwned
        + std::fmt::Debug
        + kube::Resource<DynamicType = ()>,
{
    api.patch(
        name,
        &PatchParams::apply(BACKEND_FIELD_MANAGER).force(),
        &Patch::Apply(value),
    )
    .await?;
    Ok(())
}

pub(crate) async fn delete_deployment(
    deployments: &Api<Deployment>,
    name: &str,
) -> Result<bool, kube::Error> {
    if deployments.get_opt(name).await?.is_none() {
        return Ok(false);
    }
    deployments.delete(name, &DeleteParams::default()).await?;
    Ok(true)
}

pub(crate) async fn delete_named<K>(api: &Api<K>, name: &str) -> Result<(), kube::Error>
where
    K: Clone + serde::de::DeserializeOwned + std::fmt::Debug + kube::Resource<DynamicType = ()>,
{
    match api.delete(name, &DeleteParams::default()).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(error)) if error.code == 404 => Ok(()),
        Err(error) => Err(error),
    }
}

/// The Kubernetes handles one backend reconcile touches. They travel as one value because every
/// writer and every finalizer needs the same set: threading them severally is how one path ends
/// up deleting through a handle another forgot to be given.
pub(crate) struct BackendApis {
    pub(crate) backends: Api<UpdateBackend>,
    pub(crate) deployments: Api<Deployment>,
    pub(crate) service_accounts: Api<ServiceAccount>,
    pub(crate) configmaps: Api<ConfigMap>,
    pub(crate) roles: Api<Role>,
    pub(crate) role_bindings: Api<RoleBinding>,
}

pub(crate) async fn delete_backend_inventory_range(
    configmaps: &Api<ConfigMap>,
    name: &str,
    start: usize,
    end: usize,
) -> Result<(), kube::Error> {
    for index in start..end {
        delete_named(configmaps, &backend_inventory_name(name, index)).await?;
    }
    Ok(())
}

/// Remove everything this operator generated for a backend: its RoleBinding, Role, inventory
/// ConfigMaps and ServiceAccount, in that order.
///
/// The two EndpointSlices a slice-target backend programs are deliberately NOT among them, and no
/// caller may add them: the chart's `controller-no-endpointslices` ValidatingAdmissionPolicy denies
/// this identity every EndpointSlice write, which is the whole point of the boundary — traffic
/// membership is the workload's to write, never the operator's. The workload empties them itself,
/// programming a zero-member set when it receives SIGTERM, which is why every caller deletes the
/// Deployment FIRST and only removes access once the pod is gone: reversing that order would strip
/// the permission the drain needs and leave the slices holding their last member list. What
/// survives a teardown is therefore two endpoint-less slice objects (likewise for a retarget, which
/// abandons the old service's pair) — inert clutter for an operator to collect, not traffic.
pub(crate) async fn delete_backend_access(
    apis: &BackendApis,
    name: &str,
) -> Result<(), kube::Error> {
    delete_named(&apis.role_bindings, name).await?;
    delete_named(&apis.roles, name).await?;
    delete_backend_inventory_range(
        &apis.configmaps,
        name,
        0,
        updated_contracts::backend::BACKEND_INVENTORY_SHARDS,
    )
    .await?;
    delete_named(&apis.service_accounts, name).await
}

pub(crate) async fn finalize_backend(
    apis: &BackendApis,
    backend: &UpdateBackend,
    name: &str,
) -> Result<(), kube::Error> {
    if !backend
        .finalizers()
        .iter()
        .any(|item| item == BACKEND_FINALIZER)
    {
        return Ok(());
    }
    if delete_deployment(&apis.deployments, name).await? {
        return Ok(());
    }
    delete_backend_access(apis, name).await?;
    let finalizers = finalizers_without(backend.finalizers(), BACKEND_FINALIZER);
    apis.backends
        .patch(
            &backend.name_any(),
            &PatchParams::default(),
            &Patch::Merge(finalizer_patch(backend, finalizers)),
        )
        .await?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod backend_tests {
    use super::*;

    /// The SEC1 encoding of the P-256 generator, used wherever a fixture needs a real pinned key.
    const TEST_PUBLIC_KEY: &str =
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

    fn backend(kind: BackendTargetKind) -> UpdateBackend {
        let mut backend = UpdateBackend::new(
            "edge",
            crate::UpdateBackendSpec {
                repository_ref: crate::LocalObjectReference {
                    name: "default".into(),
                },
                selector: crate::LabelSelector {
                    match_labels: BTreeMap::from([("role".into(), "edge".into())]),
                },
                health_base: "https://cdn.example/updated".into(),
                target: BackendTarget {
                    kind,
                    service: (kind == BackendTargetKind::EndpointSlice).then(|| "edge".into()),
                    port: (kind == BackendTargetKind::EndpointSlice).then_some(8080),
                    port_name: (kind == BackendTargetKind::EndpointSlice).then(|| "http".into()),
                    endpoints: if kind == BackendTargetKind::HAProxy {
                        vec!["haproxy-0:9999".into()]
                    } else {
                        Default::default()
                    },
                    backend: (kind == BackendTargetKind::HAProxy).then(|| "fleet".into()),
                },
                interval_seconds: 2,
                health_timeout_seconds: 2,
            },
        );
        backend.metadata.namespace = Some("updated-system".into());
        backend.metadata.uid = Some("backend-uid".into());
        backend
    }

    fn agent(name: &str, address: &str) -> UpdateAgent {
        UpdateAgent::new(
            name,
            crate::UpdateAgentSpec {
                repository_ref: crate::LocalObjectReference {
                    name: "default".into(),
                },
                identity: crate::AgentIdentity {
                    kind: crate::AgentIdentityKind::Enrolled,
                    registration_sha256: Some(updated_contracts::digest::sha256_bytes(
                        name.as_bytes(),
                    )),
                    public_key: Some(TEST_PUBLIC_KEY.into()),
                },
                labels: BTreeMap::from([("role".into(), "edge".into())]),
                backend_address: Some(address.into()),
                hold: false,
                cordon: false,
            },
        )
    }

    #[test]
    fn inventory_is_derived_from_selected_agents_in_stable_order() {
        let backend = backend(BackendTargetKind::EndpointSlice);
        let b = agent("node-b", "10.0.0.2");
        let a = agent("node-a", "10.0.0.1");
        let (inventory, invalid) = validate_backend(&backend, &[&b, &a]).expect("valid backend");
        assert_eq!(invalid, 0);
        assert_eq!(inventory[0].node(), "node-a");
        assert_eq!(inventory[1].node(), "node-b");
        assert!(inventory.iter().all(|member| !member.is_cordoned()));
    }

    #[test]
    fn invalid_active_routes_and_explicit_cordons_share_one_fail_closed_projection() {
        let backend = backend(BackendTargetKind::EndpointSlice);
        let mut node = agent("node-a", "not a route");
        node.spec.identity.public_key = None;
        node.spec.cordon = true;
        let (inventory, invalid) = validate_backend(&backend, &[&node])
            .expect("a malformed route cannot hold its own cordon hostage");
        assert_eq!(invalid, 0, "an explicit cordon is not malformed");
        assert_eq!(
            inventory,
            vec![
                updated_contracts::backend::BackendInventoryMember::Cordoned {
                    node: "node-a".into()
                }
            ]
        );

        node.spec.cordon = false;
        let (inventory, invalid) = validate_backend(&backend, &[&node])
            .expect("one bad endpoint is drained without freezing the complete projection");
        assert_eq!(invalid, 1);
        assert!(inventory[0].is_cordoned());

        let mut malformed = agent("node-a", "10.0.0.1");
        malformed.spec.identity.kind = crate::AgentIdentityKind::Reserved;
        malformed.spec.identity.registration_sha256 = None;
        let (inventory, invalid) = validate_backend(&backend, &[&malformed])
            .expect("a malformed identity is drained, not projected as active");
        assert_eq!(invalid, 1);
        assert!(inventory[0].is_cordoned());
    }

    #[test]
    fn every_configuration_failure_preserves_identities_only_to_drain_them() {
        let active = updated_contracts::backend::BackendInventoryMember::active(
            "node-a",
            "10.0.0.1",
            TEST_PUBLIC_KEY,
        )
        .unwrap();
        let already_cordoned =
            updated_contracts::backend::BackendInventoryMember::cordoned("node-b").unwrap();
        let drained = cordon_backend_inventory(vec![active, already_cordoned]).unwrap();
        assert_eq!(
            drained
                .iter()
                .map(|member| member.node())
                .collect::<Vec<_>>(),
            ["node-a", "node-b"]
        );
        assert!(drained.iter().all(|member| member.is_cordoned()));
    }

    #[test]
    fn fixed_inventory_projection_holds_the_maximum_admitted_fleet() {
        let backend = backend(BackendTargetKind::EndpointSlice);
        let hostname = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(60),
        ]
        .join(".");
        let agents: Vec<UpdateAgent> = (0
            ..updated_contracts::backend::MAX_BACKEND_INVENTORY_MEMBERS)
            .map(|index| {
                let node = [
                    "n".repeat(63),
                    "n".repeat(63),
                    "n".repeat(63),
                    format!("{}-{index:04}", "n".repeat(56)),
                ]
                .join(".");
                agent(&node, &hostname)
            })
            .collect();
        let selected: Vec<&UpdateAgent> = agents.iter().collect();
        let (_, invalid) = validate_backend(&backend, &selected)
            .expect("the fixed projection must hold the admitted fleet ceiling");
        assert_eq!(invalid, 0);

        let too_many = (0..=updated_contracts::backend::MAX_BACKEND_INVENTORY_MEMBERS)
            .map(|index| {
                updated_contracts::backend::BackendInventoryMember::cordoned(format!(
                    "node-{index}"
                ))
                .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(encode_backend_inventory(&too_many).is_err());
    }

    #[test]
    fn target_kinds_reject_fields_from_the_other_integration() {
        let mut backend = backend(BackendTargetKind::EndpointSlice);
        backend.spec.target.endpoints = vec!["haproxy:9999".into()];
        assert_eq!(
            validate_backend(&backend, &[]).unwrap_err().0,
            "InvalidEndpointSliceTarget"
        );
    }

    #[test]
    fn generated_access_writes_only_the_targets_two_stable_slices() {
        let backend = backend(BackendTargetKind::EndpointSlice);
        let role = backend_role(
            &backend,
            "updated-backend-edge",
            BTreeMap::new(),
            backend_owner(&backend),
        );
        let rules = role.rules.expect("role rules");
        assert_eq!(rules.len(), 2);
        // Materializing the slice is a CREATE, which RBAC cannot pin to a resourceName —
        // authorization runs before the request has one — so the bare create verb stands alone.
        assert_eq!(rules[0].verbs, ["create"]);
        assert_eq!(rules[0].resource_names, None);
        // Every ONGOING write is pinned to this backend's two family-specific slices: the
        // per-reconcile patch, the read the family-flip recovery decides on, and the delete
        // that replaces a slice whose address family changed.
        assert_eq!(rules[1].verbs, ["get", "patch", "delete"]);
        assert_eq!(
            rules[1].resource_names.as_deref(),
            Some(
                &[
                    "edge-updated-ipv4".to_string(),
                    "edge-updated-ipv6".to_string()
                ][..]
            )
        );
    }

    #[test]
    fn generated_workload_names_are_bounded_and_stable() {
        let long = "a".repeat(200);
        let first = backend_resource_name(&long);
        assert_eq!(first, backend_resource_name(&long));
        assert_eq!(first.len(), 50);
        let inventories: Vec<String> = (0..updated_contracts::backend::BACKEND_INVENTORY_SHARDS)
            .map(|index| backend_inventory_name(&first, index))
            .collect();
        assert!(inventories.iter().all(|name| name.len() == 63));
        assert_eq!(
            inventories.first().unwrap(),
            &format!("{first}-inventory-00")
        );
        assert_eq!(
            inventories.last().unwrap(),
            &format!("{first}-inventory-07")
        );
    }

    #[test]
    fn two_objects_can_never_own_the_same_traffic_target() {
        let first = backend(BackendTargetKind::EndpointSlice);
        let mut second = backend(BackendTargetKind::EndpointSlice);
        second.metadata.name = Some("other".into());
        second.metadata.uid = Some("other-uid".into());
        let conflicts = backend_target_conflicts([&first, &second].into_iter());
        assert_eq!(conflicts.len(), 2);
        assert!(conflicts.values().all(|target| target.contains("edge")));

        second.spec.target.service = Some("other-service".into());
        assert!(backend_target_conflicts([&first, &second].into_iter()).is_empty());
    }

    #[test]
    fn a_poll_interval_that_would_make_the_last_known_good_bridge_inert_is_refused() {
        // `spec.intervalSeconds` is the healthproxy's per-cycle sleep, and its last-known-good
        // cache drops an entry older than REPORT_FRESHNESS. An interval at (or past) that window
        // means cycle N-1's entry has already expired when cycle N runs — one failed fetch then
        // programs every member not-ready and drains the whole healthy fleet in a single cycle. So
        // the admitted range must end well short of the window, not merely below the old 300.
        let mut backend = backend(BackendTargetKind::EndpointSlice);
        backend.spec.interval_seconds = updated_contracts::telemetry::REPORT_FRESHNESS.as_secs();
        assert_eq!(
            validate_backend(&backend, &[]).unwrap_err().0,
            "InvalidPollPlan"
        );
        // The bound itself, so the schema the apiserver enforces and this check agree on a value
        // that leaves the bridge spanning several consecutive failed cycles.
        assert!(
            crate::BACKEND_INTERVAL_SECONDS_MAX * 3
                <= updated_contracts::telemetry::REPORT_FRESHNESS.as_secs()
        );
        backend.spec.interval_seconds = crate::BACKEND_INTERVAL_SECONDS_MAX;
        assert!(validate_backend(&backend, &[]).is_ok());
    }

    #[test]
    fn backend_health_origins_use_the_shared_safe_url_grammar() {
        for invalid in [
            "file:///ready",
            "https://user@health.example/ready",
            "https://health.example/ready?token=secret",
            "https://health.example/ready#fragment",
            "health.example/ready",
        ] {
            let mut backend = backend(BackendTargetKind::EndpointSlice);
            backend.spec.health_base = invalid.into();
            assert_eq!(
                validate_backend(&backend, &[]).unwrap_err().0,
                "InvalidHealthBase",
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn runtime_image_configuration_is_strict() {
        assert!(validate_backend_runtime(&BackendRuntimeConfig {
            image: "registry.example/healthproxy@sha256:abcd".into(),
            image_pull_policy: "Never".into(),
        })
        .is_ok());
        assert!(validate_backend_runtime(&BackendRuntimeConfig {
            image: String::new(),
            image_pull_policy: "Sometimes".into(),
        })
        .is_err());
    }
}
