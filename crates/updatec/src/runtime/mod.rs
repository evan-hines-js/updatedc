//! The controller runtime: everything one reconcile pass of `updatec controller` does.
//!
//! The pass has a fixed spine — hold the lease, read the fleet, converge backends, plan and
//! publish a generation, then write back what happened — and each stage below owns one segment of
//! it. They were a single 6,000-line module, where a change to the S3 client and a change to the
//! status writer touched the same file and the only thing separating them was scroll position.
//!
//! Shared imports and the cross-stage helpers live here; each submodule reaches them through
//! `use super::*`, so the stages stay one namespace and no stage re-imports the world.
//!
//! - [`lease`] — the single-writer Lease this controller reconciles under.
//! - [`store`] — the S3 client, presigner and object-store plumbing behind a repository.
//! - [`publish`] — signing and mirroring one generation, plus TUF metadata expiry and renewal.
//! - [`repository`] — an `UpdateRepository`'s ownership, finalizer and deletion drain.
//! - [`backend`] — reconciling `UpdateBackend` children: Deployment, RBAC, access and inventory.
//! - [`admitted`] — the admitted rollout state, sharded across ConfigMaps and recovered on restart.
//! - [`enrollment`] — the per-node enrollment objects published for the gateway to serve.
//! - [`status`] — conditions, quarantine and every status write the pass makes.
//! - [`reconcile`] — the pass itself, which drives all of the above in order.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use futures::StreamExt;
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec, DeploymentStrategy};
use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::api::core::v1::{
    Capabilities, ConfigMap, ConfigMapProjection, Container, EnvVar, KeyToPath, PodSecurityContext,
    PodSpec, PodTemplateSpec, ProjectedVolumeSource, ResourceRequirements, SeccompProfile, Secret,
    SecurityContext, ServiceAccount, Volume, VolumeMount, VolumeProjection,
};
use k8s_openapi::api::rbac::v1::{PolicyRule, Role, RoleBinding, RoleRef, Subject};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{
    LabelSelector as KubernetesLabelSelector, MicroTime, OwnerReference,
};
use k8s_openapi::ByteString;
use kube::api::{Api, DeleteParams, ListParams, Patch, PatchParams, PostParams};
use kube::{Client, Resource, ResourceExt};
use object_store::aws::{AmazonS3, AmazonS3Builder, AwsCredential};
use object_store::signer::Signer;
use object_store::{ObjectStore, ObjectStoreExt, PutMode, PutOptions, PutPayload, UpdateVersion};
use tokio::io::AsyncReadExt as _;

use crate::publisher::{publication_plan, PublishError};
use crate::rollout::SetStatus;
use crate::S3Destination;
use crate::{
    BackendTarget, BackendTargetKind, RepositoryStorageOwnership, ResolvedGroup, ResolvedNode,
    ResourceCondition, UpdateAdmissionPolicy, UpdateAgent, UpdateAgentStatus, UpdateBackend,
    UpdateBackendStatus, UpdateGroup, UpdateGroupSet, UpdateGroupSetStatus, UpdateGroupStatus,
    UpdateRepository, UpdateRepositoryStatus, UpdateSubscription,
};
use updated_contracts::key::P256PublicKey;
use updated_contracts::telemetry::Envelope;

/// Test-only: pins the chart's controller write-boundary policy to the naming rules below.
#[cfg(test)]
mod chart_boundary;

const LEASE_SECONDS: i32 = 15;
const BACKEND_FINALIZER: &str = "updated.dev/backend-resources";
const BACKEND_FIELD_MANAGER: &str = "updatec-backends";

pub(crate) const MAX_ADMITTED_STATE_SHARDS: usize = 64;
/// Headroom below the ConfigMap 1 MiB data ceiling for metadata and serialization overhead.
///
/// Deliberately 132 KiB tighter than [`updated_contracts::backend::BACKEND_INVENTORY_SHARD_MAX_BYTES`],
/// which answers the same question for the other ConfigMap family this operator writes: a state
/// shard's payload is `binaryData`, base64 on the wire, so these bytes cost 4/3 of themselves in
/// the object the apiserver validates and etcd stores — 768 KiB is exactly 1 MiB encoded. An
/// inventory shard's payload is a UTF-8 `data` value that costs its own length, so it can spend
/// 900 KiB and still leave metadata room. The two numbers differ because the two payloads are
/// measured in different units, not because either is a guess.
const ADMITTED_STATE_SHARD_MAX_BYTES: usize = 768 * 1024;
const ADMITTED_STATE_FORMAT: u8 = 1;
const LOCAL_TUF_METADATA_MAX_BYTES: usize = 16 * 1024 * 1024;
const PUBLICATION_MARKER_MAX_BYTES: usize = 512;
const PUBLISHED_GENERATION_FILE: &str = "published-generation.json";
const PENDING_STATE_MAX_BYTES: usize =
    MAX_ADMITTED_STATE_SHARDS * ADMITTED_STATE_SHARD_MAX_BYTES + 64 * 1024;

/// Async wrapper over the one bounded opened-handle reader. Controller state is node-owned, so a
/// final symlink is always corruption; blocking filesystem work is kept off the reconcile task.
async fn read_local_bounded(path: &Path, limit: usize) -> std::io::Result<Vec<u8>> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        foundation::file::read_bounded_regular(&path, limit, foundation::file::FinalSymlink::Refuse)
    })
    .await
    .map_err(std::io::Error::other)?
}

mod admitted;
mod backend;
mod enrollment;
mod lease;
mod publish;
mod reconcile;
mod repository;
mod status;
mod store;

pub(crate) use admitted::*;
pub use backend::*;
pub(crate) use enrollment::*;
pub use lease::*;
pub use publish::*;
pub use reconcile::*;
pub(crate) use repository::*;
pub use status::*;
pub use store::*;
